"""Read-only usage/support evidence with separately gated current canonical metadata."""
import asyncio
import json

from . import BackendError
from .content import _decode_cursor, read_record_detail
from .sources import read_source_links

SUPPORT_DETAIL_KINDS = {"global_support_contract", "global_support_validation"}

USAGE_DETAIL_KINDS = {"procedure_usage_revision", "procedure_negative_evidence", "procedure_negative_review", "procedure_context_effect"}


async def read_recall_trace(backend, reference, revision, request_id=None, after=None):
    """Read existing Need-scoped facts, never due/claim/cue or a generated request log."""
    try:
        return await _read_recall_trace(backend, reference, revision, request_id, after)
    except TimeoutError as error:
        raise BackendError("resource_exhausted") from error


async def _read_recall_trace(backend, reference, revision, request_id, after):
    if request_id is not None and (not isinstance(request_id, str)
        or any(ord(char) < 32 or 127 <= ord(char) < 160 or 0xD800 <= ord(char) <= 0xDFFF for char in request_id)
        or not 0 < len(request_id.encode()) <= 512):
        raise BackendError("invalid_input")
    cursor = None
    if after is not None:
        cursor = _decode_cursor(after)
        keys = {"algorithm", "reference", "revision", "request_id", "frontier", "data_identity", "after"}
        if (not isinstance(cursor, dict) or set(cursor) != keys or cursor["algorithm"] != "recall-ledger-1"
            or cursor["reference"] != reference or cursor["revision"] != revision or cursor["request_id"] != request_id
            or type(cursor["after"]) is not int or not 0 < cursor["after"] < 2**64):
            raise BackendError("invalid_input")
    async with asyncio.timeout(2):
        metadata = await backend.read_record_window(reference, None)
        if metadata["kind"] == "conflict":
            return metadata
        current = metadata["page"]
        state = current["state"]
        page = {"reference":reference, "revision":revision, "request_id":request_id, "frontier":state["frontier"],
                "state":current["content_state"], "events":[], "history_state":"unknown", "agent_seen":"unknown",
                "next_cursor":None, "previous_cursor":None}
        if page["state"] != "ready":
            return {"kind":"recall_trace", "page":page}
        if current["info"]["kind"] != "current_recall":
            raise BackendError("invalid_input")
        active_request = current["info"]["active_retrieval_request_id"]
        if current["selection"]["revision_ref"] != revision:
            return {"kind":"conflict"}
        if cursor is not None and (cursor["frontier"] != state["frontier"]
                                   or cursor["data_identity"] != state["data_identity"]):
            return {"kind":"conflict"}
        result = await backend.read_batch([{"kind":"recall_ledger", "reference":{"stable_key":reference, "revision_ref":None},
            "after":cursor["after"] if cursor else None, "limit":32}], state["frontier"], state["data_identity"])
        if result["kind"] == "conflict":
            return result
        batch = result["page"]
        item, = batch["items"]
        if item["kind"] != "recall_ledger" or batch["state"] != state:
            raise BackendError("invalid_read_response")
        native = item["page"]
        if native["reference"] != {"stable_key":reference, "revision_ref":None}:
            raise BackendError("invalid_read_response")
        page["state"] = native["content_state"]
        if page["state"] != "ready":
            return {"kind":"recall_trace", "page":page}
        events = native["records"]
        if not isinstance(events, list) or len(events) > 32:
            raise BackendError("invalid_read_response")
        last, matched = cursor["after"] if cursor else 0, False
        for event in events:
            seq = event.get("source_event_seq")
            if type(seq) is not int or not last < seq <= state["frontier"]:
                raise BackendError("invalid_read_response")
            last = seq
            if event.get("kind") not in ("need_recorded", "presentation_attempt", "retrieval_outcome"):
                raise BackendError("invalid_read_response")
            if event["kind"] == "retrieval_outcome":
                if event["outcome"]["request_id"] != active_request:
                    raise BackendError("invalid_read_response")
                if request_id is not None and active_request != request_id:
                    continue
                matched = True
            page["events"].append(event)
        next_scan = native["next_scan"]
        if next_scan is not None:
            minimum = max(last, cursor["after"] if cursor else 0)
            if type(next_scan) is not int or not minimum <= next_scan < state["frontier"]:
                raise BackendError("invalid_read_response")
            page["next_cursor"] = json.dumps({"algorithm":"recall-ledger-1", "reference":reference, "revision":revision,
                "request_id":request_id, "frontier":state["frontier"], "data_identity":state["data_identity"], "after":next_scan},
                separators=(",", ":"))
        if matched or request_id is None and events:
            page["history_state"] = "recorded"
        # The writer binds at most one retrieval request to this Need, never replacing it.
        # A matching current identity is not a historical event; leave it unknown until read.
        elif request_id is not None and active_request != request_id:
            page["history_state"] = "not_recorded"
        sealed = await backend.read_record_window(reference, None,
            data_identity=state["data_identity"], selection=current["selection"])
        if sealed["kind"] == "conflict" or not _same_page(current, sealed["page"]):
            return {"kind":"conflict"}
        return {"kind":"recall_trace", "page":page}


def _same_page(before, after):
    return (before["state"]["data_identity"] == after["state"]["data_identity"]
        and all(before[key] == after[key] for key in ("metadata", "selection", "content_state", "info")))


async def read_usage_detail(backend, reference, frontier, revision, object_kind):
    try:
        async with asyncio.timeout(2):
            return await _read_usage(backend, reference, frontier, revision, object_kind)
    except TimeoutError as error:
        raise BackendError("resource_exhausted") from error


async def _read_usage(backend, reference, frontier, revision, object_kind):
    # A review is one immutable event ID, not a logical object with a current revision.
    if object_kind == "procedure_negative_review" and revision is None:
        revision = reference
    reply = await backend.read_record_window(reference, revision)
    if reply["kind"] == "conflict":
        return reply
    origin = reply["page"]
    identity = origin["state"]["data_identity"]
    result = await read_record_detail(backend, reference, frontier, revision, object_kind, data_identity=identity)
    if result["kind"] == "conflict" or not result["items"]:
        return result
    item = result["items"][0]
    detail = item["semantic_detail"]
    if detail["state"] != "ready":
        return result
    content = detail["content"]
    value = content["value"]
    procedure_revision = value.get("procedure_revision_id")
    context = {"state":"missing", "recorded_revision":procedure_revision}
    seals = [(reference, revision, origin)]
    if object_kind == "procedure_negative_review":
        key = value["negative_evidence_id"]
        reply = await backend.read_record_window(key, key, data_identity=identity)
        if reply["kind"] == "conflict":
            return reply
        seals.append((key, key, reply["page"]))
        negative = await read_record_detail(backend, key, frontier, key, "procedure_negative_evidence", data_identity=identity)
        if negative["kind"] == "conflict":
            return negative
        context["state"] = reply["page"]["content_state"]
        if negative["items"]:
            parent = negative["items"][0]["semantic_detail"]
            context["state"] = parent["state"]
            if parent["state"] == "ready":
                procedure_revision = parent["content"]["value"]["procedure_revision_id"]
                context["recorded_revision"] = procedure_revision
    if procedure_revision:
        reply = await backend.read_record_window(procedure_revision, procedure_revision, data_identity=identity)
        if reply["kind"] == "conflict":
            return reply
        pinned = reply["page"]
        seals.append((procedure_revision, procedure_revision, pinned))
        context["state"] = pinned["content_state"]
        if pinned["content_state"] == "ready":
            if pinned["metadata"]["object_kind"] != "procedure_revision":
                raise BackendError("invalid_read_response")
            procedure_id = pinned["metadata"]["object_id"]
            reply = await backend.read_record_window(procedure_id, None, data_identity=identity)
            if reply["kind"] == "conflict":
                return reply
            current = reply["page"]
            seals.append((procedure_id, None, current))
            context.update({"state":current["content_state"], "metadata":current["metadata"]})
    # Compare the exact pages used above; an unrelated append does not invalidate immutable facts.
    for key, selected_revision, before in seals:
        reply = await backend.read_record_window(key, selected_revision,
            data_identity=identity, selection=before["selection"])
        if reply["kind"] == "conflict" or not _same_page(before, reply["page"]):
            return {"kind":"conflict"}
    content["procedure_now"] = context
    content["current_review"] = item.get("lifecycle") if object_kind == "procedure_negative_evidence" else None
    return result


async def read_support_detail(backend, reference, frontier, revision, object_kind):
    try:
        async with asyncio.timeout(2):
            return await _read_support(backend, reference, frontier, revision or reference, object_kind)
    except TimeoutError as error:
        raise BackendError("resource_exhausted") from error


def _link_seal(page):
    return tuple(page[key] for key in ("status", "items", "unavailable", "matching_count"))


async def _read_support(backend, reference, frontier, revision, object_kind):
    reply = await backend.read_record_window(reference, revision)
    if reply["kind"] == "conflict":
        return reply
    origin, seals = reply["page"], []
    identity = origin["state"]["data_identity"]
    result = await read_record_detail(backend, reference, frontier, revision, object_kind, data_identity=identity)
    if result["kind"] == "conflict" or not result["items"]:
        return result
    detail = result["items"][0]["semantic_detail"]
    if detail["state"] != "ready":
        return result
    content, value = detail["content"], detail["content"]["value"]
    seals.append((reference, revision, origin))
    successor = value["successor_revision_or_membership_ref"] if object_kind == "global_support_contract" else value["successor_ref"]
    contract = value["support_contract_revision_id"] if object_kind == "global_support_contract" else value["support_contract_ref"]
    reply = await backend.read_record_window(successor, successor, data_identity=identity)
    if reply["kind"] == "conflict":
        return reply
    pinned = reply["page"]
    seals.append((successor, successor, pinned))
    current = {"state":pinned["content_state"], "recorded_revision":successor}
    if pinned["content_state"] == "ready":
        public = pinned["metadata"]["object_id"]
        reply = await backend.read_record_window(public, None, data_identity=identity)
        if reply["kind"] == "conflict":
            return reply
        now = reply["page"]
        seals.append((public, None, now))
        current.update({"state":now["content_state"], "metadata":now["metadata"]})
    event, links, after, bound = {"state":"unavailable"}, [], None, 0
    for _ in range(3):
        page = await read_source_links(backend, contract, bound, contract, after)
        if page["kind"] == "conflict":
            return page
        links.append((after, bound, page))
        if page["status"] != "ready":
            event = {"state":page["status"]}
            break
        choices = [item for item in page["items"] if item["object_kind"] == "global_support_validation"]
        if len(choices) > 1:
            raise BackendError("invalid_read_response")
        if choices:
            selected = choices[0]
            reply = await read_record_detail(backend, selected["stable_key"], 0, selected["revision_ref"],
                "global_support_validation", data_identity=identity)
            if reply["kind"] == "conflict":
                return reply
            if reply["items"]:
                selected_detail = reply["items"][0]["semantic_detail"]
                event = {"state":selected_detail["state"]}
                if selected_detail["state"] == "ready":
                    latest = selected_detail["content"]["value"]
                    if latest["support_contract_ref"] != contract:
                        raise BackendError("invalid_read_response")
                    event["value"] = latest
            break
        if page["next_cursor"] is None:
            break
        after, bound = page["next_cursor"], page["frontier"]
    for key, selected_revision, before in seals:
        reply = await backend.read_record_window(key, selected_revision, data_identity=identity, selection=before["selection"])
        if reply["kind"] == "conflict" or not _same_page(before, reply["page"]):
            return {"kind":"conflict"}
    for after, bound, before in links:
        page = await read_source_links(backend, contract, bound, contract, after)
        if page["kind"] == "conflict" or _link_seal(page) != _link_seal(before):
            return {"kind":"conflict"}
    content.update({"asset_now":current, "contract_now":event})
    return result
