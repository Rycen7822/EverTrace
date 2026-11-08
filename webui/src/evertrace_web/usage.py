"""Stored facts plus separately observed current Procedure metadata; never route or write."""
import asyncio

from . import BackendError
from .content import read_record_detail

USAGE_DETAIL_KINDS = {"procedure_usage_revision", "procedure_negative_evidence", "procedure_negative_review", "procedure_context_effect"}


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
