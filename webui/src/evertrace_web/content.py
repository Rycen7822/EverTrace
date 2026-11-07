"""Source reading projection and stateless UTF-8 pagination; authority remains in Native exact reads."""
import json

from . import BackendError
from .backend import _decode

_ALGORITHM = "exact_source_utf8_v1"
_LIMIT = 8192
_CURSOR_KEYS = {"algorithm", "reference", "revision", "data_identity", "source", "offset", "backwards"}


def _cursor(reference, revision, identity, source, offset, backwards):
    value = {"algorithm": _ALGORITHM, "reference": reference, "revision": revision, "data_identity": identity,
             "source": source, "offset": offset, "backwards": backwards}
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode()) > 4096:
        raise BackendError("resource_exhausted")
    return encoded


def _selection(after, reference, revision):
    if after is None:
        return 0, False, None, None
    if not isinstance(after, str) or not 0 < len(after.encode()) <= 4096:
        raise BackendError("invalid_input")
    try:
        cursor = _decode(after.encode())
    except (ValueError, UnicodeError, BackendError) as error:
        raise BackendError("invalid_input") from error
    if (not isinstance(cursor, dict) or set(cursor) != _CURSOR_KEYS or cursor["algorithm"] != _ALGORITHM
        or cursor["reference"] != reference or cursor["revision"] != revision
        or type(cursor["offset"]) is not int or not 0 <= cursor["offset"] < 2**64 - 8193
        or type(cursor["backwards"]) is not bool or cursor["backwards"] and cursor["offset"] == 0
        or cursor["data_identity"] is None or cursor["source"] is None):
        raise BackendError("invalid_input")
    return cursor["offset"], cursor["backwards"], cursor["data_identity"], cursor["source"]


def _unavailable(page, reference, revision, representation="source_text"):
    return {"kind": "content", "content": {"frontier": page["state"]["frontier"], "object_ref": reference,
        "revision_ref": revision, "representation": representation, "state": page["content_state"],
        "total_bytes": None, "range_start": None, "range_end": None, "text": None,
        "previous_cursor": None, "next_cursor": None}}


async def read_source_content(backend, reference, frontier, revision, after=None):
    offset, backwards, identity, expected_source = _selection(after, reference, revision)
    start = max(0, offset - _LIMIT) if backwards else offset
    length = max(4, offset - start) if backwards else _LIMIT
    byte_range = {"offset": start, "length": length}
    reply = await backend.read_source_window(reference, revision, byte_range, identity, expected_source)
    if reply["kind"] == "conflict":
        return reply
    page = reply["page"]
    if page["state"]["frontier"] < frontier:
        return {"kind": "conflict"}
    if page["content_state"] != "ready":
        return _unavailable(page, reference, revision)
    window, source = page["window"], page["source"]
    if window is None or source is None or window["total_bytes"] != source["protected_bytes"]:
        raise BackendError("invalid_read_response")
    text = window["text"]
    raw = text.encode()
    if len(raw) > _LIMIT or window["end"] - window["start"] != len(raw):
        raise BackendError("invalid_read_response")
    if backwards:
        if not window["start"] <= offset <= window["end"]:
            raise BackendError("invalid_input")
        try:
            text = raw[:offset - window["start"]].decode()
        except UnicodeDecodeError as error:
            raise BackendError("invalid_input") from error
        end = offset
    else:
        if not window["start_boundary"] or window["start"] != offset:
            raise BackendError("invalid_input")
        end = window["end"]
    start, total = window["start"], window["total_bytes"]
    identity = page["state"]["data_identity"]
    # The final finite metadata assessment does not decode CAS again. It clears
    # the selected bytes if current access, deletion, incarnation or tuple changed.
    final = await backend.read_source_window(reference, revision, None, identity, source)
    if final["kind"] == "conflict":
        return final
    current = final["page"]
    if current["content_state"] != "ready":
        return _unavailable(current, reference, revision)
    if (current["source"] != source or current["state"]["data_identity"] != identity
        or current["selection"] != page["selection"] or current["window"] is not None):
        return {"kind": "conflict"}
    content = _unavailable(current, reference, revision)["content"]
    content.update({"text": text, "total_bytes": total, "range_start": start, "range_end": end,
        "previous_cursor": _cursor(reference, revision, identity, source, start, True) if start > 0 else None,
        "next_cursor": _cursor(reference, revision, identity, source, end, False) if end < total else None})
    return {"kind": "content", "content": content}


DETAIL_KINDS = {"atom_revision": "atom", "procedure_revision": "procedure", "core_membership": "core_membership",
                "semantic_digest": "digest", "revision_proposal_revision": None,
                "work_episode": "work_episode", "capture_receipt": "capture_receipt"}


async def read_record_detail(backend, reference, frontier, revision, object_kind):
    """A selected reading detail, never an Inbox/action or Work/System qualification projection."""
    if object_kind not in DETAIL_KINDS:
        raise BackendError("invalid_input")
    reply = await backend.read_record_window(reference, revision)
    if reply["kind"] == "conflict":
        return reply
    meta = reply["page"]
    if meta["state"]["frontier"] < frontier:
        return {"kind": "conflict"}
    row = meta["metadata"]
    if row is None:
        return {"kind": "detail", "items": []}
    if row["object_kind"] != object_kind or revision is not None and row["current_revision_id"] != revision:
        raise BackendError("invalid_input")
    revision = row["current_revision_id"]
    identity, selection = meta["state"]["data_identity"], meta["selection"]
    state, record, total = meta["content_state"], None, None
    if state == "ready" and DETAIL_KINDS[object_kind] is not None:
        reply = await backend.read_record_window(reference, revision, {"kind": "json"},
            {"offset": 0, "length": _LIMIT}, identity, selection)
        if reply["kind"] == "conflict":
            return reply
        page = reply["page"]
        state = page["content_state"]
        if page["metadata"] != row or page["selection"] != selection:
            return {"kind": "conflict"}
        if state == "ready":
            if page["info"] != meta["info"]:
                return {"kind": "conflict"}
            window = page["window"]
            total = window["total_bytes"]
            if total > _LIMIT:
                state = "too_large"
            elif window["start"] != 0 or window["end"] != total:
                raise BackendError("invalid_read_response")
            else:
                record = _decode(window["text"].encode())
                if not isinstance(record, dict):
                    raise BackendError("invalid_read_response")
    # Recheck after decoding/projection, under the same immutable identity and current access rules.
    reply = await backend.read_record_window(reference, revision, data_identity=identity, selection=selection)
    if reply["kind"] == "conflict":
        return reply
    final = reply["page"]
    if final["metadata"] != row or final["selection"] != selection:
        return {"kind": "conflict"}
    if final["content_state"] != "ready":
        state, record, total = final["content_state"], None, None
    elif final["info"] != meta["info"] or final["state"]["data_identity"] != identity:
        return {"kind": "conflict"}
    detail = None if object_kind == "revision_proposal_revision" and state == "ready" else {
        "object_ref": row["object_id"], "revision_ref": revision, "state": state,
        "preview": None, "original_bytes": total,
        "content": {"kind": DETAIL_KINDS[object_kind], "value": record} if record is not None else None}
    item = {**row, "stable_key": row["row_id"], "object_ref": row["object_id"], "revision_ref": revision,
            "semantic_detail": detail, "proposal": None}
    return {"kind": "detail", "items": [item]}


_RECORD_ALGORITHM = "exact_record_utf8_v1"
_RECORD_KEYS = {"algorithm", "reference", "revision", "representation", "data_identity", "selection", "offset", "backwards"}


def _record_cursor(reference, revision, representation, identity, selection, offset, backwards):
    value = {"algorithm": _RECORD_ALGORITHM, "reference": reference, "revision": revision,
             "representation": representation, "data_identity": identity, "selection": selection,
             "offset": offset, "backwards": backwards}
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode()) > 4096:
        raise BackendError("resource_exhausted")
    return encoded


def _record_selection(after, reference, revision, representation):
    if after is None:
        return 0, False, None, None
    if not isinstance(after, str) or not 0 < len(after.encode()) <= 4096:
        raise BackendError("invalid_input")
    try:
        cursor = _decode(after.encode())
    except (ValueError, UnicodeError, BackendError) as error:
        raise BackendError("invalid_input") from error
    if (not isinstance(cursor, dict) or set(cursor) != _RECORD_KEYS or cursor["algorithm"] != _RECORD_ALGORITHM
        or (cursor["reference"], cursor["revision"], cursor["representation"]) != (reference, revision, representation)
        or type(cursor["offset"]) is not int or not 0 <= cursor["offset"] < 2**64 - 8193
        or type(cursor["backwards"]) is not bool or cursor["backwards"] and cursor["offset"] == 0
        or cursor["data_identity"] is None or cursor["selection"] is None):
        raise BackendError("invalid_input")
    return cursor["offset"], cursor["backwards"], cursor["data_identity"], cursor["selection"]


def _utf8_slice(raw, start, end):
    end = min(end, len(raw))
    while start < end and raw[start] & 0xC0 == 0x80:
        start += 1
    while end > start and end < len(raw) and raw[end] & 0xC0 == 0x80:
        end -= 1
    return raw[start:end], start, end


def _work_parts(info):
    heading = "\n\n未解决事项\n"
    parts = [({"kind": "goal"}, None, info["goal_bytes"]), (None, heading, len(heading.encode()))]
    for index, size in enumerate(info["open_loop_bytes"]):
        label = f"{index + 1}. "
        parts.extend(((None, label, len(label.encode())), ({"kind": "open_loop", "index": index}, None, size), (None, "\n", 1)))
    return parts


async def read_record_content(backend, reference, frontier, revision, representation, after=None):
    if representation not in ("text", "semantic_json"):
        raise BackendError("invalid_input")
    offset, backwards, identity, selection = _record_selection(after, reference, revision, representation)
    reply = await backend.read_record_window(reference, revision, data_identity=identity, selection=selection)
    if reply["kind"] == "conflict":
        return reply
    meta = reply["page"]
    if meta["state"]["frontier"] < frontier:
        return {"kind": "conflict"}
    if meta["content_state"] != "ready":
        return _unavailable(meta, reference, revision, representation)
    identity, selection, info = meta["state"]["data_identity"], meta["selection"], meta["info"]
    start = max(0, offset - _LIMIT) if backwards else offset
    end = offset if backwards else offset + _LIMIT
    if representation == "text" and info["kind"] == "work":
        parts = _work_parts(info)
        total, position, pieces = sum(part[2] for part in parts), 0, []
        if offset > total:
            raise BackendError("invalid_input")
        for field, literal, size in parts:
            lower, upper = max(start, position), min(end, position + size)
            if lower < upper:
                if field is None:
                    raw, leading, _ = _utf8_slice(literal.encode(), lower - position, upper - position)
                    actual_start = position + leading
                else:
                    reply = await backend.read_record_window(reference, revision, field,
                        {"offset": lower - position, "length": max(4, upper - lower)}, identity, selection)
                    if reply["kind"] == "conflict":
                        return reply
                    page = reply["page"]
                    if page["content_state"] != "ready":
                        return _unavailable(page, reference, revision, representation)
                    window = page["window"]
                    if page["info"] != info or page["selection"] != selection or window["total_bytes"] != size:
                        return {"kind": "conflict"}
                    raw, _, _ = _utf8_slice(window["text"].encode(), 0, upper - position - window["start"])
                    actual_start = position + window["start"]
                if raw:
                    if pieces and pieces[-1][0] + len(pieces[-1][1]) != actual_start:
                        raise BackendError("invalid_read_response")
                    pieces.append((actual_start, raw))
            position += size
        text = b"".join(piece[1] for piece in pieces).decode()
        start = pieces[0][0] if pieces else total
        end = start + len(text.encode())
    else:
        field = {"kind": "json" if representation == "semantic_json" else "text"}
        if representation == "text" and info.get("text_bytes") is None:
            return _unavailable({**meta, "content_state": "unsupported"}, reference, revision, representation)
        reply = await backend.read_record_window(reference, revision, field,
            {"offset": start, "length": max(4, end - start)}, identity, selection)
        if reply["kind"] == "conflict":
            return reply
        page = reply["page"]
        if page["content_state"] != "ready":
            return _unavailable(page, reference, revision, representation)
        window = page["window"]
        if page["info"] != info or page["selection"] != selection:
            return {"kind": "conflict"}
        raw, _, _ = _utf8_slice(window["text"].encode(), 0, min(window["end"], end) - window["start"])
        start, end, total = window["start"], window["start"] + len(raw), window["total_bytes"]
        text = raw.decode()
    if (backwards and end != offset) or (not backwards and start != offset):
        raise BackendError("invalid_input")
    if end - start != len(text.encode()) or len(text.encode()) > _LIMIT:
        raise BackendError("invalid_read_response")
    final = await backend.read_record_window(reference, revision, data_identity=identity, selection=selection)
    if final["kind"] == "conflict":
        return final
    current = final["page"]
    if current["content_state"] != "ready":
        return _unavailable(current, reference, revision, representation)
    if (current["info"] != info or current["selection"] != selection or current["window"] is not None
        or current["state"]["data_identity"] != identity):
        return {"kind": "conflict"}
    content = _unavailable(current, reference, revision, representation)["content"]
    content.update({"text": text, "total_bytes": total, "range_start": start, "range_end": end,
        "previous_cursor": _record_cursor(reference, revision, representation, identity, selection, start, True) if start else None,
        "next_cursor": _record_cursor(reference, revision, representation, identity, selection, end, False) if end < total else None})
    return {"kind": "content", "content": content}
