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


def _unavailable(page, reference, revision):
    return {"kind": "content", "content": {"frontier": page["state"]["frontier"], "object_ref": reference,
        "revision_ref": revision, "representation": "source_text", "state": page["content_state"],
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
