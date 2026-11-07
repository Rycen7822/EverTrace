"""Source and revision reading models. Native owns identities, visibility, metadata counts and keyset selection."""
import json

from .backend import BackendError, _decode, _read_boundary
from .memories import _metadata_card

_REVISION_ALGORITHM = "revision_metadata_v1"


async def read_revisions(backend, reference, frontier, revision, after=None, limit=32):
    source = {"stable_key":reference, "revision_ref":revision}
    position, expected, identity = None, None, None
    if after is not None:
        if not isinstance(after, str) or not 0 < len(after.encode()) <= 4096:
            raise BackendError("invalid_input")
        cursor = _decode(after.encode())
        if not isinstance(cursor, dict) or set(cursor) != {"algorithm", "reference", "frontier", "data_identity", "position"}:
            raise BackendError("invalid_input")
        if cursor["algorithm"] != _REVISION_ALGORITHM or cursor["reference"] != source:
            raise BackendError("invalid_input")
        expected, identity = _read_boundary(cursor["frontier"], cursor["data_identity"])
        if expected is None or identity is None or expected != frontier:
            raise BackendError("invalid_input")
        position = cursor["position"]
        if not isinstance(position, dict):
            raise BackendError("invalid_input")
    reply = await backend.read_batch([{"kind":"revisions", "reference":source, "after":position, "limit":limit}], expected, identity)
    if reply["kind"] == "conflict":
        return reply
    batch = reply["page"]
    if batch["state"]["frontier"] < frontier or len(batch["items"]) != 1 or batch["items"][0]["kind"] != "revisions":
        return {"kind":"conflict"}
    page = batch["items"][0]["page"]
    if page["reference"] != source:
        raise BackendError("invalid_read_response")
    next_cursor = None
    if page["next"] is not None:
        next_cursor = json.dumps({"algorithm":_REVISION_ALGORITHM, "reference":source,
            "frontier":batch["state"]["frontier"], "data_identity":batch["state"]["data_identity"], "position":page["next"]},
            ensure_ascii=False, separators=(",", ":"))
        if len(next_cursor.encode()) > 4096:
            raise BackendError("invalid_read_response")
    return {"kind":"revisions", "frontier":batch["state"]["frontier"], "source_key":reference,
            "source_revision":revision,
            "items":[{**_metadata_card(row), "source_event_seq":row["source_event_seq"]} for row in page["records"]],
            "status":page["content_state"], "matching_count":page["matching_count"], "next_cursor":next_cursor}
