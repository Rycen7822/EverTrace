"""On-demand Jobs read model over bounded native facts; no scheduler, cache or System snapshot."""

import json

from .backend import BackendError, _decode


async def read_jobs(backend, after=None, expected_frontier=None):
    query = {"expected_frontier": expected_frontier}
    if after is not None:
        try:
            cursor = _decode(after.encode("utf-8"))
        except (AttributeError, BackendError) as error:
            raise BackendError("invalid_input") from error
        if not isinstance(cursor, dict) or set(cursor) != {"frontier", "data_identity", "after"} or cursor["after"] is None:
            raise BackendError("invalid_input")
        if expected_frontier is not None and expected_frontier != cursor["frontier"]:
            raise BackendError("invalid_input")
        query = {
            "expected_frontier": cursor["frontier"],
            "expected_data_identity": cursor["data_identity"],
            "after": cursor["after"],
        }
    result = await backend.jobs(query)
    if result["kind"] == "conflict":
        return result
    page = result["page"]
    state = page["state"]
    next_cursor = None
    if page["next_cursor"] is not None:
        next_cursor = json.dumps({
            "frontier": state["frontier"], "data_identity": state["data_identity"], "after": page["next_cursor"],
        }, separators=(",", ":"))
    return {
        "kind": "jobs", "records": page["records"], "frontier": state["frontier"],
        "total_count": page["record_count"], "next_cursor": next_cursor,
    }
