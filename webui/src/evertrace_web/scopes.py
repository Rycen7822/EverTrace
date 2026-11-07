"""Scope directory presentation over Native-authorized identities, input fields and exact/unknown counts."""
import json
from pathlib import PurePosixPath

from .backend import BackendError, _decode, _read_boundary, normalize_scope_query

_ALGORITHM = "scope_metadata_v1"


def _text(value):
    return " ".join("".join(" " if ord(char) < 32 or 127 <= ord(char) < 160 else char for char in value).split())


def _entry(record):
    selection = record["selection"]
    kind = selection["kind"]
    if kind == "task":
        label = _text(record["goal"]) if record["goal"] is not None else ""
        label = label or f"任务 {selection['task_id']}"
        title_state = "content_ready" if record["goal_state"] == "ready" else record["goal_state"]
    else:
        path = record["path_hint"]
        name = PurePosixPath(path).name if path else ""
        label = _text(name if name not in ("", "..") else path or "")
        label = label or (f"工作树 {selection['worktree_id']}" if kind == "worktree" else selection["repository_id"])
        title_state = "metadata"
    restrictions = ["current_access_not_evaluated"]
    if record["repository_user_disabled"]:
        restrictions.append("user_disabled")
    if record["repository_trust_revoked"]:
        restrictions.append("trust_revoked")
    if kind == "worktree" and record["lifecycle"] != "active":
        restrictions.append("worktree_not_active")
    return {key:record[key] for key in ("stable_key", "selection", "path_hint", "branch_hint", "lifecycle", "has_children")} | {
        "label":label[:160], "title_state":title_state, "restrictions":restrictions,
    }


async def read_scopes(backend, query=None, after=None, frontier=None, limit=32):
    query = normalize_scope_query(query)
    expected, identity = _read_boundary(frontier, None)
    position = None
    if after is not None:
        if not isinstance(after, str) or not 0 < len(after.encode()) <= 4096:
            raise BackendError("invalid_input")
        cursor = _decode(after.encode())
        if (not isinstance(cursor, dict) or set(cursor) != {"algorithm", "query", "frontier", "data_identity", "position"}
            or cursor["algorithm"] != _ALGORITHM or cursor["query"] != query):
            raise BackendError("invalid_input")
        expected, identity = _read_boundary(cursor["frontier"], cursor["data_identity"])
        if expected is None or identity is None or expected != frontier:
            raise BackendError("invalid_input")
        position = cursor["position"]
        if not isinstance(position, str):
            raise BackendError("invalid_input")
    result = await backend.read_batch([{"kind":"scopes", "query":query, "after":position, "limit":limit}], expected, identity)
    if result["kind"] == "conflict":
        return result
    batch = result["page"]
    if len(batch["items"]) != 1 or batch["items"][0]["kind"] != "scopes":
        raise BackendError("invalid_read_response")
    page = batch["items"][0]["page"]
    if page["query"] != query:
        raise BackendError("invalid_read_response")
    next_cursor = None
    if page["next"] is not None:
        next_cursor = json.dumps({"algorithm":_ALGORITHM, "query":query, "frontier":batch["state"]["frontier"],
            "data_identity":batch["state"]["data_identity"], "position":page["next"]}, ensure_ascii=False, separators=(",", ":"))
        if len(next_cursor.encode()) > 4096:
            raise BackendError("invalid_read_response")
    count = page["matching_count"]
    return {"kind":"scopes", "page":{"query":query, "frontier":batch["state"]["frontier"], "items":[_entry(row) for row in page["records"]],
        "parent_available":page["parent_available"], "complete":page["parent_available"], "names_complete":page["names_complete"],
        "next_cursor":next_cursor, "matching_count":count,
        "count_basis":{"unit":"scope_identity", "parent":query["parent"], "time_kind":"current",
                       "accuracy":"exact" if count is not None else "unknown"}}}
