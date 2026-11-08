"""Request-local, bounded differences over Native-authorized exact pairs; no authority/cache."""
import json

from .backend import BackendError, _decode

_ABSENT = object()
_ALGORITHM = "stored_fields_v1"


class _Budget(Exception):
    pass


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _value(value):
    if value is _ABSENT:
        return {"state": "absent"}
    encoded = _json(value)
    size = len(encoded.encode("utf-8"))
    return {"state": "ready", "json": encoded} if size <= 2048 else {"state": "too_large", "original_bytes": size}


def _differences(left, right):
    nodes, fields = 0, []

    def visit(depth):
        nonlocal nodes
        nodes += 1
        if nodes > 8192 or depth > 128:
            raise _Budget()

    def same(a, b, depth):
        visit(depth)
        if type(a) is not type(b):
            return False
        if isinstance(a, dict):
            if max(len(a), len(b)) > 128:
                raise _Budget()
            return a.keys() == b.keys() and all(same(a[key], b[key], depth + 1) for key in sorted(a))
        if isinstance(a, list):
            return len(a) == len(b) and all(same(x, y, depth + 1) for x, y in zip(a, b))
        return a == b

    def walk(a, b, path, depth):
        visit(depth)
        if isinstance(a, dict) and isinstance(b, dict) and depth < 8:
            if max(len(a), len(b)) > 128:
                raise _Budget()
            for key in sorted(a.keys() | b.keys()):
                escaped = key.replace("~", "~0").replace("/", "~1")
                walk(a.get(key, _ABSENT), b.get(key, _ABSENT), path + "/" + escaped, depth + 1)
            return
        if a is not _ABSENT and b is not _ABSENT and same(a, b, depth):
            return
        if len(fields) >= 128 or len(path.encode("utf-8")) > 1024:
            raise _Budget()
        change = "added" if a is _ABSENT else "removed" if b is _ABSENT else "modified"
        fields.append({"path": path or "/value", "change": change, "left": _value(a), "right": _value(b)})

    walk(left, right, "", 0)
    fields.sort(key=lambda field: field["path"])
    return fields


def _page(pair):
    return {"frontier": pair["left"]["state"]["frontier"], "query": pair["query"], "object_kind": pair["object_kind"],
            "left_state": pair["left"]["content_state"], "right_state": pair["right"]["content_state"],
            "status": "side_unavailable", "fields": [], "changed_fields": None, "next_cursor": None}


def _selection(pair):
    return {name: {key: pair[name][key] for key in ("selection", "source_observation_refs")} for name in ("left", "right")}


async def read_comparison(backend, query, frontier, after=None, limit=8):
    if type(limit) is not int or not 1 <= limit <= 32:
        raise BackendError("invalid_input")
    query = backend._comparison_query(query)
    cursor = None
    if after is not None:
        try:
            cursor = _decode(after.encode("utf-8"))
        except (AttributeError, BackendError) as error:
            raise BackendError("invalid_input") from error
        keys = {"algorithm", "query", "data_identity", "selection", "after_path"}
        if not isinstance(cursor, dict) or set(cursor) != keys or cursor["algorithm"] != _ALGORITHM or cursor["query"] != query:
            raise BackendError("invalid_input")
        if not isinstance(cursor["after_path"], str) or len(cursor["after_path"].encode()) > 1024:
            raise BackendError("invalid_input")
    pair = await backend.read_pair(query)
    if pair["object_kind"] == "result":
        raise BackendError("invalid_input")
    identity = pair["left"]["state"]["data_identity"]
    selection = _selection(pair)
    if cursor and (cursor["data_identity"] != identity or cursor["selection"] != selection):
        return {"kind": "conflict"}
    page = _page(pair)
    if page["left_state"] == page["right_state"] == "ready":
        page["status"] = "budget_exhausted"
        if pair["left"]["fields_complete"] and pair["right"]["fields_complete"]:
            try:
                fields = _differences(pair["left"]["fields"], pair["right"]["fields"])
            except _Budget:
                fields = None
            if fields is not None:
                start = 0
                if cursor:
                    matches = [index for index, field in enumerate(fields) if field["path"] == cursor["after_path"]]
                    if len(matches) != 1:
                        raise BackendError("invalid_input")
                    start = matches[0] + 1
                page.update(status="ready", changed_fields=len(fields))
                for field in fields[start:start + limit]:
                    page["fields"].append(field)
                    if len(_json(page).encode()) > 64 * 1024:
                        page["fields"].pop()
                        break
                if start + len(page["fields"]) < len(fields):
                    if not page["fields"]:
                        raise BackendError("resource_exhausted")
                    page["next_cursor"] = _json({"algorithm": _ALGORITHM, "query": query, "data_identity": identity,
                                                 "selection": selection, "after_path": page["fields"][-1]["path"]})
                    if len(page["next_cursor"].encode()) > 4096:
                        page.update(status="budget_exhausted", fields=[], changed_fields=None, next_cursor=None)
    # No SQL transaction, reader fence, Native snapshot or authorization ticket survives the Python calculation.
    current = await backend.read_pair(query)
    if current["left"]["state"]["data_identity"] != identity:
        return {"kind": "conflict"}
    if any(current[name]["content_state"] != "ready" for name in ("left", "right")):
        page = _page(current)
    elif _selection(current) != selection:
        return {"kind": "conflict"}
    elif any(current[name]["fields"] != pair[name]["fields"]
             or current[name]["fields_complete"] != pair[name]["fields_complete"] for name in ("left", "right")):
        return {"kind": "conflict"}
    page["frontier"] = current["left"]["state"]["frontier"]
    if len(_json(page).encode()) > 64 * 1024:
        raise BackendError("resource_exhausted")
    return {"kind": "revision_comparison", "comparison": page}
