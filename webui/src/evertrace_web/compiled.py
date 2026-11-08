"""Present a finite published source page; Native owns references, membership and access."""
import asyncio

from . import BackendError
from .content import read_record_detail


async def read_compiled(backend, query, frontier=None, after=None):
    try:
        async with asyncio.timeout(2):
            return await _read_compiled(backend, query, frontier, after)
    except TimeoutError as error:
        raise BackendError("resource_exhausted") from error


async def _read_compiled(backend, query, frontier, after):
    original = await backend.compiled(query, frontier, after)
    if original["kind"] == "conflict" or original["page"]["kind"] == "directory":
        return original
    page = original["page"]
    entries = []
    for source in page["entries"]:
        entry = {**source, "item":None}
        if source["state"] == "ready":
            detail = await read_record_detail(backend, source["revision_ref"], page["frontier"],
                source["revision_ref"], source["object_kind"], data_identity=page["data_identity"])
            if detail["kind"] == "conflict":
                return detail
            if detail["items"]:
                item = detail["items"][0]
                entry["state"] = item["semantic_detail"]["state"]
                if entry["state"] in ("ready", "too_large"):
                    entry["item"] = item
            else:
                entry["state"] = "missing"
        entries.append(entry)
    # Includes membership permission, source selection and incarnation, after all body decoding.
    final = await backend.compiled(query, frontier, after)
    if final != original:
        return {"kind":"conflict"}
    projected = {**page, "entries":entries,
        "complete":page["complete"] and all(entry["state"] in ("ready", "too_large") for entry in entries)}
    if not any(not entry["contextual"] and entry["item"] for entry in entries):
        projected["title"] = None
    return {**original, "page":projected}
