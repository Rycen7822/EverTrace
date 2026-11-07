"""Source and revision reading models. Native owns identities, visibility, metadata counts and keyset selection."""
import json
from datetime import datetime, timezone

from .backend import BackendError, _decode, _read_boundary, normalize_source_query, normalize_archive_query
from .memories import _metadata_card

_ARCHIVE_ALGORITHM = "source_archive_metadata_v1"
_CATALOG_ALGORITHM = "source_metadata_v1"
_BODY_LABELS = {
    "not_imported":"尚未导入", "queued":"已排队", "importing":"正在导入", "imported":"已记录导入完成",
    "blocked_untrusted":"信任限制", "blocked_unapproved":"未获读取许可", "blocked_scope_unresolved":"归属未确定",
    "partial":"部分已处理", "failed":"导入失败", "source_replaced":"来源已改写",
}
_REVISION_ALGORITHM = "revision_metadata_v1"


def _source_time(value):
    if value is None:
        return "未记录"
    seconds, micros = divmod(value, 1_000_000)
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=micros).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return f"{value} µs（UTC Unix）"


def _source_entry(record):
    origin, start, through, earlier = (record[key] for key in ("observed_end", "record_start", "archived_through", "earlier_through"))
    if origin is None:
        progress = f"已确认前缀水位 {through}" if through is not None else "此修订尚无已提交归档水位"
    else:
        progress = f"观察边界 {origin}；" + (f"后续完整记录起点 {start}" if start is not None else "后续完整记录起点未确定")
        progress += "；观察边界" + ("已关闭" if record["origin_closed"] else "未关闭")
        if through is not None:
            progress += f"；后续水位 {through}；较早前缀水位 " + (str(earlier) if earlier is not None else "未记录")
        else:
            progress += "；此修订尚无已提交归档水位"
    return {**record, "body_label":_BODY_LABELS.get(record["body_state"], record["body_state"]), "progress_label":progress,
            "started_label":_source_time(record["started_at_us"]), "ended_label":_source_time(record["ended_at_us"])}


async def read_source_catalog(backend, query=None, after=None, frontier=None, limit=32):
    query = normalize_source_query(query)
    expected, identity = _read_boundary(frontier, None)
    position = None
    if after is not None:
        if not isinstance(after, str) or not 0 < len(after.encode()) <= 4096:
            raise BackendError("invalid_input")
        cursor = _decode(after.encode())
        if (not isinstance(cursor, dict) or set(cursor) != {"algorithm", "query", "frontier", "data_identity", "position"}
            or cursor["algorithm"] != _CATALOG_ALGORITHM or cursor["query"] != query):
            raise BackendError("invalid_input")
        expected, identity = _read_boundary(cursor["frontier"], cursor["data_identity"])
        if expected is None or identity is None or expected != frontier:
            raise BackendError("invalid_input")
        position = cursor["position"]
        if not isinstance(position, str):
            raise BackendError("invalid_input")
    result = await backend.read_batch([{"kind":"sources", "query":query, "after":position, "limit":limit}], expected, identity)
    if result["kind"] == "conflict":
        return result
    batch = result["page"]
    if len(batch["items"]) != 1 or batch["items"][0]["kind"] != "sources":
        raise BackendError("invalid_read_response")
    page = batch["items"][0]["page"]
    if page["query"] != query:
        raise BackendError("invalid_read_response")
    next_cursor = None
    if page["next"] is not None:
        next_cursor = json.dumps({"algorithm":_CATALOG_ALGORITHM, "query":query, "frontier":batch["state"]["frontier"],
            "data_identity":batch["state"]["data_identity"], "position":page["next"]}, ensure_ascii=False, separators=(",", ":"))
        if len(next_cursor.encode()) > 4096:
            raise BackendError("invalid_read_response")
    entries = [_source_entry(record) for record in page["records"]]
    groups = {}
    for entry in entries:
        groups.setdefault(entry["session_id"], []).append(entry)
    return {"kind":"source_catalog", "page":{"query":query, "entries":entries,
        "groups":[{"session_id":session, "entries":items} for session, items in groups.items()],
        "frontier":batch["state"]["frontier"], "next_cursor":next_cursor, "matching_count":page["matching_count"],
        "count_basis":{"unit":"source_instance", "range":"committed_catalogue", "time_kind":"current", "accuracy":"exact"}}}



async def read_source_archive(backend, query, after=None, frontier=None, limit=32):
    if type(limit) is not int or not 1 <= limit <= 32:
        raise BackendError("invalid_input")
    query = normalize_archive_query(query)
    expected, identity = _read_boundary(frontier, None)
    position = None
    if after is not None:
        if not isinstance(after, str) or not 0 < len(after.encode()) <= 4096:
            raise BackendError("invalid_input")
        cursor = _decode(after.encode())
        if (not isinstance(cursor, dict) or set(cursor) != {"algorithm", "query", "frontier", "data_identity", "position"}
            or cursor["algorithm"] != _ARCHIVE_ALGORITHM or cursor["query"] != query):
            raise BackendError("invalid_input")
        expected, identity = _read_boundary(cursor["frontier"], cursor["data_identity"])
        if expected is None or identity is None or expected != frontier or not isinstance(cursor["position"], dict):
            raise BackendError("invalid_input")
        position = cursor["position"]
    item = {"kind":"archive", "query":query, "after":position, "limit":limit}
    result = await backend.read_batch([item], expected, identity)
    if result["kind"] == "conflict":
        return result
    batch = result["page"]
    if len(batch["items"]) != 1 or batch["items"][0]["kind"] != "archive":
        raise BackendError("invalid_read_response")
    original = batch["items"][0]["page"]
    if original["query"] != query:
        raise BackendError("invalid_read_response")
    page = {**original}
    identity, expected = batch["state"]["data_identity"], batch["state"]["frontier"]
    if page["state"] == "ready" and query["kind"] == "records":
        records = []
        for record in page["entries"]["records"]:
            row = {**record, "preview":None, "preview_truncated":False}
            if record["presentation"] in ("inline", "preview"):
                reply = await backend.read_source_window(record["stable_key"], record["observation_id"],
                    {"offset":0, "length":512}, identity, field="presentation")
                if reply["kind"] == "conflict":
                    return reply
                value = reply["page"]
                if value["content_state"] != "ready":
                    page.update(state=value["content_state"], matching_count=None, next=None)
                    records.clear()
                    break
                source, window = value["source"], value["window"]
                if (source["source_instance_ref"] != query["source_instance_id"] or source["source_revision"] != query["source_revision"]
                    or source["observation_ref"] != record["observation_id"] or source["receipt_ref"] != record["receipt_id"]
                    or value["state"]["data_identity"] != identity):
                    return {"kind":"conflict"}
                if window is None or window["start"] != 0 or window["end"] != len(window["text"].encode()) or window["end"] > 512:
                    raise BackendError("invalid_read_response")
                row["preview"], row["preview_truncated"] = window["text"], window["end"] < window["total_bytes"]
            records.append(row)
        page["entries"] = {"kind":"records", "records":records}
        # The list is fixed-watermark metadata. Recheck after all finite field projections, including current permissions.
        final = await backend.read_batch([item], expected, identity)
        if final["kind"] == "conflict":
            return final
        current = final["page"]["items"][0]["page"]
        if current["state"] != "ready":
            page = {**current}
        elif current != original or final["page"]["state"] != batch["state"]:
            return {"kind":"conflict"}
    next_cursor = None
    if page["next"] is not None:
        next_cursor = json.dumps({"algorithm":_ARCHIVE_ALGORITHM, "query":query, "frontier":expected,
            "data_identity":identity, "position":page["next"]}, ensure_ascii=False, separators=(",", ":"))
        if len(next_cursor.encode()) > 4096:
            raise BackendError("invalid_read_response")
    return {"kind":"source_archive", "page":{**page, "frontier":expected, "next_cursor":next_cursor,
        "count_basis":{"unit":"archive_revision" if query["kind"] == "revisions" else "retained_source_record",
                       "range":query, "time_kind":"current", "accuracy":"exact" if page["matching_count"] is not None else "unknown"}}}


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
