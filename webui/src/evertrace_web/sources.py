"""Source and revision reading models. Native owns identities, visibility, metadata counts and keyset selection."""
import json
from datetime import datetime, timezone
from pathlib import PurePosixPath

from .backend import BackendError, _decode, _read_boundary, normalize_source_query, normalize_archive_query
from .memories import _metadata_card

_REFERENCE_ALGORITHM = "source_revision_reference_metadata_v2"
_ARCHIVE_ALGORITHM = "source_archive_metadata_v1"
_CATALOG_ALGORITHM = "scoped_source_metadata_v1"
_SOURCE_SELECTION_LABELS = {
    "catalogue":"已登记目录", "historical_metadata":"已证明的历史归属", "prospective_origin":"实际观察后的前瞻区间",
    "retained_record":"已保留归档记录的范围", "task_request":"Task引用的原始请求", "unassigned":"暂无已证明仓库/工作树",
}
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
    retained_note = "这个范围命中的是保留的归档记录，不能据此认定当前文件也属于这里。"
    return {**record, "selection_label":_SOURCE_SELECTION_LABELS[record["selection_basis"]],
            "selection_note":retained_note if record["selection_basis"] == "retained_record" else None,
            "body_label":_BODY_LABELS.get(record["body_state"], record["body_state"]), "progress_label":progress,
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
    if query["selection"]["kind"] == "task" and page["state"] == "ready":
        final = await backend.read_batch([{"kind":"sources", "query":query, "after":position, "limit":limit}],
            batch["state"]["frontier"], batch["state"]["data_identity"])
        if final["kind"] == "conflict":
            return final
        current = final["page"]["items"][0]["page"]
        if (final["page"]["state"] != batch["state"] or current["query"] != query
            or current["state"] == "ready" and current["selection_ref"] != page["selection_ref"]):
            return {"kind":"conflict"}
        page = current
        entries = [_source_entry(record) for record in page["records"]]
        if page["next"] is None:
            next_cursor = None
    groups = {}
    for entry in entries:
        groups.setdefault(entry["session_id"], []).append(entry)
    return {"kind":"source_catalog", "page":{"query":query, "entries":entries,
        "groups":[{"session_id":session, "entries":items} for session, items in groups.items()],
        "frontier":batch["state"]["frontier"], "next_cursor":next_cursor, "matching_count":page["matching_count"], "state":page["state"],
        "count_basis":{"unit":"source_instance", "range":{"kind":"committed_catalogue", "query":query},
                      "time_kind":"current", "accuracy":"exact" if page["matching_count"] is not None else "unknown"}}}



def _inline_directory(text, info, total):
    if info["source_kind"] != "codex_hook" or info["record"]["presentation"] != "inline" or total > 32768:
        return None
    if total != info["source"]["protected_bytes"] or len(text.encode()) != total:
        return None
    try:
        value = _decode(text.encode())
    except (BackendError, ValueError, UnicodeError):
        return None
    if not isinstance(value, dict) or value.get("session_id") != info["source_session_ref"]:
        return None
    directory = value.get("cwd")
    if (not isinstance(directory, str) or not directory.startswith("/") or len(directory.encode()) > 4096
        or ".." in PurePosixPath(directory).parts or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in directory)):
        return None
    return directory


async def _source_preview(backend, reference, revision, meta):
    info, identity = meta["info"], meta["state"]["data_identity"]
    chunks, offset, total = [], 0, None
    # At most 64KiB of the stored presentation, not the CAS record; UTF-8 boundaries may require a ninth window.
    for _ in range(9):
        reply = await backend.read_source_window(reference, revision, {"offset":offset, "length":8192},
            identity, info["source"], field="presentation")
        if reply["kind"] == "conflict":
            return "conflict", None, None
        page = reply["page"]
        if page["content_state"] != "ready":
            return page["content_state"], None, None
        window = page["window"]
        if (page["source"] != info["source"] or page["selection"] != meta["selection"]
            or page["state"]["data_identity"] != identity):
            return "conflict", None, None
        if (window is None or window["start"] != offset or window["end"] - offset != len(window["text"].encode())
            or total is not None and total != window["total_bytes"] or window["end"] <= offset < window["total_bytes"]):
            raise BackendError("invalid_read_response")
        chunks.append(window["text"])
        offset, total = window["end"], window["total_bytes"]
        if offset >= min(total, 65536):
            text = "".join(chunks).encode()[:65536].decode("utf-8", errors="ignore")
            return "ready", text, total
    raise BackendError("invalid_read_response")


async def read_source_detail(backend, reference, frontier, revision, object_kind):
    """A gated immutable source pair; labels and stored-text preview are Python projections, not source authority."""
    if object_kind not in ("source_receipt", "source_observation"):
        raise BackendError("invalid_input")
    reply = await backend.read_record_window(reference, revision)
    if reply["kind"] == "conflict":
        return reply
    meta = reply["page"]
    if meta["state"]["frontier"] < frontier:
        return {"kind":"conflict"}
    row = meta["metadata"]
    if row is None:
        return {"kind":"detail", "items":[]}
    if row["object_kind"] != object_kind or revision is not None and row["current_revision_id"] != revision:
        raise BackendError("invalid_input")
    revision, state, info = row["current_revision_id"], meta["content_state"], meta["info"]
    evidence, context = None, None
    if state == "ready":
        if info is None or info["kind"] != "source":
            raise BackendError("invalid_read_response")
        record, source = info["record"], info["source"]
        text, total, presentation = None, None, None
        if record["presentation"] in ("inline", "preview"):
            state, text, total = await _source_preview(backend, reference, revision, meta)
            if state == "conflict":
                return {"kind":"conflict"}
            if state == "ready":
                presentation = {"kind":"inline" if record["presentation"] == "inline" and len(text.encode()) == total else "preview",
                                "text":text}
        elif record["presentation"] == "non_text":
            presentation = {"kind":"unavailable"}
        if state == "ready":
            directory = None
            catalog = await backend.read_batch([{"kind":"sources", "query":{
                "session_id":None, "source_instance_id":source["source_instance_ref"], "unassigned_only":False}, "limit":2}],
                expected_data_identity=meta["state"]["data_identity"])
            if catalog["kind"] == "conflict":
                return catalog
            records = catalog["page"]["items"][0]["page"]["records"]
            if len(records) == 1 and records[0]["source_revision"] == source["source_revision"]:
                directory = records[0]["workspace_hint"]
            if directory is None and text is not None:
                directory = _inline_directory(text, info, total)
            context = {"directory":directory, "session":info["source_session_ref"], "event_time_us":record["event_time_us"],
                "recorded_at_us":record["recorded_at_us"], "event_time_provenance":record.get("event_time_provenance")}
            evidence = {"source_kind":info["source_kind"], "observation_role":record["observation_role"],
                "source_role":record["source_role"], "content_trust":record["content_trust"],
                "capture_completeness":record["completeness"], "protected_length":source["protected_bytes"],
                "original_length":source["original_bytes"], "archive_mode":record["archive_mode"],
                "protected_presentation":presentation}
    final = await backend.read_record_window(reference, revision,
        data_identity=meta["state"]["data_identity"], selection=meta["selection"])
    if final["kind"] == "conflict":
        return final
    current = final["page"]
    if current["metadata"] != row or current["selection"] != meta["selection"]:
        return {"kind":"conflict"}
    if current["content_state"] != "ready":
        state, evidence, context = current["content_state"], None, None
    elif current["info"] != info or current["state"]["data_identity"] != meta["state"]["data_identity"]:
        return {"kind":"conflict"}
    return {"kind":"detail", "items":[{**row, "stable_key":row["row_id"], "object_ref":row["object_id"],
        "revision_ref":revision, "evidence_detail":evidence, "source_context":context, "source_state":state}]}


async def read_source_links(backend, reference, frontier, revision, after=None, limit=32):
    if type(limit) is not int or not 1 <= limit <= 32:
        raise BackendError("invalid_input")
    expected, identity = _read_boundary(frontier, None)
    position, bound = None, {"stable_key":reference, "revision_ref":revision}
    if after is not None:
        if not isinstance(after, str) or not 0 < len(after.encode()) <= 4096:
            raise BackendError("invalid_input")
        cursor = _decode(after.encode())
        if (not isinstance(cursor, dict) or set(cursor) != {"algorithm", "reference", "frontier", "data_identity", "position"}
            or cursor["algorithm"] != _REFERENCE_ALGORITHM or cursor["reference"] != bound):
            raise BackendError("invalid_input")
        selected, identity = _read_boundary(cursor["frontier"], cursor["data_identity"])
        if selected is None or identity is None or selected != expected or not isinstance(cursor["position"], str):
            raise BackendError("invalid_input")
        position = cursor["position"]
    item = {"kind":"references", "reference":bound, "after":position, "limit":limit}
    # The first page chooses the current watermark of an exact immutable source; a continuation keeps it fixed.
    result = await backend.read_batch([item], expected if position is not None else None, identity)
    if result["kind"] == "conflict":
        return result
    batch = result["page"]
    if len(batch["items"]) != 1 or batch["items"][0]["kind"] != "references":
        raise BackendError("invalid_read_response")
    state, page = batch["state"], batch["items"][0]["page"]
    if expected is not None and state["frontier"] < expected:
        return {"kind":"conflict"}
    final = await backend.read_batch([item], state["frontier"], state["data_identity"])
    if final["kind"] == "conflict":
        return final
    current = final["page"]["items"][0]["page"]
    if (final["page"]["state"] != state
        or current["content_state"] == "ready" and current["selection"] != page["selection"]):
        return {"kind":"conflict"}
    page = current
    items, unavailable = [], []
    for record in page["records"]:
        if record["content_state"] == "ready":
            row = _metadata_card(record["metadata"])
            row["declared_references"] = record["references"]
            items.append(row)
        else:
            unavailable.append({"references":record["references"], "state":record["content_state"]})
    next_cursor = None
    if page["next"] is not None:
        next_cursor = json.dumps({"algorithm":_REFERENCE_ALGORITHM, "reference":bound, "frontier":state["frontier"],
            "data_identity":state["data_identity"], "position":page["next"]}, ensure_ascii=False, separators=(",", ":"))
        if len(next_cursor.encode()) > 4096:
            raise BackendError("invalid_read_response")
    return {"kind":"source_links", "frontier":state["frontier"], "status":page["content_state"], "items":items,
        "unavailable":unavailable, "matching_count":page["matching_count"], "next_cursor":next_cursor,
        "count_basis":{"unit":"direct_reference_result", "accuracy":"exact" if page["matching_count"] is not None else "unknown",
                       "time_kind":"current", "range":{"reference":bound}}}


def _archive_progress(query, facts):
    if facts is None:
        return None
    end, fence, earlier = (facts[key] for key in ("confirmed_through", "earlier_fence", "earlier_through"))
    length = facts["observed_file_bytes"]
    historical = query["source_revision"] != facts["catalog_source_revision"]
    notes = []
    if historical:
        notes.append("这是保留的历史修订。目录已观测另一个修订，不能把新文件的末尾或状态套到这里。")
    if facts["replacement_recorded"]:
        notes.append("该修订有 replacement 准入记录；单凭这条记录不能确定前驱顺序。")
    if facts["observed_end"] is not None:
        start = facts["record_start"]
        notes.append(f"前瞻观察边界 {facts['observed_end']}；" +
            (f"后续完整记录起点 {start}。" if start is not None else "后续完整记录起点还未确定。"))
        notes.append("观察前的内容不会因前瞻许可自动获批；" + ("该前瞻区间已关闭。" if facts["origin_closed"] else "该前瞻区间未关闭。"))
    if fence is not None:
        notes.append(f"较早段已提交 [0, {earlier})。" if facts["earlier_commitment"]
            else f"较早段水位 {earlier}，尚无已入账的前缀承诺。")
        if earlier < fence:
            notes.append(f"较早段 [{earlier}, {fence}) 尚未处理；不能因为后续排空就称整份来源已导完。")
    if facts["forward_commitment"]:
        notes.append(f"后续段已提交 [{fence}, {end})。" if fence is not None else f"已提交连续前缀 [0, {end})。")
    elif end is not None:
        notes.append(f"后续水位 {end} 尚无对应前缀承诺，不能把它当已处理字节。")
    else:
        notes.append("没有该修订已提交的导入水位，不补成已处理 0 字节。")
    if length is not None:
        notes.append(f"目录上次观测文件长度 {length} 字节；此读取没有重新打开原文件。")
        if end is not None and end < length:
            notes.append(f"后续水位之后的 [{end}, {length}) 尚未处理，可能仍有未结束记录。")
        elif end is not None and end > length:
            notes.append("观测长度已短于原提交水位；保留旧归档，不把缩短后的文件当同一连续前缀。")
    if historical:
        status, label = "historical_revision", "保留的历史修订"
    elif facts["body_state"] == "source_replaced" or length is not None and end is not None and length < end:
        status, label = "source_changed", "已观测来源改写或缩短"
    elif (facts["body_state"] == "imported" and facts["metadata_state"] == "indexed" and end == length
          and facts["forward_commitment"] and (fence is None or earlier == fence)):
        status, label = "observed_eof", "已处理到目录上次观测的末尾"
    elif facts["observed_end"] is not None and facts["record_start"] is None:
        status, label = "boundary_pending", "等待完整记录边界"
    elif end is None:
        status, label = "unprocessed", "尚无已提交导入水位"
    else:
        status, label = "partial", "仅有部分已提交区间"
    return {"status":status, "label":label, "notes":notes}


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
    return {"kind":"source_archive", "page":{**page, "progress":_archive_progress(query, page["progress"]),
        "frontier":expected, "next_cursor":next_cursor,
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
