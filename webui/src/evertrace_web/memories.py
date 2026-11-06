"""On-demand memory cards over Native selections and individually authorized stored fields."""

import json
import time

from .backend import BackendError, _decode


def _text(value, limit):
    if not isinstance(value, str):
        return None, False
    encoded = value.encode("utf-8")
    return encoded[:limit].decode("utf-8", "ignore") or None, len(encoded) > limit


def _preview(title, excerpt=None, origin="stored_value", truncated=False):
    if isinstance(title, str):
        title = " ".join(title.replace("；", ", ").replace(";", ", ").split())
    title, title_cut = _text(title, 512)
    excerpt, excerpt_cut = _text(excerpt, 1024)
    return {"state": "ready", "title": title, "excerpt": excerpt,
            "origin": origin if title or excerpt else "type_fallback",
            "truncated": truncated or title_cut or excerpt_cut}


def _unavailable(state):
    return {"state": state, "title": None, "excerpt": None, "origin": None, "truncated": False}


def _body(kind, fields, truncated):
    """Presentation of stored values only; proposal targets never authorize reading other bodies."""
    if kind == "atom_revision":
        value = fields.get("value", {})
        return _preview(value.get("subject"), value.get("text"), truncated=truncated), fields.get("scope")
    if kind == "procedure_revision":
        draft = fields.get("draft", {})
        return _preview(draft.get("title"), draft.get("summary"), truncated=truncated), draft.get("scope")
    if kind == "work_episode":
        phase = fields.get("phase_contract", {})
        loops = fields.get("open_loops", [])
        return _preview(phase.get("local_goal"), "\n".join(loops), truncated=truncated), None
    if kind == "semantic_digest":
        application = fields.get("application", {})
        delta = next((entry for key in ("progress_delta", "decision_delta", "outcome_delta")
                      for entry in application.get(key, []) if entry.get("value", "").strip()), None)
        origins = {"deterministic_only": "digest_deterministic", "llm_enriched": "digest_llm_enriched",
                   "rejected_invalid": "digest_rejected_generation"}
        origin = origins.get(fields.get("status"), "type_fallback")
        return _preview(delta.get("label") if delta else "摘要", delta.get("value") if delta else None,
                        origin, truncated), None
    if kind == "revision_proposal_revision":
        payload = fields.get("payload", {})
        value = payload.get("value", {})
        draft = value.get("draft")
        if payload.get("kind") == "atom":
            if draft:
                atom = draft.get("value", {})
                return _preview(atom.get("subject"), atom.get("text"), truncated=truncated), draft.get("scope")
            if value.get("operation") == "deprecate":
                return _preview("弃用提案", value.get("reason"), truncated=truncated), None
            title = "拆分提案" if value.get("operation") == "split" else "提案参考"
            return _preview(title, origin="type_fallback", truncated=truncated), None
        if payload.get("kind") == "procedure" and draft:
            return _preview(draft.get("title"), draft.get("summary"), truncated=truncated), draft.get("scope")
        if payload.get("kind") == "core_membership":
            title = "规则晋升提案" if value.get("action") == "create" else "规则冲突处理提案"
            return _preview(title, origin="type_fallback", truncated=truncated), None
        return _preview(value.get("summary"), truncated=truncated), None
    return _unavailable("unsupported"), None


def _scope(row, stored):
    if isinstance(stored, dict) and stored.get("kind") == "global":
        return "global"
    # Missing scope is unknown, never implicit global. IDs remain exact Native identities, not paths.
    return " · ".join(row[key] for key in ("task_id", "repository_id", "worktree_id", "workstream_id") if row.get(key)) or None


async def _fields(backend, revision, boundary):
    page = (await backend.read_exact(revision))["page"]
    if page["state"]["data_identity"] != boundary["data_identity"]:
        return None
    selected = page.get("selection")
    if selected is not None and (selected["revision_ref"] != revision or selected["source_event_seq"] > boundary["frontier"]):
        return None
    return page


def _metadata_card(row):
    return {**row, "stable_key": row["row_id"], "revision_ref": row["current_revision_id"],
            "object_ref": row.get("object_id") or row["row_id"], "proposal": None, "scope_ref": _scope(row, None)}


async def _card(backend, row, boundary):
    item = _metadata_card(row)
    if item["revision_ref"] is None:
        item["reading_preview"] = _unavailable("missing")
        return item
    page = await _fields(backend, item["revision_ref"], boundary)
    if page is None:
        return None
    selected = page.get("selection")
    if selected:
        if selected["object_kind"] != row["object_kind"]:
            raise BackendError("invalid_read_response")
        item["object_ref"] = selected["object_ref"]
    if page["content_state"] != "ready":
        item["reading_preview"] = _unavailable(page["content_state"])
        return item
    fields = page["fields"]
    kind = row["object_kind"]
    truncated = not page["fields_complete"]
    if kind == "core_membership":
        # Follow the membership's exact immutable Atom, never its current successor.
        atom = await _fields(backend, fields["atom_revision_id"], boundary)
        if atom is None:
            return None
        if atom["content_state"] != "ready":
            item["reading_preview"] = _unavailable(atom["content_state"])
            return item
        if atom["selection"]["object_kind"] != "atom_revision":
            raise BackendError("invalid_read_response")
        preview, scope = _body("atom_revision", atom["fields"], truncated or not atom["fields_complete"])
    else:
        preview, scope = _body(kind, fields, truncated)
    item["reading_preview"], item["scope_ref"] = preview, _scope(row, scope)
    if kind == "atom_revision":
        item["display_kind"] = fields.get("kind")
    if kind == "revision_proposal_revision":
        item["proposal"] = {name: fields.get(name) for name in ("status", "eligibility", "operation")}
    return item


async def read_memories(backend, query=None, after=None, expected_frontier=None):
    identity, position = None, None
    if after is not None:
        try:
            cursor = _decode(after.encode("utf-8"))
        except (AttributeError, BackendError) as error:
            raise BackendError("invalid_input") from error
        if not isinstance(cursor, dict) or set(cursor) != {"frontier", "data_identity", "after"}:
            raise BackendError("invalid_input")
        if not isinstance(cursor["after"], dict):
            raise BackendError("invalid_input")
        if expected_frontier is not None and expected_frontier != cursor["frontier"]:
            raise BackendError("invalid_input")
        expected_frontier, identity = cursor["frontier"], cursor["data_identity"]
        position = json.dumps(cursor["after"], separators=(",", ":"), ensure_ascii=False)
    result = await backend.read_batch([{"kind": "memories", "query": query, "after": position, "limit": 32}],
                                      expected_frontier, identity)
    if result["kind"] == "conflict":
        return result
    boundary = result["page"]["state"]
    page = result["page"]["items"][0]["page"]
    items = []
    for row in page["records"]:
        item = await _card(backend, row, boundary)
        if item is None:
            return {"kind": "conflict"}
        items.append(item)
    cursor = None
    if page["next_cursor"] is not None:
        cursor = json.dumps({"frontier": boundary["frontier"], "data_identity": boundary["data_identity"],
                             "after": _decode(page["next_cursor"].encode("utf-8"))}, separators=(",", ":"), ensure_ascii=False)
    return {"kind": "memories", **page, "items": items, "frontier": boundary["frontier"], "next_cursor": cursor,
            "status": "ready" if page["counts_complete"] else "partial"}


def _count(value, complete, unit):
    return {"count": value, "unit": unit,
            "basis": "unknown" if value is None else "exact" if complete else "lower_bound"}


def _generation(work, summary_count, metadata_complete, complete, config_hash):
    observations = []
    run = work["last_run"]
    if summary_count is None or summary_count == 0:
        if work["no_inputs"] and complete:
            observations.append("no_inputs")
        if work["llm_enabled"] is False:
            observations.append("llm_disabled")
        if work["episode_enrichment_enabled"] is False:
            observations.append("episode_enrichment_disabled")
        if (work["open_work_count"] or 0) > 0:
            observations.append("work_in_progress")
        if run and bytes(run["effective_config_hash"]).hex() == config_hash:
            if run["status"] == "budget_exhausted":
                observations.append("last_attempt_budget_exhausted")
            elif run["status"] in ("provider_unavailable", "provider_failed"):
                observations.append("last_attempt_provider_unavailable")
        if not observations or not metadata_complete or summary_count is None:
            observations.append("not_read")
    return {"observations": observations, "llm_enabled": work["llm_enabled"],
            "episode_enrichment_enabled": work["episode_enrichment_enabled"],
            "last_run": {key: value for key, value in run.items() if key != "effective_config_hash"} if run else None}


async def read_overview(backend, query, expected_frontier=None):
    query = backend._overview_query(query)
    limit = query["limit"]
    # At most five finite selectors; each Native batch stays within its 64-record aggregate budget.
    scope = {key: query[key] for key in ("selection", "include_global", "time_range")}
    time_range = scope["time_range"]
    order = "event_newest" if time_range and time_range["basis"] == "event" else "recorded_newest"
    requests = [{"kind": "memories", "query": {**scope, "kind": kind, "order": order}, "limit": limit}
                for kind in ("summaries", "facts_and_constraints", "methods")]
    requests.extend({"kind": kind, "query": query} for kind in ("work", "review"))
    parts, boundary, identity = [], None, None
    batch_size = max(1, 64 // limit)
    for start in range(0, len(requests), batch_size):
        result = await backend.read_batch(requests[start:start + batch_size], expected_frontier, identity)
        if result["kind"] == "conflict":
            return result
        boundary = result["page"]["state"]
        expected_frontier, identity = boundary["frontier"], boundary["data_identity"]
        parts.extend(part["page"] for part in result["page"]["items"])
    summaries, facts, methods, work, reviews = parts
    scope_available = all(page["scope_available"] for page in (summaries, facts, methods, work, reviews))
    metadata_complete = all(page["counts_complete"] for page in (summaries, facts, methods, work, reviews))
    formal_count = None
    if facts["matching_count"] is not None and methods["matching_count"] is not None:
        formal_count = facts["matching_count"] + methods["matching_count"]
        if formal_count >= 1 << 64:
            raise BackendError("invalid_read_response")
    changes = facts["records"] + methods["records"]
    if order == "event_newest" and any(row["event_time_us"] is None for row in changes):
        raise BackendError("invalid_read_response")
    changes.sort(key=lambda row: (-row["event_time_us"] if order == "event_newest" else 0,
                                  -row["source_event_seq"], row["row_id"]))
    metadata_only = set(reviews["metadata_only_refs"])
    sections = {}
    for name, rows in (("summaries", summaries["records"]), ("changes", changes[:limit]),
                       ("unresolved", work["records"]), ("reviews", reviews["records"])):
        cards = []
        for row in rows:
            if name == "reviews" and row["row_id"] in metadata_only:
                item = {**_metadata_card(row), "reading_preview": None}
            else:
                item = await _card(backend, row, boundary)
                if item is None:
                    return {"kind": "conflict"}
            cards.append(item)
        sections[name] = cards
    complete = scope_available and metadata_complete and all(
        (item["reading_preview"] or {}).get("state") == "ready" or item["stable_key"] in metadata_only
        for cards in sections.values() for item in cards)
    return {"kind": "memory_overview", "page": {
        **sections, "frontier": boundary["frontier"], "observed_at_us": time.time_ns() // 1000,
        "query": query, "scope_available": scope_available, "complete": complete, "review_reasons": reviews["reasons"],
        "summary_count": _count(summaries["matching_count"], summaries["counts_complete"], "current_summary_revisions"),
        "formal_count": _count(formal_count, facts["counts_complete"] and methods["counts_complete"], "current_formal_revisions"),
        "loop_count": _count(work["loop_count"], work["counts_complete"], "open_loop_entries"),
        "review_count": _count(reviews["matching_count"], reviews["counts_complete"], "pending_review_items"),
        "generation": _generation(work, summaries["matching_count"], metadata_complete, complete, boundary["effective_config_hash"]),
    }}
