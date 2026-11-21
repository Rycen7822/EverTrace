"""Closed kernel-read transport; data authority and page presentation are separate responsibilities."""

import asyncio
import contextlib
import json
import math
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import time
import uuid

import orjson

from . import BackendError


def verify_peer(peer):
    if hasattr(socket, "SO_PEERCRED"):
        uid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    elif hasattr(peer, "getpeereid"):
        uid = peer.getpeereid()[0]
    else:
        raise BackendError("peer_identity_unavailable")
    if uid != os.geteuid():
        raise BackendError("socket_changed")


def normalize_scope(value, boundary=False):
    # Wire shape only. Native identity, membership and permission resolution is
    # never inferred from a path, a label or the most recent session here.
    if not isinstance(value, dict):
        raise BackendError("invalid_input")
    kind = value.get("kind")
    if not isinstance(kind, str):
        raise BackendError("invalid_input")
    if kind in ("all", "global", "unassigned") and not boundary and set(value) == {"kind"}:
        return {"kind": kind}
    field = {"task": "task_id", "repository": "repository_id", "worktree": "worktree_id"}.get(kind)
    if field is None or set(value) != {"kind", field} or not isinstance(value[field], str):
        raise BackendError("invalid_input")
    family, separator, payload = value[field].partition(":")
    if separator != ":" or family != {"task": "task", "repository": "repo", "worktree": "wt"}[kind]:
        raise BackendError("invalid_input")
    try:
        parsed = uuid.UUID(payload)
    except ValueError as error:
        raise BackendError("invalid_input") from error
    if str(parsed) != payload or parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        raise BackendError("invalid_input")
    return {"kind": kind, field: value[field]}


def signed_microseconds(value):
    if value is None:
        return None
    if isinstance(value, str):
        digits = value[1:] if value.startswith("-") else value
        if not digits or not digits.isascii() or not digits.isdecimal() or len(value) > 20:
            raise BackendError("invalid_input")
        value = int(value)
    if type(value) is not int or not -(2**63) <= value < 2**63:
        raise BackendError("invalid_input")
    return value


def normalize_time_range(value):
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"basis", "from_us", "until_us"}
        or value["basis"] not in ("event", "recorded")
    ):
        raise BackendError("invalid_input")
    return {
        "basis": value["basis"],
        "from_us": signed_microseconds(value["from_us"]),
        "until_us": signed_microseconds(value["until_us"]),
    }


MAX_FRAME = 1_048_576


def _decode(raw, *, canonical=False):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise BackendError("invalid_frame")
            result[key] = value
        return result

    def nonfinite(value):
        raise BackendError("invalid_frame")

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise BackendError("invalid_frame")
        return result

    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=number
    )
    if canonical and _encode(value) != raw:
        raise BackendError("noncanonical_frame")
    return value


def _encode(value):
    # orjson intentionally converts non-finite floats to null; protocol must not.
    def finite(value):
        if isinstance(value, float) and not math.isfinite(value):
            raise BackendError("invalid_frame")
        if isinstance(value, dict):
            for item in value.values():
                finite(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                finite(item)

    finite(value)
    return orjson.dumps(value)


def _request_id():
    value = (
        ((time.time_ns() // 1_000_000) << 80)
        | (7 << 76)
        | (secrets.randbits(12) << 64)
        | (2 << 62)
        | secrets.randbits(62)
    )
    return str(uuid.UUID(int=value))


def _private_socket(path):
    for directory in (path.parent, path.parent.parent):
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise BackendError("unsafe_namespace")
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise BackendError("unsafe_socket")
    return info.st_dev, info.st_ino, info.st_uid


def _read_boundary(frontier, identity):
    if frontier is not None and (type(frontier) is not int or not 0 <= frontier < 2**64):
        raise BackendError("invalid_input")
    if identity is not None:
        names = ("database_device", "database_inode", "incarnation")
        if not isinstance(identity, dict) or set(identity) != set(names):
            raise BackendError("invalid_input")
        if any(type(identity[name]) is not int or not 0 <= identity[name] < 2**64 for name in names):
            raise BackendError("invalid_input")
        identity = {name: identity[name] for name in names}
    return frontier, identity


def normalize_scope_query(query):
    query = {} if query is None else query
    if not isinstance(query, dict) or set(query) - {"parent", "name"}:
        raise BackendError("invalid_input")
    name, parent = query.get("name", ""), query.get("parent")
    if (not isinstance(name, str) or len(name.encode()) > 256 or name != name.strip()
        or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in name)):
        raise BackendError("invalid_input")
    return {"parent":normalize_scope(parent, boundary=True) if parent is not None else None, "name":name}


def normalize_source_query(query):
    query = {} if query is None else query
    if not isinstance(query, dict) or set(query) - {"selection", "session_id", "source_instance_id", "unassigned_only"}:
        raise BackendError("invalid_input")
    session, source = query.get("session_id"), query.get("source_instance_id")
    for value, limit in ((session, 512), (source, 1024)):
        if value is not None and (not isinstance(value, str) or not 0 < len(value.encode()) <= limit
            or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value)):
            raise BackendError("invalid_input")
    unassigned = query.get("unassigned_only", False)
    if type(unassigned) is not bool:
        raise BackendError("invalid_input")
    return {"selection":normalize_scope(query.get("selection", {"kind":"all"})),
            "session_id":session, "source_instance_id":source, "unassigned_only":unassigned}


def normalize_archive_query(query):
    if not isinstance(query, dict) or query.get("kind") not in ("revisions", "records"):
        raise BackendError("invalid_input")
    source = query.get("source_instance_id")
    if (not isinstance(source, str) or not 0 < len(source.encode()) <= 1024
        or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in source)):
        raise BackendError("invalid_input")
    value = {"kind":query["kind"], "source_instance_id":source}
    allowed = set(value)
    if value["kind"] == "records":
        allowed |= {"source_revision", "from_sequence", "until_sequence"}
        revision = query.get("source_revision")
        if not isinstance(revision, str) or len(revision) != 64 or any(char not in "0123456789abcdef" for char in revision):
            raise BackendError("invalid_input")
        value["source_revision"] = revision
        for key in ("from_sequence", "until_sequence"):
            number = query.get(key)
            if isinstance(number, str):
                if not number or not number.isascii() or not number.isdecimal() or len(number) > 20:
                    raise BackendError("invalid_input")
                number = int(number)
            if number is not None and (type(number) is not int or not 0 <= number < 2**64):
                raise BackendError("invalid_input")
            value[key] = number
        if value["from_sequence"] is not None and value["until_sequence"] is not None and value["from_sequence"] >= value["until_sequence"]:
            raise BackendError("invalid_input")
    if set(query) - allowed:
        raise BackendError("invalid_input")
    return value


class Backend:
    def __init__(self, socket_path, config_hash, build_id, confirmation_channel=None):
        self.path = Path(socket_path)
        self.config_hash = config_hash
        self.build_id = build_id
        self.confirmation_channel = confirmation_channel
        self.confirmation_lock = asyncio.Lock() if confirmation_channel is not None else None

    async def health(self):
        return await self._request(None)

    async def state(self):
        result = await self._request({"kind": "state"})
        state = result.get("state")
        if not isinstance(state, dict):
            raise BackendError("invalid_read_response")
        if state.get("effective_config_hash") != self.config_hash:
            raise BackendError("inactive_configuration")
        return state

    @staticmethod
    def _jobs_query(query=None):
        query = {} if query is None else query
        keys = {"expected_frontier", "expected_data_identity", "after", "job_id", "limit"}
        if not isinstance(query, dict) or set(query) - keys:
            raise BackendError("invalid_input")
        frontier, identity = _read_boundary(query.get("expected_frontier"), query.get("expected_data_identity"))
        after, selected = query.get("after"), query.get("job_id")
        for value in (after, selected):
            if value is not None:
                try:
                    parsed = uuid.UUID(value)
                except (TypeError, ValueError, AttributeError) as error:
                    raise BackendError("invalid_input") from error
                if str(parsed) != value or parsed.version != 7 or parsed.variant != uuid.RFC_4122:
                    raise BackendError("invalid_input")
        limit = query.get("limit", 1 if selected else 32)
        if type(limit) is not int or not 1 <= limit <= 64:
            raise BackendError("invalid_input")
        return {
            "expected_frontier": frontier,
            "expected_data_identity": identity,
            "after": after,
            "job_id": selected,
            "limit": limit,
        }

    async def jobs(self, query=None):
        result = await self._request({"kind": "jobs", "query": self._jobs_query(query)})
        if result["kind"] == "conflict":
            return result
        if result["kind"] != "jobs":
            raise BackendError("invalid_read_response")
        if result["page"]["state"]["effective_config_hash"] != self.config_hash:
            raise BackendError("inactive_configuration")
        return result

    @staticmethod
    def _memory_query(query=None):
        # Closed wire spellings/defaults, not policy: Rust owns axis combinations,
        # visibility, filtering and counts. Reject malformed enum JSON here rather
        # than misreporting the native codec's connection close as daemon loss.
        wire_values = {
            "kind": ("all", "summaries", "facts_and_constraints", "methods", "references"),
            "order": ("recorded_newest", "recorded_oldest", "event_newest", "event_oldest"),
            "epistemic_status": (
                None,
                "not_applicable",
                "unverified",
                "supported",
                "disputed",
                "refuted",
            ),
            "authority": (
                None,
                "user_explicit",
                "project_policy",
                "objective_evidence",
                "agent_inferred",
                "imported_claim",
            ),
            "atom_lifecycle": (None, "active", "superseded", "deprecated"),
        }
        if query is None:
            query = {}
        if (
            not isinstance(query, dict)
            or set(query) - (wire_values.keys() | {"selection", "include_global", "time_range"})
            or any(
                value not in wire_values[key] for key, value in query.items() if key in wire_values
            )
        ):
            raise BackendError("invalid_input")
        include_global = query.get("include_global", False)
        if type(include_global) is not bool:
            raise BackendError("invalid_input")
        # Native canonical frames follow the declared field order, including null range.
        return {
            "selection": normalize_scope(query.get("selection", {"kind": "all"})),
            "include_global": include_global,
            **{key: query.get(key, values[0]) for key, values in wire_values.items()},
            "time_range": normalize_time_range(query.get("time_range")),
        }

    async def read_exact(self, revision_ref):
        if not isinstance(revision_ref, str) or not revision_ref or len(revision_ref.encode()) > 2048:
            raise BackendError("invalid_input")
        result = await self._request({"kind": "read_exact", "query": {"kind": "fields", "revision_ref": revision_ref}})
        if result["kind"] != "stored_fields":
            raise BackendError("invalid_read_response")
        if result["page"]["state"]["effective_config_hash"] != self.config_hash:
            raise BackendError("inactive_configuration")
        return result

    async def read_source_window(self, reference, revision, byte_range=None, data_identity=None, source=None, field="protected"):
        if any(not isinstance(value, str) or not value or len(value.encode()) > 512
               or any(ord(char) < 32 for char in value) for value in (reference, revision)):
            raise BackendError("invalid_input")
        if byte_range is not None:
            if (not isinstance(byte_range, dict) or set(byte_range) != {"offset", "length"}
                or type(byte_range["offset"]) is not int or not 0 <= byte_range["offset"] < 2**64 - 8193
                or type(byte_range["length"]) is not int or not 4 <= byte_range["length"] <= 8192):
                raise BackendError("invalid_input")
            byte_range = {key: byte_range[key] for key in ("offset", "length")}
        if field not in ("protected", "presentation"):
            raise BackendError("invalid_input")
        _, data_identity = _read_boundary(None, data_identity)
        if source is not None:
            keys = ("observation_ref", "receipt_ref", "source_instance_ref", "source_revision",
                    "source_record_identity", "payload_fingerprint", "protected_bytes", "original_bytes")
            if not isinstance(source, dict) or set(source) != set(keys):
                raise BackendError("invalid_input")
            if any(not isinstance(source[key], str) or not source[key] or len(source[key].encode()) > 512
                   for key in keys[:6]):
                raise BackendError("invalid_input")
            if any(type(source[key]) is not int or not 0 <= source[key] < 2**64 for key in keys[6:]):
                raise BackendError("invalid_input")
            source = {key: source[key] for key in keys}
        result = await self._request({"kind": "read_exact", "query": {"kind": "source_text", "field":field,
            "reference": {"stable_key": reference, "revision_ref": revision}, "range": byte_range,
            "expected_data_identity": data_identity, "expected_source": source}})
        if result["kind"] == "conflict":
            return result
        if result["kind"] != "source_window" or result["page"]["field"] != field:
            raise BackendError("invalid_read_response")
        if result["page"]["state"]["effective_config_hash"] != self.config_hash:
            raise BackendError("inactive_configuration")
        return result

    async def read_record_window(self, reference, revision, field=None, byte_range=None, data_identity=None, selection=None):
        # An omitted expected revision asks Native to bind a typed public ID to canonical-current.
        values = (reference,) if revision is None else (reference, revision)
        if any(not isinstance(value, str) or not value or len(value.encode()) > 512
               or any(ord(char) < 32 for char in value) for value in values):
            raise BackendError("invalid_input")
        if (field is None) != (byte_range is None):
            raise BackendError("invalid_input")
        if field is not None:
            if not isinstance(field, dict) or field.get("kind") not in ("json", "text", "goal", "open_loop"):
                raise BackendError("invalid_input")
            keys = {"kind", "index"} if field["kind"] == "open_loop" else {"kind"}
            if set(field) != keys or "index" in keys and (type(field["index"]) is not int or not 0 <= field["index"] < 2**32):
                raise BackendError("invalid_input")
            field = {key: field[key] for key in ("kind", "index") if key in field}
            if (not isinstance(byte_range, dict) or set(byte_range) != {"offset", "length"}
                or type(byte_range["offset"]) is not int or not 0 <= byte_range["offset"] < 2**64 - 8193
                or type(byte_range["length"]) is not int or not 4 <= byte_range["length"] <= 8192):
                raise BackendError("invalid_input")
            byte_range = {key: byte_range[key] for key in ("offset", "length")}
        _, data_identity = _read_boundary(None, data_identity)
        if selection is not None:
            keys = ("object_kind", "object_ref", "revision_ref", "source_event_seq")
            if (not isinstance(selection, dict) or set(selection) != set(keys)
                or any(not isinstance(selection[key], str) or not 0 < len(selection[key].encode()) <= 512 for key in keys[:3])
                or type(selection["source_event_seq"]) is not int or not 0 <= selection["source_event_seq"] < 2**64):
                raise BackendError("invalid_input")
            selection = {key: selection[key] for key in keys}
        result = await self._request({"kind": "read_exact", "query": {"kind": "record",
            "reference": {"stable_key": reference, "revision_ref": revision}, "field": field, "range": byte_range,
            "expected_data_identity": data_identity, "expected_selection": selection}})
        if result["kind"] == "conflict":
            return result
        if result["kind"] != "record_window":
            raise BackendError("invalid_read_response")
        if result["page"]["state"]["effective_config_hash"] != self.config_hash:
            raise BackendError("inactive_configuration")
        return result

    async def read_batch(self, items, expected_frontier=None, expected_data_identity=None):
        """Closed metadata only; no content, search, action or raw native command."""
        frontier, identity = _read_boundary(expected_frontier, expected_data_identity)
        if not isinstance(items, list) or not 1 <= len(items) <= 8:
            raise BackendError("invalid_input")
        normalized, total_limit = [], 0
        for item in items:
            if not isinstance(item, dict):
                raise BackendError("invalid_input")
            kind = item.get("kind")
            if kind == "memories":
                if set(item) - {"kind", "query", "after", "limit"}:
                    raise BackendError("invalid_input")
                after = item.get("after")
                if after is not None and (not isinstance(after, str) or len(after.encode()) > 2048):
                    raise BackendError("invalid_input")
                value = {
                    "kind": kind,
                    "query": self._memory_query(item.get("query")),
                    "after": after,
                    "limit": item.get("limit", 32),
                }
            elif kind == "recall_ledger":
                if set(item) != {"kind", "reference", "after", "limit"} or len(items) != 1:
                    raise BackendError("invalid_input")
                reference, after = item["reference"], item["after"]
                if (not isinstance(reference, dict) or set(reference) != {"stable_key", "revision_ref"}
                    or reference["revision_ref"] is not None or not isinstance(reference["stable_key"], str)
                    or not 0 < len(reference["stable_key"].encode()) <= 512
                    or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in reference["stable_key"])):
                    raise BackendError("invalid_input")
                if after is not None and (type(after) is not int or not 0 <= after < 2**64
                    or frontier is None or identity is None):
                    raise BackendError("invalid_input")
                value = {"kind":kind, "reference":{"stable_key":reference["stable_key"], "revision_ref":None},
                         "after":after, "limit":item["limit"]}
            elif kind == "references":
                if set(item) - {"kind", "reference", "after", "limit"}:
                    raise BackendError("invalid_input")
                reference, after = item.get("reference"), item.get("after")
                if (not isinstance(reference, dict) or set(reference) != {"stable_key", "revision_ref"}
                    or any(not isinstance(value, str) or not 0 < len(value.encode()) <= 512
                        or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value) for value in reference.values())):
                    raise BackendError("invalid_input")
                if after is not None and (frontier is None or identity is None or not isinstance(after, str)
                    or not 0 < len(after.encode()) <= 512 or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in after)):
                    raise BackendError("invalid_input")
                value = {"kind":kind, "reference":{"stable_key":reference["stable_key"], "revision_ref":reference["revision_ref"]},
                    "after":after, "limit":item.get("limit", 32)}
            elif kind == "archive":
                if set(item) - {"kind", "query", "after", "limit"}:
                    raise BackendError("invalid_input")
                query, after = normalize_archive_query(item.get("query")), item.get("after")
                if after is not None:
                    if not isinstance(after, dict) or frontier is None or identity is None:
                        raise BackendError("invalid_input")
                    if query["kind"] == "revisions":
                        revision = after.get("revision")
                        if (set(after) != {"kind", "revision"} or after["kind"] != "revision" or not isinstance(revision, str)
                            or len(revision) != 64 or any(char not in "0123456789abcdef" for char in revision)):
                            raise BackendError("invalid_input")
                    else:
                        receipt, sequence = after.get("receipt"), after.get("sequence")
                        if (set(after) != {"kind", "sequence", "receipt"} or after["kind"] != "record"
                            or type(sequence) is not int or not 0 <= sequence < 2**64 or not isinstance(receipt, str)
                            or not receipt.startswith("src:") or len(receipt) != 68
                            or any(char not in "0123456789abcdef" for char in receipt[4:])):
                            raise BackendError("invalid_input")
                    after = ({"kind":"revision", "revision":after["revision"]} if query["kind"] == "revisions"
                             else {"kind":"record", "sequence":after["sequence"], "receipt":after["receipt"]})
                value = {"kind":kind, "query":query, "after":after, "limit":item.get("limit", 32)}
            elif kind == "sources":
                if set(item) - {"kind", "query", "after", "limit"}:
                    raise BackendError("invalid_input")
                after = item.get("after")
                if after is not None:
                    if (not isinstance(after, str) or not 0 < len(after.encode()) <= 512
                        or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in after)
                        or frontier is None or identity is None):
                        raise BackendError("invalid_input")
                value = {"kind":kind, "query":normalize_source_query(item.get("query")), "after":after, "limit":item.get("limit", 32)}
            elif kind == "scopes":
                if set(item) - {"kind", "query", "after", "limit"}:
                    raise BackendError("invalid_input")
                after = item.get("after")
                if after is not None:
                    if (not isinstance(after, str) or not 0 < len(after.encode()) <= 512
                        or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in after)
                        or frontier is None or identity is None):
                        raise BackendError("invalid_input")
                value = {"kind":kind, "query":normalize_scope_query(item.get("query")), "after":after, "limit":item.get("limit", 32)}
            elif kind == "revisions":
                if set(item) - {"kind", "reference", "after", "limit"}:
                    raise BackendError("invalid_input")
                reference, after = item.get("reference"), item.get("after")
                if not isinstance(reference, dict) or set(reference) != {"stable_key", "revision_ref"}:
                    raise BackendError("invalid_input")
                if any(not isinstance(value, str) or not 0 < len(value.encode()) <= 512
                       or any(ord(char) < 32 for char in value) for value in reference.values()):
                    raise BackendError("invalid_input")
                if after is not None:
                    if not isinstance(after, dict) or set(after) != {"source_event_seq", "row_id"}:
                        raise BackendError("invalid_input")
                    if type(after["source_event_seq"]) is not int or not 0 < after["source_event_seq"] < 2**64:
                        raise BackendError("invalid_input")
                    key = after["row_id"]
                    if not isinstance(key, str) or not 0 < len(key.encode()) <= 512 or any(ord(char) < 32 for char in key):
                        raise BackendError("invalid_input")
                    if frontier is None or identity is None:
                        raise BackendError("invalid_input")
                value = {"kind":kind, "reference":reference, "after":after, "limit":item.get("limit", 32)}
            elif kind in ("work", "review"):
                if set(item) - {"kind", "query"}:
                    raise BackendError("invalid_input")
                value = {"kind": kind, "query": self._overview_query(item.get("query", {}))}
            elif kind == "jobs":
                if set(item) - {"kind", "after", "job_id", "limit"}:
                    raise BackendError("invalid_input")
                jobs = self._jobs_query({key: value for key, value in item.items() if key != "kind"})
                value = {"kind": kind, **{key: jobs[key] for key in ("after", "job_id", "limit")}}
            else:
                raise BackendError("invalid_input")
            limit = value["query"]["limit"] if kind in ("work", "review") else value["limit"]
            if type(limit) is not int or not 1 <= limit <= 64:
                raise BackendError("invalid_input")
            total_limit += limit
            normalized.append(value)
        if total_limit > 64:
            raise BackendError("invalid_input")
        result = await self._request({"kind": "read_batch", "query": {
            "expected_frontier": frontier, "expected_data_identity": identity, "items": normalized,
        }})
        if result["kind"] == "conflict":
            return result
        if result["kind"] != "metadata_batch":
            raise BackendError("invalid_read_response")
        if result["page"]["state"]["effective_config_hash"] != self.config_hash:
            raise BackendError("inactive_configuration")
        return result

    async def compiled(self, query, expected_frontier=None, after=None):
        if not isinstance(query, dict) or query.get("kind") not in ("directory", "entries"):
            raise BackendError("invalid_input")
        include_global = query.get("include_global", False)
        if type(include_global) is not bool:
            raise BackendError("invalid_input")
        kind = query["kind"]
        field = "projection" if kind == "directory" else "reference"
        if set(query) - {"kind", "selection", "include_global", field}:
            raise BackendError("invalid_input")
        value = query.get(field)
        if kind == "directory" and value not in ("wiki", "core"):
            raise BackendError("invalid_input")
        if kind == "entries" and (not isinstance(value, str) or not 1 <= len(value) <= 256):
            raise BackendError("invalid_input")
        selection = normalize_scope(query.get("selection", {"kind": "all"}))
        normalized = {"kind": kind}
        if kind == "entries":
            normalized["reference"] = value
        normalized.update(selection=selection, include_global=include_global)
        if kind == "directory":
            normalized["projection"] = value
        return await self._request({
            "kind": "compiled_projections", "query": normalized,
            "expected_frontier": expected_frontier, "after": after,
            "limit": 32 if kind == "directory" else 4,
        })

    @staticmethod
    def _overview_query(query):
        if not isinstance(query, dict) or set(query) - {
            "selection", "include_global", "time_range", "limit"
        }:
            raise BackendError("invalid_input")
        include_global = query.get("include_global", False)
        limit = query.get("limit", 8)
        if type(include_global) is not bool or type(limit) is not int or not 1 <= limit <= 64:
            raise BackendError("invalid_input")
        return {
            "selection": normalize_scope(query.get("selection", {"kind": "all"})),
            "include_global": include_global,
            "time_range": normalize_time_range(query.get("time_range")),
            "limit": limit,
        }

    async def observations(self, after=None, expected_frontier=None):
        return await self._request({
            "kind": "list", "surface": "inbox", "expected_frontier": expected_frontier,
            "after": after, "limit": 32,
        })

    async def detail(self, reference, frontier, revision, surface):
        if surface not in ("explorer", "inbox", "system"):
            raise BackendError("invalid_input")
        return await self._request(
            {
                "kind": "detail",
                "surface": surface,
                "object_ref": reference,
                "expected_frontier": frontier,
                "expected_revision_ref": revision,
            }
        )

    async def proposal_review(self, proposal_id, revision, frontier, expected_digest=None, *, atom_edit=None):
        request = {
            "kind": "proposal_review", "proposal_id": proposal_id, "expected_revision_id": revision,
            "expected_frontier": frontier, "expected_digest": expected_digest,
        }
        if atom_edit is not None:
            request["atom_edit"] = atom_edit
        result = await self._request(request, confirmation=expected_digest is not None)
        if result["kind"] not in ("conflict", "proposal_review"):
            raise BackendError("invalid_read_response")
        if result["kind"] == "proposal_review":
            item = result["item"]
            if item is not None and (item["object_ref"] != proposal_id or item["revision_ref"] != revision):
                raise BackendError("invalid_read_response")
        return result

    async def web_creation_scope_available(self, scope, frontier):
        result = await self._request({"kind": "web_creation_scope", "scope": scope, "expected_frontier": frontier})
        if result["kind"] != "proposal_creation_scope":
            raise BackendError("invalid_read_response")
        return result["available"]

    async def web_atom_authoring(self, request_id, target, *, frontier=None, content=None, kind=None):
        creation = "scope" in target
        if content is None:
            read = "web_creation_outcome" if creation else "web_correction_outcome"
            reply = await self._request({"kind": read, "request_id": request_id, **target})
        else:
            intent = {**target, "kind": kind, "content": content} if creation else {**target, "content": content}
            action = {"operation": "act", "expected_frontier": frontier,
                      "action": {"kind": "web_create_atom" if creation else "web_correct_atom", "intent": intent}}
            reply = await self._request(None, confirmation=True, action=action, request_id=request_id)
        return proposal_action_result(reply)

    async def web_proposal_action(self, request_id, proposal, revision, frontier, digest, *, lookup, decision, atom_edit=None):
        review = {"proposal_id": proposal, "expected_revision_id": revision, "expected_digest": digest}
        fields = {"review": review}
        if decision is not None:
            fields["decision"] = decision
        if atom_edit is not None and not lookup:
            fields["atom_edit"] = atom_edit
        if lookup:
            kind = "web_acceptance_outcome" if decision is None else "web_proposal_disposition_outcome"
            reply = await self._request({"kind": kind, "request_id": request_id, "expected_frontier": frontier, **fields})
        else:
            kind = "web_accept" if decision is None else "web_proposal_disposition"
            action = {"operation": "act", "expected_frontier": frontier, "action": {"kind": kind, **fields}}
            reply = await self._request(None, confirmation=True, action=action, request_id=request_id)
        return proposal_action_result(reply)

    async def job(self, job_id, frontier):
        if not isinstance(job_id, str):
            raise BackendError("invalid_input")
        try:
            parsed = uuid.UUID(job_id)
        except ValueError as error:
            raise BackendError("invalid_input") from error
        if str(parsed) != job_id or parsed.version != 7 or parsed.variant != uuid.RFC_4122:
            raise BackendError("invalid_input")
        # This is the native closed job locator, never a filesystem path or an
        # inferred current job. The native Detail owner revalidates the record.
        return await self.detail(f"runtime:job:{job_id}", frontier, None, "system")

    @staticmethod
    def _comparison_query(query):
        if (
            not isinstance(query, dict)
            or set(query) != {"left", "right"}
            or any(
                not isinstance(ref, dict)
                or set(ref) != {"stable_key", "revision_ref"}
                or any(
                    not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512
                    for value in ref.values()
                )
                for ref in query.values()
            )
        ):
            raise BackendError("invalid_input")
        return query

    async def read_pair(self, query):
        result = await self._request({"kind": "read_revision_pair", "query": self._comparison_query(query)})
        if result["kind"] != "revision_pair":
            raise BackendError("invalid_read_response")
        page = result["page"]
        if page["query"] != query:
            raise BackendError("invalid_read_response")
        if page["left"]["state"]["effective_config_hash"] != self.config_hash:
            raise BackendError("inactive_configuration")
        if page["right"]["state"] != page["left"]["state"]:
            raise BackendError("invalid_read_response")
        return page

    async def _request(self, read, *, confirmation=False, action=None, request_id=None):
        async def execute():
            writer = None
            try:
                if confirmation:
                    if self.confirmation_channel is None:
                        raise BackendError("confirmation_channel_unavailable")
                    reader, writer = self.confirmation_channel
                else:
                    before = _private_socket(self.path)
                    reader, writer = await asyncio.open_unix_connection(str(self.path), limit=16_384)
                    verify_peer(writer.get_extra_info("socket"))
                    if before != _private_socket(self.path):
                        raise BackendError("socket_changed")
                maximum = MAX_FRAME

                async def send(value):
                    raw = _encode(value)
                    if not 0 < len(raw) <= maximum:
                        raise BackendError("frame_too_large")
                    writer.write(struct.pack("!I", len(raw)) + raw)
                    await writer.drain()

                async def receive():
                    size = struct.unpack("!I", await reader.readexactly(4))[0]
                    if not 0 < size <= maximum:
                        raise BackendError("invalid_frame")
                    return _decode(await reader.readexactly(size), canonical=True)

                if not confirmation:
                    await send({"kind": "handshake", "body": {
                        "protocol_version": 1, "client_kind": "web", "build_id": self.build_id, "max_frame": maximum,
                    }})
                    ack = await receive()
                    body = ack.get("body", {})
                    if (
                        ack.get("kind") != "handshake_ack"
                        or body.get("protocol_version") != 1
                        or body.get("build_id") != self.build_id
                        or type(body.get("max_frame")) is not int
                        or not 0 < body["max_frame"] <= maximum
                    ):
                        raise BackendError("version_mismatch")
                    maximum = body["max_frame"]

                async def call(command, identity=None):
                    identity = _request_id() if identity is None else identity
                    await send(
                        {"kind": "command", "body": {"request_id": identity, "command": command}}
                    )
                    for _ in range(32):
                        response = await receive()
                        if response.get("kind") == "notification":
                            continue
                        body = response.get("body", {})
                        if body.get("request_id") != identity:
                            raise BackendError("response_mismatch")
                        if response.get("kind") == "error":
                            raise BackendError(body.get("code", "backend_rejected"))
                        if response.get("kind") != "response":
                            raise BackendError("invalid_frame")
                        return body["response"]
                    raise BackendError("notification_budget")

                health = (await call("health"))["health"]
                if (
                    health.get("mode") != "normal"
                    or health.get("effective_config_hash") != self.config_hash
                ):
                    raise BackendError("inactive_configuration")
                if action is not None:
                    return (await call({"human_governance": action}, request_id))["human_governance"]
                if read is None:
                    return health
                response = await call({"human_governance": {"operation": "read", "request": read}})
                result = response["human_governance"]
                if read["kind"] in ("web_acceptance_outcome", "web_proposal_disposition_outcome",
                                    "web_correction_outcome", "web_creation_outcome"):
                    return result
                if result.get("kind") not in (
                    "state",
                    "jobs",
                    "metadata_batch",
                    "stored_fields",
                    "source_window",
                    "record_window",
                    "revision_pair",
                    "snapshot",
                    "memory_page",
                    "compiled_projections",
                    "proposal_creation_scope",
                    "proposal_review",
                    "source_archive",
                    "conflict",
                ):
                    raise BackendError("invalid_read_response")
                return result
            finally:
                if writer is not None and not confirmation:
                    writer.transport.abort()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()

        async def confirm():
            if self.confirmation_lock is None:
                raise BackendError("confirmation_channel_unavailable")
            async with self.confirmation_lock:
                try:
                    return await execute()
                except (Exception, asyncio.CancelledError):
                    # Never reuse a channel whose request/response boundary may be lost.
                    if self.confirmation_channel is not None:
                        self.confirmation_channel[1].transport.abort()
                        self.confirmation_channel = None
                    raise

        try:
            return await asyncio.wait_for(confirm() if confirmation else execute(), 5)
        except BackendError:
            raise
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            asyncio.IncompleteReadError,
            TimeoutError,
        ) as error:
            raise BackendError() from error


def proposal_action_result(reply):
    if reply.get("kind") != "action" or reply["result"].get("status") not in (
        "applied", "no_delta", "conflict", "unavailable", "unknown",
    ):
        raise BackendError("invalid_action_response")
    return reply["result"]
