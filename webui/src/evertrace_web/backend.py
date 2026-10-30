"""Closed human-read transport. Rust remains the sole domain/validation owner."""
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

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=number)
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
    value = ((time.time_ns() // 1_000_000) << 80) | (7 << 76) | (secrets.randbits(12) << 64) | (2 << 62) | secrets.randbits(62)
    return str(uuid.UUID(int=value))


def _private_socket(path):
    for directory in (path.parent, path.parent.parent):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise BackendError("unsafe_namespace")
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise BackendError("unsafe_socket")
    return info.st_dev, info.st_ino, info.st_uid


class Backend:
    def __init__(self, socket_path, config_hash, build_id):
        self.path = Path(socket_path)
        self.config_hash = config_hash
        self.build_id = build_id

    async def health(self):
        return await self._request(None)

    async def memories(self, after=None, expected_frontier=None, query=None):
        # Closed wire spellings/defaults, not policy: Rust owns axis combinations,
        # visibility, filtering and counts. Reject malformed enum JSON here rather
        # than misreporting the native codec's connection close as daemon loss.
        wire_values = {
            "kind": ("all", "summaries", "facts_and_constraints", "methods", "references"),
            "order": ("recorded_newest", "recorded_oldest"),
            "epistemic_status": (None, "not_applicable", "unverified", "supported", "disputed", "refuted"),
            "authority": (None, "user_explicit", "project_policy", "objective_evidence", "agent_inferred", "imported_claim"),
            "atom_lifecycle": (None, "active", "superseded", "deprecated"),
        }
        if query is None:
            query = {}
        if not isinstance(query, dict) or set(query) - (wire_values.keys() | {"selection", "include_global"}) or any(value not in wire_values[key] for key, value in query.items() if key in wire_values):
            raise BackendError("invalid_input")
        include_global = query.get("include_global", False)
        if type(include_global) is not bool:
            raise BackendError("invalid_input")
        normalized = {"selection": normalize_scope(query.get("selection", {"kind": "all"})), "include_global": include_global, **{key: query.get(key, values[0]) for key, values in wire_values.items()}}
        return await self._request({"kind": "browse_memories", "query": normalized, "expected_frontier": expected_frontier, "after": after, "limit": 32})

    async def scopes(self, query=None, after=None, expected_frontier=None):
        if query is None:
            query = {}
        if not isinstance(query, dict) or set(query) - {"parent", "name"}:
            raise BackendError("invalid_input")
        name = query.get("name", "")
        if not isinstance(name, str) or len(name.encode("utf-8")) > 256:
            raise BackendError("invalid_input")
        parent = query.get("parent")
        normalized = {"parent": normalize_scope(parent, boundary=True) if parent is not None else None, "name": name}
        return await self._request({"kind": "scope_directory", "query": normalized, "expected_frontier": expected_frontier, "after": after, "limit": 32})

    async def detail(self, reference, frontier, revision):
        return await self._request({"kind": "detail", "surface": "explorer", "object_ref": reference, "expected_frontier": frontier, "expected_revision_ref": revision})

    async def revisions(self, reference, frontier, revision, after=None):
        return await self._request({"kind": "related", "relation": "object_revisions", "source_stable_key": reference, "expected_source_revision_ref": revision, "expected_frontier": frontier, "after": after, "limit": 32})

    async def content(self, reference, frontier, revision, representation, after=None):
        if representation not in ("text", "semantic_json"):
            raise BackendError("invalid_input")
        return await self._request({"kind": "content", "object_ref": reference, "expected_revision_ref": revision, "expected_frontier": frontier, "representation": representation, "after": after, "limit": 8192})

    async def _request(self, read):
        async def execute():
            writer = None
            try:
                before = _private_socket(self.path)
                reader, writer = await asyncio.open_unix_connection(str(self.path), limit=16_384)
                peer = writer.get_extra_info("socket")
                if hasattr(socket, "SO_PEERCRED"):
                    uid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                elif hasattr(peer, "getpeereid"):
                    uid = peer.getpeereid()[0]
                else:
                    raise BackendError("peer_identity_unavailable")
                if uid != os.geteuid() or before != _private_socket(self.path):
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

                await send({"kind": "handshake", "body": {"protocol_version": 1, "client_kind": "web", "build_id": self.build_id, "max_frame": maximum}})
                ack = await receive()
                body = ack.get("body", {})
                if ack.get("kind") != "handshake_ack" or body.get("protocol_version") != 1 or body.get("build_id") != self.build_id or type(body.get("max_frame")) is not int or not 0 < body["max_frame"] <= maximum:
                    raise BackendError("version_mismatch")
                maximum = body["max_frame"]

                async def call(command):
                    identity = _request_id()
                    await send({"kind": "command", "body": {"request_id": identity, "command": command}})
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
                if health.get("mode") != "normal" or health.get("effective_config_hash") != self.config_hash:
                    raise BackendError("inactive_configuration")
                if read is None:
                    return health
                response = await call({"human_governance": {"operation": "read", "request": read}})
                result = response["human_governance"]
                if result.get("kind") not in ("snapshot", "memory_page", "revision_page", "scope_directory", "content", "conflict"):
                    raise BackendError("invalid_read_response")
                return result
            finally:
                if writer is not None:
                    writer.close()
                    # Failed/cancelled reads must not leave a buffered UDS
                    # transport alive beyond this one request.
                    writer.transport.abort()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
        try:
            return await asyncio.wait_for(execute(), 5)
        except BackendError:
            raise
        except (OSError, ValueError, KeyError, TypeError, asyncio.IncompleteReadError, TimeoutError) as error:
            raise BackendError() from error
