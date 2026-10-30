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

    async def memories(self, after=None, expected_frontier=None):
        # Declaration order/defaults are the existing Rust wire contract.
        return await self._request({"kind": "list", "surface": "explorer", "explorer_selection": "memories", "expected_frontier": expected_frontier, "after": after, "limit": 32})

    async def detail(self, reference, frontier, revision):
        return await self._request({"kind": "detail", "surface": "explorer", "object_ref": reference, "expected_frontier": frontier, "expected_revision_ref": revision})

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
                if result.get("kind") not in ("snapshot", "conflict"):
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
