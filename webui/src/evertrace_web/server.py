"""One foreground Python HTTP/presentation worker; no daemon state or DB access."""

import asyncio
import hmac
from pathlib import Path
import secrets
import socket
import time

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from starlette.requests import ClientDisconnect, Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
import uvicorn
import orjson
from uvicorn.protocols.http.h11_impl import H11Protocol

from .backend import Backend, BackendError, _decode
from .jobs import read_jobs
from .comparison import read_comparison
from .content import DETAIL_KINDS, read_record_content, read_record_detail, read_source_content
from .sources import read_revisions, read_source_catalog, read_source_archive, read_source_detail, read_source_links
from .scopes import read_scopes
from .memories import read_memories, read_overview

ROOT = Path(__file__).resolve().parent
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; "
    "frame-ancestors 'none'; form-action 'none'"
)
SECURITY = {
    "Content-Security-Policy": CSP,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Connection": "close",
}
STATIC = {"/styles.css": ("styles.css", "text/css"), "/app.js": ("app.js", "text/javascript")}
for name in (
    "IBMPlexSans-Regular.ttf",
    "IBMPlexSans-Medium.ttf",
    "IBMPlexSans-Semibold.ttf",
    "IBMPlexMono-Regular.ttf",
    "IBMPlexMono-Medium.ttf",
):
    STATIC[f"/assets/fonts/{name}"] = (f"assets/fonts/{name}", "font/ttf")
for name in ("ibmplexsans-OFL.txt", "ibmplexmono-OFL.txt"):
    STATIC[f"/assets/fonts/{name}"] = (f"assets/fonts/{name}", "text/plain")


class BoundedHTTP(H11Protocol):
    """Apply limits before ASGI starts, including an incomplete HTTP header."""

    def connection_made(self, transport):
        self.transport = transport
        self.web_deadline = None
        if len(self.connections) >= 16:
            transport.close()
            return
        super().connection_made(transport)
        self.web_deadline = self.loop.call_later(10, transport.close)

    def connection_lost(self, exc):
        if getattr(self, "web_deadline", None) is not None:
            self.web_deadline.cancel()
        super().connection_lost(exc)


class App:
    def __init__(self, backend, host):
        self.backend = backend
        self.host = host
        self.origin = f"http://{host}"
        self.cookie = f"evertrace_web_{host.rsplit(':', 1)[1]}"
        self.capability = secrets.token_hex(32)
        self.bootstrap_deadline = time.monotonic() + 120
        self.session = None
        self.templates = Environment(
            loader=FileSystemLoader(str(ROOT / "templates")),
            autoescape=select_autoescape(("html",)),
            undefined=StrictUndefined,
            cache_size=8,
            auto_reload=False,
        )
        self.templates.filters["pretty"] = lambda value: orjson.dumps(
            value, option=orjson.OPT_INDENT_2
        ).decode()
        self.templates.filters["field_value"] = display_field_value

    def authenticated(self, request, touch=False):
        current = self.session
        if current is None:
            return False
        now = time.monotonic()
        if now - current["started"] >= 8 * 3600 or now - current["seen"] >= 15 * 60:
            self.session = None
            return False
        cookies = [
            part.strip().partition("=")[2]
            for part in request.headers.get("cookie", "").split(";")
            if part.strip().partition("=")[0] == self.cookie
        ]
        if len(cookies) != 1 or not hmac.compare_digest(cookies[0], current["token"]):
            return False
        if touch:
            current["seen"] = now
        return True

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        messages = asyncio.Queue(maxsize=1)
        disconnected = asyncio.Event()
        started = False

        async def incoming():
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    disconnected.set()
                    return
                await messages.put(message)

        async def sending(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        async def respond():
            request = Request(scope, receive=messages.get)
            try:
                response = await self.handle(request)
            except (ValueError, TypeError, KeyError, BackendError, ClientDisconnect):
                response = JSONResponse({"error": "invalid_request"}, status_code=400)
            for key, value in SECURITY.items():
                response.headers[key] = value
            await response(scope, messages.get, sending)

        reader = asyncio.create_task(incoming())
        operation = asyncio.create_task(respond())
        peer = asyncio.create_task(disconnected.wait())
        expired = False
        try:
            async with asyncio.timeout(5):
                done, _ = await asyncio.wait((operation, reader, peer), return_when=asyncio.FIRST_COMPLETED)
                if operation in done:
                    await operation
                elif reader in done:
                    reader.result()
        except TimeoutError:
            expired = True
        finally:
            for task in (operation, reader, peer):
                task.cancel()
            await asyncio.gather(operation, reader, peer, return_exceptions=True)
        if expired and not started:
            response = JSONResponse({"error": "read_deadline"}, status_code=504, headers=SECURITY)
            await response(scope, receive, send)

    async def handle(self, request):
        raw = request.scope["headers"]
        sensitive = {
            b"host",
            b"origin",
            b"cookie",
            b"x-evertrace-web",
            b"x-evertrace-csrf",
            b"content-length",
            b"transfer-encoding",
        }
        if (
            len(raw) > 32
            or sum(len(key) + len(value) + 4 for key, value in raw) > 16_384
            or any(sum(key.lower() == name for key, _ in raw) > 1 for name in sensitive)
        ):
            return JSONResponse({"error": "invalid_headers"}, status_code=400)
        if (
            request.headers.get("host") != self.host
            or request.headers.get("origin", self.origin) != self.origin
        ):
            return JSONResponse({"error": "wrong_origin"}, status_code=403)
        if request.method not in ("GET", "POST"):
            return Response(status_code=405)
        path = request.url.path
        if request.method == "GET" and path == "/":
            return HTMLResponse(self.templates.get_template("index.html").render())
        if request.method == "GET" and path in STATIC:
            relative, content_type = STATIC[path]
            file = ROOT / "static" / relative
            if (
                file.is_symlink()
                or not file.resolve().is_relative_to((ROOT / "static").resolve())
                or not file.is_file()
            ):
                return Response(status_code=404)
            return FileResponse(file, media_type=content_type)
        if not path.startswith("/api/"):
            return Response(status_code=404)
        if request.headers.get("x-evertrace-web") != "1":
            return JSONResponse({"error": "web_header_required"}, status_code=403)
        expected_method = {
            "/api/session": "GET",
            "/api/status": "GET",
            "/api/bootstrap": "POST",
            "/api/logout": "POST",
            "/api/read": "POST",
        }.get(path)
        if expected_method is None:
            return Response(status_code=404)
        if request.method != expected_method:
            return Response(status_code=405)
        payload = None
        if request.method == "POST":
            if (
                request.headers.get("origin") != self.origin
                or request.headers.get("content-type") != "application/json"
            ):
                return JSONResponse({"error": "invalid_post"}, status_code=403)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 8192:
                    return JSONResponse({"error": "body_too_large"}, status_code=413)
            payload = _decode(bytes(body))
            if not isinstance(payload, dict):
                return JSONResponse({"error": "invalid_body"}, status_code=400)
        if path == "/api/bootstrap":
            supplied = payload.get("token")
            if (
                set(payload) != {"token"}
                or not isinstance(supplied, str)
                or self.capability is None
                or time.monotonic() >= self.bootstrap_deadline
                or not hmac.compare_digest(supplied, self.capability)
            ):
                return JSONResponse({"error": "invalid_capability"}, status_code=403)
            now = time.monotonic()
            self.capability = None
            self.session = {
                "token": secrets.token_hex(32),
                "csrf": secrets.token_hex(32),
                "started": now,
                "seen": now,
            }
            response = JSONResponse({"csrf": self.session["csrf"]})
            response.set_cookie(
                self.cookie, self.session["token"], httponly=True, samesite="strict", path="/"
            )
            return response
        if not self.authenticated(request, touch=True):
            return JSONResponse({"error": "session_expired"}, status_code=401)
        current = self.session
        if request.method == "POST" and not hmac.compare_digest(
            request.headers.get("x-evertrace-csrf", ""), current["csrf"]
        ):
            return JSONResponse({"error": "csrf_required"}, status_code=403)
        if path == "/api/session":
            return JSONResponse({"csrf": current["csrf"]})
        if path == "/api/logout":
            if payload:
                return JSONResponse({"error": "invalid_body"}, status_code=400)
            self.session = None
            response = JSONResponse({"closed": True})
            response.delete_cookie(self.cookie, httponly=True, samesite="strict", path="/")
            return response
        try:
            if path == "/api/status":
                result = await self.backend.health()
                data = {"mode": result["mode"], "config_hash": result["effective_config_hash"]}
            elif payload.get("kind") == "list" and not (
                set(payload) - {"kind", "query", "after", "expected_frontier"}
            ):
                after = payload.get("after")
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                if not valid_ref(after, optional=True):
                    return JSONResponse({"error": "invalid_read"}, status_code=400)
                result = await read_memories(self.backend, payload.get("query"), after, frontier)
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    empty = (
                        "范围不存在、已移除或当前不可用；这不表示记忆数量为零。"
                        if not result["scope_available"]
                        else "这些条件下没有条目；可以清除筛选。"
                        if result["total_count"]
                        else "当前范围没有可列出的元数据记录。"
                    )
                    data = {
                        "html": self.templates.get_template("list.html").render(
                            items=result["items"], empty_message=empty
                        ),
                        "frontier": str(result["frontier"]),
                        "next_cursor": result["next_cursor"],
                        "count": len(result["items"]),
                        "degraded": result["status"] != "ready",
                        "query": present_memory_query(result["query"]),
                        "total_count": str(result["total_count"])
                        if result["total_count"] is not None
                        else None,
                        "matching_count": str(result["matching_count"])
                        if result["matching_count"] is not None
                        else None,
                        "scope_available": result["scope_available"],
                        "counts_complete": result["counts_complete"],
                        "unresolved_scope_count": str(result["unresolved_scope_count"]),
                    }
            elif payload.get("kind") == "compiled" and not (
                set(payload) - {"kind", "query", "expected_frontier", "after"}
            ):
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                after = payload.get("after")
                if not valid_ref(after, optional=True):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await self.backend.compiled(payload.get("query"), frontier, after)
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    page = result["page"]
                    template = "compiled_list.html" if page["kind"] == "directory" else "compiled_entries.html"
                    data = {
                        "kind": page["kind"], "html": self.templates.get_template(template).render(page=page),
                        "frontier": str(page["frontier"]), "query": page["query"],
                        "scope_available": page["scope_available"], "complete": page["complete"],
                        "matching_count": str(page["matching_count"]) if page["matching_count"] is not None else None,
                        "next_cursor": page["next_cursor"],
                    }
            elif payload.get("kind") == "overview" and not (
                set(payload) - {"kind", "query", "expected_frontier"}
            ):
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                result = await read_overview(self.backend, payload.get("query", {}), frontier)
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    page = result["page"]
                    data = {
                        "html": self.templates.get_template("overview.html").render(page=page),
                        "frontier": str(page["frontier"]),
                        "observed_at_us": str(page["observed_at_us"]),
                        "query": present_memory_query(page["query"]),
                        "scope_available": page["scope_available"],
                        "complete": page["complete"],
                    }
            elif payload.get("kind") == "jobs" and not (
                set(payload) - {"kind", "after", "expected_frontier"}
            ):
                after = payload.get("after")
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                if not valid_ref(after, optional=True):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await read_jobs(self.backend, after, frontier)
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    data = {
                        "html": self.templates.get_template("jobs.html").render(jobs=result["records"]),
                        "frontier": str(result["frontier"]),
                        "next_cursor": result["next_cursor"],
                        "count": len(result["records"]),
                        "total_count": result["total_count"],
                        "degraded": False,
                    }
            elif payload.get("kind") == "inbox" and not (
                set(payload) - {"kind", "after", "expected_frontier"}
            ):
                after = payload.get("after")
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                if not valid_ref(after, optional=True):
                    return JSONResponse({"error": "invalid_read"}, 400)
                surface = "inbox"
                result = await self.backend.observations(after, frontier)
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    data = {
                        "html": self.templates.get_template("observations.html").render(
                            items=result["items"], surface=surface
                        ),
                        "frontier": str(result["frontier"]),
                        "next_cursor": result["next_cursor"],
                        "count": len(result["items"]),
                        "degraded": result["status"] != "ready",
                    }
            elif payload.get("kind") == "job" and set(payload) == {"kind", "job_id", "frontier"}:
                result = await self.backend.job(
                    payload["job_id"], parse_frontier(payload["frontier"])
                )
                data = present_detail(self.templates, result, "system")
            elif payload.get("kind") == "source_archive" and not (
                set(payload) - {"kind", "query", "after", "expected_frontier", "limit"}
            ):
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                after = payload.get("after")
                if not valid_ref(after, optional=True):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await read_source_archive(self.backend, payload.get("query"), after, frontier, payload.get("limit", 32))
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    page = result["page"]
                    query = dict(page["query"])
                    if query["kind"] == "records":
                        for key in ("from_sequence", "until_sequence"):
                            query[key] = str(query[key]) if query[key] is not None else None
                    data = {
                        "html": self.templates.get_template("source_archive.html").render(
                            page=page
                        ),
                        "query": query,
                        "frontier": str(page["frontier"]),
                        "next_cursor": page["next_cursor"],
                        "state": page["state"],
                        "matching_count": str(page["matching_count"]) if page["matching_count"] is not None else None,
                        "count_basis": page["count_basis"],
                    }
            elif payload.get("kind") == "source_catalog" and not (
                set(payload) - {"kind", "query", "after", "expected_frontier", "limit"}
            ):
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                after = payload.get("after")
                if not valid_ref(after, optional=True):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await read_source_catalog(self.backend, payload.get("query"), after, frontier, payload.get("limit", 32))
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    page = result["page"]
                    selected = (
                        page["entries"][0]
                        if page["query"]["source_instance_id"] is not None
                        and len(page["entries"]) == 1
                        else None
                    )
                    data = {
                        "html": self.templates.get_template("source_catalog.html").render(
                            groups=page["groups"], state=page["state"]
                        ),
                        "detail_html": self.templates.get_template(
                            "source_catalog_detail.html"
                        ).render(item=selected),
                        "query": page["query"],
                        "frontier": str(page["frontier"]),
                        "next_cursor": page["next_cursor"],
                        "count": len(page["entries"]),
                        "state": page["state"],
                        "matching_count": str(page["matching_count"]) if page["matching_count"] is not None else None,
                        "count_basis": page["count_basis"],
                    }
            elif payload.get("kind") == "scopes" and not (
                set(payload) - {"kind", "query", "after", "expected_frontier", "limit"}
            ):
                frontier = parse_frontier(payload.get("expected_frontier"), optional=True)
                after = payload.get("after")
                if not valid_ref(after, optional=True):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await read_scopes(self.backend, payload.get("query"), after, frontier, payload.get("limit", 32))
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    page = result["page"]
                    data = {
                        "html": self.templates.get_template("scopes.html").render(
                            items=page["items"]
                        ),
                        "query": page["query"],
                        "frontier": str(page["frontier"]),
                        "next_cursor": page["next_cursor"],
                        "parent_available": page["parent_available"],
                        "complete": page["complete"],
                        "names_complete": page["names_complete"],
                        "matching_count": str(page["matching_count"]) if page["matching_count"] is not None else None,
                        "count_basis": page["count_basis"],
                    }
            elif payload.get("kind") == "compare" and set(payload) == {
                "kind",
                "query",
                "frontier",
                "after",
            }:
                frontier = parse_frontier(payload["frontier"])
                if not valid_ref(payload["after"], optional=True):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await read_comparison(self.backend, payload["query"], frontier, payload["after"])
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    comparison = result["comparison"]
                    data = {
                        "html": self.templates.get_template("comparison.html").render(
                            comparison=comparison
                        ),
                        "frontier": str(comparison["frontier"]),
                        "next_cursor": comparison["next_cursor"],
                        "status": comparison["status"],
                    }
            elif payload.get("kind") == "content" and set(payload) == {
                "kind",
                "reference",
                "frontier",
                "revision",
                "representation",
                "after",
            }:
                frontier = parse_frontier(payload["frontier"])
                if (
                    not valid_ref(payload["reference"])
                    or not valid_ref(payload["revision"])
                    or not valid_ref(payload["after"], optional=True)
                ):
                    return JSONResponse({"error": "invalid_read"}, 400)
                if payload["representation"] == "source_text":
                    result = await read_source_content(
                        self.backend, payload["reference"], frontier, payload["revision"], payload["after"],
                    )
                else:
                    result = await read_record_content(
                        self.backend, payload["reference"], frontier, payload["revision"], payload["representation"], payload["after"],
                    )
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    content = result["content"]
                    data = {
                        "html": self.templates.get_template("content.html").render(content=content),
                        "text": content["text"],
                        "state": content["state"],
                        "previous_cursor": content["previous_cursor"],
                        "next_cursor": content["next_cursor"],
                        "frontier": str(content["frontier"]),
                        **{
                            key: str(content[key]) if content[key] is not None else None
                            for key in ("total_bytes", "range_start", "range_end")
                        },
                    }
            elif payload.get("kind") == "sources" and set(payload) - {"limit"} == {
                "kind",
                "reference",
                "frontier",
                "revision",
                "after",
            }:
                frontier = parse_frontier(payload["frontier"])
                if (
                    not valid_ref(payload["reference"])
                    or not valid_ref(payload["revision"])
                    or not valid_ref(payload["after"], optional=True)
                ):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await read_source_links(self.backend, payload["reference"], frontier,
                    payload["revision"], payload["after"], payload.get("limit", 32))
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    data = {
                        "html": self.templates.get_template("sources.html").render(**result),
                        "frontier": str(result["frontier"]),
                        "next_cursor": result["next_cursor"],
                        "status": result["status"],
                        "matching_count": str(result["matching_count"]) if result["matching_count"] is not None else None,
                        "count_basis": result["count_basis"],
                    }
            elif payload.get("kind") == "revisions" and set(payload) - {"limit"} == {
                "kind",
                "reference",
                "frontier",
                "revision",
                "after",
            }:
                frontier = parse_frontier(payload["frontier"])
                if (
                    not valid_ref(payload["reference"])
                    or not valid_ref(payload["revision"])
                    or not valid_ref(payload["after"], optional=True)
                ):
                    return JSONResponse({"error": "invalid_read"}, 400)
                result = await read_revisions(self.backend,
                    payload["reference"], frontier, payload["revision"], payload["after"], payload.get("limit", 32)
                )
                if result["kind"] == "conflict":
                    data = {"conflict": True}
                else:
                    data = {
                        "html": self.templates.get_template("revisions.html").render(
                            items=result["items"], source_revision=payload["revision"],
                            status=result["status"], matching_count=result["matching_count"],
                        ),
                        "frontier": str(result["frontier"]),
                        "next_cursor": result["next_cursor"],
                        "matching_count": str(result["matching_count"]) if result["matching_count"] is not None else None,
                        "state": result["status"],
                    }
            elif payload.get("kind") == "detail" and set(payload) == {
                "kind",
                "reference",
                "frontier",
                "revision",
                "surface",
                "object_kind",
            }:
                frontier = parse_frontier(payload["frontier"])
                surface = payload["surface"]
                if (
                    surface not in ("explorer", "inbox", "system")
                    or not isinstance(payload["object_kind"], str)
                    or not 0 < len(payload["object_kind"]) <= 64
                    or not valid_ref(payload["reference"])
                    or not valid_ref(payload["revision"], optional=True)
                ):
                    return JSONResponse({"error": "invalid_read"}, status_code=400)
                if surface == "explorer" and payload["object_kind"] in ("source_receipt", "source_observation"):
                    result = await read_source_detail(self.backend, payload["reference"], frontier,
                        payload["revision"], payload["object_kind"])
                elif surface == "explorer" and payload["object_kind"] in DETAIL_KINDS:
                    result = await read_record_detail(self.backend, payload["reference"], frontier,
                        payload["revision"], payload["object_kind"])
                else:
                    result = await self.backend.detail(
                        payload["reference"], frontier, payload["revision"], surface
                    )
                data = present_detail(self.templates, result, surface)
            else:
                return JSONResponse({"error": "read_unavailable"}, status_code=400)
        except BackendError as error:
            code = 400 if error.code == "invalid_input" else 503
            return JSONResponse(
                {"error": "invalid_read" if code == 400 else "daemon_unavailable"}, status_code=code
            )
        if self.session is not current or not self.authenticated(request):
            return JSONResponse({"error": "session_expired"}, status_code=401)
        return JSONResponse(data)


def present_detail(templates, result, surface):
    if result["kind"] == "conflict":
        return {"conflict": True}
    item = result["items"][0] if len(result["items"]) == 1 else None
    evidence = item.get("evidence_detail") if item else None
    presentation = evidence.get("protected_presentation") if evidence else None
    preview = (
        presentation.get("text")
        if presentation and presentation.get("kind") in ("inline", "preview")
        else None
    )
    semantic = item.get("semantic_detail") if item else None
    content = semantic.get("content") if semantic and semantic.get("state") == "ready" else None
    semantic_text = None
    if content and content["kind"] == "atom":
        semantic_text = content["value"]["value"]["text"]
    elif content and content["kind"] == "procedure":
        semantic_text = content["value"]["draft"]["summary"]
    template = "detail.html" if surface == "explorer" else "observation_detail.html"
    selection = (
        {
            "key": item["stable_key"],
            "revision": item["revision_ref"],
            "object": item["object_ref"],
            "kind": item["object_kind"],
            "surface": surface,
        }
        if item
        else None
    )
    return {
        "html": templates.get_template(template).render(items=result["items"], surface=surface),
        "source_preview": preview,
        "semantic_text": semantic_text,
        "selection": selection,
    }


def present_memory_query(query):
    result = dict(query)
    window = query.get("time_range")
    if window is not None:
        result["time_range"] = {
            "basis": window["basis"],
            "from_us": str(window["from_us"]) if window["from_us"] is not None else None,
            "until_us": str(window["until_us"]) if window["until_us"] is not None else None,
        }
    return result


def display_field_value(text):
    value = _decode(text.encode("utf-8"))
    # Preserve Native's bounded JSON presentation instead of expanding deeply
    # nested values or re-encoding their numbers in the Web process.
    return value if isinstance(value, str) else text


def valid_ref(value, optional=False):
    return (
        optional
        and value is None
        or isinstance(value, str)
        and 0 < len(value) <= 4096
        and not any(ord(char) < 32 for char in value)
    )


def parse_frontier(value, optional=False):
    if optional and value is None:
        return None
    # Browser-visible 64-bit sequence values use decimal strings, never float.
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("invalid frontier")
    return value


async def serve(context, port):
    backend = Backend(context["socket"], context["config_hash"], context["build_id"])
    await backend.health()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(16)
        listener.setblocking(False)
        host = f"127.0.0.1:{listener.getsockname()[1]}"
        app = App(backend, host)
        config = uvicorn.Config(
            app,
            http=BoundedHTTP,
            loop="asyncio",
            ws="none",
            workers=1,
            lifespan="off",
            access_log=False,
            server_header=False,
            date_header=False,
            log_level="warning",
            timeout_keep_alive=0,
            h11_max_incomplete_event_size=16_384,
        )
        print(f"WebUI: {app.origin}/#bootstrap={app.capability}", flush=True)
        await uvicorn.Server(config).serve(sockets=[listener])
    finally:
        listener.close()


def run(context, port):
    asyncio.run(serve(context, port))
