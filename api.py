#!/usr/bin/env python3
"""FastAPI application: middleware, lifespan, and router registration.

The endpoint handlers live in ``routers/*``; aggregation logic lives in
``services/aggregations/*``. This file's only job is to wire them together.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from routers import (
    address_labels,
    agent,
    analyses,
    audits,
    company,
    fleet,
    jobs,
    meta,
    monitored,
    predicate_capabilities,
    protocols,
    spa,
)
from utils.logging import bind_trace_context, configure_logging, trace_id_var
from utils.ratelimit import SlidingWindowRateLimiter, client_ip

logger = logging.getLogger(__name__)

TRACE_ID_HEADER = "X-PSAT-Trace-Id"

# Job.trace_id is String(32); the id is reflected in a response header and
# injected into log fields, so a client-supplied value must be a bounded,
# character-safe token or it is discarded and a fresh id minted.
_TRACE_ID_RE = re.compile(r"[A-Za-z0-9-]{1,32}")

# A request slower than this is logged at WARNING even on a 2xx — a slow
# endpoint is degraded service worth surfacing without a separate alert rule.
_SLOW_REQUEST_MS = 1000

# Reject a request whose declared Content-Length exceeds this ceiling before
# it is read into memory. PSAT_MAX_BODY_BYTES overrides (bytes).
_MAX_BODY_BYTES = int(os.environ.get("PSAT_MAX_BODY_BYTES", str(4 * 1024 * 1024)))

# Fleet-wide per-IP request cap. Generous by default so the SPA's burst of
# API calls per page is unaffected; a scraper/abuser is throttled.
# PSAT_GLOBAL_RATE_LIMIT / _WINDOW_S override; 0 disables.
_GLOBAL_RATE_LIMIT = int(os.environ.get("PSAT_GLOBAL_RATE_LIMIT", "300"))
_GLOBAL_RATE_WINDOW_S = float(os.environ.get("PSAT_GLOBAL_RATE_WINDOW_S", "60"))
_global_limiter = SlidingWindowRateLimiter(_GLOBAL_RATE_LIMIT, _GLOBAL_RATE_WINDOW_S)

# script-src stays 'self' (no inline scripts in the built SPA); style-src keeps
# 'unsafe-inline' for the styled-component / inline-style surface and allows the
# Google Fonts stylesheet host. connect-src adds the CoinGecko logo API the SPA
# fetches directly; img-src is pinned to the two CoinGecko asset hosts the logo
# URLs resolve to (plus 'self'/data:) rather than a blanket https: sink.
# frame-ancestors 'self' keeps the same-origin audit-pdf iframe working while
# blocking cross-site framing.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'self'; "
    "img-src 'self' data: https://assets.coingecko.com https://coin-images.coingecko.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' https://api.coingecko.com"
)
_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def _security_headers_response(
    status_code: int, detail: str, extra_headers: dict[str, str] | None = None
) -> JSONResponse:
    resp = JSONResponse(status_code=status_code, content={"detail": detail})
    for name, value in _SECURITY_HEADERS.items():
        resp.headers[name] = value
    for name, value in (extra_headers or {}).items():
        resp.headers[name] = value
    return resp


class BodySizeLimitMiddleware:
    """Reject request bodies larger than the configured cap with 413.

    A declared ``Content-Length`` is rejected up-front (the honest common
    case, and the server holds the peer to that length). A
    ``Transfer-Encoding: chunked`` request carries no length, so the received
    stream is counted and the request rejected the moment its cumulative body
    crosses the cap — closing the unbounded-buffering bypass. The cap is read
    live from ``_MAX_BODY_BYTES`` so an env/test override takes effect without
    reconstructing the app.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from starlette.datastructures import Headers

        max_bytes = _MAX_BODY_BYTES
        headers = Headers(scope=scope)
        declared = headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                length = -1
            if length < 0 or length > max_bytes:
                await self._reject(scope, send, max_bytes)
                return
            # Server enforces the declared length: the body can't exceed it.
            await self.app(scope, receive, send)
            return

        # No Content-Length (chunked): buffer-and-count before invoking the app
        # so an over-cap body is rejected without any downstream send having
        # started (no response-conflict), then replay the body downstream.
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                chunks = []
                break
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > max_bytes:
                await self._reject(scope, send, max_bytes)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    async def _reject(self, scope, send, max_bytes: int) -> None:
        response = _security_headers_response(413, f"Request body exceeds the {max_bytes}-byte limit")

        async def _noop_receive():
            return {"type": "http.disconnect"}

        await response(scope, _noop_receive, send)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Install JSON logging and verify DB reachability on startup."""
    configure_logging()
    try:
        # Local import dodges a circular at module load (db.models indirectly
        # imports modules that read api during eager evaluation in some envs).
        from db.models import engine

        with engine.connect() as conn:
            conn.execute(select(1))
        logger.info("Database connection verified")
    except Exception as exc:
        # Degraded-but-continuing: the app boots so it can serve a 503 once the
        # DB returns. Carry the root cause as a queryable field instead of a
        # bare message (matches routers/meta.py's exc_type convention).
        logger.warning(
            "Database not reachable at startup - endpoints will fail until DB is available: %s",
            exc,
            extra={"exc_type": type(exc).__name__},
        )

    # Ops watchdog: web is the only fly-health-checked, auto-started group, so it
    # is where the process that watches the monitoring daemons for silence lives.
    from services.monitoring.ops_alerts import run_ops_alerter_loop

    ops_stop = asyncio.Event()
    ops_task = asyncio.create_task(run_ops_alerter_loop(ops_stop))
    try:
        yield
    finally:
        ops_stop.set()
        ops_task.cancel()
        with suppress(asyncio.CancelledError):
            await ops_task


_raw_origins = os.environ.get("PSAT_SITE_ORIGIN", "")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    logger.warning(
        "PSAT_SITE_ORIGIN is not set - CORS will deny all cross-origin requests. "
        "Set PSAT_SITE_ORIGIN to a comma-separated list of allowed origins."
    )

app = FastAPI(title="PSAT Demo", version="0.1.0", lifespan=lifespan)


def _log_request(*, method: str, path: str, status_code: int, duration_ms: int, trace_id: str) -> None:
    """Emit one structured line per served request.

    INFO for a healthy fast response; WARNING when the response is a 5xx or
    when the request crossed the slow threshold — both are degraded service.
    Facts go in ``extra`` so request rate, latency, and error spikes are
    single Loki aggregations rather than message-regex over uvicorn plaintext.
    """
    level = logging.INFO
    if status_code >= 500 or duration_ms >= _SLOW_REQUEST_MS:
        level = logging.WARNING
    logger.log(
        level,
        "request %s %s -> %d (%dms)",
        method,
        path,
        status_code,
        duration_ms,
        extra={
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "trace_id": trace_id,
        },
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler for exceptions that escape a route.

    Logs at ERROR with the traceback and the request's ``trace_id`` — this is
    a genuinely request-failing path (it returns a 500), so ERROR + ``exc_info``
    is the correct level here, not a swallowed-continue WARNING. FastAPI routes
    ``HTTPException`` through its own handler, so this only fires on a truly
    unhandled error.
    """
    logger.error(
        "unhandled exception serving %s %s",
        request.method,
        request.url.path,
        exc_info=exc,
        extra={
            "method": request.method,
            "path": request.url.path,
            "trace_id": trace_id_var.get(),
            "exc_type": type(exc).__name__,
        },
    )
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


app.add_exception_handler(Exception, unhandled_exception_handler)


@app.middleware("http")
async def trace_id_middleware(request: Request, call_next):
    """Bind a per-request ``trace_id`` for the entire request lifecycle.

    Reads the client's ``X-PSAT-Trace-Id`` if present; otherwise mints a
    fresh 16-char hex id. Echoes the resolved id back as a response
    header so the caller can grep their fly logs for that exact id.

    Registered before GZipMiddleware below so the bind covers every
    nested middleware (compression, CORS) plus the route handler. Note
    that FastAPI runs ``add_middleware`` in reverse order of registration,
    so registering this with the decorator first puts it on the outside
    of the stack regardless of where the others land.
    """
    incoming = request.headers.get(TRACE_ID_HEADER)
    # A client-supplied id is trusted only when it is a bounded, char-safe
    # token; anything else is discarded and a fresh id minted, so the value
    # reflected back and stored on Job.trace_id is always well-formed.
    trace_id = incoming if incoming and _TRACE_ID_RE.fullmatch(incoming) else uuid.uuid4().hex[:16]
    started = time.monotonic()
    with bind_trace_context(trace_id=trace_id):
        response = await call_next(request)
        # Logged inside the bound context so the line also carries the
        # contextvar-injected trace_id. A request that raises is logged by
        # ``unhandled_exception_handler`` (registered above) instead.
        _log_request(
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=int((time.monotonic() - started) * 1000),
            trace_id=trace_id,
        )
    response.headers[TRACE_ID_HEADER] = trace_id
    return response


# Compress JSON > 1KB on the wire. /api/company/{name} routinely returns
# 1-3 MB of nested control-graph data; gzip cuts it ~5-10x and is the single
# largest win for the company page's perceived load time.
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-PSAT-Admin-Key"],
)


def _apply_security_headers(response):
    for name, value in _SECURITY_HEADERS.items():
        response.headers[name] = value
    return response


@app.middleware("http")
async def edge_guard_middleware(request: Request, call_next):
    """Per-IP rate limit + security headers on every response.

    The body-size cap runs in ``BodySizeLimitMiddleware`` (registered below,
    outermost); this guard adds the global rate limit and stamps the security
    headers, including on its own 429.
    """
    retry_after = _global_limiter.hit(client_ip(request))
    if retry_after is not None:
        return _security_headers_response(
            429,
            f"Rate limit exceeded ({_GLOBAL_RATE_LIMIT} requests / {int(_GLOBAL_RATE_WINDOW_S)}s).",
            {"Retry-After": str(retry_after)},
        )

    response = await call_next(request)
    return _apply_security_headers(response)


# Outermost: the body-size cap must see the raw request stream before any other
# middleware buffers it. Registered last so it wraps the whole stack.
app.add_middleware(BodySizeLimitMiddleware)


spa.mount_static_assets(app)

app.include_router(meta.router)
app.include_router(jobs.router)
app.include_router(fleet.router)
app.include_router(analyses.router)
app.include_router(company.router)
app.include_router(audits.router)
app.include_router(protocols.router)
app.include_router(monitored.router)
app.include_router(address_labels.router)
app.include_router(agent.router)
app.include_router(predicate_capabilities.router)
# SPA catch-all MUST be last - its /{full_path:path} would otherwise
# swallow any /api/* route registered after it.
app.include_router(spa.router)


def serve() -> None:
    """Launch uvicorn with this project's logging wired in.

    The uvicorn CLI can only accept a log config as a *file path*, so
    ``uvicorn api:app`` has no way to reach :func:`uvicorn_log_config` and
    every server line — including a bind failure like ``Address already in
    use``, which is emitted before the app's own lifespan runs — lands as
    plaintext outside the JSON stream. Launching programmatically is the one
    mechanism that covers those lines, so this is the entrypoint every launch
    script uses.

    ``access_log=False`` retires uvicorn's access line outright rather than
    reformatting it: ``trace_id_middleware`` already logs one line per served
    request carrying ``trace_id``, ``duration_ms`` and a WARNING level for
    5xx/slow — a strict superset. Keeping both logged every request twice.
    ``uvicorn.error`` (startup, shutdown, bind failures) still routes through
    ``JsonFormatter``.

    Call it from ``serve.py``, never by running this file. ``uvicorn.run`` is
    given the import string ``"api:app"``, so uvicorn imports this module —
    ``python api.py`` would have already run the same file as ``__main__``, and
    the body would execute twice (measured), building a second fully-wired app
    that is then discarded.
    """
    import uvicorn

    from utils.logging import uvicorn_log_config

    limit_concurrency = os.environ.get("PSAT_API_LIMIT_CONCURRENCY")
    uvicorn.run(
        # Import string, not the ``app`` object: ``reload`` needs it, and it
        # keeps the served app the same one under both settings.
        "api:app",
        host=os.environ.get("PSAT_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("PSAT_API_PORT", "8000")),
        reload=os.environ.get("PSAT_API_RELOAD") == "1",
        limit_concurrency=int(limit_concurrency) if limit_concurrency else None,
        log_config=uvicorn_log_config(),
        access_log=False,
    )
