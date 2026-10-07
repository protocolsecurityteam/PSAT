#!/usr/bin/env python3
"""FastAPI app wiring: middleware, lifespan, routers."""

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
from fastapi.responses import JSONResponse
from sqlalchemy import select

from routers import (
    address_labels,
    agent,
    analyses,
    audits,
    auth,
    company,
    fleet,
    jobs,
    me,
    meta,
    monitored,
    predicate_capabilities,
    protocols,
    spa,
)
from services.auth.sessions import check_production_admin_config
from utils.company_limit import CompanyReadLimit
from utils.compression import NegotiatedGZipMiddleware
from utils.edge import CloudflareBoundary, EdgeConfig
from utils.logging import bind_trace_context, configure_logging, trace_id_var
from utils.ratelimit import SlidingWindowRateLimiter, client_ip

logger = logging.getLogger(__name__)

TRACE_ID_HEADER = "X-PSAT-Trace-Id"

# Reflected in a header and log fields, so a client value must be a bounded safe token or a fresh id is minted.
_TRACE_ID_RE = re.compile(r"[A-Za-z0-9-]{1,32}")

# Slow 2xx responses log at WARNING: degraded service without a separate alert rule.
_SLOW_REQUEST_MS = 1000

_MAX_BODY_BYTES = int(os.environ.get("PSAT_MAX_BODY_BYTES", str(4 * 1024 * 1024)))

# Generous so the SPA's per-page burst is unaffected. 0 disables.
_GLOBAL_RATE_LIMIT = int(os.environ.get("PSAT_GLOBAL_RATE_LIMIT", "300"))
_GLOBAL_RATE_WINDOW_S = float(os.environ.get("PSAT_GLOBAL_RATE_WINDOW_S", "60"))
_global_limiter = SlidingWindowRateLimiter(_GLOBAL_RATE_LIMIT, _GLOBAL_RATE_WINDOW_S)

# No inline scripts in the built SPA. Inline styles and Google Fonts are allowed; img/connect pinned to the CoinGecko
# hosts. frame-ancestors 'self' keeps the audit-pdf iframe working.
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
    """413 for bodies over the cap.

    Content-Length is checked up front; chunked bodies are counted as received, closing the unbounded-buffering bypass.
    The cap is read live so overrides need no app rebuild.
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
            # The server holds the peer to the declared length.
            await self.app(scope, receive, send)
            return

        # Buffer before invoking the app so an over-cap body is rejected before any response starts.
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
            # Body completion isn't a disconnect; a plain GET has no Content-Length and the admission queue must keep
            # waiting.
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _reject(self, scope, send, max_bytes: int) -> None:
        response = _security_headers_response(413, f"Request body exceeds the {max_bytes}-byte limit")

        async def _noop_receive():
            return {"type": "http.disconnect"}

        await response(scope, _noop_receive, send)


@asynccontextmanager
async def lifespan(app: FastAPI):
    check_production_admin_config(EdgeConfig.from_env().emails)
    configure_logging()
    try:
        # Avoids a circular import at module load.
        from db.models import engine

        with engine.connect() as conn:
            conn.execute(select(1))
        logger.info("Database connection verified")
    except Exception as exc:
        # Boot anyway so the app can serve 503 once the DB returns.
        logger.warning(
            "Database not reachable at startup - endpoints will fail until DB is available: %s",
            exc,
            extra={"exc_type": type(exc).__name__},
        )

    # Web is the only health-checked, auto-started group, so the watchdog for silent monitoring daemons lives here.
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
    """One line per request: INFO when healthy, WARNING on 5xx or slow. Facts in ``extra`` for Loki aggregation."""
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
    """Last-resort handler: ERROR with traceback, since this returns a 500.

    ``HTTPException`` goes through FastAPI's own handler.
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
    return JSONResponse(
        status_code=500, content={"detail": "Internal Server Error"}, headers={"Cache-Control": "private, no-store"}
    )


app.add_exception_handler(Exception, unhandled_exception_handler)


@app.middleware("http")
async def trace_id_middleware(request: Request, call_next):
    """Bind a ``trace_id`` for the request (client ``X-PSAT-Trace-Id`` or fresh) and echo it in the response.

    Middleware runs in reverse registration order, so registering this first puts it outermost.
    """
    incoming = request.headers.get(TRACE_ID_HEADER)
    trace_id = incoming if incoming and _TRACE_ID_RE.fullmatch(incoming) else uuid.uuid4().hex[:16]
    started = time.monotonic()
    with bind_trace_context(trace_id=trace_id):
        response = await call_next(request)
        # Inside the bound context so the line carries trace_id. Raising requests are logged by
        # ``unhandled_exception_handler``.
        _log_request(
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=int((time.monotonic() - started) * 1000),
            trace_id=trace_id,
        )
    response.headers[TRACE_ID_HEADER] = trace_id
    return response


# /api/company payloads are 1-3 MB; gzip cuts them ~5-10x.
app.add_middleware(NegotiatedGZipMiddleware, minimum_size=1024, compresslevel=6)
# Outside gzip so a slot covers the full compressed response; the Cloudflare boundary authenticates first.
app.add_middleware(CompanyReadLimit)
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
    response = await call_next(request)
    return _apply_security_headers(response)


def _rate_limit_response(request: Request):
    retry_after = _global_limiter.hit(client_ip(request))
    if retry_after is not None:
        return _security_headers_response(
            429,
            f"Rate limit exceeded ({_GLOBAL_RATE_LIMIT} requests / {int(_GLOBAL_RATE_WINDOW_S)}s).",
            {"Retry-After": str(retry_after)},
        )

    return None


# Before any middleware that buffers the body.
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(CloudflareBoundary, rate_limit=_rate_limit_response, denial_headers=_SECURITY_HEADERS)


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
app.include_router(auth.router)
app.include_router(me.router)
# SPA catch-all MUST be last.
app.include_router(spa.router)


def serve() -> None:
    """Launch uvicorn with JSON logging.

    The uvicorn CLI only takes a log config file, so bind failures (emitted before lifespan) would land as plaintext;
    launching programmatically covers them. ``access_log=False``: ``trace_id_middleware`` already logs a superset line.

    Call from ``serve.py``, never ``python api.py``: uvicorn imports ``"api:app"``, so running this file as ``__main__``
    executes the module body twice.
    """
    import uvicorn

    from utils.logging import uvicorn_log_config

    limit_concurrency = os.environ.get("PSAT_API_LIMIT_CONCURRENCY")
    uvicorn.run(
        # ``reload`` needs an import string.
        "api:app",
        host=os.environ.get("PSAT_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("PSAT_API_PORT", "8000")),
        reload=os.environ.get("PSAT_API_RELOAD") == "1",
        limit_concurrency=int(limit_concurrency) if limit_concurrency else None,
        log_config=uvicorn_log_config(),
        access_log=False,
        proxy_headers=False,
    )
