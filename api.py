#!/usr/bin/env python3
"""FastAPI application: middleware, lifespan, and router registration.

The endpoint handlers live in ``routers/*``; aggregation logic lives in
``services/aggregations/*``. This file's only job is to wire them together.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager

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

logger = logging.getLogger(__name__)

TRACE_ID_HEADER = "X-PSAT-Trace-Id"

# A request slower than this is logged at WARNING even on a 2xx — a slow
# endpoint is degraded service worth surfacing without a separate alert rule.
_SLOW_REQUEST_MS = 1000


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
    yield


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
    trace_id = incoming if incoming else uuid.uuid4().hex[:16]
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
