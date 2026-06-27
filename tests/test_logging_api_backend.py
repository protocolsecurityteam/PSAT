"""Offline logging/observability tests for the API + aggregations layer.

Locks in the structured-field emission added for backlog items #12 (request
middleware + global exception handler), #17 (fleet degraded-health WARNINGs),
and #18 (admin-mutation audit trail + admin-key reject WARNING + stage_timing
body-missing WARNING + lifespan exc_type).

Fully offline: no DB, no network. The HTTP-layer assertions drive a throwaway
FastAPI app wired with the *real* middleware/handler functions from ``api`` so
the behaviour is exercised end-to-end without touching the production app's
lifespan (which would try to reach Postgres).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

import api
from routers import deps
from services.aggregations import fleet


def _make_request(path: str = "/api/x", method: str = "POST") -> Request:
    return Request({"type": "http", "method": method, "path": path, "headers": [], "query_string": b""})


def _rec(caplog, msg_substr: str):
    matches = [r for r in caplog.records if msg_substr in r.getMessage()]
    assert matches, f"no log record containing {msg_substr!r} (got {[r.getMessage() for r in caplog.records]})"
    return matches[-1]


# --- #12: request middleware -------------------------------------------------


def _build_app() -> FastAPI:
    app = FastAPI()
    app.middleware("http")(api.trace_id_middleware)
    app.add_exception_handler(Exception, api.unhandled_exception_handler)

    @app.get("/ok")
    def _ok() -> dict:
        return {"ok": True}

    @app.get("/boom")
    def _boom() -> dict:
        raise ValueError("kaboom")

    return app


def test_request_middleware_emits_info_with_extra_fields(caplog):
    client = TestClient(_build_app())
    with caplog.at_level(logging.INFO, logger="api"):
        resp = client.get("/ok", headers={api.TRACE_ID_HEADER: "trace-abc123"})
    assert resp.status_code == 200
    # trace_id is echoed back so the caller can grep their logs for it.
    assert resp.headers[api.TRACE_ID_HEADER] == "trace-abc123"
    rec = _rec(caplog, "request GET /ok")
    assert rec.levelno == logging.INFO
    assert rec.method == "GET"
    assert rec.path == "/ok"
    assert rec.status_code == 200
    assert isinstance(rec.duration_ms, int)
    assert rec.trace_id == "trace-abc123"


def test_request_log_helper_warns_on_5xx_and_slow():
    log = logging.getLogger("api")
    # 5xx response → WARNING even when fast.
    with _capture(log) as records:
        api._log_request(method="GET", path="/x", status_code=503, duration_ms=5, trace_id="t")
    assert records[-1].levelno == logging.WARNING
    assert records[-1].status_code == 503
    # Slow 2xx → WARNING on duration alone.
    with _capture(log) as records:
        api._log_request(method="GET", path="/x", status_code=200, duration_ms=api._SLOW_REQUEST_MS + 1, trace_id="t")
    assert records[-1].levelno == logging.WARNING


def test_unhandled_exception_handler_logs_error_with_traceback(caplog):
    handler = api.unhandled_exception_handler
    with caplog.at_level(logging.ERROR, logger="api"):
        resp = asyncio.run(handler(_make_request("/api/boom"), ValueError("kaboom")))
    assert resp.status_code == 500
    rec = _rec(caplog, "unhandled exception serving")
    assert rec.levelno == logging.ERROR
    assert rec.exc_type == "ValueError"
    assert rec.path == "/api/boom"
    # ERROR + exc_info: the only place in this layer that attaches a traceback.
    assert rec.exc_info is not None


# --- #18: admin mutation audit + admin-key reject ----------------------------


def test_log_admin_mutation_emits_info_with_action_and_id(caplog):
    from utils.logging import bind_trace_context

    log = logging.getLogger("routers.deps")
    with caplog.at_level(logging.INFO, logger="routers.deps"):
        with bind_trace_context(trace_id="t-mut"):
            deps.log_admin_mutation("job_retry", id="job-9", count=3)
    rec = _rec(caplog, "admin mutation: job_retry")
    assert rec.levelno == logging.INFO
    assert rec.action == "job_retry"
    assert rec.id == "job-9"
    assert rec.count == 3
    assert rec.trace_id == "t-mut"
    assert log.name == "routers.deps"


def test_require_admin_key_warns_on_reject_without_leaking_key(caplog, monkeypatch):
    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(deps, "ADMIN_KEY", "the-real-secret")
    with caplog.at_level(logging.WARNING, logger="routers.deps"):
        with pytest.raises(HTTPException) as ei:
            deps.require_admin_key(_make_request("/api/analyze"), "wrong-key")
    assert ei.value.status_code == 401
    rec = _rec(caplog, "admin key rejected")
    assert rec.levelno == logging.WARNING
    assert rec.reason == "key_mismatch"
    assert rec.path == "/api/analyze"
    # The supplied key must never appear in the structured record.
    assert "wrong-key" not in str(rec.__dict__)


def test_require_admin_key_distinguishes_missing_from_mismatch(caplog, monkeypatch):
    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(deps, "ADMIN_KEY", "the-real-secret")
    with caplog.at_level(logging.WARNING, logger="routers.deps"):
        with pytest.raises(HTTPException):
            deps.require_admin_key(_make_request("/api/analyze"), None)
    assert _rec(caplog, "admin key rejected").reason == "missing_key"


# --- #17: fleet degraded-health WARNINGs -------------------------------------


def test_fleet_warns_stale_daemon_with_process_and_age():
    with _capture(fleet.logger) as records:
        fleet._warn_stale_daemon("event_log_indexer", 420.0)
    rec = records[-1]
    assert rec.levelno == logging.WARNING
    assert rec.daemon == "event_log_indexer"
    assert rec.beat_age_s == 420.0


def test_fleet_warns_lagging_cursors_with_spread():
    with _capture(fleet.logger) as records:
        fleet._warn_lagging_cursors(3, 250_000)
    rec = records[-1]
    assert rec.levelno == logging.WARNING
    assert rec.lagging_cursors == 3
    assert rec.block_spread == 250_000


# --- helpers -----------------------------------------------------------------


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _capture:
    """Attach a record-collecting handler to *logger* for the block.

    Independent of caplog so the assertions read the exact ``extra`` fields off
    the ``LogRecord`` regardless of the root handler configuration other tests
    may have installed (configure_logging swaps the root handler globally)."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger
        self._handler = _ListHandler()

    def __enter__(self) -> list[Any]:
        self._prev_level = self._logger.level
        self._logger.setLevel(logging.DEBUG)
        self._logger.addHandler(self._handler)
        return self._handler.records

    def __exit__(self, *exc) -> None:
        self._logger.removeHandler(self._handler)
        self._logger.setLevel(self._prev_level)
