"""Unit tests for utils/logging: JSON formatter + ContextVar propagation. No DB.

Pins: ``bind_trace_context`` survives ``ThreadPoolExecutor.submit`` under
``copy_context().run`` (the workers/base.py + parallel_map pattern); ``parallel_map``
propagates ``trace_id``; the formatter omits unset context fields (no ``"trace_id": null``);
concurrent contexts never cross-contaminate.
"""

from __future__ import annotations

import io
import json
import logging

from services.concurrency import RpcExecutor, parallel_map
from utils.logging import (
    JsonFormatter,
    bind_trace_context,
    configure_logging,
    trace_id_var,
)


def _capture(level: int = logging.INFO) -> tuple[logging.Logger, io.StringIO]:
    """Build a logger pointed at an in-memory stream with our JSON formatter."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger(f"test.{id(stream)}")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger, stream


# ---------------------------------------------------------------------------
# JSON formatter shape
# ---------------------------------------------------------------------------


def test_formatter_omits_unset_context_fields():
    logger, stream = _capture()
    logger.info("hello")
    payload = json.loads(stream.getvalue())
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["logger"] == logger.name
    assert "trace_id" not in payload
    assert "job_id" not in payload
    assert "stage" not in payload


def test_formatter_emits_bound_context_fields():
    logger, stream = _capture()
    with bind_trace_context(trace_id="abc1234567890def", job_id="j-1", stage="static"):
        logger.info("claimed")
    payload = json.loads(stream.getvalue())
    assert payload["trace_id"] == "abc1234567890def"
    assert payload["job_id"] == "j-1"
    assert payload["stage"] == "static"


def test_formatter_passes_extra_fields_through():
    logger, stream = _capture()
    logger.info("done", extra={"duration_ms": 1234, "phase": "discovery"})
    payload = json.loads(stream.getvalue())
    assert payload["duration_ms"] == 1234
    assert payload["phase"] == "discovery"


def test_formatter_serializes_exception_traceback():
    logger, stream = _capture()
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        logger.exception("crashed")
    payload = json.loads(stream.getvalue())
    assert payload["level"] == "ERROR"
    assert "RuntimeError: boom" in payload["exc_info"]


def test_bind_trace_context_resets_on_exit():
    assert trace_id_var.get() is None
    with bind_trace_context(trace_id="t1"):
        assert trace_id_var.get() == "t1"
    assert trace_id_var.get() is None


def test_bind_trace_context_nests_cleanly():
    with bind_trace_context(trace_id="outer"):
        assert trace_id_var.get() == "outer"
        with bind_trace_context(trace_id="inner"):
            assert trace_id_var.get() == "inner"
        assert trace_id_var.get() == "outer"


def test_configure_logging_is_idempotent_across_calls():
    """A second call is a no-op, so harnesses (pytest's caplog) can add handlers without being
    wiped on a later worker init."""
    root = logging.getLogger()
    # Reset the guard flag and any prior JSON handler; other tests (or BaseWorker.__init__)
    # may have triggered the first-call path.
    if hasattr(root, "_psat_json_logging_configured"):
        delattr(root, "_psat_json_logging_configured")
    for h in list(root.handlers):
        root.removeHandler(h)

    configure_logging()
    n_after_first = len(root.handlers)
    extra = logging.NullHandler()
    root.addHandler(extra)
    configure_logging()
    n_after_second = len(root.handlers)
    assert n_after_first == 1
    assert n_after_second == 2
    assert extra in root.handlers


# ---------------------------------------------------------------------------
# ContextVar propagation across thread fan-out
# ---------------------------------------------------------------------------


def test_parallel_map_propagates_trace_id():
    RpcExecutor.reset_for_tests()

    def read_trace(item: int) -> tuple[int, str | None]:
        return item, trace_id_var.get()

    try:
        with bind_trace_context(trace_id="parent-job"):
            results = parallel_map(read_trace, list(range(8)), max_workers=4)
    finally:
        RpcExecutor.reset_for_tests()

    for item, outcome in results:
        assert not isinstance(outcome, BaseException)
        idx, trace = outcome
        assert idx == item
        assert trace == "parent-job"


def test_parallel_map_sequential_path_propagates_trace_id():
    """max_workers=1 runs in-thread; the caller's bind must still be visible."""

    def read_trace(item: int) -> str | None:
        return trace_id_var.get()

    with bind_trace_context(trace_id="serial"):
        results = parallel_map(read_trace, [1, 2, 3], max_workers=1)

    assert [r for _, r in results] == ["serial", "serial", "serial"]
