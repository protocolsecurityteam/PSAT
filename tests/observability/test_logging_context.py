"""Unit tests for utils/logging — JSON formatter + ContextVar propagation.

No DB required. Pins the four properties downstream code depends on:

1. ``bind_trace_context`` survives ``ThreadPoolExecutor.submit`` when
   wrapped with ``contextvars.copy_context().run`` (the standard pattern
   workers/base.py + services/concurrency.parallel_map use).
2. ``parallel_map`` propagates ``trace_id`` to its worker threads.
3. The JSON formatter emits set context fields and omits unset ones
   cleanly (no ``"trace_id": null`` spam).
4. Two concurrent contexts do not cross-contaminate — each thread
   sees its own ``trace_id``, never the sibling's.
"""

from __future__ import annotations

import contextvars
import io
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

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
    """When no context is bound the JSON body has no trace_id / job_id keys."""
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
    """Bound context shows up alongside the message."""
    logger, stream = _capture()
    with bind_trace_context(trace_id="abc1234567890def", job_id="j-1", stage="static"):
        logger.info("claimed")
    payload = json.loads(stream.getvalue())
    assert payload["trace_id"] == "abc1234567890def"
    assert payload["job_id"] == "j-1"
    assert payload["stage"] == "static"


def test_formatter_passes_extra_fields_through():
    """``extra={"duration_ms": ...}`` lands as a top-level JSON field."""
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
    """Calling configure_logging twice does not stack handlers, and a
    second call is a no-op so test harnesses (pytest's caplog) can add
    their own handlers without being wiped on a later worker init."""
    root = logging.getLogger()
    # Reset the per-process guard flag and any previous JSON handler so
    # this test exercises the first-call path deterministically — other
    # tests in the file may have triggered it via ``configure_logging``
    # or via ``BaseWorker.__init__`` indirectly.
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
    # Second call must NOT remove the test harness's added handler.
    assert n_after_second == 2
    assert extra in root.handlers


# ---------------------------------------------------------------------------
# ContextVar propagation across thread fan-out
# ---------------------------------------------------------------------------


def test_trace_id_does_not_leak_into_threadpool_without_copy_context():
    """Sanity check — bare ``executor.submit`` does NOT carry the parent's
    ContextVar. This is the bug we wrap around in workers.base + parallel_map."""

    def read_trace() -> str | None:
        return trace_id_var.get()

    with bind_trace_context(trace_id="parent"):
        with ThreadPoolExecutor(max_workers=1) as ex:
            seen = ex.submit(read_trace).result()
    assert seen is None


def test_trace_id_propagates_into_threadpool_with_copy_context():
    """The wrap pattern workers/base.py uses: copy_context().run(...)."""

    def read_trace() -> str | None:
        return trace_id_var.get()

    with bind_trace_context(trace_id="parent"):
        ctx = contextvars.copy_context()
        with ThreadPoolExecutor(max_workers=1) as ex:
            seen = ex.submit(ctx.run, read_trace).result()
    assert seen == "parent"


def test_parallel_map_propagates_trace_id():
    """parallel_map workers must inherit the caller's bound trace_id."""
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


# ---------------------------------------------------------------------------
# Cross-thread isolation
# ---------------------------------------------------------------------------


def test_concurrent_contexts_do_not_cross_contaminate():
    """Two threads each binding their own trace_id must never see the other's."""
    barrier = threading.Barrier(2, timeout=5)
    seen: dict[str, str | None] = {}

    def worker(name: str, trace: str) -> None:
        with bind_trace_context(trace_id=trace):
            barrier.wait()
            # While both threads are simultaneously inside their bind blocks,
            # each one's read must be its own value, not the sibling's.
            seen[name] = trace_id_var.get()
            barrier.wait()

    t1 = threading.Thread(target=worker, args=("a", "trace-a"))
    t2 = threading.Thread(target=worker, args=("b", "trace-b"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert seen == {"a": "trace-a", "b": "trace-b"}
