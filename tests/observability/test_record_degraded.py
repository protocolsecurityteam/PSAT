"""Unit tests for ``utils.logging.record_degraded``."""

from __future__ import annotations

import threading

from utils.logging import bind_trace_context, degraded_errors_var, record_degraded


def test_record_degraded_outside_job_context_is_noop():
    # No accumulator bound — call must not crash and must not write anywhere.
    record_degraded(phase="x", exc=RuntimeError("nope"))
    # The contextvar default stays None.
    assert degraded_errors_var.get() is None


def test_record_degraded_appends_to_accumulator_in_order():
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(
            trace_id="trace-1",
            job_id="job-1",
            stage="static",
            worker_id="StaticWorker-1",
        ):
            record_degraded(phase="dependency_static", exc=RuntimeError("first"))
            record_degraded(phase="dependency_dynamic", exc=ValueError("second"))
    finally:
        degraded_errors_var.reset(token)

    assert len(accumulator) == 2
    assert accumulator[0].phase == "dependency_static"
    assert accumulator[0].message == "first"
    assert accumulator[0].severity == "degraded"
    assert accumulator[0].stage == "static"
    assert accumulator[0].trace_id == "trace-1"
    assert accumulator[0].job_id == "job-1"
    assert accumulator[0].worker_id == "StaticWorker-1"
    assert accumulator[0].exc_type == "builtins.RuntimeError"
    assert accumulator[1].phase == "dependency_dynamic"
    assert accumulator[1].exc_type == "builtins.ValueError"


def test_record_degraded_optional_traceback_is_captured_when_requested():
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(stage="static", job_id="job-1", worker_id="w"):
            try:
                raise RuntimeError("with-tb")
            except RuntimeError as exc:
                record_degraded(phase="x", exc=exc, include_traceback=True)
    finally:
        degraded_errors_var.reset(token)
    assert accumulator[0].traceback is not None
    assert "with-tb" in accumulator[0].traceback


def test_record_degraded_per_thread_isolation():
    """Two threads each binding their own accumulator must not cross over."""

    results: dict[str, list] = {}

    def worker(name: str, stage: str, message: str) -> None:
        accumulator: list = []
        token = degraded_errors_var.set(accumulator)
        try:
            with bind_trace_context(stage=stage, job_id=name, worker_id=f"w-{name}"):
                record_degraded(phase="x", exc=RuntimeError(message))
                results[name] = list(accumulator)
        finally:
            degraded_errors_var.reset(token)

    t1 = threading.Thread(target=worker, args=("a", "discovery", "from-a"))
    t2 = threading.Thread(target=worker, args=("b", "static", "from-b"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(results["a"]) == 1
    assert len(results["b"]) == 1
    assert results["a"][0].message == "from-a"
    assert results["a"][0].stage == "discovery"
    assert results["b"][0].message == "from-b"
    assert results["b"][0].stage == "static"
