"""Unit tests for ``utils.logging.record_stage_metric``.

Mirrors ``test_record_degraded`` — same per-job contextvar accumulator
pattern, just a dict of progress metrics instead of a list of errors. The
metrics are folded into the ``stage_timing_<stage>`` artifact by
``BaseWorker`` so the monitoring UI can show what a stage did without
scraping logs.
"""

from __future__ import annotations

import threading

from utils.logging import bind_trace_context, record_stage_metric, stage_metrics_var


def test_record_stage_metric_outside_job_context_is_noop():
    # No accumulator bound — call must not crash and must not write anywhere.
    record_stage_metric("dependencies", 7)
    # The contextvar default stays None.
    assert stage_metrics_var.get() is None


def test_record_stage_metric_writes_into_accumulator():
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(stage="static", job_id="job-1", worker_id="StaticWorker-1"):
            record_stage_metric("static_dependencies", 12)
            record_stage_metric("dynamic_dependencies", 3)
            record_stage_metric("is_proxy", False)
    finally:
        stage_metrics_var.reset(token)

    assert metrics == {"static_dependencies": 12, "dynamic_dependencies": 3, "is_proxy": False}


def test_record_stage_metric_last_write_wins():
    """A worker can update a running total — later writes overwrite earlier
    ones for the same key."""
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        record_stage_metric("graph_nodes", 1)
        record_stage_metric("graph_nodes", 9)
    finally:
        stage_metrics_var.reset(token)
    assert metrics == {"graph_nodes": 9}


def test_record_stage_metric_per_thread_isolation():
    """Two threads each binding their own accumulator must not cross over —
    the K>1 dispatcher relies on this for parallel jobs."""
    results: dict[str, dict] = {}

    def worker(name: str, key: str, value: int) -> None:
        metrics: dict = {}
        token = stage_metrics_var.set(metrics)
        try:
            with bind_trace_context(stage="resolution", job_id=name, worker_id=f"w-{name}"):
                record_stage_metric(key, value)
                results[name] = dict(metrics)
        finally:
            stage_metrics_var.reset(token)

    t1 = threading.Thread(target=worker, args=("a", "controllers_resolved", 4))
    t2 = threading.Thread(target=worker, args=("b", "graph_edges", 11))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["a"] == {"controllers_resolved": 4}
    assert results["b"] == {"graph_edges": 11}
