"""``BaseWorker`` folds these into ``stage_timing_<stage>`` so the monitoring UI shows what a stage did."""

from __future__ import annotations

from utils.logging import bind_trace_context, record_stage_metric, stage_metrics_var


def test_record_stage_metric_outside_job_context_is_noop():
    record_stage_metric("dependencies", 7)
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
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        record_stage_metric("graph_nodes", 1)
        record_stage_metric("graph_nodes", 9)
    finally:
        stage_metrics_var.reset(token)
    assert metrics == {"graph_nodes": 9}
