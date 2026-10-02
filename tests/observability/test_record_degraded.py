from __future__ import annotations

from utils.logging import bind_trace_context, degraded_errors_var, record_degraded


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
