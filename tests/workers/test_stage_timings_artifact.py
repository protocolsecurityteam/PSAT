"""A shared ``stages`` array raced: once ``advance_job`` commits the next worker can clobber this stage's entry.

Schema v2 writes one ``stage_timing_<stage>`` artifact per stage.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

from db.models import Job, JobStage
from utils.logging import record_stage_metric, stage_metrics_var
from workers.base import BaseWorker


class _FakeWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0


def _job(job_id: str = "job-1") -> Job:
    """The helper only reads ``id``."""
    return cast(Job, SimpleNamespace(id=job_id, address="0xabc", name="test"))


def test_run_loop_folds_recorded_metrics_into_artifact(monkeypatch):
    from db.models import JobStatus
    from workers import base

    writes: list[tuple[str | None, dict | None]] = []

    def _fake_store(*args, **kw):
        name = args[2] if len(args) > 2 else kw.get("name")
        writes.append((name, kw.get("data")))

    class _MetricWorker(BaseWorker):
        stage = JobStage.static
        next_stage = JobStage.resolution
        poll_interval = 0.0

        def process(self, session, job):
            record_stage_metric("dependencies", 5)
            record_stage_metric("is_proxy", True)

    # No lease_id means no heartbeat thread to stub.
    job = SimpleNamespace(
        id="job-metrics",
        address="0xabc",
        name="t",
        status=JobStatus.processing,
        worker_id="w",
        stage=JobStage.static,
        request={},
        trace_id=None,
    )
    claims = iter([job, None])

    def _fake_claim(self_, _session):
        try:
            j = next(claims)
        except StopIteration:
            return None
        if j is None:
            self_._running = False
        return j

    monkeypatch.setattr(base.BaseWorker, "_claim_job", _fake_claim)
    monkeypatch.setattr(base, "store_artifact", _fake_store)
    monkeypatch.setattr(base, "advance_job", lambda *_a, **_kw: None)
    monkeypatch.setattr(base, "SessionLocal", lambda: MagicMock())
    monkeypatch.setattr(base.time, "sleep", lambda *_: None)

    _MetricWorker().run_loop()

    timing = next((data for name, data in writes if name == "stage_timing_static"), None)
    assert timing is not None, "stage_timing_static artifact was not written"
    assert timing["metrics"]["dependencies"] == 5
    assert timing["metrics"]["is_proxy"] is True
    assert timing["metrics"]["process_rss_peak_sampled_bytes"] >= timing["metrics"]["process_rss_start_bytes"]
    assert timing["metrics"]["process_rss_peak_sampled_bytes"] >= timing["metrics"]["process_rss_end_bytes"]
    assert stage_metrics_var.get() is None


def test_record_rolls_back_session_on_store_failure(monkeypatch):
    """Codex iter-2: otherwise the next ``advance_job`` raises ``PendingRollbackError``."""

    def _boom(*_a, **_kw):
        raise RuntimeError("artifact storage offline")

    monkeypatch.setattr("workers.base.store_artifact", _boom)

    fake_session = MagicMock()
    w = _FakeWorker()
    w._record_stage_timing(
        fake_session,
        _job(),
        started_at="2026-04-27T03:00:00.000Z",
        ended_at="2026-04-27T03:00:01.000Z",
        elapsed_s=1.0,
        status="success",
    )
    fake_session.rollback.assert_called_once()
