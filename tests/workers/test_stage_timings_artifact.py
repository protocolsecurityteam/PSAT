"""Regression tests for the per-job stage_timing_<stage> artifacts written by
``workers.base.BaseWorker._record_stage_timing``.

A single shared ``stages`` array had a read-modify-write race: once ``advance_job``
commits, the next-stage worker can claim, complete, and clobber this stage's entry
(also on ``JobHandledDirectly`` paths). Schema v2 writes one ``stage_timing_<stage>``
artifact per stage so each worker owns its slot; bench reads via prefix scan.
Payload keys: schema_version "2", stage, started_at, ended_at, elapsed_s, worker_id,
status ("success"|"failed"|"handled_directly").
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

from db.models import Job, JobStage
from utils.logging import record_stage_metric, stage_metrics_var
from workers.base import BaseWorker


class _FakeWorker(BaseWorker):
    """Minimal subclass for unit-testing the helper in isolation."""

    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0.0


def _job(job_id: str = "job-1") -> Job:
    """Build a duck-typed Job stub. The helper only reads ``id`` so a
    SimpleNamespace satisfies the runtime contract; ``cast`` quiets pyright."""
    return cast(Job, SimpleNamespace(id=job_id, address="0xabc", name="test"))


def test_record_writes_per_stage_artifact_with_flat_payload(monkeypatch):
    """v2: per-stage artifact name and a single-record payload, so nothing else
    writes the same name."""
    captured: dict = {}

    def _fake_store(*args, **kw):
        captured["name"] = args[2] if len(args) > 2 else kw.get("name")
        captured["data"] = kw.get("data")

    monkeypatch.setattr("workers.base.store_artifact", _fake_store)

    w = _FakeWorker()
    w._record_stage_timing(
        MagicMock(),
        _job(),
        started_at="2026-04-27T03:00:00.000Z",
        ended_at="2026-04-27T03:00:02.500Z",
        elapsed_s=2.5,
        status="success",
    )

    assert captured["name"] == "stage_timing_discovery"
    payload = captured["data"]
    assert payload["schema_version"] == "2"
    assert payload["stage"] == "discovery"
    assert payload["elapsed_s"] == 2.5
    assert payload["status"] == "success"
    assert payload["started_at"] == "2026-04-27T03:00:00.000Z"
    assert payload["ended_at"] == "2026-04-27T03:00:02.500Z"
    assert payload["worker_id"].startswith("_FakeWorker-")


def test_each_stage_writes_its_own_artifact_name(monkeypatch):
    writes: list[tuple[str | None, dict | None]] = []

    def _fake_store(*args, **kw):
        name = args[2] if len(args) > 2 else kw.get("name")
        writes.append((name, kw.get("data")))

    monkeypatch.setattr("workers.base.store_artifact", _fake_store)

    class _StaticWorker(BaseWorker):
        stage = JobStage.static
        next_stage = JobStage.resolution

    _FakeWorker()._record_stage_timing(
        MagicMock(),
        _job(),
        started_at="t0",
        ended_at="t1",
        elapsed_s=1.0,
        status="success",
    )
    _StaticWorker()._record_stage_timing(
        MagicMock(),
        _job(),
        started_at="t2",
        ended_at="t3",
        elapsed_s=2.0,
        status="success",
    )

    names = [name for name, _ in writes]
    assert names == ["stage_timing_discovery", "stage_timing_static"]
    payload0, payload1 = writes[0][1], writes[1][1]
    assert payload0 is not None and payload1 is not None
    assert payload0["stage"] == "discovery"
    assert payload1["stage"] == "static"


def test_record_folds_stage_metrics_when_bound(monkeypatch):
    """Folded under ``metrics`` so the monitoring UI can show "12 deps, 3 principals"
    without log scraping."""
    captured: dict = {}
    monkeypatch.setattr(
        "workers.base.store_artifact",
        lambda *_a, **kw: captured.update({"data": kw.get("data")}),
    )

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        record_stage_metric("dependencies", 12)
        record_stage_metric("is_proxy", False)
        _FakeWorker()._record_stage_timing(
            MagicMock(),
            _job(),
            started_at="t0",
            ended_at="t1",
            elapsed_s=1.0,
            status="success",
        )
    finally:
        stage_metrics_var.reset(token)

    assert captured["data"]["metrics"] == {"dependencies": 12, "is_proxy": False}
    # Stored payload must be a copy — a later contextvar reset / mutation
    # cannot retroactively change what we persisted.
    metrics["dependencies"] = 999
    assert captured["data"]["metrics"]["dependencies"] == 12


def test_record_omits_metrics_key_when_none_recorded(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(
        "workers.base.store_artifact",
        lambda *_a, **kw: captured.update({"data": kw.get("data")}),
    )

    _FakeWorker()._record_stage_timing(
        MagicMock(),
        _job(),
        started_at="t0",
        ended_at="t1",
        elapsed_s=1.0,
        status="success",
    )
    assert "metrics" not in captured["data"]

    token = stage_metrics_var.set({})
    try:
        _FakeWorker()._record_stage_timing(
            MagicMock(),
            _job(),
            started_at="t0",
            ended_at="t1",
            elapsed_s=1.0,
            status="success",
        )
    finally:
        stage_metrics_var.reset(token)
    assert "metrics" not in captured["data"]


def test_record_failed_status_persists(monkeypatch):
    """Timing must be captured for errored jobs too (bench: which stage fails, and after how long)."""
    captured: dict = {}
    monkeypatch.setattr(
        "workers.base.store_artifact",
        lambda *a, **kw: captured.update({"data": kw.get("data")}),
    )

    w = _FakeWorker()
    w._record_stage_timing(
        MagicMock(),
        _job(),
        started_at="2026-04-27T03:00:00.000Z",
        ended_at="2026-04-27T03:00:30.000Z",
        elapsed_s=30.0,
        status="failed",
    )
    assert captured["data"]["status"] == "failed"
    assert captured["data"]["stage"] == "discovery"


def test_record_swallows_storage_errors():

    def _boom(*_a, **_kw):
        raise RuntimeError("storage down")

    fake_session = MagicMock()
    w = _FakeWorker()
    # Patch via direct attribute on the module so the call site's
    # store_artifact name resolves to the boom.
    import workers.base as base

    original = base.store_artifact
    base.store_artifact = _boom
    try:
        w._record_stage_timing(
            fake_session,
            _job(),
            started_at="2026-04-27T03:00:00.000Z",
            ended_at="2026-04-27T03:00:01.000Z",
            elapsed_s=1.0,
            status="success",
        )
    finally:
        base.store_artifact = original


# ---------------------------------------------------------------------------
# Codex-iter-1 finding: timing must be recorded before advance/complete
# ---------------------------------------------------------------------------


def test_record_timing_runs_before_advance_in_run_loop(monkeypatch):
    """Codex iter-1: recording-first preserves this worker's exclusive control of the
    row when its artifact lands, even with the v2 per-stage schema."""
    from db.models import JobStatus
    from workers import base

    call_order: list[str] = []

    class _OrderingWorker(BaseWorker):
        stage = JobStage.discovery
        next_stage = JobStage.static
        poll_interval = 0.0

        def process(self, session, job):
            call_order.append("process")

        def _record_stage_timing(self, *_a, **_kw):
            call_order.append("record_stage_timing")

    job = SimpleNamespace(
        id="job-ordering",
        address="0xabc",
        name="t",
        status=JobStatus.processing,
        worker_id="w",
        stage=JobStage.discovery,
    )

    claims = iter([job, None])

    def _fake_claim(self_, _session):
        call_order.append("claim")
        try:
            j = next(claims)
        except StopIteration:
            return None
        if j is None:
            self_._running = False
        return j

    def _fake_advance(_session, _job_id, _next_stage, _detail, **_kw):
        call_order.append("advance_job")

    def _fake_complete(_session, _job_id, **_kw):
        call_order.append("complete_job")

    monkeypatch.setattr(base.BaseWorker, "_claim_job", _fake_claim)
    monkeypatch.setattr(base, "advance_job", _fake_advance)
    import db.queue as db_queue

    monkeypatch.setattr(db_queue, "complete_job", _fake_complete)
    monkeypatch.setattr(base, "SessionLocal", lambda: MagicMock())
    monkeypatch.setattr(base.time, "sleep", lambda *_: None)

    w = _OrderingWorker()
    w.run_loop()

    relevant = [c for c in call_order if c in {"process", "record_stage_timing", "advance_job", "complete_job"}]
    assert relevant == ["process", "record_stage_timing", "advance_job"], (
        f"timing must record BEFORE advance_job; saw {relevant}"
    )


# ---------------------------------------------------------------------------
# Codex-iter-2 finding: rollback session on artifact-write failure
# ---------------------------------------------------------------------------


def test_run_loop_folds_recorded_metrics_into_artifact(monkeypatch):
    """Exercises the full ``_execute_job`` wiring: the per-job dict is bound before
    ``process()``, folded by ``_record_stage_timing``, and reset in the ``finally``."""
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

    # lease_id absent → no heartbeat thread / inflight registration to stub.
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
    # Contextvar must be reset after the job — no leak into the next claim.
    assert stage_metrics_var.get() is None


def test_record_rolls_back_session_on_store_failure(monkeypatch):
    """Codex iter-2: a failed ``store_artifact`` leaves the session needing rollback, so
    the next ``advance_job`` would raise ``PendingRollbackError`` and mark the job failed."""

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


def test_record_does_not_rollback_on_successful_store(monkeypatch):
    """Rolling back on success would discard the caller's pending writes from process()."""
    monkeypatch.setattr("workers.base.store_artifact", lambda *_a, **_kw: None)

    fake_session = MagicMock()
    w = _FakeWorker()
    w._record_stage_timing(
        fake_session,
        _job(),
        started_at="t0",
        ended_at="t1",
        elapsed_s=1.0,
        status="success",
    )
    fake_session.rollback.assert_not_called()
