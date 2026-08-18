"""Regression tests for the per-job stage_timing_<stage> artifacts written
by ``workers.base.BaseWorker._record_stage_timing``.

Originally a single shared ``stage_timings`` artifact with a ``stages``
array. Codex iter-1 + iter-2 both flagged the read-modify-write race:
when ``advance_job`` commits before the artifact write, the next-stage
worker can claim, complete, and clobber this stage's entry. Same race
applies to ``JobHandledDirectly`` paths where ``process()`` advances
inside itself.

Schema (v2):
  artifact name: ``stage_timing_<stage>`` (one per stage, no array)
  payload:
    {"schema_version": "2",
     "stage": "discovery"|"static"|"resolution"|...,
     "started_at": ISO, "ended_at": ISO, "elapsed_s": float,
     "worker_id": str, "status": "success"|"failed"|"handled_directly"}

One artifact per stage means each worker owns its own slot. Bench reads
via prefix scan over ``stage_timing_*`` and concatenates.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
    """v2 schema: artifact name is per-stage, payload is a single record
    (not a stages array). Eliminates the read-modify-write race entirely
    because nothing else writes to the same artifact name."""
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
    """Two different stages on the same job must produce two artifacts
    with distinct names — proving there's no shared slot to race on."""
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
    # Each payload is its own self-contained record (no shared array).
    payload0, payload1 = writes[0][1], writes[1][1]
    assert payload0 is not None and payload1 is not None
    assert payload0["stage"] == "discovery"
    assert payload1["stage"] == "static"


def test_record_folds_stage_metrics_when_bound(monkeypatch):
    """Metrics recorded via ``record_stage_metric`` during a stage are folded
    into that stage's timing artifact under a ``metrics`` key — this is what
    lets the monitoring UI show "12 deps, 3 principals" without log scraping."""
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
    """No metrics bound (or none recorded) → no ``metrics`` key at all, so
    legacy readers and the v2 schema are untouched."""
    captured: dict = {}
    monkeypatch.setattr(
        "workers.base.store_artifact",
        lambda *_a, **kw: captured.update({"data": kw.get("data")}),
    )

    # Unbound contextvar (default None).
    _FakeWorker()._record_stage_timing(
        MagicMock(),
        _job(),
        started_at="t0",
        ended_at="t1",
        elapsed_s=1.0,
        status="success",
    )
    assert "metrics" not in captured["data"]

    # Bound but empty dict — still omitted (falsy).
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
    """The exception path in run_loop calls record with status='failed'.
    Ensures we capture timing for jobs that errored out — important for
    bench analysis ('which stage tends to fail and how long does it run
    before failing?')."""
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
    """A failing artifact write must NOT crash the worker — losing a
    metrics record beats failing a real job over a metrics-only bug."""

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
        # Should not raise.
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
    """Codex iter-1 finding: if ``advance_job`` commits the next stage
    before ``_record_stage_timing`` writes, the next-stage worker can
    claim/finish concurrently. Even with the v2 per-stage schema,
    recording-first is still the right call ordering — preserves the
    invariant that this worker has exclusive control over the row when
    its observability artifact lands."""
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
    """End-to-end: a worker that calls ``record_stage_metric`` inside
    ``process()`` ends up with those metrics in its ``stage_timing_<stage>``
    artifact. Exercises the full ``_execute_job`` wiring — the per-job dict is
    bound before ``process()``, folded by ``_record_stage_timing``, and reset
    in the ``finally`` — not just the helper in isolation."""
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
    assert timing["metrics"] == {"dependencies": 5, "is_proxy": True}
    # Contextvar must be reset after the job — no leak into the next claim.
    assert stage_metrics_var.get() is None


def test_record_rolls_back_session_on_store_failure(monkeypatch):
    """Codex iter-2 finding: when ``store_artifact`` fails mid-transaction
    SQLAlchemy leaves the session needing rollback. Without explicit
    cleanup, the success path's subsequent ``advance_job`` raises
    ``PendingRollbackError`` → outer try marks the job as failed.

    Verify that a failed timing write triggers ``session.rollback()`` so
    the caller's session stays usable. Timing being best-effort means
    the swallowed exception must not leave a footgun for the next op."""

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
    """Counterpoint: when the store succeeds, the session must NOT be
    rolled back — that would discard the caller's pending writes
    (e.g., updates from process() that haven't been advance_job-committed
    yet). Rollback is strictly the failure-path cleanup."""
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
