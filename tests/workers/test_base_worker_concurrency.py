"""Tests for in-process job concurrency in workers.base.BaseWorker.

K=1 keeps the legacy single-job loop byte-identical (see test_base_worker.py).
K>1 dispatches each claimed job into a per-worker ThreadPoolExecutor: env
precedence, real parallelism, per-job sessions (no ORM identity-map mixing),
SIGTERM drain, slot cap, and error isolation.
"""

from __future__ import annotations

import signal
import threading
import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from db.models import JobStage, JobStatus
from workers.base import BaseWorker, JobHandledDirectly, _resolve_job_concurrency

# ---------------------------------------------------------------------------
# Concrete subclass for testing
# ---------------------------------------------------------------------------


class _ConcurrentWorker(BaseWorker):
    """Discovery-stage worker stub; per-test K is set via env (monkeypatch)."""

    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0


class _DoneConcurrentWorker(BaseWorker):
    stage = JobStage.policy
    next_stage = JobStage.done
    poll_interval = 0


def _make_job(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        address="0x" + "a" * 40,
        name="test-job",
        status=JobStatus.processing,
        stage=JobStage.discovery,
        updated_at=datetime.now(timezone.utc),
        worker_id="some-worker",
        detail=None,
        retry_count=0,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Env-var resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "env, stage, expected",
    [
        pytest.param(
            {"PSAT_JOB_CONCURRENCY": "2", "PSAT_RESOLUTION_JOB_CONCURRENCY": "5"}, "resolution", 5, id="per-stage-wins"
        ),
        pytest.param(
            {"PSAT_JOB_CONCURRENCY": "2", "PSAT_RESOLUTION_JOB_CONCURRENCY": "5"},
            "policy",
            2,
            id="global-for-other-stage",
        ),
        pytest.param({}, "discovery", 1, id="unset-falls-back-to-one"),
        pytest.param({"PSAT_DISCOVERY_JOB_CONCURRENCY": "garbage"}, "discovery", 1, id="invalid-falls-back-to-one"),
        pytest.param({"PSAT_DISCOVERY_JOB_CONCURRENCY": "0"}, "discovery", 1, id="zero-clamped-to-one"),
    ],
)
def test_resolve_job_concurrency(monkeypatch, env, stage, expected):
    for key in ("PSAT_JOB_CONCURRENCY", "PSAT_DISCOVERY_JOB_CONCURRENCY", "PSAT_RESOLUTION_JOB_CONCURRENCY"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert _resolve_job_concurrency(stage) == expected


@patch("workers.base.signal.signal")
def test_init_creates_pool_when_concurrency_gt_one(mock_signal, monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "3")
    w = _ConcurrentWorker()
    try:
        assert w._job_concurrency == 3
        assert w._job_pool is not None
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


@patch("workers.base.signal.signal")
def test_init_no_pool_when_concurrency_is_one(mock_signal, monkeypatch):
    monkeypatch.delenv("PSAT_DISCOVERY_JOB_CONCURRENCY", raising=False)
    monkeypatch.delenv("PSAT_JOB_CONCURRENCY", raising=False)
    w = _ConcurrentWorker()
    assert w._job_concurrency == 1
    assert w._job_pool is None


# ---------------------------------------------------------------------------
# K>1 dispatcher: actual parallelism
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
def test_concurrent_dispatcher_runs_jobs_in_parallel(
    mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch
):
    """A serial loop deadlocks on the 4-party barrier; the parallel dispatcher releases it."""
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "4")
    mock_session_cls.return_value = MagicMock()

    barrier = threading.Barrier(4, timeout=2.0)

    job_ids = [uuid.uuid4() for _ in range(4)]
    queue = list(job_ids)
    queue_lock = threading.Lock()

    def _claim_side_effect(_session, _stage, _worker_id):
        with queue_lock:
            if not queue:
                return None
            jid = queue.pop(0)
        return _make_job(id=jid)

    mock_claim.side_effect = _claim_side_effect

    process_calls: list = []
    process_lock = threading.Lock()

    def _process(session, job):
        with process_lock:
            process_calls.append(job.id)
        # All 4 jobs must reach this barrier within the timeout, otherwise
        # the test fails — proves they're running concurrently.
        barrier.wait()

    w = _ConcurrentWorker()

    # Need session.get to return the job (the dispatcher re-fetches via id).
    def _fake_get(_model, jid):
        return _make_job(id=jid)

    mock_session_cls.return_value.get.side_effect = _fake_get

    try:
        w.process = _process
        original_claim = mock_claim.side_effect

        def _stop_after_drain(*args, **kwargs):
            res = original_claim(*args, **kwargs)
            if res is None:
                w._running = False
            return res

        mock_claim.side_effect = _stop_after_drain

        w.run_loop()

        assert len(process_calls) == 4
        assert mock_advance.call_count == 4
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
def test_concurrent_dispatcher_uses_distinct_session_per_job(
    mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch
):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "3")

    sessions_returned: list = []
    sessions_lock = threading.Lock()

    def _session_factory():
        with sessions_lock:
            s = MagicMock(name=f"Session-{len(sessions_returned)}")
            s.get.side_effect = lambda _m, jid: _make_job(id=jid)
            sessions_returned.append(s)
            return s

    mock_session_cls.side_effect = _session_factory

    job_ids = [uuid.uuid4() for _ in range(3)]
    queue = list(job_ids)
    queue_lock = threading.Lock()

    def _claim_side_effect(_session, _stage, _worker_id):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim_side_effect

    barrier = threading.Barrier(3, timeout=2.0)
    sessions_during_process: list = []
    swp_lock = threading.Lock()

    def _process(session, job):
        with swp_lock:
            sessions_during_process.append(id(session))
        barrier.wait()

    w = _ConcurrentWorker()
    w.process = _process

    original = mock_claim.side_effect

    def _stop(*a, **kw):
        res = original(*a, **kw)
        if res is None:
            w._running = False
        return res

    mock_claim.side_effect = _stop

    try:
        w.run_loop()
        assert len(set(sessions_during_process)) == 3
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Slot accounting
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
def test_dispatcher_never_exceeds_concurrency_cap(mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "2")

    session = MagicMock()
    session.get.side_effect = lambda _m, jid: _make_job(id=jid)
    mock_session_cls.return_value = session

    job_ids = [uuid.uuid4() for _ in range(5)]
    queue = list(job_ids)
    queue_lock = threading.Lock()

    def _claim_side_effect(*_a, **_kw):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim_side_effect

    inflight = 0
    peak = 0
    state_lock = threading.Lock()

    def _process(session, job):
        nonlocal inflight, peak
        with state_lock:
            inflight += 1
            peak = max(peak, inflight)
        time.sleep(0.05)
        with state_lock:
            inflight -= 1

    w = _ConcurrentWorker()
    w.process = _process

    original = mock_claim.side_effect

    def _stop(*a, **kw):
        res = original(*a, **kw)
        if res is None:
            w._running = False
        return res

    mock_claim.side_effect = _stop

    try:
        w.run_loop()
        assert peak <= 2, f"saw {peak} concurrent jobs, expected ≤ 2"
        assert mock_advance.call_count == 5
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


# ---------------------------------------------------------------------------
# SIGTERM drain
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
def test_sigterm_drains_inflight_jobs(mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "2")

    session = MagicMock()
    session.get.side_effect = lambda _m, jid: _make_job(id=jid)
    mock_session_cls.return_value = session

    started = threading.Event()

    job_ids = [uuid.uuid4(), uuid.uuid4()]
    queue = list(job_ids)
    queue_lock = threading.Lock()

    def _claim_side_effect(*_a, **_kw):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim_side_effect

    finished_jobs: list = []
    finished_lock = threading.Lock()

    def _process(session, job):
        started.set()
        time.sleep(0.1)
        with finished_lock:
            finished_jobs.append(job.id)

    w = _ConcurrentWorker()
    w.process = _process

    def _trigger_term():
        started.wait(timeout=1.0)
        time.sleep(0.02)
        w._handle_sigterm(signal.SIGTERM, None)

    threading.Thread(target=_trigger_term, daemon=True).start()

    try:
        w.run_loop()
        assert len(finished_jobs) >= 1
        assert mock_advance.call_count == len(finished_jobs)
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
def test_sigterm_waits_for_jobs_even_past_stale_timeout(mock_claim, mock_session_cls, mock_signal, monkeypatch):
    """An idle drain must never abandon work just because a stale timeout passed."""
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "1")
    monkeypatch.setattr("workers.base.STALE_JOB_TIMEOUT", 0)

    session = MagicMock()
    session.get.side_effect = lambda _m, jid: _make_job(id=jid)
    mock_session_cls.return_value = session

    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "2")

    started = threading.Event()
    finished = threading.Event()
    queue = [uuid.uuid4()]
    queue_lock = threading.Lock()

    def _claim_side_effect(*_a, **_kw):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim_side_effect

    # Keep process() blocked until the assertions finish. This proves the
    # worker abandons an in-flight future without relying on scheduler timing.
    release = threading.Event()

    def _slow_process(session, job):
        started.set()
        release.wait(timeout=10.0)
        finished.set()

    w = _ConcurrentWorker()
    w.process = _slow_process

    runner = threading.Thread(target=w.run_loop)
    runner.start()
    try:
        assert started.wait(timeout=5.0), "worker did not start the claimed job"
        w._handle_sigterm(signal.SIGTERM, None)
        runner.join(timeout=0.1)

        assert runner.is_alive(), "run_loop must wait for its live job"
        assert not finished.is_set()
        release.set()
        runner.join(timeout=5.0)
        assert finished.is_set()
        assert not runner.is_alive()
    finally:
        # Drain the abandoned worker thread before yielding to the next test.
        release.set()
        runner.join(timeout=5.0)
        if w._job_pool:
            w._job_pool.shutdown(wait=True)


# ---------------------------------------------------------------------------
# Error isolation
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
@patch("workers.base.fail_job_terminal")
def test_concurrent_job_exception_doesnt_kill_dispatcher(
    mock_fail, mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch
):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "2")

    session = MagicMock()
    session.get.side_effect = lambda _m, jid: _make_job(id=jid)
    mock_session_cls.return_value = session

    job_ids = [uuid.uuid4() for _ in range(3)]
    queue = list(job_ids)
    queue_lock = threading.Lock()

    def _claim_side_effect(*_a, **_kw):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim_side_effect

    call_count = {"n": 0}
    call_lock = threading.Lock()

    def _process(session, job):
        with call_lock:
            call_count["n"] += 1
            n = call_count["n"]
        if n == 1:
            raise RuntimeError("boom")

    w = _ConcurrentWorker()
    w.process = _process

    original = mock_claim.side_effect

    def _stop(*a, **kw):
        res = original(*a, **kw)
        if res is None:
            w._running = False
        return res

    mock_claim.side_effect = _stop

    try:
        w.run_loop()
        # All 3 jobs were dispatched (the failing first one didn't poison the loop).
        assert call_count["n"] == 3
        # 2 successful → 2 advances; 1 failed → 1 fail_job call.
        assert mock_advance.call_count == 2
        assert mock_fail.call_count == 1
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


# ---------------------------------------------------------------------------
# JobHandledDirectly under K>1
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
def test_concurrent_job_handled_directly_skips_advance(
    mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch
):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "2")
    session = MagicMock()
    session.get.side_effect = lambda _m, jid: _make_job(id=jid)
    mock_session_cls.return_value = session

    job_id = uuid.uuid4()
    queue = [job_id]
    queue_lock = threading.Lock()

    def _claim(*_a, **_kw):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim

    def _process(session, job):
        raise JobHandledDirectly()

    w = _ConcurrentWorker()
    w.process = _process

    original = mock_claim.side_effect

    def _stop(*a, **kw):
        res = original(*a, **kw)
        if res is None:
            w._running = False
        return res

    mock_claim.side_effect = _stop

    try:
        w.run_loop()
        mock_advance.assert_not_called()
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Parity: K=1 path is byte-identical to the legacy loop
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# K>1 with next_stage=done
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("db.queue.complete_job")
def test_concurrent_done_stage_calls_complete_job(
    mock_complete, mock_claim, mock_session_cls, mock_signal, monkeypatch
):
    monkeypatch.setenv("PSAT_POLICY_JOB_CONCURRENCY", "2")
    session = MagicMock()
    session.get.side_effect = lambda _m, jid: _make_job(id=jid)
    mock_session_cls.return_value = session

    job_id = uuid.uuid4()
    queue = [job_id]
    queue_lock = threading.Lock()

    def _claim(*_a, **_kw):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim

    w = _DoneConcurrentWorker()
    w.process = MagicMock()

    original = mock_claim.side_effect

    def _stop(*a, **kw):
        res = original(*a, **kw)
        if res is None:
            w._running = False
        return res

    mock_claim.side_effect = _stop

    try:
        w.run_loop()
        assert mock_complete.call_count == 1
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Vanished job (race: claim succeeds, row deleted before dispatch)
# ---------------------------------------------------------------------------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
def test_dispatched_job_vanishing_is_handled_gracefully(mock_claim, mock_session_cls, mock_signal, monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "2")

    session = MagicMock()
    session.get.return_value = None
    mock_session_cls.return_value = session

    queue = [uuid.uuid4()]
    queue_lock = threading.Lock()

    def _claim(*_a, **_kw):
        with queue_lock:
            if not queue:
                return None
            return _make_job(id=queue.pop(0))

    mock_claim.side_effect = _claim

    w = _ConcurrentWorker()
    w.process = MagicMock(side_effect=AssertionError("must not call process for vanished job"))

    original = mock_claim.side_effect

    def _stop(*a, **kw):
        res = original(*a, **kw)
        if res is None:
            w._running = False
        return res

    mock_claim.side_effect = _stop

    try:
        w.run_loop()
        w.process.assert_not_called()
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)
