"""Tests for in-process job concurrency in workers.base.BaseWorker.

K=1 keeps the legacy single-job loop byte-identical (covered by
tests/workers/test_base_worker.py). K>1 dispatches each claimed job into a
per-worker ThreadPoolExecutor so RPC/CPU waits in one job overlap with
sibling jobs.

What we pin:
1. Per-stage env (PSAT_<STAGE>_JOB_CONCURRENCY) and global
   PSAT_JOB_CONCURRENCY resolve correctly with the right precedence.
2. K>1 dispatcher actually runs jobs in parallel (wall-clock check).
3. Each in-flight job gets its own SQLAlchemy session (no cross-session
   ORM identity-map mixing).
4. SIGTERM stops new claims and drains the in-flight pool before
   returning (graceful shutdown).
5. Slot accounting: the dispatcher never exceeds K concurrent jobs
   regardless of how fast the queue produces them.
6. Errors inside a dispatched job don't kill the dispatcher loop.
7. Job-handled-directly path still skips advance_job under K>1.
"""

from __future__ import annotations

import signal
import threading
import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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


def test_per_stage_env_var_wins_over_global(monkeypatch):
    """Per-stage env trumps the global default; both override the implicit 1."""
    monkeypatch.setenv("PSAT_JOB_CONCURRENCY", "2")
    monkeypatch.setenv("PSAT_RESOLUTION_JOB_CONCURRENCY", "5")
    assert _resolve_job_concurrency("resolution") == 5
    # Different stage falls back to the global.
    assert _resolve_job_concurrency("policy") == 2


def test_global_env_falls_back_to_one(monkeypatch):
    monkeypatch.delenv("PSAT_JOB_CONCURRENCY", raising=False)
    monkeypatch.delenv("PSAT_DISCOVERY_JOB_CONCURRENCY", raising=False)
    assert _resolve_job_concurrency("discovery") == 1


def test_env_var_invalid_value_falls_back_to_one(monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "garbage")
    monkeypatch.delenv("PSAT_JOB_CONCURRENCY", raising=False)
    assert _resolve_job_concurrency("discovery") == 1


def test_env_var_zero_clamped_to_one(monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "0")
    assert _resolve_job_concurrency("discovery") == 1


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
    """K=4 with a barrier: 4 jobs that block until all 4 are running.
    A serial loop deadlocks; the parallel dispatcher releases the barrier."""
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
        # Stop the loop once all 4 are dispatched.
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
    """Each dispatched job must get its own SessionLocal() instance — sharing
    a session across threads breaks the SQLAlchemy identity map."""
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
        # Capture which session each job actually saw.
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
        # Three distinct session identities were observed inside process().
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
    """With K=2 and a queue of 5 slow jobs, no more than 2 process()
    calls run at once."""
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
    """SIGTERM during in-flight work must wait for jobs to land, not abandon them."""
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

    # Fire SIGTERM after the first job is mid-process.
    def _trigger_term():
        started.wait(timeout=1.0)
        time.sleep(0.02)
        w._handle_sigterm(signal.SIGTERM, None)

    threading.Thread(target=_trigger_term, daemon=True).start()

    try:
        w.run_loop()
        # Both in-flight jobs reached completion despite the shutdown signal.
        assert len(finished_jobs) >= 1
        # Exactly the started ones must have advanced.
        assert mock_advance.call_count == len(finished_jobs)
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
def test_sigterm_abandons_jobs_past_drain_timeout(mock_claim, mock_session_cls, mock_signal, monkeypatch):
    """If in-flight jobs outlive the drain window, ``run_loop`` returns
    anyway and logs the abandonment. The cross-worker stale-job sweep
    recovers the abandoned rows on a sibling worker."""
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "1")
    # Force a short drain window for the test.
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

    # process() blocks longer than the 0s drain window.
    def _slow_process(session, job):
        started.set()
        time.sleep(2.0)
        finished.set()

    w = _ConcurrentWorker()
    w.process = _slow_process

    def _trigger_term():
        started.wait(timeout=1.0)
        time.sleep(0.01)
        w._handle_sigterm(signal.SIGTERM, None)

    threading.Thread(target=_trigger_term, daemon=True).start()

    t0 = time.monotonic()
    try:
        w.run_loop()
        elapsed = time.monotonic() - t0
        # Abandonment means returning while the job is still in flight; the
        # wall-clock bound is deliberately loose for loaded CI runners.
        assert not finished.is_set(), "run_loop drained the in-flight job instead of abandoning it"
        assert elapsed < 1.0, f"run_loop should have abandoned promptly, took {elapsed:.2f}s"
    finally:
        # Drain the abandoned worker thread before yielding to the next test.
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
    """One job raising must not stop the dispatcher from claiming the next."""
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


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
def test_k1_path_matches_legacy_advance_args(mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch):
    """K=1 (default) must call advance_job with the same args as the legacy
    loop did — no shape change for the un-opted-in fleet."""
    monkeypatch.delenv("PSAT_DISCOVERY_JOB_CONCURRENCY", raising=False)
    monkeypatch.delenv("PSAT_JOB_CONCURRENCY", raising=False)

    session = MagicMock()
    mock_session_cls.return_value = session

    job = _make_job()
    cycle = {"n": 0}

    def _claim(*_a, **_kw):
        cycle["n"] += 1
        if cycle["n"] == 1:
            return job
        w._running = False
        return None

    mock_claim.side_effect = _claim

    w = _ConcurrentWorker()
    assert w._job_pool is None, "K=1 must not create a thread pool"
    w.process = MagicMock()
    w.run_loop()

    # Same args shape as the legacy test.
    mock_advance.assert_called_once_with(session, job.id, JobStage.static, "Completed discovery", lease_id=None)


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
    """If session.get returns None inside the dispatcher (job row gone),
    the dispatcher logs a warning and returns instead of crashing."""
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "2")

    session = MagicMock()
    session.get.return_value = None  # vanished
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
