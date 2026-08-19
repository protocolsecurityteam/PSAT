"""Regression tests for the graceful-shutdown lease release on BaseWorker.

The bug, observed live on PR-63:
  Fly drained a worker machine mid ``forge build`` (SIGTERM at
  09:45:05 UTC; static stage had been running ~6m11s on
  EtherFiRedemptionManager impl). The worker process exited within
  Fly's 30s ``kill_timeout``, but the in-flight job was not released
  back to the queue. ``lease_expires_at`` was set to NOW+15min at
  claim time, so the row sat in ``processing`` until 09:53:16 — at
  which point ``reclaim_stuck_jobs`` finally swept it and a sibling
  worker re-ran the static stage from scratch, taking another ~5-6m.
  Net: ~16 minutes wedged on a healthy pipeline that was killed
  through no fault of its own.

The fix:
  ``BaseWorker._handle_sigterm`` spawns a daemon thread that calls
  ``db.queue.release_job_lease`` for every entry in
  ``self._inflight_jobs``. The daemon thread runs even when the main
  thread is blocked in ``subprocess.run``, so the lease is released
  inside Fly's 30s grace window — sibling workers can claim the row
  immediately, collapsing the 16-minute wedge to seconds.

These tests pin both halves of the contract:
  1. ``_handle_sigterm`` actually spawns the daemon thread, the daemon
     calls ``release_job_lease`` for each in-flight entry, and
     duplicate signals don't double-fire (Fly sends two SIGTERMs).
  2. ``_execute_job`` registers the job_id+lease_id at claim time and
     deregisters in ``finally`` so a clean completion doesn't leave a
     stale entry that a later SIGTERM would mistakenly try to release.

The race-safety of ``release_job_lease`` itself (SQL-level conditional
UPDATE on lease_id) is covered by the queue-layer tests; this file is
about the worker side.
"""

from __future__ import annotations

import signal
import threading
import time
import uuid
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

from db.models import Job, JobStage, JobStatus
from workers.base import BaseWorker


class _Worker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0


def _make_job(*, lease_id: uuid.UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        address="0x" + "a" * 40,
        name="t",
        status=JobStatus.processing,
        stage=JobStage.discovery,
        request={},
        trace_id="t" * 16,
        lease_id=lease_id,
        retry_count=0,
    )


# ---- _handle_sigterm releases inflight leases via a daemon thread -----


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
def test_sigterm_releases_inflight_lease(mock_release, mock_session_cls, _mock_signal):
    """The regression case: a worker mid-job receives SIGTERM. The
    daemon-thread release fires immediately so the row goes back to
    queued in seconds, not after the 15min lease TTL."""
    mock_session_cls.return_value = MagicMock()
    mock_release.return_value = True  # the SQL UPDATE matched the row

    w = _Worker()
    job_id = uuid.uuid4()
    lease_id = uuid.uuid4()
    with w._inflight_lock:
        w._inflight_jobs[job_id] = lease_id

    w._handle_sigterm(signal.SIGTERM, None)

    # Poll for the daemon's call rather than enumerating threads by
    # name — the daemon can complete in microseconds under mocks and
    # already be gone by the time we look.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and mock_release.call_count == 0:
        time.sleep(0.01)

    assert w._running is False
    assert mock_release.call_count == 1, "daemon thread never invoked release_job_lease"
    call = mock_release.call_args
    assert call.args[1] == job_id
    assert call.kwargs["lease_id"] == lease_id
    assert "graceful shutdown" in call.kwargs["reason"]


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
def test_double_sigterm_does_not_double_release(mock_release, mock_session_cls, _mock_signal):
    """Fly sends SIGTERM twice (graceful, then escalate) before SIGKILL.
    The handler must be idempotent — a second invocation must NOT spawn
    a second release thread that re-enters the DB unnecessarily."""
    mock_session_cls.return_value = MagicMock()
    mock_release.return_value = True

    w = _Worker()
    with w._inflight_lock:
        w._inflight_jobs[uuid.uuid4()] = uuid.uuid4()

    w._handle_sigterm(signal.SIGTERM, None)
    w._handle_sigterm(signal.SIGTERM, None)  # second SIGTERM

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and mock_release.call_count == 0:
        time.sleep(0.01)

    # Even after waiting, only one release call total — the second
    # SIGTERM was a no-op via the _shutdown_release_started flag.
    time.sleep(0.05)  # give a hypothetical second daemon time to fire if it existed
    assert mock_release.call_count == 1, "a second SIGTERM must not spawn a second release thread"


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
def test_sigterm_with_no_inflight_jobs_is_noop(mock_release, mock_session_cls, _mock_signal):
    """Idle worker (between claims) shouldn't open a session or call
    release on an empty inflight dict."""
    mock_session_cls.return_value = MagicMock()

    w = _Worker()
    w._handle_sigterm(signal.SIGTERM, None)

    # Even after a generous wait, no release should fire — the inflight
    # dict was empty, so the daemon's snapshot was empty and it returned
    # without opening a session.
    time.sleep(0.1)
    assert mock_release.call_count == 0


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
def test_release_failure_is_swallowed(mock_release, mock_session_cls, _mock_signal):
    """A DB failure during release must not crash the daemon thread —
    the worker is shutting down anyway and crashing the daemon would
    just leave the lease unreleased AND emit a confusing traceback."""
    mock_session_cls.return_value = MagicMock()
    mock_release.side_effect = RuntimeError("DB temporarily unavailable")

    w = _Worker()
    with w._inflight_lock:
        w._inflight_jobs[uuid.uuid4()] = uuid.uuid4()
        w._inflight_jobs[uuid.uuid4()] = uuid.uuid4()

    w._handle_sigterm(signal.SIGTERM, None)

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and mock_release.call_count < 2:
        time.sleep(0.01)

    # Both jobs were attempted even though the first raised.
    assert mock_release.call_count == 2, f"daemon should have attempted both releases; got {mock_release.call_count}"


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
def test_release_returns_false_when_already_released(mock_release, mock_session_cls, _mock_signal):
    """If ``release_job_lease`` returns False (sibling reclaimed first or
    main thread completed first), the daemon must not raise — that's the
    happy no-op path."""
    mock_session_cls.return_value = MagicMock()
    mock_release.return_value = False

    w = _Worker()
    with w._inflight_lock:
        w._inflight_jobs[uuid.uuid4()] = uuid.uuid4()

    w._handle_sigterm(signal.SIGTERM, None)

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and mock_release.call_count == 0:
        time.sleep(0.01)
    # Daemon called release once and returned cleanly; no exception
    # propagation despite the False return.
    assert mock_release.call_count == 1


# ---- _execute_job registers/deregisters around the lifecycle ----------


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
@patch("workers.base.fail_job_terminal")
@patch("workers.base.requeue_job")
@patch("workers.base.store_artifact")
def test_execute_job_registers_and_deregisters_on_success(_store, _requeue, _fail_terminal, _advance, _mock_signal):
    """On normal success the inflight entry is removed in finally so a
    later SIGTERM can't mistakenly try to release a job whose lease is
    already gone (which would just be a no-op via the SQL filter, but
    leaving stale entries also leaks memory across many jobs)."""
    w = _Worker()
    w.process = lambda *_a, **_kw: None

    lease_id = uuid.uuid4()
    job = _make_job(lease_id=lease_id)
    session = MagicMock()
    w._execute_job(session, cast(Job, job))

    with w._inflight_lock:
        assert job.id not in w._inflight_jobs, "successful completion must clear inflight entry"


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
@patch("workers.base.fail_job_terminal")
@patch("workers.base.requeue_job")
@patch("workers.base.store_artifact")
def test_execute_job_deregisters_on_exception(_store, _requeue, _fail_terminal, _advance, _mock_signal):
    """A raising ``process()`` still has to clear the inflight entry —
    otherwise a SIGTERM after a job error would try to release a row
    that's already in failed_terminal/queued state."""
    w = _Worker()

    def _boom(*_a, **_kw):
        raise RuntimeError("boom")

    w.process = _boom

    lease_id = uuid.uuid4()
    job = _make_job(lease_id=lease_id)
    session = MagicMock()
    w._execute_job(session, cast(Job, job))  # _execute_job swallows exceptions

    with w._inflight_lock:
        assert job.id not in w._inflight_jobs


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
@patch("workers.base.fail_job_terminal")
@patch("workers.base.store_artifact")
def test_execute_job_skips_registration_when_lease_id_is_none(_store, _fail_terminal, _advance, _mock_signal):
    """Pre-migration rows / test stubs without a lease_id shouldn't
    populate the inflight dict — there's nothing meaningful to release
    on shutdown for them."""
    w = _Worker()
    w.process = lambda *_a, **_kw: None

    job = _make_job(lease_id=None)
    session = MagicMock()
    w._execute_job(session, cast(Job, job))

    with w._inflight_lock:
        assert w._inflight_jobs == {}


# ---- end-to-end-ish: SIGTERM during a real _execute_job call ----------


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
@patch("workers.base.advance_job")
def test_sigterm_during_execute_job_releases_lease(_advance, mock_release, mock_session_cls, _mock_signal):
    """The whole point of the fix in one test: a job is mid-flight, a
    SIGTERM arrives, the daemon thread sees the lease in the inflight
    map and releases it — even while the main thread is still running.
    """
    mock_session_cls.return_value = MagicMock()
    mock_release.return_value = True

    w = _Worker()
    started = threading.Event()
    finish = threading.Event()

    def _slow_process(session, job):  # noqa: ARG001
        started.set()
        # Simulates forge build blocking on subprocess.run; the daemon
        # thread does its work concurrently.
        finish.wait(timeout=2.0)

    w.process = _slow_process

    lease_id = uuid.uuid4()
    job = _make_job(lease_id=lease_id)
    session = MagicMock()

    main = threading.Thread(target=w._execute_job, args=(session, job), daemon=True)
    main.start()

    assert started.wait(timeout=1.0), "process never started"
    # While the main thread is blocked in process(), fire SIGTERM. The
    # daemon thread spawned by the handler runs immediately and releases.
    w._handle_sigterm(signal.SIGTERM, None)

    # Poll for the call rather than racing to enumerate the daemon by
    # name — under mocks the daemon completes in microseconds and may
    # have already exited by the time we look.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and mock_release.call_count == 0:
        time.sleep(0.01)

    # Daemon released the lease before the main thread finished — that's
    # the entire fix. The SQL conditional UPDATE means main thread's
    # subsequent advance_job is a safe no-op (its lease_id check fails).
    assert mock_release.call_count == 1, "daemon thread did not invoke release_job_lease"
    assert mock_release.call_args.args[1] == job.id
    assert mock_release.call_args.kwargs["lease_id"] == lease_id

    finish.set()
    main.join(timeout=2.0)
    assert not main.is_alive()
