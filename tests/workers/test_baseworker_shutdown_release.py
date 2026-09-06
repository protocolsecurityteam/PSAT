"""Shutdown cancels attempts before release and always cleans registries."""

from __future__ import annotations

import signal
import threading
import uuid
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

from db.models import Job, JobStage, JobStatus
from tests.attempt_helpers import claimed_call
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


@patch("workers.base.signal.signal")
@patch("workers.base.release_job_lease")
def test_sigterm_cancels_every_attempt_without_early_release(release, _signal):
    from db.attempts import JobAttempt

    worker = _Worker()
    attempts = [JobAttempt(uuid.uuid4(), uuid.uuid4()) for _ in range(2)]
    worker._attempts = {a.job_id: a for a in attempts}
    worker._handle_sigterm(signal.SIGTERM, None)
    worker._handle_sigterm(signal.SIGTERM, None)
    assert not worker._running
    assert all(a.cancelled.is_set() for a in attempts)
    release.assert_not_called()


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
def test_sigterm_with_no_inflight_jobs_is_noop(release, sessions, _signal):
    _Worker()._handle_sigterm(signal.SIGTERM, None)
    sessions.assert_not_called()
    release.assert_not_called()


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
    claimed_call(w._execute_job, session, cast(Job, job))

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
    claimed_call(w._execute_job, session, cast(Job, job))  # _execute_job swallows exceptions

    with w._inflight_lock:
        assert job.id not in w._inflight_jobs


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
@patch("workers.base.fail_job_terminal")
@patch("workers.base.store_artifact")
def test_execute_job_rejects_missing_lease(_store, _fail_terminal, _advance, _mock_signal):
    import pytest

    from db.attempts import LeaseLost

    worker = _Worker()
    worker.process = MagicMock()
    with pytest.raises(LeaseLost):
        worker._execute_job(MagicMock(), cast(Job, _make_job()))
    worker.process.assert_not_called()
    assert worker._inflight_jobs == {}


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease")
@patch("workers.base.advance_job")
@patch("workers.base.store_artifact")
def test_sigterm_releases_only_after_main_task_cleanup(_store, _advance, release, sessions, _signal):
    from db.attempts import current_attempt

    worker = _Worker()
    started, finish = threading.Event(), threading.Event()
    authority = []

    def process(session, job):
        authority.append(current_attempt.get())
        started.set()
        assert finish.wait(5)

    worker.process = process
    job = _make_job(lease_id=uuid.uuid4())
    session = MagicMock()
    session.info = {}

    def released(*args, **kwargs):
        assert authority[0].cancelled.is_set()
        session.rollback.assert_called()

    release.side_effect = released
    thread = threading.Thread(target=worker._execute_job, args=(session, job))
    thread.start()
    try:
        assert started.wait(3)
        worker._handle_sigterm(signal.SIGTERM, None)
        assert authority[0].cancelled.is_set()
        release.assert_not_called()
    finally:
        finish.set()
        thread.join(5)
    assert not thread.is_alive()
    release.assert_called_once()
    assert release.call_args.kwargs["lease_id"] == job.lease_id
    assert worker._attempts == worker._inflight_jobs == {}


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.release_job_lease", side_effect=RuntimeError("offline DB"))
@patch("workers.base.advance_job")
@patch("workers.base.store_artifact")
def test_release_failure_still_cleans_attempt(_store, _advance, release, sessions, _signal):
    from db.attempts import current_attempt

    worker = _Worker()
    worker.process = lambda *_a, **_kw: None
    claimed_call(worker._execute_job, MagicMock(), _make_job(lease_id=uuid.uuid4()))
    release.assert_called_once()
    assert worker._attempts == worker._inflight_jobs == {}
    assert current_attempt.get() is None
