"""SIGTERM must not release a lease while its work can still execute."""

from __future__ import annotations

import signal
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


def _make_job(*, lease_id=None):
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
@patch("workers.base.SessionLocal")
def test_sigterm_preserves_live_leases(mock_session, _signal):
    w = _Worker()
    job_id, lease = uuid.uuid4(), uuid.uuid4()
    w._inflight_jobs[job_id] = lease
    w._handle_sigterm(signal.SIGTERM, None)
    w._handle_sigterm(signal.SIGTERM, None)
    assert not w._running
    assert w._inflight_jobs == {job_id: lease}
    mock_session.assert_not_called()


# ---- _execute_job registers/deregisters around the lifecycle ----------


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
@patch("workers.base.fail_job_terminal")
@patch("workers.base.requeue_job")
@patch("workers.base.store_artifact")
def test_execute_job_registers_and_deregisters_on_success(_store, _requeue, _fail_terminal, _advance, _mock_signal):
    """Successful completion clears tracking so later drains cannot treat a
    completed claim as live, and long-running workers do not leak entries."""
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
    """A raising ``process()`` clears tracking after finalizing its failure."""
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
    """Legacy rows / test stubs without a token do not populate claim tracking."""
    w = _Worker()
    w.process = lambda *_a, **_kw: None

    job = _make_job(lease_id=None)
    session = MagicMock()
    w._execute_job(session, cast(Job, job))

    with w._inflight_lock:
        assert w._inflight_jobs == {}
