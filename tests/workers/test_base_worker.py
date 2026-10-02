from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from db.models import JobStage, JobStatus
from tests.support.worker_stubs import _make_job, _TestWorker
from workers.base import BaseWorker


class _DoneWorker(BaseWorker):
    stage = JobStage.policy
    next_stage = JobStage.done
    poll_interval = 0

    def process(self, session, job):
        pass


@pytest.fixture(autouse=True)
def _force_single_job_concurrency(monkeypatch):
    """A developer ``.env`` may set concurrency > 1."""
    for key in list(os.environ):
        if key.startswith("PSAT_") and key.endswith("_JOB_CONCURRENCY"):
            monkeypatch.delenv(key, raising=False)


@patch("workers.base.signal.signal")
def test_recover_stale_jobs_requeues(mock_signal):
    w = _TestWorker()
    stale_job = _make_job(
        updated_at=datetime.now(timezone.utc) - timedelta(seconds=300),
    )
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.all.return_value = [stale_job]

    w._recover_stale_jobs(mock_session)

    assert stale_job.status == JobStatus.queued
    assert stale_job.worker_id is None
    assert stale_job.detail == "Re-queued after stale processing timeout"
    mock_session.commit.assert_called_once()


@patch("workers.base.signal.signal")
@patch("workers.base.advance_job")
def test_execute_job_heartbeats_while_process_blocks(mock_advance, mock_signal, monkeypatch):
    monkeypatch.setenv("PSAT_JOB_HEARTBEAT_INTERVAL_S", "0.01")
    release = threading.Event()
    job = _make_job(lease_id=uuid.uuid4())
    mock_session = MagicMock()

    w = _TestWorker()
    w._record_stage_timing = MagicMock()
    w._satisfy_dependencies = MagicMock(return_value=0)

    def heartbeat(_session, _job):
        release.set()

    def process(_session, _job):
        assert release.wait(timeout=2)

    w._heartbeat = MagicMock(side_effect=heartbeat)
    w.process = MagicMock(side_effect=process)

    w._execute_job(mock_session, cast(Any, job))

    assert w._heartbeat.call_count >= 1
    mock_advance.assert_called_once_with(
        mock_session, job.id, JobStage.static, "Completed discovery", lease_id=job.lease_id
    )


@patch("workers.base.configure_logging")
@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.requeue_job")
def test_requeued_failure_carries_no_traceback(
    mock_requeue, mock_claim, mock_session_cls, mock_signal, mock_configure, caplog
):
    import logging

    import requests

    job = _make_job()
    job.retry_count = 0
    mock_session_cls.return_value = MagicMock()

    call_count = 0

    def _claim_side_effect(session, stage, worker_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return job
        w._running = False
        return None

    mock_claim.side_effect = _claim_side_effect

    w = _TestWorker()
    w.process = MagicMock(side_effect=requests.exceptions.ConnectionError("rpc down"))
    with caplog.at_level(logging.WARNING, logger="workers.base"):
        w.run_loop()

    record = next(r for r in caplog.records if r.getMessage().startswith("worker failure"))
    assert record.levelno == logging.WARNING
    assert record.outcome == "requeued"
    assert record.failure_kind == "transient"
    assert record.exc_message == "rpc down"
    assert record.exc_info is None


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("db.queue.complete_job")
def test_run_loop_next_stage_done_calls_complete_job(mock_complete, mock_claim, mock_session_cls, mock_signal):
    job = _make_job(stage=JobStage.policy)
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    call_count = 0

    def _claim_side_effect(session, stage, worker_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return job
        w._running = False
        return None

    mock_claim.side_effect = _claim_side_effect

    w = _DoneWorker()
    w.process = MagicMock()
    w.run_loop()

    mock_complete.assert_called_once_with(mock_session, job.id, lease_id=None)


@patch("workers.base.SessionLocal")
@patch("workers.base.signal.signal")
def test_heartbeat_issues_update_and_commits(mock_signal, SessionLocalMock):
    """See ``test_heartbeat_fresh_session.py``."""
    fresh = MagicMock()
    fresh.__enter__ = MagicMock(return_value=fresh)
    fresh.__exit__ = MagicMock(return_value=False)
    SessionLocalMock.return_value = fresh

    w = _TestWorker()
    worker_session = MagicMock()
    mock_job = _make_job(detail="processing 42 deps")

    w._heartbeat(worker_session, cast(Any, mock_job))

    SessionLocalMock.assert_called_once()
    assert fresh.execute.call_count == 1
    update_stmt = fresh.execute.call_args[0][0]
    compiled = str(update_stmt.compile(compile_kwargs={"literal_binds": False}))
    assert "updated_at" in compiled.lower()
    assert "detail" not in compiled.lower()
    fresh.commit.assert_called_once()
    worker_session.execute.assert_not_called()


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.fail_job_terminal")
def test_run_loop_fail_job_exception_retries_with_fresh_session(mock_fail, mock_claim, mock_session_cls, mock_signal):
    job = _make_job()
    job.retry_count = 0
    mock_session = MagicMock()
    fresh_session = MagicMock()

    session_call_count = 0

    def _session_factory():
        nonlocal session_call_count
        session_call_count += 1
        if session_call_count == 1:
            return mock_session
        return fresh_session

    mock_session_cls.side_effect = _session_factory

    call_count = 0

    def _claim_side_effect(session, stage, worker_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return job
        w._running = False
        return None

    mock_claim.side_effect = _claim_side_effect

    mock_fail.side_effect = [Exception("db gone"), None]

    w = _TestWorker()
    w.process = MagicMock(side_effect=RuntimeError("boom"))
    w.run_loop()

    assert mock_fail.call_count == 2
    second_call_args = mock_fail.call_args_list[1][0]
    assert second_call_args[0] is fresh_session
    # It may also be called when SessionLocal returns it as the main session.
    assert fresh_session.close.call_count >= 1


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.fail_job_terminal")
def test_run_loop_both_fail_job_attempts_fail_gracefully(mock_fail, mock_claim, mock_session_cls, mock_signal):
    job = _make_job()
    job.retry_count = 0
    mock_session = MagicMock()
    fresh_session = MagicMock()

    session_call_count = 0

    def _session_factory():
        nonlocal session_call_count
        session_call_count += 1
        if session_call_count == 1:
            return mock_session
        return fresh_session

    mock_session_cls.side_effect = _session_factory

    call_count = 0

    def _claim_side_effect(session, stage, worker_id):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return job
        w._running = False
        return None

    mock_claim.side_effect = _claim_side_effect

    mock_fail.side_effect = [Exception("db gone"), Exception("still gone")]

    w = _TestWorker()
    w.process = MagicMock(side_effect=RuntimeError("boom"))
    w.run_loop()

    assert mock_fail.call_count == 2
