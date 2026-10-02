"""K=1 keeps the legacy loop byte-identical; K>1 dispatches into a ThreadPoolExecutor with per-job sessions."""

from __future__ import annotations

import threading
import uuid
from unittest.mock import MagicMock, patch

from db.models import JobStage
from tests.support.worker_stubs import _make_job
from workers.base import BaseWorker


class _ConcurrentWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static
    poll_interval = 0


@patch("workers.base.signal.signal")
@patch("workers.base.SessionLocal")
@patch("workers.base.claim_job")
@patch("workers.base.advance_job")
def test_concurrent_dispatcher_runs_jobs_in_parallel(
    mock_advance, mock_claim, mock_session_cls, mock_signal, monkeypatch
):
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
        barrier.wait()

    w = _ConcurrentWorker()

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
        assert call_count["n"] == 3
        assert mock_advance.call_count == 2
        assert mock_fail.call_count == 1
    finally:
        if w._job_pool:
            w._job_pool.shutdown(wait=False)


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
