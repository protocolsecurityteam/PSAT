"""Exercise loop behavior, including resetting after work and after exceptions."""

from unittest.mock import MagicMock

import pytest

from db.models import JobStage
from workers import base


class Worker(base.BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static


@pytest.mark.parametrize("concurrency", [1, 2])
def test_idle_delay_caps_and_resets_after_claim(monkeypatch, concurrency):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", str(concurrency))
    monkeypatch.setattr(base.signal, "signal", lambda *_: None)
    session = MagicMock()
    monkeypatch.setattr(base, "SessionLocal", lambda: session)
    worker = Worker()
    worker._job_pool = MagicMock() if concurrency > 1 else None
    sleeps = []
    claims = iter([None] * 5 + [MagicMock()] + [None] * 2)

    def claim(_):
        try:
            return next(claims)
        except StopIteration:
            worker._running = False
            return None

    monkeypatch.setattr(worker, "_claim_job", claim)
    monkeypatch.setattr(worker, "_execute_job", lambda *_: None)
    monkeypatch.setattr(worker, "_reap_finished_futures", lambda: worker._inflight.clear())
    monkeypatch.setattr(base.time, "sleep", sleeps.append)
    worker.run_loop()
    assert sleeps[:5] == [2, 4, 8, 15, 15]
    assert sleeps[5:7] == [2, 4]
    assert session.close.call_count >= 8


def test_repeated_claim_errors_back_off_and_close_session(monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "1")
    monkeypatch.setattr(base.signal, "signal", lambda *_: None)
    session = MagicMock()
    monkeypatch.setattr(base, "SessionLocal", lambda: session)
    worker = Worker()
    sleeps = []

    def claim(_):
        raise RuntimeError("temporary database error")

    def sleep(delay):
        assert session.close.called
        sleeps.append(delay)
        if len(sleeps) == 5:
            worker._running = False

    monkeypatch.setattr(worker, "_claim_job", claim)
    monkeypatch.setattr(base.time, "sleep", sleep)
    worker.run_loop()
    assert sleeps == [2, 4, 8, 15, 15]


def test_idle_backoff_does_not_delay_recovery_to_thirty_slow_polls(monkeypatch):
    monkeypatch.setenv("PSAT_DISCOVERY_JOB_CONCURRENCY", "1")
    monkeypatch.setattr(base.signal, "signal", lambda *_: None)
    monkeypatch.setattr(base, "SessionLocal", MagicMock())
    worker = Worker()
    now = [0.0]
    recovery = []

    def sleep(delay):
        now[0] += delay
        if now[0] > 145:
            worker._running = False

    monkeypatch.setattr(base.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(base.time, "sleep", sleep)
    monkeypatch.setattr(worker, "_claim_job", lambda _: None)
    monkeypatch.setattr(worker, "_recover_stale_jobs", lambda _: recovery.append(now[0]))
    worker.run_loop()
    assert len(recovery) == 2
    assert 60 <= recovery[0] <= 75
    assert 60 <= recovery[1] - recovery[0] <= 75
