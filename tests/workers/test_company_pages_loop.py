"""Prepared-page scheduling must not spend the freshness budget between builds."""

from threading import Event
from unittest.mock import MagicMock

import pytest

from workers import company_pages as worker


@pytest.mark.parametrize("terminal", ["idle", "leased", "error"])
def test_drains_due_work_including_backed_off_failures_before_waiting(monkeypatch, terminal):
    stop = Event()
    events = []
    outcomes = ["prepared"] * 12 + ["failed", "prepared", terminal]
    pending = iter(outcomes)

    def refresh():
        outcome = next(pending)
        events.append(outcome)
        if outcome == "error":
            raise RuntimeError("database unavailable")
        return outcome

    def wait(seconds):
        events.append(("wait", seconds))
        stop.set()
        return True

    heartbeat = MagicMock()
    monkeypatch.setattr(worker, "enabled", lambda: True)
    monkeypatch.setattr(worker, "refresh_one", refresh)
    monkeypatch.setattr(worker, "record_heartbeat", heartbeat)
    monkeypatch.setattr(stop, "wait", wait)
    worker.run(stop)
    assert events == outcomes + [("wait", 5)]
    assert heartbeat.call_count == len(outcomes)
    assert heartbeat.call_args_list[12].kwargs["status"] == "error"


def test_disabled_worker_waits_without_querying(monkeypatch):
    stop = Event()
    refresh = MagicMock()
    waits = []

    def wait(seconds):
        waits.append(seconds)
        stop.set()
        return True

    monkeypatch.setattr(worker, "enabled", lambda: False)
    monkeypatch.setattr(worker, "refresh_one", refresh)
    monkeypatch.setattr(worker, "record_heartbeat", MagicMock())
    monkeypatch.setattr(stop, "wait", wait)
    worker.run(stop)
    refresh.assert_not_called()
    assert waits == [5]


def test_stop_interrupts_a_busy_queue_between_builds(monkeypatch):
    stop = Event()
    refresh = MagicMock(return_value="prepared")
    wait = MagicMock()
    monkeypatch.setattr(worker, "enabled", lambda: True)
    monkeypatch.setattr(worker, "refresh_one", refresh)
    monkeypatch.setattr(worker, "record_heartbeat", lambda *args, **kwargs: stop.set())
    monkeypatch.setattr(stop, "wait", wait)
    worker.run(stop)
    refresh.assert_called_once()
    wait.assert_not_called()
