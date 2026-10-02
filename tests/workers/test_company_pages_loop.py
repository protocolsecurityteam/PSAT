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
    monkeypatch.setattr(worker, "purge_one", lambda: "disabled")
    monkeypatch.setattr(worker, "record_heartbeat", heartbeat)
    monkeypatch.setattr(stop, "wait", wait)
    worker.run(stop)
    assert events == outcomes + [("wait", 5)]
    assert heartbeat.call_count == len(outcomes)
    assert heartbeat.call_args_list[12].kwargs["status"] == "error"


def test_builds_take_priority_and_purges_drain_without_delaying_new_work(monkeypatch):
    stop = Event()
    events = []
    builds = iter(["prepared", "prepared", "idle", "prepared", "idle", "idle"])
    purges = iter(["failed", "purged", "idle"])

    def refresh():
        result = next(builds)
        events.append(("build", result))
        return result

    def purge():
        result = next(purges)
        events.append(("purge", result))
        return result

    def wait(seconds):
        events.append(("wait", seconds))
        stop.set()

    monkeypatch.setattr(worker, "enabled", lambda: True)
    monkeypatch.setattr(worker, "refresh_one", refresh)
    monkeypatch.setattr(worker, "purge_one", purge)
    monkeypatch.setattr(worker, "record_heartbeat", MagicMock())
    monkeypatch.setattr(stop, "wait", wait)
    worker.run(stop)
    assert events == [
        ("build", "prepared"),
        ("build", "prepared"),
        ("build", "idle"),
        ("purge", "failed"),
        ("build", "prepared"),
        ("build", "idle"),
        ("purge", "purged"),
        ("build", "idle"),
        ("purge", "idle"),
        ("wait", 5),
    ]
