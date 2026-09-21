"""Deployment invariants, Fly API boundary and intentional-sleep health."""

from unittest.mock import Mock

import pytest

from services.monitoring.process_meta import planned_sleep
from workers.lifecycle_controller import FlyMachines


def machine(**config):
    return {
        "id": "abc123",
        "state": "stopped",
        "config": {
            "metadata": {"fly_process_group": "workers"},
            "restart": {"policy": "on-failure"},
            "env": {"PSAT_INDEXER_GROUP": "monitor"},
            **config,
        },
    }


@pytest.fixture
def fly(monkeypatch):
    monkeypatch.setenv("FLY_APP_NAME", "psat-test")
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_TOKEN", "FlyV1 fake-scoped-token")
    client = FlyMachines()
    client.http = Mock()
    return client


def test_fly_only_starts_the_unique_worker_and_ignores_standby(fly):
    fly.http.get.return_value.json.return_value = [machine(), machine(standby_for=["abc123"])]
    assert fly.target()["id"] == "abc123"
    fly.start("abc123")
    assert fly.http.post.call_args.args[0].endswith("/machines/abc123/start")


@pytest.mark.parametrize(
    "machines",
    [
        [],
        [machine(), machine()],
        [machine(services=[{}])],
        [machine(restart={"policy": "always"})],
        [machine(env={"PSAT_INDEXER_GROUP": "workers"})],
    ],
)
def test_ambiguous_or_unsafe_fleet_fails_closed(fly, machines):
    fly.http.get.return_value.json.return_value = machines
    with pytest.raises(RuntimeError):
        fly.target()
    fly.http.post.assert_not_called()


def test_failed_fly_read_cannot_stop_workers(fly):
    fly.http.get.side_effect = TimeoutError()
    with pytest.raises(TimeoutError):
        fly.target()
    fly.http.post.assert_not_called()


def test_active_standby_inhibits_waking_an_additional_machine(fly):
    standby = machine(standby_for=["abc123"])
    standby["state"] = "started"
    fly.http.get.return_value.json.return_value = [machine(), standby]
    with pytest.raises(RuntimeError, match="standby"):
        fly.target()
    fly.http.post.assert_not_called()


def test_sleep_exemption_requires_fresh_controller_and_no_work():
    controller = {
        "status": "running",
        "beat_age_s": 5,
        "detail": {"mode": "enforce", "machine_state": "stopped", "active": False, "ready_sources": []},
    }
    assert planned_sleep("audit_text_extraction", controller)
    assert not planned_sleep("event_log_indexer", controller)
    assert not planned_sleep("protocol_scanner", controller)
    controller["detail"]["ready_sources"] = ["jobs"]
    assert not planned_sleep("audit_text_extraction", controller)
    controller["detail"]["ready_sources"] = []
    controller["beat_age_s"] = 60
    assert not planned_sleep("audit_text_extraction", controller)
