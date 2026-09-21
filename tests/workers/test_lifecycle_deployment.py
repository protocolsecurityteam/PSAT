from unittest.mock import Mock

import pytest

from scripts import worker_lifecycle_deploy as deploy
from scripts.worker_lifecycle_report import summarize


def worker(mode="observe", state="started"):
    return {
        "id": "abc",
        "state": state,
        "config": {"metadata": {"fly_process_group": "workers"}, "env": {"PSAT_WORKER_LIFECYCLE_MODE": mode}},
    }


def test_cannot_skip_bridge_release(monkeypatch):
    monkeypatch.setattr(deploy, "machines", lambda: [worker("off")])
    with pytest.raises(RuntimeError, match="bridge"):
        deploy.prepare(indexer="monitor")


def test_cannot_remove_singleton_while_indexer_is_still_on_monitor(monkeypatch):
    old = worker("enforce")
    old["config"]["env"]["PSAT_INDEXER_GROUP"] = "monitor"
    monkeypatch.setattr(deploy, "machines", lambda: [old])
    with pytest.raises(RuntimeError, match="observe mode"):
        deploy.prepare(indexer="workers", mode="off")


def test_legacy_layout_deploy_does_not_invoke_new_admin_code(monkeypatch):
    monkeypatch.setattr(deploy, "machines", lambda: [worker("off")])
    admin = Mock()
    monkeypatch.setattr(deploy, "admin", admin)
    assert deploy.prepare(indexer="workers") is False
    admin.assert_not_called()


def test_managed_deploy_waits_for_real_stop(monkeypatch):
    states = iter([[worker()], [worker(state="stopping")], [worker(state="stopped")]])
    monkeypatch.setattr(deploy, "machines", lambda: next(states))
    monkeypatch.setattr(deploy.time, "sleep", lambda _: None)
    admin = Mock()
    monkeypatch.setattr(deploy, "admin", admin)
    assert deploy.prepare(indexer="monitor") is True
    admin.assert_called_once_with("drain")


def test_deploy_timeout_never_forces_stop_or_resumes(monkeypatch):
    monkeypatch.setattr(deploy, "machines", lambda: [worker()])
    admin = Mock()
    monkeypatch.setattr(deploy, "admin", admin)
    with pytest.raises(TimeoutError):
        deploy.prepare(indexer="monitor", timeout=0)
    admin.assert_called_once_with("drain")


def test_cost_report_charges_unknown_gaps_and_all_overhead():
    rows = [
        {
            "message": "worker lifecycle observation",
            "timestamp": f"2026-09-21T00:0{minute}:00Z",
            "machine_state": "started",
            "idle_seconds": 900,
            "sample_seconds": 15,
            "ready_sources": [],
            "active": False,
        }
        for minute in (0, 1, 2)
    ]
    result = summarize(rows, grace=300, startup_s=30, hourly=0.1189, monitor_delta=8.20, rootfs_gb=5, other_delta=2)
    assert result["coverage_fraction"] == 0.25
    assert result["projected_running_fraction_with_gaps_billed"] == 0.75
    assert result["projected_savings_per_720h"] == round(180 * 0.1189 - 8.2 - 0.15 * 5 * 0.25 - 2, 2)


def test_cost_report_no_savings_if_always_busy():
    rows = [
        {
            "message": "worker lifecycle observation",
            "timestamp": f"2026-09-21T00:00:{s:02d}Z",
            "machine_state": "started",
            "idle_seconds": 0,
            "sample_seconds": 15,
            "ready_sources": ["jobs"],
            "active": True,
        }
        for s in (0, 15, 30)
    ]
    result = summarize(rows, grace=300, startup_s=30, hourly=0.1189, monitor_delta=8.20, rootfs_gb=5, other_delta=0)
    assert result["projected_savings_per_720h"] == -8.20
