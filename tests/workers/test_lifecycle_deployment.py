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


class FakeFly:
    """Model Fly's stopped update semantics; only explicit start changes state."""

    def __init__(self, monkeypatch, *, mode="observe", state="started", paused=False):
        import copy

        self.copy = copy.deepcopy
        self.clock = 0.0
        self.events = []
        self.commands = []
        self.lose_start_response = False
        self.start_status = {}
        self.status = {
            "control_version": 1,
            "paused": paused,
            "phase": "running",
            "machine_id": "abc",
            "boot_id": "old-boot",
            "boot_fresh": True,
        }
        self.rows = []
        for name in ("workers", "monitor", "web", "browser"):
            self.rows.append(
                {
                    "id": "abc" if name == "workers" else name,
                    "state": state if name == "workers" else "started",
                    "image_ref": {"registry": "registry.fly.io", "repository": "psat", "digest": "sha256:old"},
                    "config": {
                        "image": "registry.fly.io/psat:old-mutable-tag",
                        "metadata": {"fly_process_group": name},
                        "env": {"PSAT_WORKER_LIFECYCLE_MODE": mode, "PSAT_INDEXER_GROUP": "workers"},
                        "guest": {
                            "cpu_kind": "shared",
                            "cpus": 8 if name == "workers" else 1,
                            "memory_mb": 16384 if name == "workers" else 512,
                        },
                    },
                }
            )
        self.saved_config = {
            "app": "psat",
            "env": self.copy(self.rows[0]["config"]["env"]),
            "processes": {name: f"start-{name}" for name in ("workers", "monitor", "web", "browser")},
            "vm": [{"processes": ["workers"], "cpus": 1, "memory_mb": 512}],
        }
        monkeypatch.setattr(deploy.subprocess, "check_output", self.check_output)
        monkeypatch.setattr(deploy.subprocess, "run", self.run)
        monkeypatch.setattr(deploy.time, "monotonic", lambda: self.clock)
        monkeypatch.setattr(deploy.time, "sleep", self.sleep)

    def sleep(self, seconds):
        self.clock += seconds

    def check_output(self, command, **_kwargs):
        import json

        self.commands.append(command)
        if command[1:3] == ["machines", "list"]:
            return json.dumps(self.rows)
        assert command[1:3] == ["ssh", "console"]
        target_id = command[command.index("--machine") + 1]
        target = next(row for row in self.rows if row["id"] == target_id)
        assert target["state"] == "started"
        assert target["config"]["env"]["PSAT_WORKER_LIFECYCLE_MODE"] != "off", "legacy admin absent"
        action = command[-1].split()[-1]
        self.events.append(f"admin:{action}")
        if action in {"pause", "drain", "resume"}:
            self.status["paused"] = action != "resume"
        if action == "drain":
            self.rows[0]["state"] = "stopped"
            self.status["phase"] = "stopped"
        return "Connecting to machine...\n" + json.dumps(self.status)

    def run(self, command, **_kwargs):
        import json
        import subprocess
        from pathlib import Path

        self.commands.append(command)
        if command[1:3] == ["config", "save"]:
            self.events.append("config:save")
            Path(command[command.index("--config") + 1]).write_text(json.dumps(self.saved_config))
        elif command[1:3] == ["machine", "start"]:
            self.events.append("start")
            assert command[3] == "abc"
            self.rows[0]["state"] = "started"
            self.status.update(phase="running", boot_id="new-boot", boot_fresh=True)
            self.status.update(self.start_status)
            if self.lose_start_response:
                raise subprocess.TimeoutExpired(command, timeout=30)
        elif command[1] == "deploy":
            self.events.append("deploy")
            config = json.loads(Path(command[command.index("--config") + 1]).read_text())
            image = command[command.index("--image") + 1]
            for row in self.rows:
                row["config"]["env"] = self.copy(config["env"])
                row["config"]["image"] = image
                row["image_ref"]["digest"] = image.split("@")[-1]
                for allocation in config.get("vm", []):
                    if row["config"]["metadata"]["fly_process_group"] in allocation["processes"]:
                        row["config"]["guest"] = {k: v for k, v in allocation.items() if k != "processes"}
            # Critically: deployment updates a stopped worker without starting it.
        else:
            raise AssertionError(f"unexpected Fly command: {command}")

    def update(self, tmp_path, *, mode, indexer="workers"):
        import json

        config = self.copy(self.saved_config)
        config["env"] = {"PSAT_WORKER_LIFECYCLE_MODE": mode, "PSAT_INDEXER_GROUP": indexer}
        config_path = tmp_path / "new-release.json"
        config_path.write_text(json.dumps(config))
        deploy.subprocess.run(
            ["flyctl", "deploy", "--config", str(config_path), "--image", "registry.fly.io/psat@sha256:new"],
            check=True,
        )


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_full_handover_explicitly_starts_stopped_update_and_checks_new_boot(monkeypatch, tmp_path, mode):
    fly = FakeFly(monkeypatch, mode=mode)
    snapshot = deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    assert deploy.prepare(indexer="monitor", mode=mode)
    fly.update(tmp_path, mode=mode, indexer="monitor")
    assert fly.rows[0]["state"] == "stopped"
    deploy.restore(timeout=30)
    assert fly.rows[0]["state"] == "started"
    assert fly.status["boot_id"] == "new-boot"
    assert fly.status["paused"] is True
    assert fly.clock >= 10  # Running boot must remain healthy across observations.
    deploy.resume(snapshot)
    assert fly.status["paused"] is False
    assert fly.events.index("admin:drain") < fly.events.index("deploy") < fly.events.index("start")
    assert fly.events[-1] == "admin:resume"
    assert fly.events.count("start") == 1


def test_lost_start_response_reconciles_actual_started_state_without_duplicate_start(monkeypatch):
    fly = FakeFly(monkeypatch, state="stopped")
    fly.lose_start_response = True
    deploy.restore(timeout=30)
    assert fly.rows[0]["state"] == "started"
    assert fly.events.count("start") == 1
    assert fly.status["paused"] is True


@pytest.mark.parametrize(
    "start_status",
    [
        {"boot_id": "old-boot"},
        {"boot_fresh": False},
        {"phase": "draining"},
        {"machine_id": "wrong-machine"},
        {"paused": False},
    ],
)
def test_restore_rejects_stale_or_unready_boot_even_if_machine_started(monkeypatch, start_status):
    fly = FakeFly(monkeypatch, state="stopped")
    fly.start_status = start_status
    with pytest.raises(TimeoutError, match="did not become ready"):
        deploy.restore(timeout=15, stable_seconds=0)
    assert "admin:resume" not in fly.events


def test_preexisting_operator_pause_survives_successful_handover(monkeypatch, tmp_path):
    fly = FakeFly(monkeypatch, paused=True)
    snapshot = deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    assert snapshot["paused"] is True
    assert deploy.prepare(indexer="workers")
    fly.update(tmp_path, mode="observe")
    deploy.restore(timeout=30)
    deploy.resume(snapshot)
    assert fly.status["paused"] is True
    assert "admin:resume" not in fly.events


def test_snapshot_preserves_immutable_image_remote_config_and_actual_allocations(monkeypatch, tmp_path):
    import hashlib
    import json
    import stat

    fly = FakeFly(monkeypatch)
    fly.rows[1]["config"]["guest"] = {"cpu_kind": "shared", "cpus": 2, "memory_mb": 4096}
    config_path = tmp_path / "rollback.json"
    state_path = tmp_path / "state.json"
    snapshot = deploy.capture(state_path, config_path)
    assert snapshot["image"] == "registry.fly.io/psat@sha256:old"
    assert snapshot["config_sha256"] == hashlib.sha256(config_path.read_bytes()).hexdigest()
    config = json.loads(config_path.read_text())
    assert config["env"] == fly.saved_config["env"]
    allocations = {row["processes"][0]: row for row in config["vm"]}
    assert allocations["workers"]["cpus"] == 8
    assert allocations["workers"]["memory_mb"] == 16384
    assert allocations["monitor"]["memory_mb"] == 4096
    assert stat.S_IMODE(config_path.stat().st_mode) == stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert "admin:drain" not in fly.events and "start" not in fly.events


def test_first_bridge_failure_rolls_back_matching_legacy_release_and_can_deploy_again(monkeypatch, tmp_path):
    fly = FakeFly(monkeypatch, mode="off")
    snapshot = deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    assert snapshot["paused"] is None
    assert deploy.prepare(indexer="workers", mode="observe") is False
    fly.update(tmp_path, mode="observe")
    # The bridge is healthy enough to drain but fails subsequent release smoke.
    deploy.rollback(snapshot)
    assert fly.rows[0]["state"] == "started"
    assert deploy.layout(fly.rows[0]) == ("off", "workers")
    assert fly.rows[0]["config"]["image"] == snapshot["image"]
    assert fly.rows[0]["config"]["guest"]["memory_mb"] == 16384
    rollback_command = [command for command in fly.commands if command[1] == "deploy"][-1]
    assert rollback_command[rollback_command.index("--config") + 1] == snapshot["config"]
    assert "--skip-release-command" in rollback_command
    # FakeFly raises on any invocation of unavailable legacy lifecycle_admin.
    deploy.resume(snapshot)
    assert deploy.prepare(indexer="workers", mode="observe") is False
    assert "admin:resume" not in fly.events


def test_rollback_rejects_modified_snapshot_before_any_mutation(monkeypatch, tmp_path):
    fly = FakeFly(monkeypatch)
    config_path = tmp_path / "rollback.json"
    snapshot = deploy.capture(tmp_path / "state.json", config_path)
    config_path.write_text(config_path.read_text() + "\n")
    fly.events.clear()
    with pytest.raises(RuntimeError, match="changed after snapshot"):
        deploy.rollback(snapshot)
    assert fly.events == []


@pytest.mark.parametrize("drift", ["image", "layout", "remote_config", "worker_settings"])
def test_snapshot_rejects_release_or_configuration_drift(monkeypatch, tmp_path, drift):
    fly = FakeFly(monkeypatch)
    if drift == "image":
        fly.rows[2]["image_ref"]["digest"] = "sha256:other"
    elif drift == "layout":
        fly.rows[1]["config"]["env"]["PSAT_INDEXER_GROUP"] = "monitor"
    elif drift == "remote_config":
        fly.saved_config["env"]["PSAT_WORKER_LIFECYCLE_MODE"] = "enforce"
    else:
        fly.saved_config["env"]["PSAT_WORKER_CONCURRENCY"] = "999"
    with pytest.raises(RuntimeError, match="mixed|disagree"):
        deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    assert "admin:drain" not in fly.events and "deploy" not in fly.events and "start" not in fly.events


@pytest.mark.parametrize("worker_state", ["started", "stopped"])
def test_partial_first_bridge_rolls_back_without_legacy_admin(monkeypatch, tmp_path, worker_state):
    fly = FakeFly(monkeypatch, mode="off")
    snapshot = deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    # Rolling bridge deployment updates workers, then fails before old monitoring.
    fly.rows[0]["config"]["env"]["PSAT_WORKER_LIFECYCLE_MODE"] = "observe"
    fly.rows[0]["config"]["image"] = "registry.fly.io/psat@sha256:new"
    fly.rows[0]["image_ref"]["digest"] = "sha256:new"
    fly.rows[0]["state"] = worker_state
    deploy.rollback(snapshot)
    assert fly.rows[0]["state"] == "started"
    assert deploy.layout(fly.rows[0]) == ("off", "workers")
    ssh = [command for command in fly.commands if command[1:3] == ["ssh", "console"]]
    if worker_state == "started":
        assert len(ssh) == 1
        assert ssh[0][ssh[0].index("--machine") + 1] == "abc"
        assert ssh[0][-1].endswith(" drain")
    else:
        assert ssh == []
    deploy.resume(snapshot)
    assert deploy.prepare(indexer="workers", mode="observe") is False


def test_admin_prefers_managed_monitor_and_validates_control_protocol(monkeypatch):
    fly = FakeFly(monkeypatch)
    assert deploy.admin("status")["control_version"] == 1
    assert fly.commands[-1][fly.commands[-1].index("--machine") + 1] == "monitor"
    fly.status["control_version"] = 2
    with pytest.raises(RuntimeError, match="control protocol"):
        deploy.admin("status")


def test_restore_detects_mid_handover_configuration_drift(monkeypatch):
    fly = FakeFly(monkeypatch, state="stopped")

    def change_layout(seconds):
        fly.sleep(seconds)
        fly.rows[0]["config"]["env"]["PSAT_INDEXER_GROUP"] = "monitor"

    monkeypatch.setattr(deploy.time, "sleep", change_layout)
    with pytest.raises(RuntimeError, match="configuration changed"):
        deploy.restore(timeout=30)
    assert "admin:resume" not in fly.events


def test_unaccepted_start_retries_after_cooldown_then_verifies_boot(monkeypatch):
    import subprocess

    fly = FakeFly(monkeypatch, state="stopped")
    starts = []

    def fail_first_start(command, **kwargs):
        if command[1:3] == ["machine", "start"]:
            starts.append(fly.clock)
            if len(starts) == 1:
                raise subprocess.TimeoutExpired(command, timeout=30)
        return fly.run(command, **kwargs)

    monkeypatch.setattr(deploy.subprocess, "run", fail_first_start)
    deploy.restore(timeout=90)
    assert starts == [0.0, 60.0]
    assert fly.rows[0]["state"] == "started" and fly.status["paused"] is True


def test_snapshot_rejects_unresolved_mutable_image(monkeypatch, tmp_path):
    fly = FakeFly(monkeypatch)
    fly.rows[0].pop("image_ref")
    with pytest.raises(RuntimeError, match="immutable image"):
        deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    assert "config:save" not in fly.events
