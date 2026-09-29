from pathlib import Path
from unittest.mock import Mock

import pytest

from deploy.production import control as deploy


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


def test_stuck_drain_uses_bounded_fly_stop_without_releasing_claims(monkeypatch):
    fly = FakeFly(monkeypatch)
    fly.drain_stuck = True
    assert deploy.prepare(indexer="monitor", timeout=10) is True
    assert fly.clock >= 10
    assert fly.events == ["admin:drain", "stop"]
    assert fly.status["paused"] is True


@pytest.mark.parametrize("accepted", [False, True])
def test_stop_response_failure_requires_observed_stopped_state(monkeypatch, accepted):
    import subprocess

    fly = FakeFly(monkeypatch)
    fly.drain_stuck = True

    def stop_loses_response(command, **kwargs):
        if accepted:
            fly.run(command, **kwargs)
        raise subprocess.TimeoutExpired(command, 90)

    monkeypatch.setattr(deploy.subprocess, "run", stop_loses_response)
    if accepted:
        assert deploy.prepare(indexer="monitor", timeout=0, stop_timeout=10) is True
    else:
        with pytest.raises(TimeoutError, match="could not be confirmed"):
            deploy.prepare(indexer="monitor", timeout=0, stop_timeout=10)
    assert "admin:resume" not in fly.events and "deploy" not in fly.events


def test_drain_rejects_changed_worker_before_forced_stop(monkeypatch):
    fly = FakeFly(monkeypatch)
    fly.drain_stuck = True
    original_sleep = fly.sleep

    def change_worker(seconds):
        original_sleep(seconds)
        fly.rows[0]["id"] = "replacement"

    monkeypatch.setattr(deploy.time, "sleep", change_worker)
    with pytest.raises(RuntimeError, match="topology/configuration"):
        deploy.prepare(indexer="monitor", timeout=5)
    assert "stop" not in fly.events


def test_layout_preserves_analysis_capacity_and_concurrency():
    source = Path("fly.toml").read_text()
    rendered = deploy.render_config(source, mode="enforce", indexer="monitor", monitor_mb=2048)
    worker = rendered.split('processes = ["workers"]')[1].split("[[vm]]")[0]
    assert 'size = "shared-cpu-8x"' in worker and 'memory = "16gb"' in worker
    for line in source.splitlines():
        if any(
            key in line
            for key in (
                "PSAT_STATIC_WORKERS =",
                "PSAT_POLICY_WORKERS =",
                "PSAT_RESOLUTION_WORKERS =",
                "PSAT_POLICY_JOB_CONCURRENCY =",
            )
        ):
            assert line in rendered
    assert 'size = "shared-cpu-2x"\n  memory = "2048mb"' in rendered
    assert 'policy = "on-failure"' in rendered


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(mode="invalid"),
        dict(mode="enforce", indexer="workers"),
        dict(indexer="monitor", monitor_mb=512),
        dict(monitor_mb=1024),
    ],
)
def test_unsafe_config_rejected(kwargs):
    with pytest.raises(ValueError):
        deploy.render_config(Path("fly.toml").read_text(), **kwargs)


class FakeFly:
    """Model Fly's stopped update semantics; only explicit start changes state."""

    def __init__(self, monkeypatch, *, mode="observe", state="started", paused=False):
        import copy

        self.copy = copy.deepcopy
        self.clock = 0.0
        self.events = []
        self.commands = []
        self.lose_start_response = False
        self.drain_stuck = False
        self.start_status = {}
        self.readiness_overrides = {}
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
        if command[1:3] == ["config", "show"]:
            assert command == ["flyctl", "config", "show", "-a", "psat"]
            self.events.append("config:show")
            return json.dumps(self.saved_config)
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
            if not self.drain_stuck:
                next(row for row in self.rows if row["id"] == "abc")["state"] = "stopped"
                self.status["phase"] = "stopped"
        result = dict(self.status)
        if action == "ready":
            mode, indexer = deploy.layout(self.rows[0])
            result.update(
                controller={
                    "status": "running",
                    "fresh": True,
                    "detail": {
                        "mode": mode,
                        "paused": self.status["paused"],
                        "boot_id": self.status["boot_id"],
                        "controller_machine_id": "monitor",
                    },
                },
                indexer_owner=f"psat-singleton-indexer:{'monitor' if indexer == 'monitor' else 'abc'}",
            )
            result.update(self.readiness_overrides)
        return "Connecting to machine...\n" + json.dumps(result)

    def run(self, command, **_kwargs):
        import json
        import subprocess

        self.commands.append(command)
        if command[1:3] == ["machine", "stop"]:
            assert command == [
                "flyctl",
                "machine",
                "stop",
                "abc",
                "-a",
                "psat",
                "--signal",
                "SIGTERM",
                "--timeout",
                "30",
                "--wait-timeout",
                "60s",
            ]
            self.events.append("stop")
            self.rows[0]["state"] = "stopped"
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
    assert not config_path.exists() and not state_path.exists()
    snapshot = deploy.capture(state_path, config_path)
    assert ["flyctl", "config", "show", "-a", "psat"] in fly.commands
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


def test_snapshot_config_fetch_failure_leaves_no_backup_or_state(monkeypatch, tmp_path):
    import subprocess

    fly = FakeFly(monkeypatch, mode="off")

    def fail_config_fetch(command, **kwargs):
        if command[1:3] == ["config", "show"]:
            raise subprocess.CalledProcessError(1, command)
        return fly.check_output(command, **kwargs)

    monkeypatch.setattr(deploy.subprocess, "check_output", fail_config_fetch)
    state_path, config_path = tmp_path / "state.json", tmp_path / "rollback.json"
    with pytest.raises(subprocess.CalledProcessError):
        deploy.capture(state_path, config_path)
    assert not state_path.exists() and not config_path.exists()
    assert fly.events == []


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
    assert "config:show" not in fly.events


def add_fly_standbys(fly):
    # Fly's --standby-for flag serializes as config.standbys, not standby_for.
    # Match the live topology: a stopped standby for each non-service group.
    for primary in list(fly.rows):
        if primary["config"]["metadata"]["fly_process_group"] in {"workers", "monitor"}:
            standby = fly.copy(primary)
            standby["id"] += "-standby"
            standby["state"] = "stopped"
            standby["config"]["standbys"] = [primary["id"]]
            # A cold spare need not have the same image as the active release.
            standby["image_ref"]["digest"] = "sha256:older-standby"
            fly.rows.insert(0, standby)


@pytest.mark.parametrize("mode", ["off", "observe"])
def test_live_standby_shape_allows_snapshot_and_preparation(monkeypatch, tmp_path, mode):
    fly = FakeFly(monkeypatch, mode=mode)
    add_fly_standbys(fly)
    rows = deploy.machines()
    assert [m["id"] for m in deploy.group(rows, "workers")] == ["abc"]
    assert [m["id"] for m in deploy.group(rows, "monitor")] == ["monitor"]
    snapshot = deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    assert snapshot["image"] == "registry.fly.io/psat@sha256:old"
    assert snapshot["mode"] == mode
    assert deploy.prepare(indexer="workers", mode=mode) is (mode != "off")
    assert all(row["state"] == "stopped" for row in fly.rows if row["config"].get("standbys"))
    assert not any(command[1:3] == ["machine", "start"] for command in fly.commands)


@pytest.mark.parametrize("group", ["workers", "monitor"])
@pytest.mark.parametrize("state", ["starting", "started", "stopping", "suspended"])
def test_active_standby_blocks_deployment_before_any_mutation(monkeypatch, tmp_path, group, state):
    fly = FakeFly(monkeypatch, mode="off")
    add_fly_standbys(fly)
    next(row for row in fly.rows if row["id"] == ("abc" if group == "workers" else group) + "-standby")["state"] = state
    with pytest.raises(RuntimeError, match="active standby"):
        deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    assert fly.events == []


def test_first_activation_installs_bridge_then_split_and_enables_sleep(monkeypatch, tmp_path):
    fly = FakeFly(monkeypatch, mode="off", paused=True)
    state_path, config_path = tmp_path / "state.json", tmp_path / "rollback.json"
    state = deploy.capture(state_path, config_path)
    original_snapshot = state_path.read_bytes(), config_path.read_bytes()
    fly.update(tmp_path, mode="observe")
    deploy.restore(timeout=30)
    bridge_image = deploy.verify(mode="observe", indexer="workers", timeout=15)
    assert bridge_image.endswith("@sha256:new")
    assert fly.status["paused"] is True
    deploy.prepare(mode="enforce", indexer="monitor")
    fly.update(tmp_path, mode="enforce", indexer="monitor")
    deploy.restore(timeout=30)
    assert deploy.verify(mode="enforce", indexer="monitor", timeout=15) == bridge_image
    assert original_snapshot == (state_path.read_bytes(), config_path.read_bytes())
    deploy.resume(state, activate=True)
    assert fly.status["paused"] is False


@pytest.mark.parametrize("paused", [False, True])
def test_activation_preserves_existing_enforce_operator_pause(monkeypatch, tmp_path, paused):
    fly = FakeFly(monkeypatch, mode="enforce", paused=paused)
    state = deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    fly.status["paused"] = True
    deploy.resume(state, activate=True)
    assert fly.status["paused"] is paused


@pytest.mark.parametrize(
    "overrides",
    [
        {"controller": None},
        {"controller": {"status": "error", "fresh": True}},
        {"indexer_owner": None},
        {"indexer_owner": "psat-singleton-indexer:abc"},
    ],
)
def test_activation_requires_controller_health_and_actual_monitor_indexer_owner(monkeypatch, overrides):
    fly = FakeFly(monkeypatch, mode="enforce", paused=True)
    for row in fly.rows:
        row["config"]["env"]["PSAT_INDEXER_GROUP"] = "monitor"
    fly.readiness_overrides = overrides
    with pytest.raises(TimeoutError, match="ownership not ready"):
        deploy.verify(mode="enforce", indexer="monitor", timeout=10)
    assert "admin:resume" not in fly.events


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "observe"),
        ("paused", False),
        ("boot_id", "stale"),
        ("controller_machine_id", "wrong-monitor"),
    ],
)
def test_activation_rejects_stale_or_wrong_controller_observations(monkeypatch, field, value):
    fly = FakeFly(monkeypatch, paused=True)
    observation = deploy.admin("ready")["controller"]
    observation["detail"][field] = value if field != "mode" else "enforce"
    fly.readiness_overrides = {"controller": observation}
    with pytest.raises(TimeoutError):
        deploy.verify(mode="observe", indexer="workers", timeout=10)


def test_activation_rejects_partial_group_update(monkeypatch):
    fly = FakeFly(monkeypatch, paused=True)
    fly.rows[1]["image_ref"]["digest"] = "sha256:stale-monitor"
    with pytest.raises(RuntimeError, match="mixed layouts or images"):
        deploy.verify(mode="observe", indexer="workers", timeout=10)


@pytest.mark.parametrize("partial", [False, True])
def test_legacy_rollback_moves_indexer_back_even_with_failed_controller(monkeypatch, tmp_path, partial):
    import json

    fly = FakeFly(monkeypatch, mode="off")
    state = deploy.capture(tmp_path / "state.json", tmp_path / "rollback.json")
    fly.update(tmp_path, mode="observe")
    bridge_config = tmp_path / "bridge.json"
    bridge_config.write_text((tmp_path / "new-release.json").read_text())
    deploy.prepare(mode="enforce", indexer="monitor")
    fly.update(tmp_path, mode="enforce", indexer="monitor")
    if partial:
        fly.rows[0]["config"]["env"] = json.loads(bridge_config.read_text())["env"]
    fly.readiness_overrides = {"controller": {"status": "error", "fresh": True}}
    deploy.rollback(state, bridge_config=bridge_config)
    deploy.resume(state)
    assert all(deploy.layout(row) == ("off", "workers") for row in fly.rows)
    assert fly.rows[0]["state"] == "started"
    assert fly.rows[0]["config"]["image"] == state["image"]
    updates = [command for command in fly.commands if command[1] == "deploy"]
    assert updates[-2][updates[-2].index("--config") + 1] == str(bridge_config)
    assert updates[-1][updates[-1].index("--config") + 1] == state["config"]
    assert "admin:resume" not in fly.events


def test_production_defaults_enable_split_with_two_gib_monitor():
    source = Path("fly.toml").read_text()
    assert 'PSAT_WORKER_LIFECYCLE_MODE = "enforce"' in source
    assert 'PSAT_INDEXER_GROUP = "monitor"' in source
    monitor = source.split('processes = ["monitor"]')[1].split("[[restart]]")[0]
    assert 'size = "shared-cpu-2x"' in monitor and 'memory = "2048mb"' in monitor
