"""Cooperative CI handover; the controller is the only automatic starter.

Deployment explicitly restores availability while the controller is paused.
Rollback uses the captured image AND configuration, including a legacy release.
Run only during an authorized deployment. No stop/scale/force-kill API exists here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

APP = "psat"


def render_config(source: str, *, mode: str = "off", indexer: str = "workers", monitor_mb: int = 512) -> str:
    if mode not in {"off", "observe", "enforce"} or indexer not in {"workers", "monitor"}:
        raise ValueError("invalid lifecycle mode or indexer placement")
    if monitor_mb not in {512, 2048, 4096}:
        raise ValueError("monitor_mb must be 512, 2048, or 4096")
    if mode != "off" and monitor_mb < 2048:
        raise ValueError("managed monitoring requires measured headroom; start with at least the 2-GiB candidate")
    if indexer == "monitor" and monitor_mb < 2048:
        raise ValueError("monitor indexer requires at least the candidate 2-GiB allocation")
    if mode == "enforce" and indexer != "monitor":
        raise ValueError("enforce mode requires the always-on indexer")
    for key, value in (("PSAT_WORKER_LIFECYCLE_MODE", mode), ("PSAT_INDEXER_GROUP", indexer)):
        source, count = re.subn(rf'(?m)^(\s*{key}\s*=\s*)"[^"]*"', rf'\g<1>"{value}"', source)
        if count != 1:
            raise ValueError(f"expected one {key} setting")
    pattern = r'(\[\[vm\]\]\s*processes = \["monitor"\]\s*)size = "[^"]+"\s*memory = "[^"]+"'
    size = "shared-cpu-1x" if monitor_mb == 512 else "shared-cpu-2x"
    source, count = re.subn(pattern, rf'\g<1>size = "{size}"\n  memory = "{monitor_mb}mb"', source)
    if count != 1:
        raise ValueError("expected one monitor VM block")
    return source


def machines() -> list[dict]:
    rows = json.loads(
        subprocess.check_output(["flyctl", "machines", "list", "-a", APP, "--json"], text=True, timeout=30)
    )
    if any(
        row.get("config", {}).get("standby_for")
        and row.get("config", {}).get("metadata", {}).get("fly_process_group") in {"workers", "monitor"}
        and row.get("state") not in {"stopped", "destroyed"}
        for row in rows
    ):
        raise RuntimeError("active standby requires failover reconciliation before deployment")
    return rows


def group(rows: list[dict], name: str) -> list[dict]:
    return [
        row
        for row in rows
        if row.get("config", {}).get("metadata", {}).get("fly_process_group") == name
        and not row.get("config", {}).get("standby_for")
        and row.get("state") != "destroyed"
    ]


def worker() -> dict:
    rows = group(machines(), "workers")
    if len(rows) != 1:
        raise RuntimeError("expected one worker machine before deployment")
    return rows[0]


def layout(machine: dict) -> tuple[str, str]:
    env = machine["config"].get("env", {})
    return env.get("PSAT_WORKER_LIFECYCLE_MODE", "off"), env.get("PSAT_INDEXER_GROUP", "workers")


def admin(action: str) -> dict:
    rows = machines()
    monitors = group(rows, "monitor")
    workers = group(rows, "workers")
    if len(monitors) != 1 or len(workers) != 1:
        raise RuntimeError("deployment requires one monitor and one worker")
    # A first bridge can fail after updating workers but before monitoring.
    # Both managed images expose the same DB control protocol; never ask the
    # legacy monitor to import a module that did not exist in its release.
    targets = [row for row in (*monitors, *workers) if row["state"] == "started" and layout(row)[0] != "off"]
    if not targets:
        raise RuntimeError("deployment requires an available managed control process")
    output = subprocess.check_output(
        [
            "flyctl",
            "ssh",
            "console",
            "-a",
            APP,
            "--machine",
            targets[0]["id"],
            "-C",
            f"/app/.venv/bin/python -m workers.lifecycle_admin {action}",
        ],
        text=True,
        timeout=30,
    )
    # flyctl may print a connection notice before the module's JSON response.
    for line in reversed(output.splitlines()):
        if line.startswith("{"):
            result = json.loads(line)
            if result.get("control_version") == 1:
                return result
    raise RuntimeError("monitor image lacks the expected lifecycle control protocol")


def save_private(path: Path, value: dict) -> None:
    with os.fdopen(os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600), "w") as stream:
        json.dump(value, stream, indent=2)
    path.chmod(0o600)


def image(machine: dict) -> str:
    ref = machine.get("image_ref", {})
    if ref.get("digest") and ref.get("registry") and ref.get("repository"):
        return f"{ref['registry']}/{ref['repository']}@{ref['digest']}"
    value = machine["config"]["image"]
    if "@sha256:" not in value:
        raise RuntimeError("deployment snapshot requires a resolved immutable image")
    return value


def capture(state_path: Path, config_path: Path) -> dict:
    """Capture before any drain/deploy. Refuse mixed images or configuration drift."""
    rows = machines()
    workers = group(rows, "workers")
    monitors = group(rows, "monitor")
    if len(workers) != 1 or len(monitors) != 1 or monitors[0]["state"] != "started":
        raise RuntimeError("snapshot requires one worker and one available monitor")
    previous = workers[0]
    mode, indexer = layout(previous)
    paused = admin("status")["paused"] if mode != "off" else None
    if layout(monitors[0]) != (mode, indexer):
        raise RuntimeError("mixed lifecycle configuration; reconcile deployment before retrying")
    expected_image = image(previous)
    for name in ("web", "browser", "monitor", "workers"):
        if any(image(row) != expected_image for row in group(rows, name)):
            raise RuntimeError("mixed release images; automatic rollback cannot capture a coherent release")
    if config_path.suffix != ".json":
        raise ValueError("rollback configuration must use .json")
    # Config is stored remotely by Fly, so it belongs to the old release, not
    # this checkout. --image rollback needs no local build section.
    subprocess.run(
        ["flyctl", "config", "save", "-a", APP, "--json", "--yes", "--config", str(config_path)],
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=30,
    )
    config_path.chmod(0o600)
    config = json.loads(config_path.read_text())
    if config.get("app") != APP:
        raise RuntimeError("captured configuration belongs to a different app")
    old_env = config.get("env", {})
    if (old_env.get("PSAT_WORKER_LIFECYCLE_MODE", "off"), old_env.get("PSAT_INDEXER_GROUP", "workers")) != (
        mode,
        indexer,
    ):
        raise RuntimeError("saved config and deployed lifecycle mode disagree")
    for key, value in old_env.items():
        if key.startswith("PSAT_") and previous["config"].get("env", {}).get(key) != value:
            raise RuntimeError("saved config and worker settings disagree")
    # Preserve actual allocations even if an operator previously used fly scale.
    allocations = []
    for name in config.get("processes", {}):
        members = group(rows, name)
        if not members:
            raise RuntimeError("captured process group has no machine")
        guest = members[0]["config"]["guest"]
        if any(row["config"]["guest"] != guest for row in members):
            raise RuntimeError("heterogeneous VM sizes require a manual rollback plan")
        allocations.append({"processes": [name], **guest})
    config["vm"] = allocations
    save_private(config_path, config)
    state = {
        "image": expected_image,
        "config": str(config_path.resolve()),
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "mode": mode,
        "indexer": indexer,
        "paused": paused,
    }
    save_private(state_path, state)
    return state


def prepare(*, indexer: str, mode: str = "observe", timeout: float = 1200) -> bool:
    previous = worker()
    old_mode, old_indexer = layout(previous)
    if mode == "off" and (old_indexer == "monitor" or indexer == "monitor"):
        raise RuntimeError("move indexing back in observe mode before disabling managed ownership")
    if old_mode == "off":
        if indexer == "monitor":
            raise RuntimeError("deploy the observe/workers bridge release before moving the indexer")
        return False
    if previous["state"] == "stopped":
        monitors = group(machines(), "monitor")
        if len(monitors) == 1 and layout(monitors[0])[0] == "off":
            # Partial first bridge: workers are already safe and no lifecycle
            # controller exists on the legacy monitor. Roll back without SSH.
            return True
    admin("drain")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = worker()
        if current["id"] != previous["id"]:
            raise RuntimeError("worker topology changed during drain; deployment aborted")
        if current["state"] == "stopped":
            return True
        time.sleep(5)
    raise TimeoutError("workers did not drain; lifecycle remains paused, operator recovery required")


def restore(*, timeout: float = 300, stable_seconds: float = 10) -> None:
    """Restore an updated stopped worker in ALL modes; leave automation paused.

    The one-shot deployment owns starts only inside this paused handover. Fly
    updates stopped machines without starting them, including service-free VMs.
    A lost start response is reconciled from actual state with bounded retries.
    """
    target = worker()
    managed = layout(target)[0] != "off"
    previous_boot = admin("pause").get("boot_id") if managed else None
    expect_new_boot = target["state"] != "started"
    deadline = time.monotonic() + timeout
    start_after = 0.0
    healthy_since = None
    while time.monotonic() < deadline:
        current = worker()
        if current["id"] != target["id"] or layout(current) != layout(target):
            raise RuntimeError("worker topology/configuration changed during restoration")
        ready = current["state"] == "started"
        if ready and managed:
            status = admin("status")
            ready = bool(
                status.get("paused") is True
                and status.get("phase") == "running"
                and status.get("machine_id") == current["id"]
                and status.get("boot_fresh") is True
                and (not expect_new_boot or status.get("boot_id") != previous_boot)
            )
        if ready:
            healthy_since = healthy_since if healthy_since is not None else time.monotonic()
            if time.monotonic() - healthy_since >= stable_seconds:
                return
        else:
            healthy_since = None
        if current["state"] in {"stopped", "suspended"} and time.monotonic() >= start_after:
            start_after = time.monotonic() + 60
            try:
                subprocess.run(["flyctl", "machine", "start", current["id"], "-a", APP], check=True, timeout=30)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # Do not assume a failed response means the start was rejected.
                pass
        time.sleep(5)
    raise TimeoutError("worker did not become ready; lifecycle remains paused")


def resume(state: dict) -> None:
    # Restore an operator's pre-existing pause, including an initially paused
    # first bridge. Legacy rollback needs no module on its old monitor image.
    if layout(worker())[0] != "off":
        admin("resume" if state.get("paused") is False else "pause")


def rollback(state: dict) -> None:
    config = Path(state["config"])
    if hashlib.sha256(config.read_bytes()).hexdigest() != state["config_sha256"]:
        raise RuntimeError("rollback configuration changed after snapshot")
    prepare(indexer=state["indexer"], mode=state["mode"])
    subprocess.run(
        [
            "flyctl",
            "deploy",
            "-a",
            APP,
            "--config",
            str(config),
            "--image",
            state["image"],
            "--remote-only",
            "--strategy",
            "rolling",
            "--skip-release-command",
        ],
        check=True,
    )
    # Migrations are additive. The legacy image cannot run Alembic against an
    # unknown newer revision; rollback must not downgrade or rerun migrations.
    restore()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("snapshot", "prepare", "restore", "resume", "rollback"))
    parser.add_argument("--state", type=Path, default=os.getenv("PSAT_LIFECYCLE_STATE_FILE", "fly.lifecycle.json"))
    parser.add_argument("--config", type=Path, default="fly.rollback.json")
    args = parser.parse_args()
    if args.action == "snapshot":
        capture(args.state, args.config)
    elif args.action == "prepare":
        prepare(indexer=os.getenv("PSAT_INDEXER_GROUP", "workers"), mode=os.getenv("PSAT_LIFECYCLE_MODE", "off"))
    elif args.action == "restore":
        restore()
    else:
        state = json.loads(args.state.read_text())
        if args.action == "rollback":
            rollback(state)
        else:
            resume(state)


if __name__ == "__main__":
    main()
