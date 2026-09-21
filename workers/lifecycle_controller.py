"""One monitor-owned queue controller. Fly access is read + start only.

No stop API: the worker launcher drains and exits successfully. Reconcile real
machine state on every pass, so a job arriving during drain or a lost start
response cannot strand durable work. Default mode never changes VM state.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import threading
import time
from datetime import timedelta

import requests
from sqlalchemy import text

from db.models import SessionLocal
from db.queue import record_heartbeat
from services.worker_lifecycle import lifecycle_mode
from services.worker_workload import snapshot
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


class FlyMachines:
    def __init__(self):
        app = os.environ["FLY_APP_NAME"]
        if not re.fullmatch(r"[a-z0-9-]+", app):
            raise ValueError("invalid Fly app name")
        self.base = f"https://api.machines.dev/v1/apps/{app}/machines"
        token = os.environ["PSAT_WORKER_LIFECYCLE_TOKEN"]
        self.http = requests.Session()
        scheme = "FlyV1" if token.startswith("fm2_") else "Bearer"
        self.http.headers["Authorization"] = token if token.startswith(("FlyV1 ", "Bearer ")) else f"{scheme} {token}"

    def target(self, *, require_split: bool = True) -> dict:
        response = self.http.get(self.base, timeout=(5, 10))
        response.raise_for_status()
        rows = response.json()
        if any(
            m.get("config", {}).get("metadata", {}).get("fly_process_group") == "workers"
            and m.get("config", {}).get("standbys")
            and m.get("state") not in {"stopped", "destroyed"}
            for m in rows
        ):
            raise RuntimeError("worker standby is active; reconcile failover ownership before lifecycle actions")
        machines = [
            m
            for m in rows
            if m.get("config", {}).get("metadata", {}).get("fly_process_group") == "workers"
            and not m.get("config", {}).get("standbys")
            and m.get("state") != "destroyed"
        ]
        if len(machines) != 1:
            raise RuntimeError("expected exactly one non-standby workers machine; lifecycle actions inhibited")
        machine = machines[0]
        config = machine["config"]
        if config.get("services") or config.get("restart", {}).get("policy") != "on-failure":
            raise RuntimeError("workers must have no HTTP service and an explicit on-failure restart policy")
        if require_split and config.get("env", {}).get("PSAT_INDEXER_GROUP", "workers") != "monitor":
            raise RuntimeError("workers cannot sleep while they own the indexer")
        return machine

    def start(self, machine_id: str) -> None:
        if not re.fullmatch(r"[a-f0-9]+", machine_id):
            raise ValueError("invalid machine id")
        response = self.http.post(f"{self.base}/{machine_id}/start", json={}, timeout=(5, 10))
        response.raise_for_status()


def tick(session, machine: dict | None, *, mode: str, grace: float, cooldown: float = 60) -> dict:
    """Persist the decision before external I/O; failed calls retry after cooldown.

    The gate lock precedes readiness reads, matching all claimers' lock ordering.
    Enqueues need no lock: a late enqueue will be seen after the VM actually stops.
    """
    session.execute(text("SET LOCAL statement_timeout = '5s'"))
    state = session.execute(text("SELECT *, clock_timestamp() AS now FROM worker_lifecycle WHERE id=1 FOR UPDATE"))
    row = state.mappings().one()
    work = snapshot(session)
    now = row["now"]
    idle_since = None if work.busy else (row["idle_since"] or now)
    if idle_since and row["last_work_at"] and row["last_work_at"] > idle_since:
        idle_since = row["last_work_at"]
    idle_seconds = (now - idle_since).total_seconds() if idle_since else 0
    action = "busy" if work.busy else "idle"
    actual = machine["state"] if machine else "unobserved"
    enabled = mode == "enforce" and not row["paused"]
    # An orphaned but unexpired lease cannot be reclaimed yet. Let it mature
    # while stopped rather than spending running minutes waiting for its TTL.
    if work.ready and actual in {"stopped", "suspended"}:
        if not row["next_start_at"] or row["next_start_at"] <= now:
            action = "start" if enabled else "would_start"
            if enabled:
                session.execute(
                    text("UPDATE worker_lifecycle SET next_start_at=:at WHERE id=1"),
                    {"at": now + timedelta(seconds=cooldown)},
                )
    elif not work.busy and idle_seconds >= grace:
        action = "would_drain"
        if (
            enabled
            and machine is not None
            and actual == "started"
            and row["phase"] == "running"
            and row["machine_id"] == machine["id"]
            and row["heartbeat_at"]
            and (now - row["heartbeat_at"]).total_seconds() < 30
        ):
            session.execute(text("UPDATE worker_lifecycle SET phase='draining' WHERE id=1"))
            action = "drain"
    session.execute(text("UPDATE worker_lifecycle SET idle_since=:at WHERE id=1"), {"at": idle_since})
    session.commit()
    return {
        "action": action,
        "machine_state": actual,
        "ready_sources": list(work.ready),
        "active": work.active,
        "idle_seconds": round(idle_seconds, 3),
        "mode": mode,
        "paused": row["paused"],
        "boot_id": str(row["boot_id"]),
    }


def run(stop: threading.Event) -> None:
    mode = lifecycle_mode()
    if mode == "off":
        return
    interval = max(1, float(os.getenv("PSAT_LIFECYCLE_POLL_S", "15")))
    grace = max(30, float(os.getenv("PSAT_LIFECYCLE_IDLE_S", "300")))
    fly = FlyMachines() if os.getenv("PSAT_WORKER_LIFECYCLE_TOKEN") else None
    if mode == "enforce" and fly is None:
        raise ValueError("enforce mode requires PSAT_WORKER_LIFECYCLE_TOKEN")
    sweep_at = 0.0
    while not stop.is_set():
        started = time.monotonic()
        try:
            # Lightweight durable scheduling belongs on the always-on side.
            # Import lazily; never call the governance builder here.
            if time.monotonic() >= sweep_at:
                from services.monitoring.enrollment_schedule import DEFAULT_RECONCILE_INTERVAL_S, sweep_enqueue_stale

                with SessionLocal() as session:
                    sweep_enqueue_stale(session)
                sweep_at = time.monotonic() + DEFAULT_RECONCILE_INTERVAL_S
            machine = fly.target(require_split=mode == "enforce") if fly else None
            with SessionLocal() as session:
                decision = tick(session, machine, mode=mode, grace=grace)
            decision["controller_machine_id"] = os.getenv("FLY_MACHINE_ID", "local")
            logger.info("worker lifecycle observation", extra={**decision, "sample_seconds": interval})
            record_heartbeat("worker_lifecycle", status="running", detail=decision)
            if decision["action"] == "start":
                assert fly is not None and machine is not None
                fly.start(machine["id"])
        except Exception as exc:
            # Do not log HTTP bodies/config or credentials. Any uncertainty
            # inhibits shutdown. Durable queue plus next pass repairs wakeups.
            logger.error("worker lifecycle pass failed", extra={"exc_type": type(exc).__name__})
            record_heartbeat("worker_lifecycle", status="error", detail={"exc_type": type(exc).__name__})
        stop.wait(max(0, interval - (time.monotonic() - started)))


def main() -> None:
    configure_logging()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    run(stop)


if __name__ == "__main__":
    main()
