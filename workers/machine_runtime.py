"""Local child supervision and cooperative exit; no Fly lifecycle credentials.

Only the monitor controller requests a drain. This launcher closes no leases
and sends no stop API calls. It waits for every child (including their thread
pools/subprocesses) before releasing singleton ownership and exiting zero.
"""

from __future__ import annotations

import logging
import os
import runpy
import signal
import subprocess
import sys
import threading
import time
import uuid

from db.models import SessionLocal
from services.process_singleton import ProcessSingleton
from services.worker_lifecycle import boot_phase, finish_boot, lifecycle_mode, register_boot
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


def commands(group: str) -> list[list[str]]:
    python = sys.executable
    if group == "workers":
        return [["bash", "deploy/start_workers.sh"]]
    if group == "indexer":
        return [[python, "-m", "workers.event_log_indexer"]]
    result = [[python, "-m", "workers.protocol_monitor"]]
    if os.getenv("PSAT_INDEXER_GROUP", "workers") == "monitor":
        result.append([python, "-m", "workers.machine_runtime", "indexer"])
    if lifecycle_mode() != "off":
        result.append([python, "-m", "workers.lifecycle_controller"])
    return result


def kill_groups(children: list[subprocess.Popen]) -> None:
    """After failure, kill descendants too, before releasing ownership."""
    for child in children:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for child in children:
        child.wait()


def run(group: str, stop: threading.Event) -> int:
    if group not in {"workers", "monitor", "indexer"}:
        raise ValueError("unknown process group")
    if lifecycle_mode() == "enforce" and os.getenv("PSAT_INDEXER_GROUP", "workers") != "monitor":
        raise ValueError("enforce mode requires PSAT_INDEXER_GROUP=monitor")
    singleton = ProcessSingleton(group)
    children: list[subprocess.Popen] = []
    launches: list[tuple[list[str], dict[str, str]]] = []
    boot = uuid.uuid4()
    draining = False
    try:
        while not stop.is_set():
            if singleton.acquire():
                break
            stop.wait(2)
        if stop.is_set():
            return 0
        if group == "workers":
            with SessionLocal() as session:
                register_boot(session, boot, os.getenv("FLY_MACHINE_ID", "local"))
        for command in commands(group):
            env = dict(os.environ, PSAT_RUNTIME_CHILD="1")
            if group == "workers":
                env["PSAT_WORKER_BOOT_ID"] = str(boot)
            else:
                env.pop("PSAT_WORKER_BOOT_ID", None)
            if "workers.lifecycle_controller" not in command:
                env.pop("PSAT_WORKER_LIFECYCLE_TOKEN", None)
            launches.append((command, env))
            children.append(subprocess.Popen(command, env=env, start_new_session=True))
        logger.info("process group started", extra={"group": group, "boot_id": str(boot)})
        restart_at = [0.0] * len(children)
        failures = [0] * len(children)
        launched_at = [time.monotonic()] * len(children)
        check_at = 0.0
        phase = "running"
        while True:
            if time.monotonic() >= check_at:
                singleton.check()
                if group == "workers":
                    with SessionLocal() as session:
                        phase = boot_phase(session, boot)
                check_at = time.monotonic() + 5
            if not draining and (stop.is_set() or phase == "draining"):
                draining = True
                for child in children:
                    if child.poll() is None:
                        child.send_signal(signal.SIGTERM)
                logger.info("process group draining", extra={"group": group, "boot_id": str(boot)})
            if group == "monitor" and not draining:
                # Controller/indexer failure must not interrupt monitoring.
                # This launcher supervises processes; the existing monitoring
                # Supervisor still isolates the loops within its interpreter.
                for index, child in enumerate(children):
                    if child.poll() is None:
                        continue
                    if not restart_at[index]:
                        if time.monotonic() - launched_at[index] > 60:
                            failures[index] = 0
                        restart_at[index] = time.monotonic() + min(300, 5 * 2 ** min(failures[index], 6))
                        failures[index] += 1
                        logger.error(
                            "monitor child exited; restarting independently",
                            extra={"command": launches[index][0], "exit_code": child.returncode},
                        )
                    if time.monotonic() >= restart_at[index]:
                        kill_groups([child])
                        command, env = launches[index]
                        children[index] = subprocess.Popen(command, env=env, start_new_session=True)
                        launched_at[index] = time.monotonic()
                        restart_at[index] = 0.0
            exited = [child.returncode for child in children if child.poll() is not None]
            if exited and (not draining or any(code != 0 for code in exited)):
                if group != "monitor" or draining:
                    logger.error("unexpected child exit", extra={"group": group, "exit_codes": exited})
                    return 1
            if draining and len(exited) == len(children):
                if group == "workers":
                    with SessionLocal() as session:
                        finish_boot(session, boot)
                logger.info("process group drained", extra={"group": group, "boot_id": str(boot)})
                return 0
            # Event.wait would spin once stop is set while a long job drains.
            time.sleep(1)
    except Exception as exc:
        logger.error("process ownership or supervision failed", extra={"group": group, "exc_type": type(exc).__name__})
        return 1
    finally:
        # Forced loss cannot safely finish: terminate all descendants, retain
        # their leases for ordinary expiry/recovery, then relinquish ownership.
        kill_groups(children)
        singleton.close()


def main() -> None:
    configure_logging()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if sys.argv[1] == "indexer":
        run_indexer(stop)
    else:
        raise SystemExit(run(sys.argv[1], stop))


def run_indexer(stop: threading.Event) -> None:
    """Indexer owns its lock in-process, including during placement changes."""
    owner = ProcessSingleton("indexer")
    finished = threading.Event()
    try:
        while not stop.is_set():
            if owner.acquire():
                break
            stop.wait(2)
        if stop.is_set():
            return

        def guard():
            while not finished.wait(5):
                try:
                    owner.check()
                except Exception:
                    # No child processes: immediate death stops both indexer
                    # threads, rolling back pending DB work before takeover.
                    os.kill(os.getpid(), signal.SIGKILL)

        guard_thread = threading.Thread(target=guard, daemon=True)
        guard_thread.start()
        try:
            runpy.run_module("workers.event_log_indexer", run_name="__main__")
        finally:
            finished.set()
            guard_thread.join()
    finally:
        owner.close()


if __name__ == "__main__":
    main()
