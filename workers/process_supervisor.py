"""Per-process supervision for the workers machine.

A worker that dies is restarted alone, after a backoff, while every other worker keeps its in-flight jobs. Only a worker
that keeps dying (``PSAT_SUPERVISOR_MAX_RESTARTS`` deaths within ``PSAT_SUPERVISOR_WINDOW_S``) escalates: the supervisor
stops everything and exits nonzero, which is the machine restart the platform already performs. Each worker starts
under its own address-space cap. SIGTERM drains: workers are told to stop, none is restarted, and the supervisor exits
zero once all have finished.

Usage: ``python -m workers.process_supervisor NAME|CAP_MB|MODULE [ARG ...] ...``, one spec per worker; a ``CAP_MB`` of 0
leaves the worker uncapped.
"""

from __future__ import annotations

import logging
import os
import resource
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("workers.process_supervisor")

HEARTBEAT_PREFIX = "worker_supervisor"


def _env_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class WorkerSpec:
    name: str
    argv: tuple[str, ...]
    address_space_bytes: int | None

    @classmethod
    def parse(cls, raw: str, python: str = sys.executable) -> WorkerSpec:
        name, cap_mb, command = raw.split("|", 2)
        module_argv = shlex.split(command)
        if not name or not module_argv:
            raise ValueError(f"malformed worker spec {raw!r}")
        cap = int(cap_mb)
        return cls(name=name, argv=(python, "-m", *module_argv), address_space_bytes=cap * 1024 * 1024 or None)


@dataclass
class _Worker:
    spec: WorkerSpec
    process: subprocess.Popen | None = None
    started_at: float = 0.0
    restart_at: float | None = None
    deaths: deque[float] = field(default_factory=deque)
    restarts: int = 0


class Supervisor:
    def __init__(
        self,
        specs: list[WorkerSpec],
        *,
        max_restarts: int = 5,
        window_s: float = 600.0,
        backoff_base_s: float = 5.0,
        backoff_cap_s: float = 120.0,
        stop_grace_s: float = 300.0,
        heartbeat_interval_s: float = 60.0,
        heartbeat: Callable[[str, dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.workers = [_Worker(spec) for spec in specs]
        self.max_restarts = max_restarts
        self.window_s = window_s
        self.backoff_base_s = backoff_base_s
        self.backoff_cap_s = backoff_cap_s
        self.stop_grace_s = stop_grace_s
        self.heartbeat_interval_s = heartbeat_interval_s
        self._heartbeat = heartbeat
        self._clock = clock
        self._next_beat = 0.0
        self.escalated_by: str | None = None

    def _launch(self, worker: _Worker) -> None:
        cap = worker.spec.address_space_bytes

        def _limit() -> None:
            if cap is not None:
                resource.setrlimit(resource.RLIMIT_AS, (cap, cap))

        worker.process = subprocess.Popen(worker.spec.argv, preexec_fn=_limit)
        worker.started_at = self._clock()
        worker.restart_at = None

    def _beat(self, status: str, **detail: Any) -> None:
        if self._heartbeat is None:
            return
        workers = {
            w.spec.name: {
                "pid": w.process.pid if w.process is not None and w.process.poll() is None else None,
                "restarts": w.restarts,
                "recent_deaths": len(w.deaths),
            }
            for w in self.workers
        }
        self._heartbeat(status, {**detail, "workers": workers})
        self._next_beat = self._clock() + self.heartbeat_interval_s

    def start(self) -> None:
        for worker in self.workers:
            self._launch(worker)
        logger.info(
            "workers started",
            extra={"workers": {w.spec.name: w.process.pid for w in self.workers if w.process is not None}},
        )
        self._beat("running")

    def poll(self) -> bool:
        """One supervision pass; ``False`` once a worker's restart loop calls for the machine to restart."""
        now = self._clock()
        for worker in self.workers:
            process = worker.process
            if process is not None and process.poll() is not None:
                worker.process = None
                worker.deaths.append(now)
                while worker.deaths and now - worker.deaths[0] > self.window_s:
                    worker.deaths.popleft()
                recent = len(worker.deaths)
                if recent >= self.max_restarts:
                    self.escalated_by = worker.spec.name
                    logger.error(
                        "worker %s is in a restart loop; restarting the machine",
                        worker.spec.name,
                        extra={
                            "worker": worker.spec.name,
                            "exit_code": process.returncode,
                            "recent_deaths": recent,
                            "window_s": self.window_s,
                        },
                    )
                    self._beat("escalating", worker=worker.spec.name, exit_code=process.returncode)
                    return False
                backoff = min(self.backoff_cap_s, self.backoff_base_s * 2 ** (recent - 1))
                worker.restart_at = now + backoff
                logger.error(
                    "worker %s exited; restarting it alone",
                    worker.spec.name,
                    extra={
                        "worker": worker.spec.name,
                        "exit_code": process.returncode,
                        "uptime_s": round(now - worker.started_at, 1),
                        "recent_deaths": recent,
                        "backoff_s": backoff,
                    },
                )
                self._beat("restarting", worker=worker.spec.name, exit_code=process.returncode, backoff_s=backoff)
            if worker.process is None and worker.restart_at is not None and now >= worker.restart_at:
                self._launch(worker)
                worker.restarts += 1
                assert worker.process is not None
                logger.info(
                    "worker %s restarted",
                    worker.spec.name,
                    extra={"worker": worker.spec.name, "pid": worker.process.pid, "restarts": worker.restarts},
                )
                self._beat("running", worker=worker.spec.name, restarted=True)
        if now >= self._next_beat:
            self._beat("running")
        return True

    def stop(self, *, grace_s: float | None) -> None:
        """SIGTERM every live worker and wait for it, past *grace_s* with SIGKILL (``None`` waits)."""
        live = [w.process for w in self.workers if w.process is not None and w.process.poll() is None]
        for process in live:
            try:
                process.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = None if grace_s is None else self._clock() + grace_s
        for process in live:
            timeout = None if deadline is None else max(0.0, deadline - self._clock())
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for worker in self.workers:
            worker.process = None
            worker.restart_at = None

    def run(self, stop: threading.Event, *, poll_s: float = 1.0) -> int:
        self.start()
        while not stop.is_set():
            if not self.poll():
                self.stop(grace_s=self.stop_grace_s)
                return 1
            stop.wait(poll_s)
        logger.info("draining workers")
        self._beat("draining")
        self.stop(grace_s=None)
        self._beat("stopped")
        logger.info("workers drained")
        return 0


def _record(process: str) -> Callable[[str, dict[str, Any]], None]:
    def beat(status: str, detail: dict[str, Any]) -> None:
        from db.queue import record_heartbeat

        record_heartbeat(process, status=status, detail=detail)

    return beat


def main(argv: list[str] | None = None) -> int:
    from utils.logging import configure_logging

    # Each worker samples itself and its descendants; sampling them again here would double-count them.
    interval = os.environ.get("PSAT_MEMORY_SAMPLE_INTERVAL_S")
    os.environ["PSAT_MEMORY_SAMPLE_INTERVAL_S"] = "0"
    configure_logging()
    if interval is None:
        os.environ.pop("PSAT_MEMORY_SAMPLE_INTERVAL_S")
    else:
        os.environ["PSAT_MEMORY_SAMPLE_INTERVAL_S"] = interval
    specs = [WorkerSpec.parse(raw) for raw in (sys.argv[1:] if argv is None else argv)]
    machine = os.getenv("FLY_MACHINE_ID") or socket.gethostname()
    supervisor = Supervisor(
        specs,
        max_restarts=int(_env_float("PSAT_SUPERVISOR_MAX_RESTARTS", 5)),
        window_s=_env_float("PSAT_SUPERVISOR_WINDOW_S", 600),
        backoff_base_s=_env_float("PSAT_SUPERVISOR_BACKOFF_S", 5),
        backoff_cap_s=_env_float("PSAT_SUPERVISOR_BACKOFF_CAP_S", 120),
        stop_grace_s=_env_float("PSAT_SUPERVISOR_STOP_GRACE_S", 300),
        heartbeat=_record(f"{HEARTBEAT_PREFIX}:{machine}"[:64]),
    )
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    return supervisor.run(stop)


if __name__ == "__main__":
    raise SystemExit(main())
