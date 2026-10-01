"""Unified protocol monitor: scanner, poller and TVL loops as supervised threads in one process.

One loop's death never touches its siblings; a crash-loop pages via the error heartbeat but never stops. ``--poll`` /
``--tvl`` / ``--reconcile`` run a single loop in the foreground as rollback levers and the reconciler entrypoint.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time
from pathlib import Path
from typing import Callable, Sequence

from dotenv import load_dotenv

from db.queue import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_RESTAKING,
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_SCORE,
    HEARTBEAT_PROTOCOL_TVL,
    HEARTBEAT_ROLE_HOLDER_PLANE,
    record_heartbeat,
)
from services.clients.rpc import default_rpc_url
from utils.logging import configure_logging
from utils.secrets import sanitize_url

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logger = logging.getLogger(__name__)


def _default_rpc_seed() -> str:
    """Mainnet eRPC seed, resolved at call time so env changes are honored; loops derive per-chain RPCs from it."""
    return default_rpc_url(chain_id=1) or ""


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


LoopTarget = Callable[[threading.Event], None]


class Supervisor:
    """Runs each named loop in a daemon thread, restarting on death with exponential backoff; a healthy stretch
    resets the backoff.
    """

    def __init__(
        self,
        loops: Sequence[tuple[str, LoopTarget]],
        *,
        stop_event: threading.Event | None = None,
        base_backoff_s: float | None = None,
        max_backoff_s: float | None = None,
        healthy_stretch_s: float | None = None,
        join_timeout_s: float | None = None,
    ) -> None:
        self._loops = list(loops)
        self.stop_event = stop_event or threading.Event()
        self.base_backoff_s = (
            base_backoff_s if base_backoff_s is not None else _env_float("PSAT_MONITOR_SUPERVISOR_BASE_BACKOFF_S", 5.0)
        )
        self.max_backoff_s = (
            max_backoff_s if max_backoff_s is not None else _env_float("PSAT_MONITOR_SUPERVISOR_MAX_BACKOFF_S", 300.0)
        )
        self.healthy_stretch_s = (
            healthy_stretch_s
            if healthy_stretch_s is not None
            else _env_float("PSAT_MONITOR_SUPERVISOR_HEALTHY_S", 60.0)
        )
        self.join_timeout_s = (
            join_timeout_s if join_timeout_s is not None else _env_float("PSAT_MONITOR_JOIN_TIMEOUT_S", 10.0)
        )
        self._threads: list[threading.Thread] = []

    def _supervise(self, name: str, target: LoopTarget) -> None:
        backoff = self.base_backoff_s
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                target(self.stop_event)
            except BaseException as exc:
                ran_for = time.monotonic() - started
                logger.error(
                    "monitor daemon %s crashed after %.1fs: %s",
                    name,
                    ran_for,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                record_heartbeat(name, status="error", detail={"exc_type": type(exc).__name__})
            else:
                ran_for = time.monotonic() - started
                if self.stop_event.is_set():
                    return
                # Fell through without a stop request: restart, but not an error.
                logger.warning(
                    "monitor daemon %s returned unexpectedly after %.1fs; restarting",
                    name,
                    ran_for,
                )
            if self.stop_event.is_set():
                return
            if ran_for >= self.healthy_stretch_s:
                backoff = self.base_backoff_s
            if self.stop_event.wait(backoff):
                return
            backoff = min(backoff * 2, self.max_backoff_s)

    def start(self) -> None:
        for name, target in self._loops:
            thread = threading.Thread(
                target=self._supervise,
                args=(name, target),
                name=f"supervise-{name}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def request_stop(self) -> None:
        self.stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        deadline = time.monotonic() + (self.join_timeout_s if timeout is None else timeout)
        for thread in self._threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(remaining)

    def run_forever(self) -> None:
        self.start()
        # Poll so a signal to the main thread is observed promptly.
        while not self.stop_event.is_set():
            self.stop_event.wait(0.5)
        self.join()


def _build_default_supervisor(rpc_url: str, interval: float | None) -> Supervisor:
    """Restaking and role-holder planes are sibling loops so one plane's read failure stays out of another's failure
    domain.
    """
    from services.monitoring.restaking_cycle import DEFAULT_RESTAKING_INTERVAL, run_restaking_loop
    from services.monitoring.role_holder_cycle import DEFAULT_ROLE_PLANE_INTERVAL, run_role_holder_plane_loop
    from services.monitoring.tvl import DEFAULT_TVL_INTERVAL, run_tvl_loop
    from services.monitoring.unified_watcher import (
        DEFAULT_POLL_INTERVAL,
        DEFAULT_SCAN_INTERVAL,
        run_poll_loop,
        run_scan_loop,
    )
    from services.scoring.loop import DEFAULT_SCORE_INTERVAL, run_score_loop

    scan_interval = interval if interval is not None else DEFAULT_SCAN_INTERVAL
    poll_interval = interval if interval is not None else DEFAULT_POLL_INTERVAL
    tvl_interval = interval if interval is not None else DEFAULT_TVL_INTERVAL
    restaking_interval = interval if interval is not None else DEFAULT_RESTAKING_INTERVAL
    role_plane_interval = interval if interval is not None else DEFAULT_ROLE_PLANE_INTERVAL
    score_interval = interval if interval is not None else DEFAULT_SCORE_INTERVAL

    loops: list[tuple[str, LoopTarget]] = [
        (HEARTBEAT_PROTOCOL_SCANNER, lambda ev: run_scan_loop(rpc_url, scan_interval, stop_event=ev)),
        (HEARTBEAT_PROTOCOL_POLLER, lambda ev: run_poll_loop(rpc_url, poll_interval, stop_event=ev)),
        (HEARTBEAT_PROTOCOL_TVL, lambda ev: run_tvl_loop(tvl_interval, stop_event=ev)),
        (HEARTBEAT_PROTOCOL_RESTAKING, lambda ev: run_restaking_loop(restaking_interval, stop_event=ev)),
        (HEARTBEAT_ROLE_HOLDER_PLANE, lambda ev: run_role_holder_plane_loop(role_plane_interval, stop_event=ev)),
        # A plane read failing in the grade fold must degrade this heartbeat alone.
        (HEARTBEAT_PROTOCOL_SCORE, lambda ev: run_score_loop(score_interval, stop_event=ev)),
    ]
    return Supervisor(loops)


def _run_supervised_default(rpc_url: str, interval: float | None) -> None:
    supervisor = _build_default_supervisor(rpc_url, interval)

    def handle_signal(signum, _frame):
        # Every daemon logs this as ``__main__``; the name and pid say which one is still up.
        logger.info(
            "Received signal %s, shutting down",
            signum,
            extra={"daemon": "protocol_monitor_supervised", "pid": os.getpid(), "signal": int(signum)},
        )
        supervisor.request_stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info("Supervised protocol monitor starting (rpc=%s)", sanitize_url(rpc_url))
    supervisor.run_forever()


def main():
    configure_logging()

    parser = argparse.ArgumentParser(description="Unified protocol monitor worker")
    parser.add_argument(
        "--rpc-url",
        default=None,
        help="RPC URL seed (defaults to the mainnet eRPC route; per-chain routes are resolved from it)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Scan/poll interval in seconds (default depends on mode)",
    )
    parser.add_argument(
        "--poll",
        action="store_true",
        help="Run state-polling loop instead of event-based scanning",
    )
    parser.add_argument(
        "--tvl",
        action="store_true",
        help="Run TVL tracking loop (periodic balance snapshots)",
    )
    parser.add_argument(
        "--reconcile",
        action="store_true",
        help=(
            "Run the enrollment reconciler loop — periodically re-runs "
            "enroll_protocol_contracts for every protocol so monitored_contracts "
            "converges with Contract+Job state regardless of how that state changed "
            "(orphan-adoption migrations, deployer-cascade, manual fix-ups, etc.)."
        ),
    )
    args = parser.parse_args()
    if args.rpc_url is None:
        args.rpc_url = _default_rpc_seed()

    mode = "tvl" if args.tvl else "poll" if args.poll else "reconcile" if args.reconcile else "scan"

    def handle_signal(signum, frame):
        logger.info(
            "Received signal %s, shutting down",
            signum,
            extra={"daemon": f"protocol_monitor_{mode}", "pid": os.getpid(), "signal": int(signum)},
        )
        raise SystemExit(0)

    if args.tvl:
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        from services.monitoring.tvl import DEFAULT_TVL_INTERVAL, run_tvl_loop

        interval = args.interval if args.interval is not None else DEFAULT_TVL_INTERVAL
        logger.info("TVL tracker starting (interval=%ss)", interval)
        run_tvl_loop(interval)
        return

    if args.reconcile:
        stop_event = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())
        from services.monitoring.reconciler import (
            DEFAULT_RECONCILE_INTERVAL_S,
            RECONCILER_FALLBACK_CHAIN,
            run_enrollment_reconciler_loop,
        )

        interval = args.interval if args.interval is not None else DEFAULT_RECONCILE_INTERVAL_S
        logger.info(
            "Enrollment reconciler starting (interval=%ss, fallback chain=%s)",
            interval,
            RECONCILER_FALLBACK_CHAIN,
        )
        run_enrollment_reconciler_loop(
            args.rpc_url, RECONCILER_FALLBACK_CHAIN, interval=interval, stop_event=stop_event
        )
        return

    if args.poll:
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        from services.monitoring.unified_watcher import DEFAULT_POLL_INTERVAL, run_poll_loop

        interval = args.interval if args.interval is not None else DEFAULT_POLL_INTERVAL
        logger.info("Unified protocol poller starting (rpc=%s, interval=%ss)", sanitize_url(args.rpc_url), interval)
        # No co-scheduled scanner here, so nothing to de-phase from.
        run_poll_loop(args.rpc_url, interval, startup_offset_s=0.0)
        return

    _run_supervised_default(args.rpc_url, args.interval)


if __name__ == "__main__":
    main()
