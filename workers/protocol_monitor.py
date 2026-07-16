"""Unified protocol monitor worker — one supervised single-process daemon.

Default mode (no flags) runs the scanner, poller, and TVL loops as three
supervised daemon threads inside a single interpreter (design §2.5). The
Supervisor restarts any loop that dies with exponential backoff and never lets
one loop's death touch its siblings or the process; a crash-loop degrades and
pages (via the ``status="error"`` heartbeat + fly ``[[restart]] policy="always"``)
but never permanently stops. SIGTERM/SIGINT set a shared stop event and the
threads are joined within a bounded timeout.

The ``--poll`` / ``--tvl`` / ``--reconcile`` / ``--legacy`` flags remain as
rollback levers and as the workers-group reconciler entrypoint; each still runs
its single loop in the foreground.
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
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_TVL,
    record_heartbeat,
)
from utils.logging import configure_logging
from utils.rpc import default_rpc_url
from utils.secrets import sanitize_url

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logger = logging.getLogger(__name__)


def _default_rpc_seed() -> str:
    """The mainnet eRPC seed the monitor loops start from, resolved at call time.

    The scan / poll / enrollment / TVL loops resolve each contract's own chain
    RPC internally from this seed (``services.monitoring.chain_rpc``), so this is
    only the mainnet base + local-fork override. Resolved on demand rather than
    at import so ``ERPC_BASE_URL`` / test env changes are honored, not frozen at
    module load."""
    return default_rpc_url(chain_id=1) or ""


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# A loop target takes the shared stop event and blocks until it is set (or
# until it dies — the Supervisor restarts it either way).
LoopTarget = Callable[[threading.Event], None]


class Supervisor:
    """Runs each named loop in its own daemon thread and restarts it on death.

    Each loop body runs inside a wrapper that catches *any* escape, records an
    error heartbeat carrying the exception type, and restarts the loop after an
    exponential backoff (``base`` → ``max`` cap). A loop that survives a healthy
    stretch resets its own backoff. One loop crashing — even repeatedly — never
    interrupts its siblings and never propagates to the process.
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
        # A run lasting at least this long is "healthy" and resets the backoff,
        # so an occasional crash after a long healthy period doesn't inherit the
        # penalty accrued during an earlier crash-loop.
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
                # A clean return without a stop request means the loop fell
                # through unexpectedly — restart it, but it isn't an error.
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
        """Join all supervisor threads within a bounded overall budget."""
        deadline = time.monotonic() + (self.join_timeout_s if timeout is None else timeout)
        for thread in self._threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(remaining)

    def run_forever(self) -> None:
        """Start the loops and block the calling thread until stop is requested."""
        self.start()
        # Poll rather than a single blocking wait so a signal delivered to the
        # main thread is observed promptly on the next tick.
        while not self.stop_event.is_set():
            self.stop_event.wait(0.5)
        self.join()


def _build_default_supervisor(rpc_url: str, interval: float | None) -> Supervisor:
    """Build (but do not start) the three-thread default-mode Supervisor."""
    from services.monitoring.tvl import DEFAULT_TVL_INTERVAL, run_tvl_loop
    from services.monitoring.unified_watcher import (
        DEFAULT_POLL_INTERVAL,
        DEFAULT_SCAN_INTERVAL,
        run_poll_loop,
        run_scan_loop,
    )

    scan_interval = interval if interval is not None else DEFAULT_SCAN_INTERVAL
    poll_interval = interval if interval is not None else DEFAULT_POLL_INTERVAL
    tvl_interval = interval if interval is not None else DEFAULT_TVL_INTERVAL

    loops: list[tuple[str, LoopTarget]] = [
        (HEARTBEAT_PROTOCOL_SCANNER, lambda ev: run_scan_loop(rpc_url, scan_interval, stop_event=ev)),
        (HEARTBEAT_PROTOCOL_POLLER, lambda ev: run_poll_loop(rpc_url, poll_interval, stop_event=ev)),
        (HEARTBEAT_PROTOCOL_TVL, lambda ev: run_tvl_loop(tvl_interval, stop_event=ev)),
    ]
    return Supervisor(loops)


def _run_supervised_default(rpc_url: str, interval: float | None) -> None:
    supervisor = _build_default_supervisor(rpc_url, interval)

    def handle_signal(signum, _frame):
        logger.info("Received signal %s, shutting down", signum)
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
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Run the legacy proxy-only scanner (backward compat fallback)",
    )
    args = parser.parse_args()
    if args.rpc_url is None:
        args.rpc_url = _default_rpc_seed()

    # The flag modes run a single loop in the foreground and exit cleanly on a
    # signal. The default (no-flag) mode installs its own signal handlers around
    # the Supervisor, so it is handled separately below.
    def handle_signal(signum, frame):
        logger.info("Received signal %s, shutting down", signum)
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
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        from services.monitoring.reconciler import (
            DEFAULT_RECONCILE_INTERVAL_S,
            RECONCILER_FALLBACK_CHAIN,
            run_enrollment_reconciler_loop,
        )

        interval = args.interval if args.interval is not None else DEFAULT_RECONCILE_INTERVAL_S
        # Explicit daemon-edge fallback chain (inv. 6); each protocol's real chain
        # is still derived per-protocol inside the loop.
        logger.info(
            "Enrollment reconciler starting (interval=%ss, fallback chain=%s)",
            interval,
            RECONCILER_FALLBACK_CHAIN,
        )
        run_enrollment_reconciler_loop(args.rpc_url, RECONCILER_FALLBACK_CHAIN, interval=interval)
        return

    if args.legacy:
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        # Fall back to the old proxy-only scanner
        from services.monitoring.proxy_watcher import (
            DEFAULT_POLL_INTERVAL,
            DEFAULT_SCAN_INTERVAL,
            run_poll_loop,
            run_scan_loop,
        )

        rpc_for_log = sanitize_url(args.rpc_url)
        if args.poll:
            interval = args.interval if args.interval is not None else DEFAULT_POLL_INTERVAL
            logger.info("Legacy proxy poll monitor starting (rpc=%s, interval=%ss)", rpc_for_log, interval)
            run_poll_loop(args.rpc_url, interval)
        else:
            interval = args.interval if args.interval is not None else DEFAULT_SCAN_INTERVAL
            logger.info("Legacy proxy monitor starting (rpc=%s, interval=%ss)", rpc_for_log, interval)
            run_scan_loop(args.rpc_url, interval)
        return

    if args.poll:
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        from services.monitoring.unified_watcher import DEFAULT_POLL_INTERVAL, run_poll_loop

        interval = args.interval if args.interval is not None else DEFAULT_POLL_INTERVAL
        logger.info("Unified protocol poller starting (rpc=%s, interval=%ss)", sanitize_url(args.rpc_url), interval)
        # No co-scheduled scanner in this process, so nothing to de-phase from.
        run_poll_loop(args.rpc_url, interval, startup_offset_s=0.0)
        return

    # Default mode: scanner + poller + TVL as supervised daemon threads.
    _run_supervised_default(args.rpc_url, args.interval)


if __name__ == "__main__":
    main()
