"""Unified protocol monitor worker — long-running scanner process."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

from dotenv import load_dotenv

from utils.secrets import sanitize_url

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logger = logging.getLogger(__name__)

DEFAULT_RPC_URL = os.environ.get("ETH_RPC", "https://ethereum-rpc.publicnode.com")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Unified protocol monitor worker")
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL, help="Ethereum RPC URL")
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

    # Graceful shutdown
    def handle_signal(signum, frame):
        logger.info("Received signal %s, shutting down", signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if args.tvl:
        from services.monitoring.tvl import DEFAULT_TVL_INTERVAL, run_tvl_loop

        interval = args.interval if args.interval is not None else DEFAULT_TVL_INTERVAL
        logger.info("TVL tracker starting (interval=%ss)", interval)
        run_tvl_loop(interval)
        return

    if args.reconcile:
        from services.monitoring.reconciler import (
            DEFAULT_RECONCILE_INTERVAL_S,
            run_enrollment_reconciler_loop,
        )

        interval = args.interval if args.interval is not None else DEFAULT_RECONCILE_INTERVAL_S
        logger.info("Enrollment reconciler starting (interval=%ss)", interval)
        run_enrollment_reconciler_loop(args.rpc_url, interval=interval)
        return

    if args.legacy:
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
    else:
        from services.monitoring.unified_watcher import (
            DEFAULT_POLL_INTERVAL,
            DEFAULT_SCAN_INTERVAL,
            run_poll_loop,
            run_scan_loop,
        )

        rpc_for_log = sanitize_url(args.rpc_url)
        if args.poll:
            interval = args.interval if args.interval is not None else DEFAULT_POLL_INTERVAL
            logger.info("Unified protocol poller starting (rpc=%s, interval=%ss)", rpc_for_log, interval)
            run_poll_loop(args.rpc_url, interval)
        else:
            interval = args.interval if args.interval is not None else DEFAULT_SCAN_INTERVAL
            logger.info("Unified protocol monitor starting (rpc=%s, interval=%ss)", rpc_for_log, interval)
            run_scan_loop(args.rpc_url, interval)


if __name__ == "__main__":
    main()
