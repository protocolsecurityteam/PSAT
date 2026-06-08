"""Unified protocol monitor worker — long-running scanner process."""

from __future__ import annotations

import argparse
import logging
import signal
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from utils.rpc import default_rpc_url, require_supported_chain_id, supported_chain_ids
from utils.secrets import sanitize_url

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logger = logging.getLogger(__name__)
_CHILDREN: list[subprocess.Popen] = []


def _terminate_children() -> None:
    for child in _CHILDREN:
        if child.poll() is None:
            child.terminate()
    deadline = time.monotonic() + 15
    for child in _CHILDREN:
        remaining = max(0.0, deadline - time.monotonic())
        if child.poll() is None:
            try:
                child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                child.kill()
    for child in _CHILDREN:
        if child.poll() is None:
            child.wait()


def _child_argv_for_chain(args: argparse.Namespace, *, chain_id: int) -> list[str]:
    argv = [sys.executable, "-m", "workers.protocol_monitor", "--chain-id", str(chain_id)]
    if args.interval is not None:
        argv.extend(["--interval", str(args.interval)])
    if args.poll:
        argv.append("--poll")
    if args.reconcile:
        argv.append("--reconcile")
    if args.legacy:
        argv.append("--legacy")
    return argv


def _run_all_supported_chains(args: argparse.Namespace, chain_ids: list[int]) -> None:
    logger.info("Starting %d chain-scoped monitor subprocess(es): %s", len(chain_ids), chain_ids)
    try:
        for chain_id in chain_ids:
            argv = _child_argv_for_chain(args, chain_id=chain_id)
            child = subprocess.Popen(argv)
            _CHILDREN.append(child)
            logger.info("Started chain-scoped monitor child pid=%s chain_id=%s", child.pid, chain_id)

        while True:
            for chain_id, child in zip(chain_ids, _CHILDREN, strict=True):
                exit_code = child.poll()
                if exit_code is None:
                    continue
                logger.error(
                    "Chain-scoped monitor child exited chain_id=%s pid=%s exit_code=%s",
                    chain_id,
                    child.pid,
                    exit_code,
                )
                _terminate_children()
                raise RuntimeError(
                    f"chain-scoped monitor child exited for chain_id={chain_id} exit_code={exit_code}"
                )
            time.sleep(1.0)
    except BaseException:
        _terminate_children()
        raise


def _run_monitor_mode(args: argparse.Namespace, *, chain_id: int) -> None:
    rpc_url = default_rpc_url(chain_id=chain_id)

    if args.reconcile:
        from services.monitoring.reconciler import (
            DEFAULT_RECONCILE_INTERVAL_S,
            run_enrollment_reconciler_loop,
        )

        interval = args.interval if args.interval is not None else DEFAULT_RECONCILE_INTERVAL_S
        logger.info("Enrollment reconciler starting (chain_id=%s, interval=%ss)", chain_id, interval)
        run_enrollment_reconciler_loop(rpc_url, chain_id=chain_id, interval=interval)
        return

    if args.legacy:
        from services.monitoring.proxy_watcher import (
            DEFAULT_POLL_INTERVAL,
            DEFAULT_SCAN_INTERVAL,
            run_poll_loop,
            run_scan_loop,
        )

        rpc_for_log = sanitize_url(rpc_url)
        if args.poll:
            interval = args.interval if args.interval is not None else DEFAULT_POLL_INTERVAL
            logger.info(
                "Legacy proxy poll monitor starting (chain_id=%s, rpc=%s, interval=%ss)",
                chain_id,
                rpc_for_log,
                interval,
            )
            run_poll_loop(rpc_url, interval, chain_id=chain_id)
            return
        interval = args.interval if args.interval is not None else DEFAULT_SCAN_INTERVAL
        logger.info(
            "Legacy proxy monitor starting (chain_id=%s, rpc=%s, interval=%ss)",
            chain_id,
            rpc_for_log,
            interval,
        )
        run_scan_loop(rpc_url, interval, chain_id=chain_id)
        return

    from services.monitoring.unified_watcher import (
        DEFAULT_POLL_INTERVAL,
        DEFAULT_SCAN_INTERVAL,
        run_poll_loop,
        run_scan_loop,
    )

    rpc_for_log = sanitize_url(rpc_url)
    if args.poll:
        interval = args.interval if args.interval is not None else DEFAULT_POLL_INTERVAL
        logger.info(
            "Unified protocol poller starting (chain_id=%s, rpc=%s, interval=%ss)",
            chain_id,
            rpc_for_log,
            interval,
        )
        run_poll_loop(rpc_url, interval, chain_id=chain_id)
        return
    interval = args.interval if args.interval is not None else DEFAULT_SCAN_INTERVAL
    logger.info(
        "Unified protocol monitor starting (chain_id=%s, rpc=%s, interval=%ss)",
        chain_id,
        rpc_for_log,
        interval,
    )
    run_scan_loop(rpc_url, interval, chain_id=chain_id)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Unified protocol monitor worker")
    parser.add_argument("--chain-id", type=int, default=None, help="EIP-155 chain id to monitor")
    parser.add_argument(
        "--all-supported-chains",
        action="store_true",
        help="Run one chain-scoped monitor loop for every supported eRPC chain id.",
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
        help="Run the legacy proxy-only scanner compatibility mode",
    )
    args = parser.parse_args()

    # Graceful shutdown
    def handle_signal(signum, frame):
        logger.info("Received signal %s, shutting down", signum)
        _terminate_children()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if args.tvl:
        if args.chain_id is not None or args.all_supported_chains:
            parser.error("--tvl is protocol-wide and does not accept chain routing options")
        from services.monitoring.tvl import DEFAULT_TVL_INTERVAL, run_tvl_loop

        interval = args.interval if args.interval is not None else DEFAULT_TVL_INTERVAL
        logger.info("TVL tracker starting (interval=%ss)", interval)
        run_tvl_loop(interval)
        return

    try:
        if args.all_supported_chains:
            if args.chain_id is not None:
                parser.error("--chain-id cannot be combined with --all-supported-chains")
            chain_ids = sorted(supported_chain_ids())
            if not chain_ids:
                parser.error("protocol monitor requires at least one supported chain id")
        else:
            chain_ids = [require_supported_chain_id(chain_id=args.chain_id, context="protocol monitor")]
    except RuntimeError as exc:
        parser.error(str(exc))

    if len(chain_ids) == 1:
        try:
            _run_monitor_mode(args, chain_id=chain_ids[0])
        except RuntimeError as exc:
            parser.error(str(exc))
        return

    _run_all_supported_chains(args, chain_ids)


if __name__ == "__main__":
    main()
