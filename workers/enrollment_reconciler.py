"""Enrollment-reconciler daemon shell — ``python -m workers.enrollment_reconciler``.

The reconcile logic (queue claim/drain, sweep, loop) lives in
``services.monitoring.reconciler``; this module only owns the process edge:
signal handling and the CLI entry. Production runs the same loop via
``workers/protocol_monitor.py --reconcile`` (deploy/start_workers.sh).
"""

from __future__ import annotations

import logging
import os
import signal
from threading import Event

from services.clients.rpc import require_rpc_url
from services.monitoring.reconciler import (
    RECONCILER_FALLBACK_CHAIN,
    run_enrollment_reconciler_loop,
)
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    stop_event = Event()

    def handle_signal(signum, _frame):
        # Named and pid-stamped: this line is emitted by every daemon in the
        # stack under the ``__main__`` logger, and identical copies of it say
        # nothing about which process actually went down.
        logger.info(
            "received signal %s, shutting down",
            signum,
            extra={"daemon": "enrollment_reconciler", "pid": os.getpid(), "signal": int(signum)},
        )
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Daemon edge (inv. 6): the reconciler is one process serving every chain;
    # ``RECONCILER_FALLBACK_CHAIN`` is the explicit, documented base + ambiguous-
    # protocol fallback (``_protocol_chain`` still derives each protocol's own
    # chain, and ``rpc_for_chain`` picks the per-chain URL). Logged so the choice
    # is visible, not a buried default.
    fallback_chain = RECONCILER_FALLBACK_CHAIN
    logger.info("enrollment reconciler daemon starting with fallback chain=%s", fallback_chain)
    rpc_url = require_rpc_url(chain=fallback_chain)
    run_enrollment_reconciler_loop(rpc_url, fallback_chain, stop_event=stop_event)


if __name__ == "__main__":
    main()
