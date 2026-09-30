"""Enrollment-reconciler process edge; logic lives in ``services.monitoring.reconciler``.

Production runs the same loop via ``protocol_monitor.py --reconcile``.
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
        # Every daemon logs this as ``__main__``; the name and pid say which one went down.
        logger.info(
            "received signal %s, shutting down",
            signum,
            extra={"daemon": "enrollment_reconciler", "pid": os.getpid(), "signal": int(signum)},
        )
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # One process serves every chain; each protocol's own chain is still derived. Logged so the fallback isn't
    # a buried default.
    fallback_chain = RECONCILER_FALLBACK_CHAIN
    logger.info("enrollment reconciler daemon starting with fallback chain=%s", fallback_chain)
    rpc_url = require_rpc_url(chain=fallback_chain)
    run_enrollment_reconciler_loop(rpc_url, fallback_chain, stop_event=stop_event)


if __name__ == "__main__":
    main()
