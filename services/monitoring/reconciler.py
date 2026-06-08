"""Periodic enrollment reconciler — convergence backstop for monitored_contracts.

Background
----------
``MonitoredContract`` is derived state computed from ``Contract`` +
``Job`` + analysis output (``ControlGraphNode`` / ``FunctionPrincipal`` /
``ContractSummary`` / ``ControllerValue``). The historical write path
fires once per completed job from ``PolicyWorker.process()`` via
``maybe_enroll_protocol``. That edge-triggered pattern lets monitoring
drift from ground truth in two ways:

1. The in-flight gate in ``maybe_enroll_protocol`` skips when any
   sibling job for the protocol is ``queued``/``processing``. When the
   sibling fails terminally and no later trigger fires, the missed
   enrollment is never retried.

2. ``Contract.protocol_id`` is set from several write sites that don't
   re-trigger enrollment: the deployer-cascade in
   ``workers/discovery.py:538-545``, the orphan-adoption migrations
   ``3a8f4d1c9b07`` + ``4d72e9b1f035``, admin DB fix-ups, ``routers/
   audits.py:282``. A contract adopted by one of these paths after
   PolicyWorker already ran for its job has no MonitoredContract row
   until someone hits ``POST /api/protocols/{id}/re-enroll`` by hand.

The general fix is to stop relying on a single trigger moment and
converge enrollment on a cadence. ``enroll_protocol_contracts`` is
already idempotent (upsert by ``(address, chain)``, stale-row
deactivation by enrollment_source). The reconciler walks every
``Protocol`` row and calls it.

``maybe_enroll_protocol`` stays as a low-latency hint so fresh analyses
land in ``monitored_contracts`` within milliseconds in the common case.
This reconciler bounds staleness to ``interval`` for everything else.

Concurrency
-----------
The reconciler and a concurrent ``PolicyWorker``-triggered enrollment
for the same protocol both upsert ``(address, chain)`` so the second
writer's UPDATE is a no-op. ``_enroll_controller_addresses`` runs its
Pass 1 / Pass 2 (promote / demote) inside one ``enroll_protocol_
contracts`` call, so a single pass converges; a brief inter-pass
window during overlapping calls self-corrects on the next tick.
"""

from __future__ import annotations

import logging
import os
import signal
from threading import Event

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Protocol, SessionLocal
from db.queue import HEARTBEAT_ENROLLMENT_RECONCILER, record_heartbeat
from services.monitoring.enrollment import enroll_protocol_contracts

logger = logging.getLogger(__name__)


# Default convergence interval. Configurable via env so an operator can
# trade staleness for query load without a redeploy. 600s matches the
# unified watcher's scan cadence — same order of magnitude as
# "MonitoredContract may be stale for up to ten minutes."
DEFAULT_RECONCILE_INTERVAL_S = int(os.getenv("PSAT_ENROLLMENT_RECONCILE_INTERVAL", "600"))


def reconcile_enrollments(
    session: Session,
    rpc_url: str,
    chain: str = "ethereum",
) -> int:
    """One reconciliation pass — re-enroll every protocol.

    Walks every ``Protocol`` row and calls
    ``enroll_protocol_contracts``. Returns the count of protocols
    successfully reconciled. A per-protocol exception is logged and
    swallowed so one broken protocol does not abort the sweep.

    The function is the inner unit of work used by
    ``run_enrollment_reconciler_loop``. It is exposed separately so
    tests and the boot-pass at watcher startup can drive a single
    pass without spinning up a loop.
    """
    protocol_ids = list(session.execute(select(Protocol.id)).scalars())
    if not protocol_ids:
        return 0

    reconciled = 0
    for pid in protocol_ids:
        try:
            enroll_protocol_contracts(session, pid, rpc_url, chain)
            reconciled += 1
        except Exception:
            logger.exception("reconciler enrollment failed for protocol %s", pid)
            # ``enroll_protocol_contracts`` commits internally; a
            # partial write may have landed before the exception.
            # Rollback so the next protocol's queries don't see the
            # failed transaction's autobegun state.
            session.rollback()

    if reconciled:
        logger.info(
            "reconciler pass reconciled %d/%d protocols",
            reconciled,
            len(protocol_ids),
        )
    return reconciled


def run_enrollment_reconciler_loop(
    rpc_url: str,
    interval: float = DEFAULT_RECONCILE_INTERVAL_S,
    stop_event: Event | None = None,
    chain: str = "ethereum",
) -> None:
    """Long-running reconciler. Opens a fresh session per pass.

    Designed to be hosted by ``workers/protocol_monitor.py --reconcile``.
    Each pass uses its own ``SessionLocal()`` so a connection blip on
    one tick does not poison the next.
    """
    stop_event = stop_event or Event()
    logger.info("starting enrollment reconciler interval=%ss", interval)
    while not stop_event.is_set():
        reconciled = 0
        status = "running"
        try:
            with SessionLocal() as session:
                reconciled = reconcile_enrollments(session, rpc_url, chain)
        except Exception:
            logger.exception("reconciler outer loop failed")
            status = "error"
        record_heartbeat(
            HEARTBEAT_ENROLLMENT_RECONCILER,
            status=status,
            detail={"protocols_reconciled_last_pass": reconciled},
        )
        stop_event.wait(interval)


def main() -> None:
    """CLI entry point — used by ``workers/protocol_monitor.py --reconcile``."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    stop_event = Event()

    def handle_signal(signum, _frame):
        logger.info("received signal %s, shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    from utils.rpc import require_rpc_url

    rpc_url = require_rpc_url(chain="ethereum")
    run_enrollment_reconciler_loop(rpc_url, stop_event=stop_event)


if __name__ == "__main__":
    main()
