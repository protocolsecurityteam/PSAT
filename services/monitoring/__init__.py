"""Monitoring daemons + shared per-cycle observability primitives.

The scan / poll / TVL loops run outside ``BaseWorker``, so the job-scoped
``record_degraded`` / ``record_stage_metric`` accumulators are no-ops here.
The substitute (house standard §2.4) is a per-cycle ``record_heartbeat`` whose
``detail`` carries the cycle counts, plus one unconditional INFO per cycle so a
wedged or silently-idle watcher is detectable even when nothing happened.

The ``HEARTBEAT_PROTOCOL_*`` process-name constants live here rather than in
``db.queue`` because the Wave-0 foundation did not land them; ``/api/fleet``
keys off the constants exported by ``db.queue`` and so will not surface these
daemons until they are promoted there (see patch blocker note).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from db.queue import record_heartbeat

logger = logging.getLogger(__name__)

# Canonical process names for the three unified-watcher cycle daemons.
HEARTBEAT_PROTOCOL_SCANNER = "protocol_scanner"
HEARTBEAT_PROTOCOL_POLLER = "protocol_poller"
HEARTBEAT_PROTOCOL_TVL = "protocol_tvl"


def emit_monitor_cycle(
    process: str,
    *,
    started: float,
    contracts_scanned: int,
    blocks_scanned: int,
    events_found: int,
    partial: bool,
    note: str | None = None,
) -> None:
    """Emit one per-cycle summary: a fleet heartbeat plus a single INFO.

    ``started`` is a ``time.monotonic()`` stamp from the top of the cycle.
    Counts go in ``extra``/``detail`` (queryable), never the message text.
    ``partial=True`` (an RPC chunk failed mid-scan, a sub-unit raised) flips
    the heartbeat to ``degraded`` so the fleet view distinguishes a healthy
    quiet cycle from a degraded one. Called once per cycle regardless of
    outcome — including the 0-active-contracts and 0-event branches.
    """
    duration_ms = int((time.monotonic() - started) * 1000)
    detail: dict[str, Any] = {
        "contracts_scanned": contracts_scanned,
        "blocks_scanned": blocks_scanned,
        "events_found": events_found,
        "partial": partial,
        "duration_ms": duration_ms,
    }
    if note:
        detail["note"] = note
    record_heartbeat(process, status="degraded" if partial else "running", detail=detail)
    # ``process`` is reserved on LogRecord (the OS pid) — expose the daemon
    # name as ``daemon`` so the JsonFormatter promotes it without collision.
    logger.info("monitor cycle complete", extra={"daemon": process, **detail})
