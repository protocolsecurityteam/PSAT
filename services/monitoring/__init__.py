"""Monitoring daemons + shared per-cycle observability primitives.

The scan / poll / TVL loops run outside ``BaseWorker``, so the job-scoped
``record_degraded`` / ``record_stage_metric`` accumulators are no-ops here.
The substitute (house standard §2.4) is a per-cycle ``record_heartbeat`` whose
``detail`` carries the cycle counts, plus one unconditional INFO per cycle so a
wedged or silently-idle watcher is detectable even when nothing happened.

The ``HEARTBEAT_PROTOCOL_*`` process-name constants are defined in ``db.queue``
alongside the other daemon heartbeat names — ``/api/fleet`` keys off the
constants that module exports, so co-locating them there is what lets it
surface the scan/poll/TVL daemons. They are re-exported here for the
watcher/TVL call sites that import them from this package.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from db.queue import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_RESTAKING,
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_TVL,
    HEARTBEAT_ROLE_HOLDER_PLANE,
    record_heartbeat,
)

logger = logging.getLogger(__name__)

__all__ = [
    "HEARTBEAT_PROTOCOL_POLLER",
    "HEARTBEAT_PROTOCOL_RESTAKING",
    "HEARTBEAT_PROTOCOL_SCANNER",
    "HEARTBEAT_PROTOCOL_TVL",
    "HEARTBEAT_ROLE_HOLDER_PLANE",
    "emit_monitor_cycle",
]


def emit_monitor_cycle(
    process: str,
    *,
    started: float,
    contracts_scanned: int,
    blocks_scanned: int,
    events_found: int,
    partial: bool,
    note: str | None = None,
    extra_detail: dict[str, Any] | None = None,
) -> None:
    """Emit one per-cycle summary: a fleet heartbeat plus a single INFO.

    ``started`` is a ``time.monotonic()`` stamp from the top of the cycle.
    Counts go in ``extra``/``detail`` (queryable), never the message text.
    ``partial=True`` means some unit of the cycle failed to be observed —
    an RPC chunk failed or went unanswered, a sub-unit raised, a per-call
    error came back, or an answered call yielded nothing parseable (the
    emitting loop's docstring defines its exact grounds; an observed value,
    including a type's conventional empty like the zero address, is never
    one of them). It flips the heartbeat to ``degraded`` so the fleet view
    distinguishes a healthy quiet cycle from a degraded one. Called once
    per cycle regardless of outcome — including the 0-active-contracts and
    0-event branches.
    ``extra_detail`` carries daemon-specific fields (the scanner's
    ``max_lag_blocks`` / ``windows_scanned`` / ``budget_exhausted``, the
    poller's rotation-slice counts) so a pass still emits exactly one
    heartbeat.
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
    if extra_detail:
        detail.update(extra_detail)
    record_heartbeat(process, status="degraded" if partial else "running", detail=detail)
    # ``process`` is reserved on LogRecord (the OS pid) — expose the daemon
    # name as ``daemon`` so the JsonFormatter promotes it without collision.
    logger.info("monitor cycle complete", extra={"daemon": process, **detail})
