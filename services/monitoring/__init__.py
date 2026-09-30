"""Monitoring daemons and shared per-cycle observability.

These loops run outside ``BaseWorker``, so observability is one heartbeat plus one INFO per cycle, even when nothing
happened.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from db.queue import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_RESTAKING,
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_SCORE,
    HEARTBEAT_PROTOCOL_TVL,
    HEARTBEAT_ROLE_HOLDER_PLANE,
    record_heartbeat,
)

logger = logging.getLogger(__name__)

__all__ = [
    "HEARTBEAT_PROTOCOL_POLLER",
    "HEARTBEAT_PROTOCOL_RESTAKING",
    "HEARTBEAT_PROTOCOL_SCANNER",
    "HEARTBEAT_PROTOCOL_SCORE",
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
    """Emit the cycle's heartbeat plus one INFO; call exactly once per cycle, including idle cycles.

    ``partial=True`` means some unit went unobserved (failed or unanswered call, unparseable answer) and marks the
    heartbeat ``degraded``. An observed empty value is not partial.
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
