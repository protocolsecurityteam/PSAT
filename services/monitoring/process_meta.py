"""Per-process display metadata and the staleness rule.

Shared by ``/api/fleet`` and the ops watchdog, so a daemon shown green is never paged on.
"""

from __future__ import annotations

import os
from typing import Any

from db.queue import (
    HEARTBEAT_AUDIT_SCOPE,
    HEARTBEAT_AUDIT_TEXT,
    HEARTBEAT_COVERAGE_VERIFY,
    HEARTBEAT_ENROLLMENT_RECONCILER,
    HEARTBEAT_EVENT_INDEXER,
    HEARTBEAT_OPS_ALERTER,
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_RESTAKING,
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_SCORE,
    HEARTBEAT_PROTOCOL_TVL,
    HEARTBEAT_ROLE_HOLDER_PLANE,
)

# ``interval_s`` is the loop cadence; ``kind`` groups processes in the UI.
PROCESS_META: dict[str, dict[str, Any]] = {
    HEARTBEAT_COVERAGE_VERIFY: {"kind": "drainer", "interval_s": 30, "label": "Coverage / source-equivalence"},
    HEARTBEAT_AUDIT_TEXT: {"kind": "drainer", "interval_s": 30, "label": "Audit text extraction"},
    HEARTBEAT_AUDIT_SCOPE: {"kind": "drainer", "interval_s": 30, "label": "Audit scope extraction"},
    HEARTBEAT_EVENT_INDEXER: {"kind": "indexer", "interval_s": 90, "label": "Event-log indexer"},
    HEARTBEAT_ENROLLMENT_RECONCILER: {"kind": "daemon", "interval_s": 660, "label": "Enrollment reconciler"},
    HEARTBEAT_PROTOCOL_SCANNER: {
        "kind": "watcher",
        "interval_s": int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600")),
        "label": "Protocol event scanner",
    },
    HEARTBEAT_PROTOCOL_POLLER: {
        "kind": "watcher",
        "interval_s": int(os.getenv("PROTOCOL_POLL_INTERVAL", "600")),
        "label": "Protocol state poller",
    },
    HEARTBEAT_PROTOCOL_TVL: {"kind": "watcher", "interval_s": 3600, "label": "Protocol TVL refresh"},
    HEARTBEAT_PROTOCOL_RESTAKING: {"kind": "watcher", "interval_s": 3600, "label": "Restaking position refresh"},
    HEARTBEAT_ROLE_HOLDER_PLANE: {"kind": "watcher", "interval_s": 3600, "label": "Role-holder plane refresh"},
    HEARTBEAT_PROTOCOL_SCORE: {"kind": "watcher", "interval_s": 300, "label": "Protocol score fold"},
    HEARTBEAT_OPS_ALERTER: {"kind": "daemon", "interval_s": 120, "label": "Ops watchdog / alerter"},
}

if os.getenv("PSAT_WORKER_LIFECYCLE_MODE", "off") != "off":
    PROCESS_META["worker_lifecycle"] = {"kind": "daemon", "interval_s": 15, "label": "Worker lifecycle"}


def planned_sleep(process: str, controller: dict | None) -> bool:
    """Suppress only expected sleep, proved by a fresh, successful Fly read.

    A queued job, failed controller or missed wake immediately removes this
    exemption. Monitoring and the indexer are never exempted.
    """
    if (
        process
        not in {HEARTBEAT_AUDIT_TEXT, HEARTBEAT_AUDIT_SCOPE, HEARTBEAT_COVERAGE_VERIFY, HEARTBEAT_ENROLLMENT_RECONCILER}
        or not controller
    ):
        return False
    detail = controller.get("detail") or {}
    age = controller.get("beat_age_s")
    return bool(
        controller.get("status") == "running"
        and age is not None
        and age < 45
        and detail.get("mode") == "enforce"
        and detail.get("machine_state") in {"stopped", "suspended"}
        and detail.get("active") is False
        and detail.get("ready_sources") == []
    )


FRESH = "fresh"
STALE = "stale"
ERROR = "error"

_STALE_FLOOR_S = 120


def stale_after_seconds(interval_s: int) -> float:
    """``3 × interval``, floored at 120s: absorbs one slow pass, still surfaces a crash."""
    return float(max(3 * interval_s, _STALE_FLOOR_S))


def is_stale(beat_age_s: float | None, interval_s: int) -> bool:
    """A missing heartbeat is stale."""
    return beat_age_s is None or beat_age_s >= stale_after_seconds(interval_s)


def classify(status: str | None, beat_age_s: float | None, interval_s: int) -> str:
    """Staleness dominates the last written status; among live beats an ``error`` status maps to :data:`ERROR`."""
    if is_stale(beat_age_s, interval_s):
        return STALE
    if status == ERROR:
        return ERROR
    return FRESH
