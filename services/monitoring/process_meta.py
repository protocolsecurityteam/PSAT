"""Shared per-process display metadata + one staleness rule.

Both the ``/api/fleet`` reader (``services.aggregations.fleet``) and the ops
watchdog (``services.monitoring.ops_alerts``) need to answer the same question —
"is this daemon fresh, stale, or errored?" — off the same ``worker_heartbeats``
rows. Keeping ``PROCESS_META`` and the staleness formula in one module (imported
by both) is what stops the fleet view and the alerter from drifting: a daemon the
operator sees as green in ``/api/fleet`` is exactly one the watchdog won't page on.

Kept import-light on purpose (only the ``db.queue`` name constants) so both a
FastAPI router and a low-level aggregation can import it without a cycle.
"""

from __future__ import annotations

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

# Per-process display metadata + staleness window. ``interval_s`` is the loop
# cadence; a process is flagged stale when its last beat is older than
# ``3 × interval`` (with a 120s floor) — long enough to absorb one slow pass,
# short enough to surface a crash. ``kind`` groups processes for the UI.
PROCESS_META: dict[str, dict[str, Any]] = {
    HEARTBEAT_COVERAGE_VERIFY: {"kind": "drainer", "interval_s": 30, "label": "Coverage / source-equivalence"},
    HEARTBEAT_AUDIT_TEXT: {"kind": "drainer", "interval_s": 30, "label": "Audit text extraction"},
    HEARTBEAT_AUDIT_SCOPE: {"kind": "drainer", "interval_s": 30, "label": "Audit scope extraction"},
    HEARTBEAT_EVENT_INDEXER: {"kind": "indexer", "interval_s": 90, "label": "Event-log indexer"},
    HEARTBEAT_ENROLLMENT_RECONCILER: {"kind": "daemon", "interval_s": 660, "label": "Enrollment reconciler"},
    HEARTBEAT_PROTOCOL_SCANNER: {"kind": "watcher", "interval_s": 600, "label": "Protocol event scanner"},
    HEARTBEAT_PROTOCOL_POLLER: {"kind": "watcher", "interval_s": 600, "label": "Protocol state poller"},
    HEARTBEAT_PROTOCOL_TVL: {"kind": "watcher", "interval_s": 3600, "label": "Protocol TVL refresh"},
    HEARTBEAT_PROTOCOL_RESTAKING: {"kind": "watcher", "interval_s": 3600, "label": "Restaking position refresh"},
    HEARTBEAT_ROLE_HOLDER_PLANE: {"kind": "watcher", "interval_s": 3600, "label": "Role-holder plane refresh"},
    HEARTBEAT_PROTOCOL_SCORE: {"kind": "watcher", "interval_s": 300, "label": "Protocol score fold"},
    HEARTBEAT_OPS_ALERTER: {"kind": "daemon", "interval_s": 120, "label": "Ops watchdog / alerter"},
}

# Classification labels shared by the fleet view and the watchdog.
FRESH = "fresh"
STALE = "stale"
ERROR = "error"

_STALE_FLOOR_S = 120


def stale_after_seconds(interval_s: int) -> float:
    """The age past which a heartbeat is stale: ``3 × interval``, floored at 120s.

    The single source of the staleness window — imported by both the fleet
    aggregation and the ops watchdog so the two can never disagree.
    """
    return float(max(3 * interval_s, _STALE_FLOOR_S))


def is_stale(beat_age_s: float | None, interval_s: int) -> bool:
    """A missing heartbeat (``beat_age_s is None``) or one older than the
    staleness window counts as stale."""
    return beat_age_s is None or beat_age_s >= stale_after_seconds(interval_s)


def classify(status: str | None, beat_age_s: float | None, interval_s: int) -> str:
    """Bucket a heartbeat into :data:`FRESH` / :data:`STALE` / :data:`ERROR`.

    Staleness dominates: a process whose heartbeat has gone silent is stale
    regardless of the last status it wrote. Among live beats, an explicit
    ``error`` status (the supervisor stamps it when a loop escapes) is
    surfaced as :data:`ERROR`; everything else is :data:`FRESH`.
    """
    if is_stale(beat_age_s, interval_s):
        return STALE
    if status == ERROR:
        return ERROR
    return FRESH
