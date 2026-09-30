"""The role-holder plane's periodic step: select, fold, read, persist.

Role floors change as grants and revokes land, so the plane runs on a clock in its own loop (a failed ``hasRole`` probe
degrades only this heartbeat). The resolution stage keeps its opportunistic call site.

Registries are re-selected only when a recorded observation changed (new AccessControl log, cursors going warm, floors
aging out), so "ran, found nothing" is durable. ``resolve_role_holder_planes`` owns all read and refusal semantics; this
module only chooses whom to call and records that it did.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Event

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    ROLE_REFRESH_OUTCOME_NO_ROWS,
    ROLE_REFRESH_OUTCOME_ROWS_WRITTEN,
    IndexedEventCursor,
    IndexedEventLog,
    RoleHolderPlaneRefresh,
    SessionLocal,
)
from db.queue import HEARTBEAT_ROLE_HOLDER_PLANE, record_heartbeat
from services.clients.rpc import rpc_url_for_chain_id
from services.monitoring import emit_monitor_cycle
from services.resolution.role_holder_plane import (
    ACCESS_CONTROL_TOPIC0S,
    ProbeBlock,
    persist_role_holder_planes,
    pin_probe_block,
    resolve_role_holder_planes,
)
from utils.chains import supported_chain_ids

logger = logging.getLogger(__name__)

# Emitted every pass so all three shapes are visible; only the third used to be recorded.
OUTCOME_GATE_CLOSED = "gate_closed"
OUTCOME_NO_ROWS = ROLE_REFRESH_OUTCOME_NO_ROWS
OUTCOME_ROWS_WRITTEN = ROLE_REFRESH_OUTCOME_ROWS_WRITTEN
# Only reachable from the resolution stage (a job with no runtime address).
OUTCOME_NO_REGISTRY = "no_registry_address"

# Diagnostic only; never stored or published.
DUE_NEVER_REFRESHED = "never_refreshed"
DUE_NEW_ROLE_LOGS = "new_role_logs"
DUE_CURSORS_WARMED = "cursors_warmed"
DUE_MAX_AGE = "max_age"

DEFAULT_ROLE_PLANE_INTERVAL = int(os.getenv("PSAT_ROLE_PLANE_INTERVAL", "3600"))
# Also keeps the pass's single pinned height close to its reads.
DEFAULT_REGISTRIES_PER_PASS = int(os.getenv("PSAT_ROLE_PLANE_REGISTRIES_PER_PASS", "25"))
# Budgeted from indexed AccessControl log counts, an upper bound on proposed (role, account) pairs.
DEFAULT_READ_BUDGET = int(os.getenv("PSAT_ROLE_PLANE_READ_BUDGET", "500"))
# Floors cite a block, so they age even without events.
DEFAULT_MAX_AGE_S = int(os.getenv("PSAT_ROLE_PLANE_MAX_AGE_S", "86400"))

_NO_BLOCK = -1


def access_control_gate_open(session: Session, *, chain_id: int, registry_address: str) -> bool:
    """True iff both AccessControl cursors exist.

    Existence, not warmth: a cold cursor still mints a row with a withheld floor.
    """
    enrolled = {
        str(topic).lower()
        for topic in session.execute(
            select(IndexedEventCursor.topic0)
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(func.lower(IndexedEventCursor.event_address) == registry_address.lower())
            .where(IndexedEventCursor.topic0.in_(ACCESS_CONTROL_TOPIC0S))
        ).scalars()
    }
    return set(ACCESS_CONTROL_TOPIC0S).issubset(enrolled)


@dataclass(frozen=True)
class RegistryCandidate:
    registry_address: str
    gate_open: bool
    cursors_warm: bool
    max_log_block: int | None
    log_rows: int
    due_reason: str | None


@dataclass
class PassCounters:
    registries_considered: int = 0
    gate_closed: int = 0
    due: int = 0
    refreshed: int = 0
    no_rows: int = 0
    rows_written: int = 0
    rows: int = 0
    failures: int = 0
    budget_exhausted: bool = False
    notes: list[str] = field(default_factory=list)


def _block_or_floor(value: int | None) -> int:
    return _NO_BLOCK if value is None else int(value)


def _due_reason(
    mark: RoleHolderPlaneRefresh | None,
    *,
    cursors_warm: bool,
    max_log_block: int | None,
    now: datetime,
    max_age_s: int,
) -> str | None:
    """Why this registry is due, or ``None``. Each arm is a change in something the last pass recorded."""
    if mark is None:
        return DUE_NEVER_REFRESHED
    if cursors_warm and not mark.cursors_warm:
        return DUE_CURSORS_WARMED
    if _block_or_floor(max_log_block) > _block_or_floor(mark.trigger_log_block):
        return DUE_NEW_ROLE_LOGS
    refreshed_at = mark.refreshed_at
    if refreshed_at is not None:
        if refreshed_at.tzinfo is None:
            refreshed_at = refreshed_at.replace(tzinfo=timezone.utc)
        if now - refreshed_at >= timedelta(seconds=max_age_s):
            return DUE_MAX_AGE
    return None


def collect_candidates(
    session: Session,
    *,
    chain_id: int,
    now: datetime | None = None,
    max_age_s: int = DEFAULT_MAX_AGE_S,
) -> list[RegistryCandidate]:
    """Every address with an AccessControl cursor on this chain.

    Addresses with only one of the pair are kept as gate-closed so half-enrolled registries stay visible.
    """
    now = now or datetime.now(timezone.utc)
    cursor_rows = session.execute(
        select(
            IndexedEventCursor.event_address,
            func.count(func.distinct(IndexedEventCursor.topic0)).label("topics"),
            func.bool_and(IndexedEventCursor.backfill_complete).label("warm"),
        )
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(IndexedEventCursor.topic0.in_(ACCESS_CONTROL_TOPIC0S))
        .group_by(IndexedEventCursor.event_address)
        .order_by(IndexedEventCursor.event_address)
    ).all()
    if not cursor_rows:
        return []
    addresses = [str(row.event_address).lower() for row in cursor_rows]

    log_stats: dict[str, tuple[int | None, int]] = {}
    for address, max_block, count in session.execute(
        select(
            IndexedEventLog.event_address,
            func.max(IndexedEventLog.block_number),
            func.count(),
        )
        .where(IndexedEventLog.chain_id == chain_id)
        .where(IndexedEventLog.event_address.in_(addresses))
        .where(IndexedEventLog.topic0.in_(ACCESS_CONTROL_TOPIC0S))
        .group_by(IndexedEventLog.event_address)
    ):
        log_stats[str(address).lower()] = (max_block, int(count or 0))

    marks = {
        str(mark.registry_address).lower(): mark
        for mark in session.execute(
            select(RoleHolderPlaneRefresh).where(RoleHolderPlaneRefresh.chain_id == chain_id)
        ).scalars()
    }

    candidates: list[RegistryCandidate] = []
    for row, address in zip(cursor_rows, addresses):
        # The query is filtered to the pair, so a distinct count of two is the gate.
        gate_open = int(row.topics or 0) == len(ACCESS_CONTROL_TOPIC0S)
        cursors_warm = gate_open and bool(row.warm)
        max_log_block, log_rows = log_stats.get(address, (None, 0))
        due = (
            _due_reason(
                marks.get(address),
                cursors_warm=cursors_warm,
                max_log_block=max_log_block,
                now=now,
                max_age_s=max_age_s,
            )
            if gate_open
            else None
        )
        candidates.append(
            RegistryCandidate(
                registry_address=address,
                gate_open=gate_open,
                cursors_warm=cursors_warm,
                max_log_block=max_log_block if max_log_block is None else int(max_log_block),
                log_rows=log_rows,
                due_reason=due,
            )
        )
    return candidates


def select_due(
    candidates: list[RegistryCandidate],
    *,
    limit: int = DEFAULT_REGISTRIES_PER_PASS,
    read_budget: int = DEFAULT_READ_BUDGET,
) -> tuple[list[RegistryCandidate], bool]:
    """The bounded slice of due registries, and whether more remain.

    Stops at the first registry that won't fit rather than skipping it, so an oversized registry runs first in a later
    pass instead of never.
    """
    selected: list[RegistryCandidate] = []
    reads = 0
    for candidate in candidates:
        if candidate.due_reason is None:
            continue
        if len(selected) >= limit:
            return selected, True
        if selected and reads + candidate.log_rows > read_budget:
            return selected, True
        selected.append(candidate)
        reads += candidate.log_rows
    return selected, False


def _record_watermark(
    session: Session,
    *,
    chain_id: int,
    candidate: RegistryCandidate,
    rows_written: int,
) -> None:
    mark = session.get(RoleHolderPlaneRefresh, (chain_id, candidate.registry_address))
    outcome = ROLE_REFRESH_OUTCOME_ROWS_WRITTEN if rows_written else ROLE_REFRESH_OUTCOME_NO_ROWS
    values = {
        "refreshed_at": datetime.now(timezone.utc),
        "trigger_log_block": candidate.max_log_block,
        "cursors_warm": candidate.cursors_warm,
        "rows_written": rows_written,
        "outcome": outcome,
    }
    if mark is None:
        session.add(
            RoleHolderPlaneRefresh(
                chain_id=chain_id,
                registry_address=candidate.registry_address,
                **values,
            )
        )
    else:
        for key, value in values.items():
            setattr(mark, key, value)


def refresh_chain_role_holder_planes(
    session: Session,
    *,
    chain_id: int,
    rpc_url: str | None = None,
    probe_block: ProbeBlock | None = None,
    limit: int = DEFAULT_REGISTRIES_PER_PASS,
    read_budget: int = DEFAULT_READ_BUDGET,
    max_age_s: int = DEFAULT_MAX_AGE_S,
) -> PassCounters:
    """One chain's pass; returns counters and emits no heartbeat."""
    counters = PassCounters()
    candidates = collect_candidates(session, chain_id=chain_id, max_age_s=max_age_s)
    counters.registries_considered = len(candidates)
    counters.gate_closed = sum(1 for c in candidates if not c.gate_open)
    counters.due = sum(1 for c in candidates if c.due_reason is not None)
    for candidate in candidates:
        if candidate.gate_open:
            continue
        # Per registry: a half-enrolled registry used to be silent.
        logger.info(
            "role holder plane refresh skipped",
            extra={
                "chain_id": chain_id,
                "registry_address": candidate.registry_address,
                "outcome": OUTCOME_GATE_CLOSED,
            },
        )
    if not counters.due:
        return counters

    selected, counters.budget_exhausted = select_due(candidates, limit=limit, read_budget=read_budget)
    if not selected:
        return counters

    url = rpc_url or rpc_url_for_chain_id(chain_id)
    if not url:
        # Registries are due and nothing observed them: degraded, not quiet.
        counters.notes.append("no_rpc_route")
        counters.failures += 1
        return counters

    if probe_block is None:
        probe_block = pin_probe_block(url, chain_id=chain_id)
    if probe_block is None:
        # Nothing is watermarked, so every due registry stays due.
        counters.notes.append("no_pinned_head")
        counters.failures += 1
        return counters

    for candidate in selected:
        try:
            rows = resolve_role_holder_planes(
                session,
                chain_id=chain_id,
                registry_address=candidate.registry_address,
                rpc_url=url,
                probe_block=probe_block,
            )
            written = persist_role_holder_planes(session, rows) if rows else 0
            _record_watermark(session, chain_id=chain_id, candidate=candidate, rows_written=written)
            session.commit()
            if written:
                # Role holders anchor membership-gate chains; re-verify witnesses resting on this registry.
                from services.discovery.membership_gate import evaluate_role_plane_change

                evaluate_role_plane_change(
                    session,
                    registry_address=candidate.registry_address,
                    rows=rows,
                    context=f"role_holder_plane_cycle:{candidate.registry_address}",
                )
        except Exception as exc:
            # No watermark, so it stays due; other registries are unaffected.
            session.rollback()
            counters.failures += 1
            logger.warning(
                "role holder plane refresh failed",
                extra={
                    "chain_id": chain_id,
                    "registry_address": candidate.registry_address,
                    "exc_type": type(exc).__name__,
                },
            )
            continue
        counters.refreshed += 1
        counters.rows += written
        if written:
            counters.rows_written += 1
        else:
            counters.no_rows += 1
        logger.info(
            "role holder plane refreshed",
            extra={
                "chain_id": chain_id,
                "registry_address": candidate.registry_address,
                "outcome": OUTCOME_ROWS_WRITTEN if written else OUTCOME_NO_ROWS,
                "role_holder_planes": written,
                "due_reason": candidate.due_reason,
                "as_of_block": probe_block.number,
            },
        )
    return counters


def refresh_role_holder_planes(
    session: Session,
    *,
    chain_id: int | None = None,
    rpc_url: str | None = None,
    probe_block: ProbeBlock | None = None,
    limit: int = DEFAULT_REGISTRIES_PER_PASS,
    read_budget: int = DEFAULT_READ_BUDGET,
    max_age_s: int = DEFAULT_MAX_AGE_S,
) -> int:
    """One pass across every supported chain; returns rows written.

    Always emits one cycle summary, including when nothing was selected.
    """
    started = time.monotonic()
    chain_ids = [chain_id] if chain_id is not None else sorted(supported_chain_ids())
    total = PassCounters()
    for target_chain in chain_ids:
        try:
            counters = refresh_chain_role_holder_planes(
                session,
                chain_id=target_chain,
                rpc_url=rpc_url,
                probe_block=probe_block,
                limit=limit,
                read_budget=read_budget,
                max_age_s=max_age_s,
            )
        except Exception as exc:
            session.rollback()
            total.failures += 1
            total.notes.append("chain_error")
            logger.warning(
                "role holder plane chain pass failed",
                extra={"chain_id": target_chain, "exc_type": type(exc).__name__},
            )
            continue
        total.registries_considered += counters.registries_considered
        total.gate_closed += counters.gate_closed
        total.due += counters.due
        total.refreshed += counters.refreshed
        total.no_rows += counters.no_rows
        total.rows_written += counters.rows_written
        total.rows += counters.rows
        total.failures += counters.failures
        total.budget_exhausted = total.budget_exhausted or counters.budget_exhausted
        total.notes.extend(counters.notes)

    emit_monitor_cycle(
        HEARTBEAT_ROLE_HOLDER_PLANE,
        started=started,
        contracts_scanned=total.registries_considered,
        # Reads at one pinned height and folds an already indexed range, so no block span applies.
        blocks_scanned=0,
        events_found=total.rows,
        partial=total.failures > 0,
        note=";".join(sorted(set(total.notes))) or None,
        extra_detail={
            "chains": len(chain_ids),
            "registries_due": total.due,
            "registries_refreshed": total.refreshed,
            "registries_gate_closed": total.gate_closed,
            "registries_no_rows": total.no_rows,
            "registries_rows_written": total.rows_written,
            "registries_failed": total.failures,
            "budget_exhausted": total.budget_exhausted,
        },
    )
    return total.rows


def run_role_holder_plane_loop(
    interval: float = DEFAULT_ROLE_PLANE_INTERVAL,
    stop_event: Event | None = None,
    *,
    chain_id: int | None = None,
) -> None:
    stop_event = stop_event or Event()
    logger.info("Starting role-holder plane refresher (interval=%ss)", interval)
    while not stop_event.is_set():
        try:
            with SessionLocal() as session:
                refresh_role_holder_planes(session, chain_id=chain_id)
        except Exception as exc:
            logger.warning("role holder plane cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
            record_heartbeat(
                HEARTBEAT_ROLE_HOLDER_PLANE,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        stop_event.wait(interval)


__all__ = [
    "DEFAULT_MAX_AGE_S",
    "DEFAULT_READ_BUDGET",
    "DEFAULT_REGISTRIES_PER_PASS",
    "DEFAULT_ROLE_PLANE_INTERVAL",
    "OUTCOME_GATE_CLOSED",
    "OUTCOME_NO_REGISTRY",
    "OUTCOME_NO_ROWS",
    "OUTCOME_ROWS_WRITTEN",
    "RegistryCandidate",
    "access_control_gate_open",
    "collect_candidates",
    "refresh_chain_role_holder_planes",
    "refresh_role_holder_planes",
    "run_role_holder_plane_loop",
    "select_due",
]
