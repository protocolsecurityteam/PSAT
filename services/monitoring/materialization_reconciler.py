"""Keeping every monitored contract's materialization current, at a decided price.

Invariant 8 says a completed analysis leaves a current materialization row.
The main pipeline now writes one (F4a), so the invariant holds going forward —
but it does not hold *retroactively*, and it stops holding the moment
``ANALYSIS_SCHEMA_VERSION`` is bumped: every existing row reads as a miss at
once, and the whole monitored fleet silently falls back to baseline-only
watching until something re-analyzes it.

This module is the two halves of not letting that happen quietly:

  * :func:`materialization_backlog` — how many active monitored contracts have
    no current row, and why. Published unconditionally on the fleet and ops
    surfaces (F9c) so the decay is visible while it is small.
  * :func:`plan_rebuilds` — which contracts to re-analyze, capped by a daily
    budget. Rebuild is real spend (forge + Slither + LLM per job), so the work
    is *decided*, never emergent: the cap is an env knob, the jobs already
    queued against it are counted, and the remainder is reported rather than
    quietly issued (invariant 11).

The mutating half lives in ``scripts/reconcile_materializations.py``, which is
``--dry-run`` by default and operator-run.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import ContractMaterialization, Job, MonitoredContract
from utils.chains import chain_cache_token

logger = logging.getLogger(__name__)

#: Marker on a job this reconciler queued. Also how the budget counts itself:
#: a rebuild is only budgeted against reconciler-issued work, never against
#: re-analysis a governance event triggered.
REBUILD_REQUEST_KEY = "materialization_rebuild"

#: Why a monitored contract has no current materialization row. Four distinct
#: facts with four different remedies — a failed build is not a missing one,
#: and an in-flight build needs nothing at all.
REASON_NO_ROW = "no_row"
REASON_SUPERSEDED_VERSION = "superseded_version"
REASON_FAILED = "failed"
REASON_IN_PROGRESS = "in_progress"

#: What the census is a census *of*: rows present at read time. A contract
#: counted here is one whose enrollment reads ``no_current_materialization``
#: today — not a claim about how long it has been that way.
BACKLOG_BASIS = "materialization rows present at read time, per active monitored contract"

DEFAULT_REBUILD_BUDGET_PER_DAY = 25


def rebuild_budget_per_day() -> int:
    """Daily cap on reconciler-issued rebuild jobs. ``0`` disables queuing.

    Deliberately small by default: a schema bump invalidates the whole fleet at
    once, and draining it at full speed is a bill nobody decided to pay.
    """
    raw = os.getenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY")
    if raw is None:
        return DEFAULT_REBUILD_BUDGET_PER_DAY
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning(
            "PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY=%r is not an integer; using %d",
            raw,
            DEFAULT_REBUILD_BUDGET_PER_DAY,
        )
        return DEFAULT_REBUILD_BUDGET_PER_DAY


@dataclass(frozen=True)
class RebuildCandidate:
    """One monitored contract whose materialization is not current."""

    address: str
    chain: str
    reason: str
    protocol_id: int | None


def _materialization_state_by_key(session: Session) -> dict[tuple[str, str], tuple[str, int | None]]:
    """``(chain_token, address) -> (status, analysis_schema_version)``.

    Not a SQL join: ``contract_materializations.chain`` holds chain-id tokens
    while ``monitored_contracts.chain`` holds names, and the two are only
    comparable through ``chain_cache_token`` (see ``tracking_plan_state``).
    """
    return {
        (row.chain, (row.address or "").lower()): (row.status, row.analysis_schema_version)
        for row in session.execute(
            select(
                ContractMaterialization.chain,
                ContractMaterialization.address,
                ContractMaterialization.status,
                ContractMaterialization.analysis_schema_version,
            )
        ).all()
    }


def _backlog_reason(state: tuple[str, int | None] | None) -> str | None:
    """The reason this address has no current row, or None when it has one."""
    if state is None:
        return REASON_NO_ROW
    status, version = state
    if status in ("building", "pending"):
        return REASON_IN_PROGRESS
    if status == "failed":
        return REASON_FAILED
    if version != ANALYSIS_SCHEMA_VERSION:
        return REASON_SUPERSEDED_VERSION
    if status != "ready":
        return REASON_NO_ROW
    return None


def backlog_candidates(session: Session) -> list[RebuildCandidate]:
    """Every active monitored contract without a current materialization row.

    Unbudgeted and unordered-by-priority — the backlog itself. ``plan_rebuilds``
    is what turns it into work.
    """
    states = _materialization_state_by_key(session)
    out: list[RebuildCandidate] = []
    for mc in (
        session.execute(
            select(MonitoredContract)
            .where(MonitoredContract.is_active.is_(True))
            .order_by(MonitoredContract.chain, MonitoredContract.address)
        )
        .scalars()
        .all()
    ):
        key = (chain_cache_token(mc.chain), (mc.address or "").lower())
        reason = _backlog_reason(states.get(key))
        if reason is None:
            continue
        out.append(RebuildCandidate(address=mc.address, chain=mc.chain, reason=reason, protocol_id=mc.protocol_id))
    return out


def count_rebuilds_queued_since(session: Session, since: datetime) -> int:
    """Reconciler-issued jobs created since *since* — the budget already spent."""
    return (
        session.execute(
            select(func.count())
            .select_from(Job)
            .where(Job.created_at >= since, Job.request[REBUILD_REQUEST_KEY].astext == "true")
        ).scalar()
        or 0
    )


def materialization_backlog(session: Session, *, now: datetime | None = None) -> dict[str, Any]:
    """Backlog census for the fleet and ops surfaces (F9c).

    ``by_reason`` partitions ``contracts``. The budget fields are published
    alongside because the backlog on its own does not say whether anything is
    being done about it: a large backlog under a spent budget and the same
    backlog under an untouched one are different operational facts.

    No alert threshold is invented here — the counts ride the same
    publish-unconditionally rule as ``plan_coverage`` and ``verification_gaps``.
    """
    now = now or datetime.now(timezone.utc)
    candidates = backlog_candidates(session)
    by_reason: dict[str, int] = {}
    for candidate in candidates:
        by_reason[candidate.reason] = by_reason.get(candidate.reason, 0) + 1
    budget = rebuild_budget_per_day()
    queued = count_rebuilds_queued_since(session, now - timedelta(days=1))
    return {
        "contracts": len(candidates),
        "by_reason": by_reason,
        "budget_per_day": budget,
        "queued_last_24h": queued,
        "queueable_now": max(0, budget - queued),
        "basis": BACKLOG_BASIS,
    }


def plan_rebuilds(
    session: Session,
    *,
    budget: int | None = None,
    now: datetime | None = None,
) -> tuple[list[RebuildCandidate], dict[str, Any]]:
    """The rebuild jobs the budget allows right now, and the census behind them.

    Returns ``(candidates, backlog)``. ``in_progress`` candidates are excluded:
    a builder is already running for them, and queuing a job would pay for the
    same bundle twice. The remaining order is stable (chain, address) so a
    repeated dry run proposes the same work.
    """
    now = now or datetime.now(timezone.utc)
    backlog = materialization_backlog(session, now=now)
    allowed = backlog["queueable_now"] if budget is None else max(0, budget - backlog["queued_last_24h"])
    workable = [c for c in backlog_candidates(session) if c.reason != REASON_IN_PROGRESS]
    return workable[:allowed], backlog
