"""Keep monitored contracts' materializations current, within a budget.

An ``ANALYSIS_SCHEMA_VERSION`` bump makes every row a miss and drops the fleet to baseline-only watching.
:func:`materialization_backlog` publishes that decay; :func:`plan_rebuilds` picks re-analysis jobs under a daily cap,
since rebuilds are real spend. ``scripts/reconcile_materializations.py`` does the queuing (dry-run by default).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION, builder_claim_is_stale
from db.models import ContractMaterialization, Job, JobStatus, MonitoredContract
from utils.chains import chain_cache_token

logger = logging.getLogger(__name__)

# Marks reconciler-queued jobs; only these count against the budget.
REBUILD_REQUEST_KEY = "materialization_rebuild"

# Why a contract has no current row; each reason has a different remedy.
REASON_NO_ROW = "no_row"
REASON_SUPERSEDED_VERSION = "superseded_version"
REASON_FAILED = "failed"
REASON_IN_PROGRESS = "in_progress"

# Rows present at read time, not how long a contract has lacked one.
BACKLOG_BASIS = "materialization rows present at read time, per active monitored contract"

DEFAULT_REBUILD_BUDGET_PER_DAY = 25


def rebuild_budget_per_day() -> int:
    """Daily cap on reconciler rebuild jobs; ``0`` disables.

    Small by default: a schema bump invalidates the whole fleet at once.
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


def _materialization_state_by_key(
    session: Session, addresses: set[str]
) -> dict[tuple[str, str], tuple[str, int | None, datetime | None]]:
    """``(chain_token, address) -> (status, analysis_schema_version, builder_started_at)``.

    Not a SQL join: the two tables spell chains differently (see ``chain_cache_token``). Filtered by address because
    this runs on every ``/api/fleet`` request.
    """
    if not addresses:
        return {}
    return {
        (row.chain, (row.address or "").lower()): (row.status, row.analysis_schema_version, row.builder_started_at)
        for row in session.execute(
            select(
                ContractMaterialization.chain,
                ContractMaterialization.address,
                ContractMaterialization.status,
                ContractMaterialization.analysis_schema_version,
                ContractMaterialization.builder_started_at,
            ).where(ContractMaterialization.address.in_(sorted(addresses)))
        ).all()
    }


def _backlog_reason(state: tuple[str, int | None, datetime | None] | None) -> str | None:
    if state is None:
        return REASON_NO_ROW
    status, version, builder_started_at = state
    if status == "building":
        # A stale builder claim is a crashed worker's leftover, so it needs a rebuild.
        return REASON_NO_ROW if builder_claim_is_stale(status, builder_started_at) else REASON_IN_PROGRESS
    if status == "pending":
        return REASON_IN_PROGRESS
    if status == "failed":
        return REASON_FAILED
    if version != ANALYSIS_SCHEMA_VERSION:
        return REASON_SUPERSEDED_VERSION
    if status != "ready":
        return REASON_NO_ROW
    return None


def backlog_candidates(session: Session) -> list[RebuildCandidate]:
    """Every active monitored contract without a current row (unbudgeted)."""
    monitored = (
        session.execute(
            select(MonitoredContract)
            .where(MonitoredContract.is_active.is_(True))
            .order_by(MonitoredContract.chain, MonitoredContract.address)
        )
        .scalars()
        .all()
    )
    states = _materialization_state_by_key(session, {(mc.address or "").lower() for mc in monitored})
    out: list[RebuildCandidate] = []
    for mc in monitored:
        key = (chain_cache_token(mc.chain), (mc.address or "").lower())
        reason = _backlog_reason(states.get(key))
        if reason is None:
            continue
        out.append(RebuildCandidate(address=mc.address, chain=mc.chain, reason=reason, protocol_id=mc.protocol_id))
    return out


def _job_key(job: Job) -> tuple[str, str]:
    """Chain-qualified: a mainnet rebuild must not suppress its Base twin."""
    request = job.request if isinstance(job.request, dict) else {}
    chain = job.chain_id if isinstance(getattr(job, "chain_id", None), int) else request.get("chain")
    return (chain_cache_token(chain), (job.address or "").lower())


def _rebuild_jobs_since(session: Session, since: datetime) -> list[Job]:
    """Reconciler jobs since *since* (budget spent), plus any still in flight regardless of age."""
    return list(
        session.execute(
            select(Job).where(
                Job.request[REBUILD_REQUEST_KEY].astext == "true",
                or_(Job.created_at >= since, Job.status.in_([JobStatus.queued, JobStatus.processing])),
            )
        )
        .scalars()
        .all()
    )


def materialization_backlog(
    session: Session,
    *,
    now: datetime | None = None,
    _candidates: list[RebuildCandidate] | None = None,
) -> dict[str, Any]:
    """Backlog census for the fleet and ops surfaces, with budget fields alongside.

    ``attempted_not_yet_resolved`` counts contracts with a job out that are still in the backlog. *_candidates* lets a
    caller reuse a backlog it already computed.
    """
    now = now or datetime.now(timezone.utc)
    candidates = _candidates or backlog_candidates(session)
    by_reason: dict[str, int] = {}
    for candidate in candidates:
        by_reason[candidate.reason] = by_reason.get(candidate.reason, 0) + 1
    budget = rebuild_budget_per_day()
    window_start = now - timedelta(days=1)
    recent = _rebuild_jobs_since(session, window_start)
    queued = sum(1 for job in recent if job.created_at is not None and _aware(job.created_at) >= window_start)
    unresolved = {_job_key(job) for job in recent} & {
        (chain_cache_token(c.chain), (c.address or "").lower()) for c in candidates
    }
    return {
        "contracts": len(candidates),
        "by_reason": by_reason,
        "budget_per_day": budget,
        "queued_last_24h": queued,
        "queueable_now": max(0, budget - queued),
        "attempted_not_yet_resolved": len(unresolved),
        "basis": BACKLOG_BASIS,
    }


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def plan_rebuilds(
    session: Session,
    *,
    budget: int | None = None,
    now: datetime | None = None,
) -> tuple[list[RebuildCandidate], dict[str, Any]]:
    """The rebuild jobs the budget allows now, and the census; returns ``(candidates, backlog)``.

    Excludes ``in_progress`` builds and any deployment with a job already out (in flight or within the window); without
    the latter, a contract that keeps failing would starve the tail. Order is stable so a dry run matches the
    ``--apply`` after it.
    """
    now = now or datetime.now(timezone.utc)
    candidates = backlog_candidates(session)
    backlog = materialization_backlog(session, now=now, _candidates=candidates)
    allowed = backlog["queueable_now"] if budget is None else max(0, budget - backlog["queued_last_24h"])
    attempted = {_job_key(job) for job in _rebuild_jobs_since(session, now - timedelta(days=1))}
    workable = [
        c
        for c in candidates
        if c.reason != REASON_IN_PROGRESS and (chain_cache_token(c.chain), (c.address or "").lower()) not in attempted
    ]
    return workable[:allowed], backlog
