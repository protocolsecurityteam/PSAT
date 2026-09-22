"""Keeping every monitored contract's materialization current, at a decided price.

Invariant 8 says a completed analysis leaves a current materialization row.
The main pipeline now writes one (F4a), so the invariant holds going forward —
but it does not hold *retroactively*, and it stops holding the moment
``STATIC_FACTS_SCHEMA_VERSION`` is bumped: every existing row reads as a miss at
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

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from db.contract_materializations import STATIC_FACTS_SCHEMA_VERSION, builder_claim_is_stale
from db.models import ContractMaterialization, Job, JobStatus, MonitoredContract
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


def _materialization_state_by_key(
    session: Session, addresses: set[str]
) -> dict[tuple[str, str], tuple[str, int | None, datetime | None]]:
    """``(chain_token, address) -> (status, static_facts_schema_version, builder_started_at)``.

    Not a SQL join: ``contract_materializations.chain`` holds chain-id tokens
    while ``monitored_contracts.chain`` holds names, and the two are only
    comparable through ``chain_cache_token`` (see ``observation_plan_state``). The
    address filter keeps the read proportional to the monitored fleet rather
    than to every contract the pipeline has ever materialized — this runs on
    every ``/api/fleet`` request and every ops tick.
    """
    if not addresses:
        return {}
    return {
        (row.chain, (row.address or "").lower()): (row.status, row.static_facts_schema_version, row.builder_started_at)
        for row in session.execute(
            select(
                ContractMaterialization.chain,
                ContractMaterialization.address,
                ContractMaterialization.status,
                ContractMaterialization.static_facts_schema_version,
                ContractMaterialization.builder_started_at,
            ).where(ContractMaterialization.address.in_(sorted(addresses)))
        ).all()
    }


def _backlog_reason(state: tuple[str, int | None, datetime | None] | None) -> str | None:
    """The reason this address has no current row, or None when it has one."""
    if state is None:
        return REASON_NO_ROW
    status, version, builder_started_at = state
    if status == "building":
        # A claim whose builder has gone stale is a crashed worker's leftover,
        # not a build in flight — ``materialize_or_wait`` takes such a row over.
        # Counting it as in-flight would exempt it from rebuild forever.
        return REASON_NO_ROW if builder_claim_is_stale(status, builder_started_at) else REASON_IN_PROGRESS
    if status == "pending":
        return REASON_IN_PROGRESS
    if status == "failed":
        return REASON_FAILED
    if version != STATIC_FACTS_SCHEMA_VERSION:
        return REASON_SUPERSEDED_VERSION
    if status != "ready":
        return REASON_NO_ROW
    return None


def backlog_candidates(session: Session) -> list[RebuildCandidate]:
    """Every active monitored contract without a current materialization row.

    Unbudgeted and unordered-by-priority — the backlog itself. ``plan_rebuilds``
    is what turns it into work.
    """
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
    """``(chain_token, address)`` for a rebuild job.

    Chain-qualified because the same address on two chains is two deployments
    with two materializations: keying on the address alone would let a rebuild
    in flight for the mainnet contract suppress its Base twin indefinitely.
    """
    request = job.request if isinstance(job.request, dict) else {}
    chain = job.chain_id if isinstance(getattr(job, "chain_id", None), int) else request.get("chain")
    return (chain_cache_token(chain), (job.address or "").lower())


def _rebuild_jobs_since(session: Session, since: datetime) -> list[Job]:
    """Reconciler-issued jobs created since *since*, plus any still in flight.

    Both halves matter: the recent ones are the budget already spent, and their
    deployments are the ones a second pass must not re-queue. An older job that
    is still queued or processing is in flight regardless of age.
    """
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
    """Backlog census for the fleet and ops surfaces (F9c).

    ``by_reason`` partitions ``contracts``. The budget fields are published
    alongside because the backlog on its own does not say whether anything is
    being done about it: a large backlog under a spent budget and the same
    backlog under an untouched one are different operational facts.

    ``attempted_not_yet_resolved`` counts the deployments this reconciler has a
    job out for that are STILL IN THE BACKLOG — work issued that has not yet
    produced a row, which is a different fact from work not yet issued. An
    attempt whose contract now has its row is resolved and is not counted; the
    number is meant to answer "how much outstanding work is there", and counting
    successes in it would answer nothing.

    No alert threshold is invented here — the counts ride the same
    publish-unconditionally rule as ``plan_coverage`` and ``verification_gaps``.

    *_candidates* lets a caller that already computed the backlog pass it in
    rather than pay for the scan twice; it is not part of the surface contract.
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
    """The rebuild jobs the budget allows right now, and the census behind them.

    Returns ``(candidates, backlog)``. Two exclusions, and the second is why a
    second pass makes progress:

    * ``in_progress`` — a builder is already running, so a job would pay for the
      same bundle twice.
    * any deployment this reconciler already has a job out for (in flight, or
      issued within the budget window). The 24 h counter bounds how MANY jobs
      are issued, not WHICH — without this, every pass re-proposes the head of
      the list, and a contract that keeps failing to rebuild starves the tail
      forever. Chain-qualified, so a mainnet rebuild does not suppress its Base
      twin.

    The remaining order is stable (chain, address), so a dry run and the
    ``--apply`` that follows it propose the same work.
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
