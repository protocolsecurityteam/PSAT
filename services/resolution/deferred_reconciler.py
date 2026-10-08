"""Self-heal reconciler for index-cold capability deferrals.

Event-indexed authorities (Solmate ``canCall``, OZ AccessControl, mapping ACLs) resolve from the durable event index,
which is only enrolled after a job completes. So the first resolution of a new authority is cold and fails closed to
``external_check_only`` (``no_index_cursor``), and that result is persisted and never recomputed.

Adapters tag cold deferrals with ``check.extra.deferred_pending_index``. Once every authority a completed job deferred
on has a ``backfill_complete`` cursor, this re-enqueues the job's policy stage, which re-resolves and re-persists
everything. Any adapter setting the marker gets this for free.

* Fail-safe: re-resolution only upgrades deferrals; still-cold ones re-defer.
* Thrash-free: re-enqueued only when all its authorities are warm (monotonic); the re-run clears the marker.
* No double work: skipped if a job for the address is already in flight.
* Orphans: ``contracts.job_id`` is ``ON DELETE SET NULL``, so deleting a job strands its rows. Orphans are selected by
``(address, chain)`` and relinked before re-enqueueing (the policy stage writes by ``Contract.job_id``). Orphans with no
job at all can't be converged here and are counted.
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

from sqlalchemy import Text, and_, cast, exists, func, select
from sqlalchemy.orm import Session, aliased

from db.jsonb import jsonb_has_payload
from db.models import (
    Contract,
    ControlGraphNode,
    EffectiveFunction,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStage,
    JobStatus,
    exactness_eligible_cursor_clause,
)
from services.resolution.mapping_enumerator import MAPPING_ENUMERATION_AWAITS, MAPPING_ENUMERATION_STATUS
from services.resolution.role_store_standards import all_topic0s
from utils.chains import UnknownChainError, chain_by_id, supported_chain_ids
from utils.scoring_status import TRACE_STEP_ENUMERABLE_ROLE_STORE

logger = logging.getLogger(__name__)

# Shared with the adapters by value to avoid an import dependency.
DEFERRED_MARKER = "deferred_pending_index"

_ROLE_STORE_TOPIC0S = [t.lower() for t in all_topic0s()]


# A deferral's authority and the topic cursors it waits on; an empty tuple (adapters that don't name topics) waits on
# any exactness-eligible cursor at the address.
Deferral = tuple[str, tuple[str, ...]]


def _deferral(addr: Any, topic0s: Any) -> Deferral | None:
    if not (isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42):
        return None
    topics = tuple(sorted({t.lower() for t in topic0s if isinstance(t, str)})) if isinstance(topic0s, list) else ()
    return addr.lower(), topics


def _iter_deferrals(node: Any) -> Iterator[Deferral]:
    """Yield every deferral flagged ``deferred_pending_index``: on an ``external_check_only`` leaf, or carried as a
    trace step by a combinator that folded the probe away (a negated denylist), walking ``children`` and ``signer``.
    """
    if not isinstance(node, dict):
        return
    if node.get("kind") == "external_check_only":
        check = node.get("check") or {}
        extra = check.get("extra") or {}
        if extra.get(DEFERRED_MARKER):
            deferral = _deferral(check.get("target_address"), extra.get("deferred_topic0s"))
            if deferral is not None:
                yield deferral
    for step in node.get("trace") or []:
        if isinstance(step, dict) and step.get(DEFERRED_MARKER):
            deferral = _deferral(step.get("target_address"), step.get("deferred_topic0s"))
            if deferral is not None:
                yield deferral
    for child in node.get("children") or []:
        yield from _iter_deferrals(child)
    signer = node.get("signer")
    if isinstance(signer, dict):
        yield from _iter_deferrals(signer)


def _iter_deferred_authorities(node: Any) -> Iterator[str]:
    """The authority address of every deferral :func:`_iter_deferrals` finds."""
    for address, _topic0s in _iter_deferrals(node):
        yield address


def _chain_name_for(chain_id: int) -> str | None:
    """Mainnet-coalesced chain name for ``chain_id``, or ``None`` if unregistered.

    ``contracts`` only has a ``chain`` string (NULL on legacy mainnet rows), so NULL is coalesced to ``'ethereum'`` like
    ``db.queue._mainnet_coalesced_chain``. ``None`` makes the caller skip the contract-keyed route.
    """
    try:
        return chain_by_id(chain_id).name.lower()
    except UnknownChainError:
        return None


def _orphaned_marker_rows(session: Session, chain_id: int) -> list[Any]:
    """Marker-bearing ``effective_functions`` rows on orphaned contracts (``job_id IS NULL``), paired with a job that
    can rewrite them.

    Keyed on ``(address, chain)`` (``uq_contract_address_chain``), never bare address. ``NOT EXISTS`` on the job's own
    contract limits this to orphans, so ``copy_static_cache`` reassignments aren't stolen back and no job gets two
    contracts.
    """
    chain_name = _chain_name_for(chain_id)
    if chain_name is None:
        return []
    owned = aliased(Contract)
    return list(
        session.execute(
            select(Job.id, Job.address, EffectiveFunction.capability_expr, Contract.id)
            .select_from(Contract)
            .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
            .join(
                Job,
                and_(
                    Job.address.isnot(None),
                    func.lower(Job.address) == func.lower(Contract.address),
                    Job.chain_id == chain_id,
                ),
            )
            .where(Contract.job_id.is_(None))
            .where(func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_name)
            .where(Job.status == JobStatus.completed)
            .where(Job.stage == JobStage.done)
            .where(jsonb_has_payload(EffectiveFunction.capability_expr))
            .where(cast(EffectiveFunction.capability_expr, Text).ilike(f"%{DEFERRED_MARKER}%"))
            .where(~exists(select(owned.id).where(owned.job_id == Job.id)))
            .order_by(Job.created_at.desc(), Job.id)
        ).all()
    )


def _unreachable_orphan_contracts(session: Session, chain_id: int) -> int:
    """Count of orphaned marker-carrying contracts with no job at their ``(address, chain)``.

    Their artifacts went with the deleted job, so they need a fresh analysis.
    """
    chain_name = _chain_name_for(chain_id)
    if chain_name is None:
        return 0
    candidate = aliased(Job)
    owned = aliased(Contract)
    return int(
        session.execute(
            select(func.count(func.distinct(Contract.id)))
            .select_from(Contract)
            .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
            .where(Contract.job_id.is_(None))
            .where(func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_name)
            .where(jsonb_has_payload(EffectiveFunction.capability_expr))
            .where(cast(EffectiveFunction.capability_expr, Text).ilike(f"%{DEFERRED_MARKER}%"))
            .where(
                ~exists(
                    select(candidate.id)
                    .where(candidate.address.isnot(None))
                    .where(func.lower(candidate.address) == func.lower(Contract.address))
                    .where(candidate.chain_id == chain_id)
                    .where(candidate.status == JobStatus.completed)
                    .where(candidate.stage == JobStage.done)
                    .where(~exists(select(owned.id).where(owned.job_id == candidate.id)))
                )
            )
        ).scalar()
        or 0
    )


def _authority_backfilled(session: Session, chain_id: int, event_address: str) -> bool:
    """Whether any exactness-eligible cursor for ``event_address`` has ``backfill_complete``.

    Mid-backfill cursors don't count (re-resolving would re-defer), and neither do cursors ``cursor_state`` refuses, or
    every pass would re-enqueue a resolution that still defers.
    """
    row = session.execute(
        select(IndexedEventCursor.event_address)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
        .where(IndexedEventCursor.backfill_complete.is_(True))
        .where(exactness_eligible_cursor_clause())
        .limit(1)
    ).first()
    return row is not None


def _deferral_backfilled(session: Session, chain_id: int, deferral: Deferral) -> bool:
    """Whether a deferral's re-resolution can answer: each topic cursor it named is backfilled and exactness-eligible,
    or, when it named none, some cursor at the address is (:func:`_authority_backfilled`).

    Waiting on the named cursors keeps a still-cold topic from re-enqueueing every pass while another topic at the
    same address is already warm.
    """
    address, topic0s = deferral
    if not topic0s:
        return _authority_backfilled(session, chain_id, address)
    warm = set(
        session.execute(
            select(func.lower(IndexedEventCursor.topic0))
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(func.lower(IndexedEventCursor.event_address) == address)
            .where(func.lower(IndexedEventCursor.topic0).in_(topic0s))
            .where(IndexedEventCursor.backfill_complete.is_(True))
            .where(exactness_eligible_cursor_clause())
        ).scalars()
    )
    return warm.issuperset(topic0s)


def _address_has_active_job(session: Session, address: str | None, *, chain_id: int, exclude_job_id: Any) -> bool:
    """Whether a queued/processing job exists for ``(address, chain_id)`` other than ``exclude_job_id``.

    Chain-scoped.
    """
    if not address:
        return False
    row = session.execute(
        select(Job.id)
        .where(func.lower(Job.address) == address.lower())
        .where(Job.chain_id == chain_id)
        .where(Job.id != exclude_job_id)
        .where(Job.request["effects_resume_work_id"].astext.is_(None))
        .where(Job.status.in_((JobStatus.queued, JobStatus.processing)))
        .limit(1)
    ).first()
    return row is not None


def reconcile_deferred_resolutions(session: Session, *, chain_id: int, limit: int = 200) -> int:
    """One reconciliation pass.

    Re-enqueues the policy stage of every completed job whose deferred authorities are all backfilled; returns the
    count. Commits only when something was re-enqueued.
    """
    # Pre-filter on the marker via a text cast (catches nested leaves); the precise walk is below. ``jsonb_has_payload``
    # because a Python ``None`` is stored as jsonb null, which passes a SQL null test.
    rows = session.execute(
        select(Job.id, Job.address, EffectiveFunction.capability_expr)
        .join(Contract, Contract.job_id == Job.id)
        .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
        .where(Job.status == JobStatus.completed)
        .where(Job.stage == JobStage.done)
        .where(Job.chain_id == chain_id)
        .where(jsonb_has_payload(EffectiveFunction.capability_expr))
        .where(cast(EffectiveFunction.capability_expr, Text).ilike(f"%{DEFERRED_MARKER}%"))
    ).all()

    # job_id -> (address, deferrals)
    by_job: dict[Any, tuple[str | None, set[Deferral]]] = {}
    for job_id, address, capability_expr in rows:
        authorities = set(_iter_deferrals(capability_expr))
        if not authorities:
            continue
        _addr, existing = by_job.setdefault(job_id, (address, set()))
        existing.update(authorities)

    # Orphaned contracts, which the join above can't reach. Linkage is repaired below; see ``adopt``. ``setdefault``
    # doesn't overwrite, since a linked-route job owns a contract and can't be an orphan candidate.
    adopt: dict[Any, int] = {}
    for job_id, address, capability_expr, contract_id in _orphaned_marker_rows(session, chain_id):
        authorities = set(_iter_deferrals(capability_expr))
        if not authorities:
            continue
        _addr, existing = by_job.setdefault(job_id, (address, set()))
        existing.update(authorities)
        adopt.setdefault(job_id, contract_id)

    stranded = _unreachable_orphan_contracts(session, chain_id)
    if stranded:
        # Just a count so the condition isn't invisible.
        logger.warning(
            "deferred-resolution reconciler: %s orphaned contract(s) on chain %s carry index-cold "
            "deferrals with no completed job at their (address, chain) — a fresh analysis is required "
            "to converge them",
            stranded,
            chain_id,
        )

    reenqueued = 0
    for job_id, (address, authorities) in by_job.items():
        if reenqueued >= limit:
            break
        # Wait until every deferral can answer, bounding re-enqueues to one per transition.
        if not all(_deferral_backfilled(session, chain_id, deferral) for deferral in authorities):
            continue
        job = session.get(Job, job_id)
        if job is None or job.status != JobStatus.completed or job.stage != JobStage.done:
            continue
        if _address_has_active_job(session, job.address, chain_id=chain_id, exclude_job_id=job.id):
            continue
        orphan_contract_id = adopt.get(job_id)
        if orphan_contract_id is not None:
            contract = session.get(Contract, orphan_contract_id)
            # Re-check within the same transaction.
            if contract is None or contract.job_id is not None:
                continue
            if session.execute(select(Contract.id).where(Contract.job_id == job.id).limit(1)).first() is not None:
                continue
            # Repair the linkage: the policy stage writes for ``Contract.job_id == job.id``, so re-enqueueing without it
            # writes nothing, leaves the marker, and re-enqueues forever.
            contract.job_id = job.id
            logger.info(
                "deferred-resolution reconciler re-linked orphaned contract %s (%s) to job %s before "
                "re-enqueue; contracts.job_id had been cleared by a job deletion",
                orphan_contract_id,
                contract.address,
                job_id,
            )
        _requeue_policy(job, "Re-resolving: durable event index caught up for a deferred authority")
        reenqueued += 1
        logger.info(
            "deferred-resolution reconciler re-enqueued policy for job %s address=%s authorities=%s",
            job_id,
            address,
            sorted({addr for addr, _topics in authorities}),
        )

    if reenqueued:
        session.commit()
    else:
        session.rollback()
    return reenqueued


# An unsettled replay's awaited authority and topics, plus the frontier a failed tail left unproven (``None`` if any).
MappingAwait = tuple[str, tuple[str, ...], int | None]


def unsettled_mapping_await(details: Any, chain_id: int) -> MappingAwait | None:
    """The await an unsettled node on ``chain_id`` names, or ``None`` when it is settled, on another chain, or names no
    topics (a re-run could not be told apart from this one).
    """
    if not isinstance(details, dict) or details.get(MAPPING_ENUMERATION_STATUS) == "complete":
        return None
    awaits = details.get(MAPPING_ENUMERATION_AWAITS)
    if not isinstance(awaits, dict) or awaits.get("chain_id") != chain_id:
        return None
    deferral = _deferral(awaits.get("event_address"), awaits.get("topic0s"))
    if deferral is None or not deferral[1]:
        return None
    covers = awaits.get("covers_block")
    return deferral[0], deferral[1], covers if isinstance(covers, int) and not isinstance(covers, bool) else None


def _mapping_await_satisfied(session: Session, chain_id: int, pending: MappingAwait) -> bool:
    """Whether the index can now answer the replay: every awaited topic cursor is backfilled and exactness-eligible,
    and, after a failed tail, every one has reached the block that tail missed.
    """
    address, topic0s, covers_block = pending
    if not _deferral_backfilled(session, chain_id, (address, topic0s)):
        return False
    if covers_block is None:
        return True
    frontier = session.execute(
        select(func.min(IndexedEventCursor.last_indexed_block))
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == address)
        .where(func.lower(IndexedEventCursor.topic0).in_(topic0s))
    ).scalar()
    return isinstance(frontier, int) and frontier >= covers_block


def reconcile_unsettled_mapping_replays(session: Session, *, chain_id: int, limit: int = 200) -> int:
    """One pass over completed jobs whose graph holds a mapping-member replay that didn't settle.

    Re-enqueues a job's policy stage once the index can answer one of its awaited replays; returns the count. The re-run
    reads that replay from the index and drops the await, so a job isn't selected again for it; an await whose cursors
    never warm never re-enqueues. Commits only when something was re-enqueued.
    """
    rows = session.execute(
        select(Job.id, Job.address, ControlGraphNode.details)
        .join(Contract, Contract.job_id == Job.id)
        .join(ControlGraphNode, ControlGraphNode.contract_id == Contract.id)
        .where(Job.status == JobStatus.completed)
        .where(Job.stage == JobStage.done)
        .where(Job.chain_id == chain_id)
        .where(ControlGraphNode.details.has_key(MAPPING_ENUMERATION_AWAITS))
    ).all()

    by_job: dict[Any, tuple[str | None, set[MappingAwait]]] = {}
    for job_id, address, details in rows:
        pending = unsettled_mapping_await(details, chain_id)
        if pending is None:
            continue
        by_job.setdefault(job_id, (address, set()))[1].add(pending)

    reenqueued = 0
    satisfied: dict[MappingAwait, bool] = {}
    for job_id, (address, awaits) in by_job.items():
        if reenqueued >= limit:
            break
        ready = []
        for pending in sorted(awaits, key=lambda a: (a[0], a[1], a[2] or 0)):
            if pending not in satisfied:
                satisfied[pending] = _mapping_await_satisfied(session, chain_id, pending)
            if satisfied[pending]:
                ready.append(pending[0])
        if not ready:
            continue
        job = session.get(Job, job_id)
        if job is None or job.status != JobStatus.completed or job.stage != JobStage.done:
            continue
        if _address_has_active_job(session, job.address, chain_id=chain_id, exclude_job_id=job.id):
            continue
        _requeue_policy(job, "Re-resolving: durable event index caught up for an unsettled mapping replay")
        reenqueued += 1
        logger.info(
            "mapping-replay reconciler re-enqueued policy for job %s address=%s authorities=%s",
            job_id,
            address,
            sorted(set(ready)),
        )

    if reenqueued:
        session.commit()
    else:
        session.rollback()
    return reenqueued


def _requeue_policy(job: Job, detail: str) -> None:
    """Reset a completed job to a queued policy stage, clearing lease and backoff so ``claim_job`` picks it up
    immediately.
    """
    job.stage = JobStage.policy
    job.status = JobStatus.queued
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    job.next_attempt_at = None
    job.detail = detail


def _iter_role_store_frontiers(node: Any) -> Iterator[tuple[str, int]]:
    """Yield ``(authority, fold_frontier)`` for every ``enumerable_role_store`` trace step, walking ``children`` /
    ``signer``.
    """
    if not isinstance(node, dict):
        return
    for step in node.get("trace") or []:
        if not isinstance(step, dict) or step.get("step") != TRACE_STEP_ENUMERABLE_ROLE_STORE:
            continue
        authority = step.get("authority")
        frontier = step.get("fold_frontier")
        if (
            isinstance(authority, str)
            and authority.startswith("0x")
            and len(authority) == 42
            and isinstance(frontier, int)
        ):
            yield authority.lower(), frontier
    for child in node.get("children") or []:
        yield from _iter_role_store_frontiers(child)
    signer = node.get("signer")
    if isinstance(signer, dict):
        yield from _iter_role_store_frontiers(signer)


def _role_row_past_frontier(session: Session, chain_id: int, event_address: str, frontier: int) -> bool:
    """Whether a grant/revoke for ``event_address`` is indexed past ``frontier`` (the fold covered ``<= frontier``)."""
    row = session.execute(
        select(IndexedEventLog.block_number)
        .where(IndexedEventLog.chain_id == chain_id)
        .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
        .where(IndexedEventLog.topic0.in_(_ROLE_STORE_TOPIC0S))
        .where(IndexedEventLog.block_number > frontier)
        .limit(1)
    ).first()
    return row is not None


def reconcile_role_set_drift(session: Session, *, chain_id: int, limit: int = 200) -> int:
    """One role-drift pass, the warm counterpart to the cold self-heal.

    Re-enqueues the policy stage of jobs whose role-store enumeration has a grant/revoke indexed past its fold frontier;
    returns the count. The re-run stamps a higher frontier, so it doesn't re-select. Gated on ``backfill_complete``.
    """
    rows = session.execute(
        select(Job.id, Job.address, EffectiveFunction.capability_expr)
        .join(Contract, Contract.job_id == Job.id)
        .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
        .where(Job.status == JobStatus.completed)
        .where(Job.stage == JobStage.done)
        .where(Job.chain_id == chain_id)
        .where(jsonb_has_payload(EffectiveFunction.capability_expr))
        .where(cast(EffectiveFunction.capability_expr, Text).ilike(f"%{TRACE_STEP_ENUMERABLE_ROLE_STORE}%"))
    ).all()

    # job_id -> (address, {authority: lowest frontier})
    by_job: dict[Any, tuple[str | None, dict[str, int]]] = {}
    for job_id, address, capability_expr in rows:
        _addr, frontiers = by_job.setdefault(job_id, (address, {}))
        for authority, frontier in _iter_role_store_frontiers(capability_expr):
            # The lowest frontier is the conservative one.
            prior = frontiers.get(authority)
            frontiers[authority] = frontier if prior is None else min(prior, frontier)

    reenqueued = 0
    backfilled: dict[str, bool] = {}
    drift: dict[tuple[str, int], bool] = {}

    def has_drift(authority: str, frontier: int) -> bool:
        if authority not in backfilled:
            backfilled[authority] = _authority_backfilled(session, chain_id, authority)
        if not backfilled[authority]:
            return False
        key = (authority, frontier)
        if key not in drift:
            drift[key] = _role_row_past_frontier(session, chain_id, authority, frontier)
        return drift[key]

    for job_id, (address, frontiers) in by_job.items():
        if reenqueued >= limit:
            break
        drifted = [authority for authority, frontier in frontiers.items() if has_drift(authority, frontier)]
        if not drifted:
            continue
        job = session.get(Job, job_id)
        if job is None or job.status != JobStatus.completed or job.stage != JobStage.done:
            continue
        if _address_has_active_job(session, job.address, chain_id=chain_id, exclude_job_id=job.id):
            continue
        _requeue_policy(job, "Re-resolving: role-store membership drifted past the folded frontier")
        reenqueued += 1
        logger.info(
            "role-drift reconciler re-enqueued policy for job %s address=%s authorities=%s",
            job_id,
            address,
            sorted(drifted),
        )

    if reenqueued:
        session.commit()
    else:
        session.rollback()
    return reenqueued


def enqueue_reorg_refreshes(session: Session, *, chain_id: int, authority: str) -> int:
    """Queue per-job refreshes for removed history, even below fold frontiers.

    The caller commits the fanout and reorg acknowledgement together.
    """
    from services.resolution.indexer_work import mark_dirty

    rows = session.execute(
        select(Job.id, EffectiveFunction.capability_expr)
        .join(Contract, Contract.job_id == Job.id)
        .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
        .where(Job.chain_id == chain_id, jsonb_has_payload(EffectiveFunction.capability_expr))
        .where(cast(EffectiveFunction.capability_expr, Text).ilike(f"%{TRACE_STEP_ENUMERABLE_ROLE_STORE}%"))
        .execution_options(yield_per=100)
    )
    affected = {job_id for job_id, expr in rows if authority in {addr for addr, _ in _iter_role_store_frontiers(expr)}}
    for job_id in sorted(affected, key=str):
        mark_dirty(session, "refresh_job", str(job_id))
    return len(affected)


def refresh_invalidated_job(session: Session, job_id: Any) -> int:
    from services.resolution.indexer_work import WorkPending

    job = session.execute(
        select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if job is None or job.status == JobStatus.failed_terminal:
        return 0
    if job.status != JobStatus.completed or job.stage != JobStage.done:
        raise WorkPending("invalidated job is not completed")
    chain_id = job.chain_id
    if chain_id is None or chain_id not in supported_chain_ids():
        raise WorkPending("invalidated job has no enabled chain")
    rows = (
        session.execute(
            select(EffectiveFunction.capability_expr)
            .join(Contract, EffectiveFunction.contract_id == Contract.id)
            .where(Contract.job_id == job.id)
        )
        .scalars()
        .all()
    )
    authorities = {addr for expr in rows for addr, _ in _iter_role_store_frontiers(expr)}
    if not authorities:
        return 0  # Deleted/relinked source or a later result no longer uses event folds.
    if not all(_authority_backfilled(session, chain_id, addr) for addr in authorities):
        raise WorkPending("invalidated authority is still backfilling")
    cold = session.execute(
        select(IndexedEventCursor.event_address)
        .where(
            IndexedEventCursor.chain_id == chain_id,
            func.lower(IndexedEventCursor.event_address).in_(sorted(authorities)),
            IndexedEventCursor.topic0.in_(_ROLE_STORE_TOPIC0S),
            IndexedEventCursor.backfill_complete.is_(False),
        )
        .limit(1)
    ).first()
    if cold is not None:
        raise WorkPending("a sibling role cursor is still backfilling")
    if _address_has_active_job(session, job.address, chain_id=chain_id, exclude_job_id=job.id):
        raise WorkPending("another analysis owns this address")
    _requeue_policy(job, "Re-resolving: indexed role-store history changed during a reorg")
    session.flush()
    return 1
