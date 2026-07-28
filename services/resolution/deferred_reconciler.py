"""Self-heal reconciler for index-cold capability deferrals.

Background
----------
"Who may call this privileged function" for event-indexed authorities
(Solmate ``RolesAuthority`` ``canCall``, OZ ``AccessControl`` /
mapping-ACL membership) is resolved by folding the authority's on-chain
events out of the durable Postgres index (``indexed_event_logs`` /
``indexed_event_cursors``). That index is populated *after* a job
completes (``enroll_from_completed_jobs`` is gated on
``Job.status == completed``) and then backfilled asynchronously, but the
resolution that needs those events runs *during* the job (the policy
stage). So the first — and persisted — resolution of the first contract
to reference a given authority is cold: the adapter fails closed to
``external_check_only`` (basis ``no_index_cursor``).

That is fail-safe (never a wrong/over-broad controller set — just
"unknown"), but it is *sticky*: the cold result lands in
``EffectiveFunction`` / ``FunctionPrincipal`` / the ``effective_permissions``
artifact and onward into the control graph + Surface, and nothing
recomputes it once the index catches up.

This module is the convergence backstop. The cold paths now tag their
deferral with ``check.extra.deferred_pending_index = True`` (see
``adapters/solmate_roles.py`` + ``adapters/event_indexed.py``). Once
every authority a completed job deferred on has a ``backfill_complete``
cursor, this reconciler re-enqueues that job's *policy* stage. The
production policy pipeline then re-resolves against the now-warm index
and re-persists everything (function rows + artifact + control graph +
principal labels) — no logic is duplicated here.

Why this is the general fix (not a Solmate patch)
-------------------------------------------------
It keys on the adapter-agnostic ``deferred_pending_index`` marker that
*any* event-indexed adapter sets, extracts the backing authority from the
``external_check_only`` leaf the adapter already wrote, and re-runs the
*whole* adapter registry via the policy stage. A new event-indexed
standard inherits the self-heal for free by setting the same marker.

Safety properties
------------------
* **Fail-safe.** Re-resolution can only *upgrade* a deferral to a concrete
  set when the events are present; it never emits a wrong or empty set.
  If the index is somehow still cold the function simply re-defers.
* **Thrash-free.** A job is re-enqueued only when *all* of its deferred
  authorities are ``backfill_complete`` (a monotonic flag). After one
  re-run the ``no_index_cursor`` marker is gone, so the job is not
  selected again.
* **No double work.** A job with a re-analysis already queued/processing
  for its address is skipped.
* **Reachable.** ``contracts.job_id`` is ``ON DELETE SET NULL`` and every stage
  finds its contract through it, so deleting a job strands that contract's rows
  outside the reconciler's reach permanently (L-12). Orphaned contracts are
  selected on their own ``(address, chain)`` identity and their linkage is
  REPAIRED before the re-enqueue, because the policy stage writes rows for
  ``Contract.job_id == job.id`` and would otherwise re-run and write nothing.
  Orphans with no job at their ``(address, chain)`` at all cannot be converged
  from here — their artifacts and sources went with the deleted job — so they are
  counted and logged instead of silently skipped.
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

from sqlalchemy import Text, and_, cast, exists, func, select
from sqlalchemy.orm import Session, aliased

from db.jsonb import jsonb_has_payload
from db.models import Contract, EffectiveFunction, IndexedEventCursor, IndexedEventLog, Job, JobStage, JobStatus
from services.resolution.role_store_standards import all_topic0s
from utils.chains import UnknownChainError, chain_by_id

logger = logging.getLogger(__name__)

# The marker the index-cold adapter paths stamp into
# ``external_check_only.check.extra``. Shared with the adapters by value
# (a bare string) to avoid a worker→adapter import dependency.
DEFERRED_MARKER = "deferred_pending_index"

# The adapter's trace step (``adapters/enumerable_role_store.py``) whose fold the
# role-drift arm watches — shared by value, same rationale as ``DEFERRED_MARKER``.
ROLE_STORE_TRACE_STEP = "enumerable_role_store"
_ROLE_STORE_TOPIC0S = [t.lower() for t in all_topic0s()]


def _iter_deferred_authorities(node: Any) -> Iterator[str]:
    """Yield the ``target_address`` of every ``external_check_only`` leaf in a
    serialized ``capability_expr`` tree that is flagged ``deferred_pending_index``.

    Walks ``children`` (AND/OR composition) and ``signer`` (signature_witness)
    so a deferral nested inside a composite is still found — the cold leaf is
    often one branch of an ``AND`` with side conditions.
    """
    if not isinstance(node, dict):
        return
    if node.get("kind") == "external_check_only":
        check = node.get("check") or {}
        extra = check.get("extra") or {}
        if extra.get(DEFERRED_MARKER):
            addr = check.get("target_address")
            if isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42:
                yield addr.lower()
    for child in node.get("children") or []:
        yield from _iter_deferred_authorities(child)
    signer = node.get("signer")
    if isinstance(signer, dict):
        yield from _iter_deferred_authorities(signer)


def _chain_name_for(chain_id: int) -> str | None:
    """Mainnet-coalesced chain name for ``chain_id``, or ``None`` when the id is
    not in the registry.

    ``contracts`` has no ``chain_id`` — its only scoping key is the string
    ``chain``, which persisted NULL for mainnet on legacy rows. Coalescing
    NULL→``'ethereum'`` lets a chain-1 pass match those rows while a
    non-mainnet pass (its own name ≠ ``'ethereum'``) stays isolated; mirrors
    ``db.queue._mainnet_coalesced_chain``. ``None`` makes the caller skip the
    contract-keyed route entirely rather than guess a chain.
    """
    try:
        return chain_by_id(chain_id).name.lower()
    except UnknownChainError:
        return None


def _orphaned_marker_rows(session: Session, chain_id: int) -> list[Any]:
    """Marker-bearing ``effective_functions`` rows whose contract is ORPHANED —
    ``contracts.job_id IS NULL`` — paired with the job that can rewrite them.

    ``contracts.job_id`` is ``ON DELETE SET NULL``, so deleting a job (the admin
    routes do) detaches its contract permanently. Every stage finds "its"
    contract by ``Contract.job_id == job.id``, so an orphaned contract's rows are
    unreachable to the main query below and its deferred authority NEVER
    resolves: a permanent index-cold capability on the published surface.

    The pair is keyed on the system's own contract identity — ``(address,
    chain)``, the ``uq_contract_address_chain`` unique key — never on the bare
    address (handoff §3): a twin deployment of the same address on another chain
    is a different contract and must not be re-enqueued by this chain's pass.

    ``NOT EXISTS`` on the job's own contract is what keeps this to exactly the
    orphaned class and makes the adoption in the caller safe. A job that already
    owns a contract row is never a candidate, so the ``copy_static_cache``
    reassignment case (where the row legitimately belongs to a later target job)
    cannot be stolen back, and no job can end up with two contracts.
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
    """How many orphaned contracts carry the marker with NO job at their
    ``(address, chain)`` that could rewrite them — the residue this reconciler
    still cannot converge, counted so it stops being silent.

    Deleting a job deletes its artifacts and source files too, so these
    contracts cannot be re-resolved from anything on disk: closing them takes a
    fresh analysis job, which is a decision for an operator, not a background
    pass. 2 contracts / 32 rows on the local corpus, and a lower bound (one
    protocol, one chain).
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
    """True iff at least one cursor for ``event_address`` has
    ``backfill_complete = True``.

    "Any topic backfilled" is the right gate: the re-resolution re-reads every
    topic an adapter needs; this check only answers "did the index this function
    was waiting on catch up to head". A cursor that exists but is still
    mid-backfill (``backfill_complete = False``) does NOT count — re-resolving
    then would just re-defer.
    """
    row = session.execute(
        select(IndexedEventCursor.event_address)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
        .where(IndexedEventCursor.backfill_complete.is_(True))
        .limit(1)
    ).first()
    return row is not None


def _address_has_active_job(session: Session, address: str | None, *, chain_id: int, exclude_job_id: Any) -> bool:
    """True iff a non-terminal job (queued/processing) already exists for
    ``(address, chain_id)`` other than ``exclude_job_id`` — so the reconciler does
    not pile a second re-analysis on top of one already in flight. Chain-scoped:
    a twin deployment's in-flight job on another chain must not block this chain's
    re-enqueue."""
    if not address:
        return False
    row = session.execute(
        select(Job.id)
        .where(func.lower(Job.address) == address.lower())
        .where(Job.chain_id == chain_id)
        .where(Job.id != exclude_job_id)
        .where(Job.status.in_((JobStatus.queued, JobStatus.processing)))
        .limit(1)
    ).first()
    return row is not None


def reconcile_deferred_resolutions(session: Session, *, chain_id: int, limit: int = 200) -> int:
    """One reconciliation pass.

    Re-enqueue the policy stage of every completed job whose index-cold
    capability deferrals can now be resolved (every deferred authority has a
    ``backfill_complete`` cursor). Returns the number of jobs re-enqueued.

    Exposed separately from the loop so tests and an at-startup boot pass can
    drive a single pass. Commits only when it re-enqueued at least one job;
    otherwise it rolls back so the read-only pass leaves no open transaction.
    """
    # Cheap pre-filter: only effective_functions whose serialized capability
    # tree mentions the marker. The JSONB→text cast LIKE catches the marker even
    # when the deferred leaf is nested inside an AND/OR; the precise per-leaf
    # walk happens in Python below.
    #
    # ``jsonb_has_payload``, not a SQL null test: a column written from a Python
    # ``None`` holds the jsonb scalar null, which passes a null test and casts to
    # the four-character text ``null`` — a row with no capability tree at all,
    # carried into the Python walk below as a ``None`` to re-check.
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

    # job_id -> (address, set(deferred authority addresses))
    by_job: dict[Any, tuple[str | None, set[str]]] = {}
    for job_id, address, capability_expr in rows:
        authorities = set(_iter_deferred_authorities(capability_expr))
        if not authorities:
            continue
        _addr, existing = by_job.setdefault(job_id, (address, set()))
        existing.update(authorities)

    # Second route: marker rows on ORPHANED contracts (``contracts.job_id IS
    # NULL``), which the join above cannot reach at all. Their linkage is
    # repaired below, before the re-enqueue — reaching them without repairing is
    # worse than not reaching them, see ``adopt``.
    #
    # ``setdefault`` deliberately does NOT overwrite: a job already selected by
    # the linked route owns a contract, so it can never be an orphan candidate
    # (``_orphaned_marker_rows`` requires the job to own none), and the ordering
    # inside the orphan query picks the newest candidate job per contract.
    adopt: dict[Any, int] = {}
    for job_id, address, capability_expr, contract_id in _orphaned_marker_rows(session, chain_id):
        authorities = set(_iter_deferred_authorities(capability_expr))
        if not authorities:
            continue
        _addr, existing = by_job.setdefault(job_id, (address, set()))
        existing.update(authorities)
        adopt.setdefault(job_id, contract_id)

    stranded = _unreachable_orphan_contracts(session, chain_id)
    if stranded:
        # Not a sentinel that mitigates anything — a count that stops the
        # condition being invisible. These contracts have no job at their
        # (address, chain), so nothing here can converge them.
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
        # Wait until EVERY authority this job deferred on is backfilled. Partial
        # re-resolution would leave some leaves cold and risk re-selecting the
        # job every pass; gating on "all warm" bounds re-enqueues to one per
        # all-warm transition (backfill_complete is monotonic).
        if not all(_authority_backfilled(session, chain_id, addr) for addr in authorities):
            continue
        job = session.get(Job, job_id)
        if job is None or job.status != JobStatus.completed or job.stage != JobStage.done:
            continue
        if _address_has_active_job(session, job.address, chain_id=chain_id, exclude_job_id=job.id):
            continue
        orphan_contract_id = adopt.get(job_id)
        if orphan_contract_id is not None:
            contract = session.get(Contract, orphan_contract_id)
            # Re-check under the same transaction that produced the plan: the row
            # must still be orphaned and the job must still own nothing.
            if contract is None or contract.job_id is not None:
                continue
            if session.execute(select(Contract.id).where(Contract.job_id == job.id).limit(1)).first() is not None:
                continue
            # Repair the linkage, do not merely reach past it. The policy stage
            # writes ``effective_functions`` for ``Contract.job_id == job.id``;
            # re-enqueueing an address-matched job WITHOUT this would make that
            # stage log "no Contract row for job; wrote zero DB rows", leave the
            # marker in place, and hand the same job back to the next pass
            # forever — the thrash-free property depends on the re-run clearing
            # the marker. So the choice is repair-and-re-enqueue or leave it
            # alone; reach-without-repair is a re-enqueue storm plus a
            # guaranteed no-op.
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
            sorted(authorities),
        )

    if reenqueued:
        session.commit()
    else:
        session.rollback()
    return reenqueued


def _requeue_policy(job: Job, detail: str) -> None:
    """Reset a completed job to a fresh queued policy stage so the production
    pipeline re-resolves and re-persists everything. Clears the lease / backoff
    columns so ``claim_job`` mints a fresh lease immediately."""
    job.stage = JobStage.policy
    job.status = JobStatus.queued
    job.worker_id = None
    job.lease_id = None
    job.lease_expires_at = None
    job.next_attempt_at = None
    job.detail = detail


def _iter_role_store_frontiers(node: Any) -> Iterator[tuple[str, int]]:
    """Yield ``(authority, fold_frontier)`` for every ``enumerable_role_store`` trace
    step in a serialized ``capability_expr`` tree — the (address, height) the adapter
    folded a controller set up to. Walks ``children`` / ``signer`` like
    ``_iter_deferred_authorities`` so a step nested in an AND/OR composition is found.
    """
    if not isinstance(node, dict):
        return
    for step in node.get("trace") or []:
        if not isinstance(step, dict) or step.get("step") != ROLE_STORE_TRACE_STEP:
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
    """True iff a role-store grant/revoke row for ``event_address`` is indexed at a
    block PAST ``frontier`` — a membership change the persisted enumeration did not
    fold (``> frontier`` because the fold covered ``<= frontier`` inclusive)."""
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
    """One role-drift pass — the warm counterpart to the cold self-heal above.

    Re-enqueue the policy stage of every completed job whose persisted capability
    enumerated a role store (an ``enumerable_role_store`` trace step) once a
    grant/revoke has been indexed PAST that trace's fold frontier. Returns the
    number of jobs re-enqueued.

    Thrash-bounded: the re-run folds to the current head and stamps a higher
    ``fold_frontier``, so the same row never re-selects the job (the frontier is
    monotonic under the indexer). Gated on ``backfill_complete`` so a re-run lands
    a warm fold rather than bouncing straight back to a cold deferral. Reuses the
    reconciler's requeue machinery; does not touch the monitoring pipeline (§5).
    """
    rows = session.execute(
        select(Job.id, Job.address, EffectiveFunction.capability_expr)
        .join(Contract, Contract.job_id == Job.id)
        .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
        .where(Job.status == JobStatus.completed)
        .where(Job.stage == JobStage.done)
        .where(Job.chain_id == chain_id)
        .where(jsonb_has_payload(EffectiveFunction.capability_expr))
        .where(cast(EffectiveFunction.capability_expr, Text).ilike(f"%{ROLE_STORE_TRACE_STEP}%"))
    ).all()

    # job_id -> (address, {authority: lowest folded frontier seen})
    by_job: dict[Any, tuple[str | None, dict[str, int]]] = {}
    for job_id, address, capability_expr in rows:
        _addr, frontiers = by_job.setdefault(job_id, (address, {}))
        for authority, frontier in _iter_role_store_frontiers(capability_expr):
            # The lowest frontier is the conservative one: a row past even the
            # least-advanced fold means some persisted enumeration is stale.
            prior = frontiers.get(authority)
            frontiers[authority] = frontier if prior is None else min(prior, frontier)

    reenqueued = 0
    for job_id, (address, frontiers) in by_job.items():
        if reenqueued >= limit:
            break
        drifted = [
            authority
            for authority, frontier in frontiers.items()
            if _authority_backfilled(session, chain_id, authority)
            and _role_row_past_frontier(session, chain_id, authority, frontier)
        ]
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
