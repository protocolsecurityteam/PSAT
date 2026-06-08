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
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

from sqlalchemy import Text, cast, func, select
from sqlalchemy.orm import Session

from db.models import Contract, EffectiveFunction, IndexedEventCursor, Job, JobStage, JobStatus
from utils.rpc import require_supported_chain_id

logger = logging.getLogger(__name__)

# The marker the index-cold adapter paths stamp into
# ``external_check_only.check.extra``. Shared with the adapters by value
# (a bare string) to avoid a worker→adapter import dependency.
DEFERRED_MARKER = "deferred_pending_index"


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
    ``address`` on ``chain_id`` other than ``exclude_job_id`` — so the reconciler
    does not pile a second re-analysis on top of one already in flight."""
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
    chain_id = require_supported_chain_id(chain_id=chain_id, context="deferred resolution reconciliation")
    # Cheap pre-filter: only effective_functions whose serialized capability
    # tree mentions the marker. The JSONB→text cast LIKE catches the marker even
    # when the deferred leaf is nested inside an AND/OR; the precise per-leaf
    # walk happens in Python below.
    rows = session.execute(
        select(Job.id, Job.address, EffectiveFunction.capability_expr)
        .join(
            Contract,
            (func.lower(Contract.address) == func.lower(Job.address)) & (Contract.chain_id == Job.chain_id),
        )
        .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
        .where(Job.status == JobStatus.completed)
        .where(Job.stage == JobStage.done)
        .where(Job.chain_id == chain_id)
        .where(Contract.chain_id == chain_id)
        .where(EffectiveFunction.capability_expr.isnot(None))
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
        # Reset to the policy stage so the production pipeline re-resolves and
        # re-persists everything against the now-warm index. Clear the lease /
        # backoff columns so ``claim_job`` mints a fresh lease immediately.
        job.stage = JobStage.policy
        job.status = JobStatus.queued
        job.worker_id = None
        job.lease_id = None
        job.lease_expires_at = None
        job.next_attempt_at = None
        job.detail = "Re-resolving: durable event index caught up for a deferred authority"
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
