"""Resume selected effects once deferred token collection supplies their inputs.

A collection dependency, not a general retry or coverage queue. All writes use the caller's transaction; completed work
is never rearmed.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert

from db.models import Contract, ContractBalanceFetch, EffectVerdict, Job, JobStage, JobStatus
from db.models.balance_work import PendingEffectsWork
from services.effects.config import EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT
from utils.chains import UnknownChainError, chain_by_id, chain_by_name

logger = logging.getLogger(__name__)
DEPENDENT_FAMILIES = frozenset({EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT})
MAX_ATTEMPTS = 4


def balance_owners(session, protocol_id, chain_id, addresses):
    wanted = {a.lower() for a in addresses}
    owners = {}
    for cid, address, chain in session.execute(
        select(Contract.id, Contract.address, Contract.chain)
        .where(Contract.protocol_id == protocol_id, func.lower(Contract.address).in_(wanted))
        .order_by(Contract.id)
    ):
        try:
            if chain_by_name(chain or "ethereum").chain_id == chain_id:
                owners[address.lower()] = cid
        except UnknownChainError:
            continue
    return owners


def needs_token_inventory(session, candidate):
    from services.effects.calldata.executor import executor_call
    from services.effects.calldata.facts import load_contract_facts, resolve_function
    from services.effects.calldata.flows import _flow_directions
    from services.effects.calldata.roles import address_param_roles
    from services.resolution.differential_probe import _parse_arg_types

    facts = load_contract_facts(session, candidate.contract_address)
    fn = resolve_function(facts, candidate.selector) if facts else None
    if fn is None:
        return False  # missing facts do not establish a collection dependency
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return False
    roles = address_param_roles(fn, types, frozenset(_flow_directions(fn)))
    executor = executor_call(fn, types, held_tokens=(), recipient=candidate.probe_target)
    return "token" in roles.values() or executor is not None


def dependent_families(session, candidate):
    if candidate.restrict_families is not None:
        return DEPENDENT_FAMILIES & candidate.restrict_families
    from services.effects.calldata.facts import load_contract_facts, resolve_function
    from services.effects.calldata.flows import _OUT_DIRECTIONS, _flow_directions

    facts = load_contract_facts(session, candidate.contract_address)
    fn = resolve_function(facts, candidate.selector) if facts else None
    if fn is None:
        return frozenset()
    directions = _flow_directions(fn)
    labels = set(fn.effect_info.get("effect_labels") or ())
    families = set()
    if directions & _OUT_DIRECTIONS:
        families.add(EFFECT_CLASS_VALUE_OUT)
    if (directions | labels) & {"mint", "burn"}:
        families.add(EFFECT_CLASS_SUPPLY)
    return frozenset(families)


def collected_owners(session, owner_ids):
    if not owner_ids:
        return set()
    return set(
        session.scalars(
            select(ContractBalanceFetch.contract_id)
            .where(
                ContractBalanceFetch.contract_id.in_(owner_ids),
                ContractBalanceFetch.asset_set_status.in_(("returned_assets", "returned_empty")),
            )
            .distinct()
        )
    )


def prepare_work(session, candidates, *, protocol_id, chain_id, job_id):
    """Record missing collection inputs for already-selected functions only.

    Existing probes still run (their seeding may succeed without a portfolio); nothing else changes.
    """
    owners = balance_owners(session, protocol_id, chain_id, [c.probe_target for c in candidates])
    collected = collected_owners(session, list(owners.values()))
    families = {c.function_id: dependent_families(session, c) for c in candidates}
    ready = {
        c.function_id: bool(c.input_token_addresses) or owners.get(c.probe_target.lower()) in collected
        for c in candidates
    }
    inserts = []
    for c in candidates:
        if ready[c.function_id] or c.probe_target.lower() not in owners or not needs_token_inventory(session, c):
            continue
        for family in families[c.function_id]:
            inserts.append(
                dict(
                    protocol_id=protocol_id,
                    chain_id=chain_id,
                    deployment_address=c.probe_target.lower(),
                    contract_id=c.contract_id,
                    function_id=c.function_id,
                    effect_family=family,
                    reason="balance_inputs_pending",
                    state="pending",
                    attempts=0,
                )
            )
    for start in range(0, len(inserts), 1000):
        stmt = insert(PendingEffectsWork).values(inserts[start : start + 1000])
        session.execute(stmt.on_conflict_do_nothing(constraint="uq_pending_effects_identity"))
    session.flush()
    rows = session.scalars(
        select(PendingEffectsWork)
        .where(
            PendingEffectsWork.protocol_id == protocol_id,
            PendingEffectsWork.chain_id == chain_id,
            PendingEffectsWork.function_id.in_(families),
            PendingEffectsWork.state.in_(("pending", "queued")),
        )
        .with_for_update()
    ).all()
    by_function = {c.function_id: c for c in candidates}
    owned = {}
    for row in rows:
        c = by_function[row.function_id]
        if row.effect_family not in families[c.function_id] or row.deployment_address != c.probe_target.lower():
            continue
        if row.queued_job_id and row.queued_job_id != job_id:
            owner = session.get(Job, row.queued_job_id)
            if owner is not None and owner.status not in (JobStatus.completed, JobStatus.failed_terminal):
                continue
        row.queued_job_id = job_id
        row.state = "queued"
        # The inputs actually supplied, not ones published while probes ran.
        row._inputs_ready = ready[c.function_id]
        owned[(row.function_id, row.effect_family)] = row
    return owned


def finish_work(session, rows, *, job_id):
    """Close after input-backed analysis or proof; otherwise await collection.

    Call after persistence. An unknown with inputs available is an ordinary outcome, not a retry reason.
    """
    owned = [row for row in rows.values() if row.queued_job_id == job_id]
    waiting = [row.function_id for row in owned if not row._inputs_ready]
    proofs = (
        set(
            session.execute(
                select(EffectVerdict.function_id, EffectVerdict.chain_id, EffectVerdict.effect_class).where(
                    EffectVerdict.function_id.in_(waiting), EffectVerdict.verdict == "proven"
                )
            )
        )
        if waiting
        else set()
    )
    for row in owned:
        resolved = row._inputs_ready or (row.function_id, row.chain_id, row.effect_family) in proofs
        row.state = "complete" if resolved else "pending"
        row.reason = "collection_resolved" if resolved else "balance_inputs_pending"
        row.queued_job_id = None
        row.next_attempt_at = None
    pending = sum(row.state == "pending" for row in rows.values())
    if pending:
        logger.info("effects awaiting token collection job=%s dependencies=%d", job_id, pending)


def reconcile_pending_effects(session, protocol_id=None, limit=25):
    from services.effects.selection import _MAX_TOKEN_ARG_CANDIDATES, _token_holdings_by_contract

    now = datetime.now(timezone.utc)
    query = select(PendingEffectsWork).where(
        PendingEffectsWork.state.in_(("pending", "queued")),
        or_(PendingEffectsWork.next_attempt_at.is_(None), PendingEffectsWork.next_attempt_at <= now),
    )
    if protocol_id is not None:
        query = query.where(PendingEffectsWork.protocol_id == protocol_id)
    rows = session.scalars(
        query.order_by(PendingEffectsWork.updated_at, PendingEffectsWork.id)
        .with_for_update(skip_locked=True)
        .limit(limit)
    ).all()
    grouped_addresses = {}
    for row in rows:
        grouped_addresses.setdefault((row.protocol_id, row.chain_id), []).append(row.deployment_address)
    owners = {key: balance_owners(session, key[0], key[1], addresses) for key, addresses in grouped_addresses.items()}
    collected = collected_owners(session, [cid for group in owners.values() for cid in group.values()])
    holdings = {
        pid: _token_holdings_by_contract(session, pid, _MAX_TOKEN_ARG_CANDIDATES)
        for pid in {r.protocol_id for r in rows}
    }
    count = 0
    for row in rows:
        row.updated_at = now
        if row.queued_job_id:
            job = session.get(Job, row.queued_job_id)
            if job is not None and job.status not in (JobStatus.completed, JobStatus.failed_terminal):
                continue
            row.queued_job_id = None
            row.attempts += 1
            row.reason = "resume_job_interrupted"
            row.state = "degraded" if row.attempts >= MAX_ATTEMPTS else "pending"
            row.next_attempt_at = now + timedelta(minutes=min(60, 2**row.attempts))
            continue
        owner_id = owners[(row.protocol_id, row.chain_id)].get(row.deployment_address)
        if owner_id is None or (owner_id not in collected and not holdings[row.protocol_id].get(owner_id)):
            row.next_attempt_at = now + timedelta(minutes=1)
            continue
        job_id = uuid.uuid4()
        contract = session.get(Contract, row.contract_id)
        source_job = session.get(Job, contract.job_id) if contract is not None and contract.job_id else None
        root_id = ((source_job.request or {}).get("root_job_id") or str(source_job.id)) if source_job else str(job_id)
        job = Job(
            id=job_id,
            address=row.deployment_address,
            chain_id=row.chain_id,
            protocol_id=row.protocol_id,
            stage=JobStage.effects,
            status=JobStatus.queued,
            request={
                "address": row.deployment_address,
                "chain": chain_by_id(row.chain_id).name,
                "protocol_id": row.protocol_id,
                "root_job_id": root_id,
                "effects_resume_work_id": row.id,
                "effects_function_ids": [row.function_id],
            },
            detail="Resuming effects after token collection",
        )
        session.add(job)
        session.flush([job])
        row.queued_job_id = job_id
        row.state = "queued"
        row.next_attempt_at = None
        count += 1
    if count:
        logger.info("effects balance recovery queued=%d protocol_id=%s", count, protocol_id)
    return count
