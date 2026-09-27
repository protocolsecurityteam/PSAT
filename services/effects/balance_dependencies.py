"""Durable recovery of effects work whose balance inputs are incomplete.

All writes use the caller's transaction. Enqueue and pending ownership are atomic;
a worker crash is recovered by the ordinary job lease machinery.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.dialects.postgresql import insert

from db.models import Contract, ContractBalanceFetch, ContractBalanceLatest, Job, JobStage, JobStatus
from db.models.balance_work import PendingEffectsWork
from services.effects.config import EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT
from utils.chains import UnknownChainError, chain_by_id, chain_by_name

logger = logging.getLogger(__name__)
DEPENDENT_FAMILIES = frozenset({EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT})
MAX_ATTEMPTS = 4
SEMANTICS_VERSION = 2
# Independent calldata has no portfolio identity prerequisite. Persist this
# dependency kind in the fingerprint slot, so unrelated arrivals cannot rearm it.
INVENTORY_INDEPENDENT = "independent:v2"


def token_fingerprint(tokens):
    """Identity/eligibility only: quantity or price fluctuations do not re-probe."""
    return hashlib.sha256(json.dumps([SEMANTICS_VERSION, sorted(set(tokens))]).encode()).hexdigest()


def balance_owners(session, protocol_id, chain_id, addresses):
    """Resolve observed holders separately from the contracts supplying code."""
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


def evidence_inputs(session, owner_ids):
    """Batch bounded current read evidence; historical rows never reach Python."""
    if not owner_ids:
        return {}
    observations = {}
    queries = (
        (
            "generation",
            select(ContractBalanceFetch.contract_id, func.max(ContractBalanceFetch.id))
            .where(ContractBalanceFetch.contract_id.in_(owner_ids))
            .group_by(ContractBalanceFetch.contract_id),
        ),
        (
            "native",
            select(ContractBalanceFetch.contract_id, ContractBalanceFetch.native_status)
            .where(
                ContractBalanceFetch.contract_id.in_(owner_ids),
                ContractBalanceFetch.native_status.in_(("proven_zero", "proven_nonzero")),
                ContractBalanceFetch.block_number.is_not(None),
            )
            .distinct(ContractBalanceFetch.contract_id)
            .order_by(ContractBalanceFetch.contract_id, ContractBalanceFetch.id.desc()),
        ),
        (
            "assets",
            select(ContractBalanceFetch.contract_id, ContractBalanceFetch.asset_set_status)
            .where(
                ContractBalanceFetch.contract_id.in_(owner_ids),
                ContractBalanceFetch.asset_set_status.in_(("returned_assets", "returned_empty", "at_page_cap")),
            )
            .distinct(ContractBalanceFetch.contract_id)
            .order_by(ContractBalanceFetch.contract_id, ContractBalanceFetch.id.desc()),
        ),
    )
    for field, query in queries:
        for cid, value in session.execute(query):
            observations.setdefault(cid, {})[field] = value
    for cid, token, raw in session.execute(
        select(
            ContractBalanceLatest.contract_id, ContractBalanceLatest.token_address, ContractBalanceLatest.raw_balance
        ).where(ContractBalanceLatest.contract_id.in_(owner_ids))
    ):
        observations.setdefault(cid, {}).setdefault("quantities", []).append(
            (token.lower() if token else "native", str(raw))
        )
    from services.monitoring.balance_reads import partial_asset_rows

    protocol_ids = session.scalars(select(Contract.protocol_id).where(Contract.id.in_(owner_ids)).distinct()).all()
    for protocol_id in protocol_ids:
        if protocol_id is None:
            continue
        for cid, partials in partial_asset_rows(session, protocol_id).items():
            if cid in observations:
                observations[cid]["partial_quantities"] = [
                    (row.token_address.lower(), str(row.raw_balance)) for row in partials if row.token_address
                ]
    return observations


def evidence_snapshot(inputs, owner_id, tokens):
    """Required quantity/read-quality progress, excluding quotes and block churn."""
    data = inputs.get(owner_id, {})
    relevant = {t.lower() for t in tokens} or {"native"}
    quantities = sorted((token, raw) for token, raw in data.get("quantities", ()) if token in relevant)
    partial_quantities = sorted((token, raw) for token, raw in data.get("partial_quantities", ()) if token in relevant)
    payload = [data.get("native") if "native" in relevant else None, data.get("assets"), quantities, partial_quantities]
    return data.get("generation", 0), hashlib.sha256(json.dumps(payload).encode()).hexdigest()


def needs_token_inventory(session, candidate):
    """Only a token argument/executor payload needs a discovered token universe."""
    from services.effects.calldata.executor import executor_call
    from services.effects.calldata.facts import load_contract_facts, resolve_function
    from services.effects.calldata.flows import _flow_directions
    from services.effects.calldata.roles import address_param_roles
    from services.resolution.differential_probe import _parse_arg_types

    facts = load_contract_facts(session, candidate.contract_address)
    fn = resolve_function(facts, candidate.selector) if facts else None
    if fn is None:
        return True  # no static proof that this family is independent
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return True
    roles = address_param_roles(fn, types, frozenset(_flow_directions(fn)))
    executor = executor_call(fn, types, held_tokens=(), recipient=candidate.probe_target)
    return "token" in roles.values() or executor is not None


def accepted_generations(session, contract_ids):
    if not contract_ids:
        return {}
    rows = session.execute(
        select(ContractBalanceFetch.contract_id, ContractBalanceFetch.id)
        .where(
            ContractBalanceFetch.contract_id.in_(contract_ids),
            ContractBalanceFetch.asset_set_status.in_(("returned_assets", "returned_empty", "at_page_cap")),
            ContractBalanceFetch.asset_set_source == "etherscan_pages",
        )
        .distinct(ContractBalanceFetch.contract_id)
        .order_by(ContractBalanceFetch.contract_id, ContractBalanceFetch.id.desc())
    ).all()
    return {cid: generation for cid, generation in rows}


def inventory_fingerprints(session, contract_ids):
    """Identity changes can require new probes; quote/amount changes cannot."""
    from services.monitoring.balance_reads import positive_raw_balance

    if not contract_ids:
        return {}
    rows = session.execute(
        select(
            ContractBalanceLatest.contract_id, ContractBalanceLatest.token_address, ContractBalanceLatest.raw_balance
        ).where(ContractBalanceLatest.contract_id.in_(contract_ids))
    ).all()
    assets = {cid: [] for cid in contract_ids}
    for cid, token, raw in rows:
        if token and positive_raw_balance(raw):
            assets[cid].append(token.lower())
    from db.models import Contract
    from services.monitoring.balance_reads import partial_asset_rows

    protocol_ids = session.scalars(select(Contract.protocol_id).where(Contract.id.in_(contract_ids)).distinct()).all()
    for protocol_id in protocol_ids:
        if protocol_id is None:
            continue
        for cid, partials in partial_asset_rows(session, protocol_id).items():
            if cid in assets:
                assets[cid].extend(
                    r.token_address.lower() for r in partials if r.token_address and positive_raw_balance(r.raw_balance)
                )
    return {cid: token_fingerprint(tokens) for cid, tokens in assets.items()}


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


def prepare_work(session, candidates, *, protocol_id, chain_id, selected_ids, job_id=None):
    """Persist prerequisites AND resource deferrals before any simulation runs."""
    owners = balance_owners(session, protocol_id, chain_id, [c.probe_target for c in candidates])
    owner_ids = list(owners.values())
    evidence = evidence_inputs(session, owner_ids)
    owner_generations = accepted_generations(session, owner_ids)
    fingerprints = inventory_fingerprints(session, owner_ids)
    generations = {c.function_id: owner_generations.get(owners.get(c.probe_target.lower()), 0) for c in candidates}
    inventory_required = {c.function_id: needs_token_inventory(session, c) for c in candidates}
    inserts = []
    for c in candidates:
        families = dependent_families(session, c)
        if c.function_id not in selected_ids:
            families = families | {"candidate_selection"}
        for family in families:
            owner_id = owners.get(c.probe_target.lower())
            generation = generations.get(c.function_id, 0)
            evidence_generation, evidence_fingerprint = evidence_snapshot(evidence, owner_id, c.input_token_addresses)
            reason = "resource_cap" if c.function_id not in selected_ids else "balance_inputs_pending"
            inserts.append(
                dict(
                    protocol_id=protocol_id,
                    chain_id=chain_id,
                    deployment_address=c.probe_target.lower(),
                    contract_id=c.contract_id,
                    function_id=c.function_id,
                    effect_family=family,
                    reason=reason,
                    state="pending",
                    required_generation=generation,
                    consumed_generation=0,
                    input_fingerprint=(
                        fingerprints.get(owner_id) if inventory_required[c.function_id] else INVENTORY_INDEPENDENT
                    ),
                    evidence_generation=evidence_generation,
                    evidence_fingerprint=evidence_fingerprint,
                    covered_tokens=[],
                    candidate_tokens=list(c.input_token_addresses),
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
            PendingEffectsWork.function_id.in_([c.function_id for c in candidates]),
        )
        .with_for_update()
    ).all()
    by_function = {c.function_id: c for c in candidates}
    for row in rows:
        if job_id and row.queued_job_id and row.queued_job_id != job_id:
            owner = session.get(Job, row.queued_job_id)
            if owner is not None and owner.status not in (JobStatus.completed, JobStatus.failed_terminal):
                continue
        row.candidate_tokens = sorted(
            set(row.candidate_tokens or ()) | set(by_function[row.function_id].input_token_addresses)
        )
        owner_id = owners.get(row.deployment_address.lower())
        fingerprint = fingerprints.get(owner_id) if inventory_required[row.function_id] else INVENTORY_INDEPENDENT
        if row.input_fingerprint != fingerprint:
            row.input_fingerprint = fingerprint
            row.state = "pending"
            row.reason = "asset_inputs_changed"
            row.attempts = 0
        row.evidence_generation, row.evidence_fingerprint = evidence_snapshot(evidence, owner_id, row.candidate_tokens)
        # Preserve the inputs captured before probing; later getter identities must
        # not accidentally acknowledge a concurrently published observation.
        row._probe_evidence = (evidence, owner_id)
        if job_id and row.function_id in selected_ids and row.state != "complete":
            row.queued_job_id = job_id
            row.state = "queued"
    return {(r.function_id, r.effect_family): r for r in rows}, generations


def should_block(row, generation, *, requires_inventory=True, tokens=()):
    return row is not None and requires_inventory and generation == 0 and not tokens


def finish_work(row, *, generation, tokens, remaining, succeeded, job_id):
    """A bounded degraded outcome remains visible; a changed input can revive it."""
    row.required_generation = generation
    row.queued_job_id = None
    row.attempts += 1
    row.next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=min(60, 2**row.attempts))
    if succeeded:
        row.consumed_generation = generation
        row.covered_tokens = sorted(set(row.covered_tokens or ()) | set(tokens))
        if not remaining:
            row.state = "complete"
            row.reason = "covered"
            row.attempts = 0
            row.next_attempt_at = None
            return
        row.reason = "token_budget"
        row.attempts = 0  # durable progress earns the next bounded chunk
    else:
        row.reason = "probe_incomplete"
    row.state = "degraded" if row.attempts >= MAX_ATTEMPTS else "pending"


def reconcile_pending_effects(session, protocol_id=None, limit=25):
    """Queue targeted effects retries, using durable pending rows as the outbox.

    Call in a short transaction periodically, including after balance publication.
    No provider calls, internal commits, or dependence on a best-effort callback.
    """
    now = datetime.now(timezone.utc)
    usable_fetch = exists(
        select(ContractBalanceFetch.id).where(
            ContractBalanceFetch.contract_id == Contract.id,
            Contract.protocol_id == PendingEffectsWork.protocol_id,
            ContractBalanceFetch.chain_id == PendingEffectsWork.chain_id,
            func.lower(ContractBalanceFetch.observed_address) == PendingEffectsWork.deployment_address,
            ContractBalanceFetch.id > PendingEffectsWork.evidence_generation,
        )
    )
    query = select(PendingEffectsWork).where(
        or_(
            and_(
                PendingEffectsWork.state.in_(("pending", "queued")),
                or_(PendingEffectsWork.next_attempt_at.is_(None), PendingEffectsWork.next_attempt_at <= now),
                or_(
                    usable_fetch,
                    PendingEffectsWork.effect_family == "candidate_selection",
                    PendingEffectsWork.required_generation > 0,
                    PendingEffectsWork.state == "queued",
                    PendingEffectsWork.reason.in_(
                        (
                            "resource_cap",
                            "resume_job_interrupted",
                            "token_budget",
                            "probe_incomplete",
                            "planning_incomplete",
                            "token_getter_pending",
                        )
                    ),
                ),
            ),
            and_(
                PendingEffectsWork.state.in_(("complete", "degraded")),
                or_(PendingEffectsWork.state != "complete", PendingEffectsWork.effect_family != "candidate_selection"),
                usable_fetch,
            ),
        )
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
    grouped_owners = {
        key: balance_owners(session, key[0], key[1], addresses) for key, addresses in grouped_addresses.items()
    }
    owner_by_row = {
        row.id: grouped_owners[(row.protocol_id, row.chain_id)].get(row.deployment_address.lower()) for row in rows
    }
    owner_ids = [cid for cid in owner_by_row.values() if cid is not None]
    evidence = evidence_inputs(session, owner_ids)
    generations = accepted_generations(session, owner_ids)
    fingerprints = inventory_fingerprints(session, owner_ids)
    count = 0
    for row in rows:
        if row.queued_job_id:
            job = session.get(Job, row.queued_job_id)
            if job is not None and job.status not in (JobStatus.completed, JobStatus.failed_terminal):
                row.updated_at = now
                continue
            row.queued_job_id = None
            row.attempts += 1
            row.reason = "resume_job_interrupted"
            row.state = "degraded" if row.attempts >= MAX_ATTEMPTS else "pending"
            row.next_attempt_at = now + timedelta(minutes=min(60, 2**row.attempts))
            row.updated_at = now
            continue
        owner_id = owner_by_row[row.id]
        generation = generations.get(owner_id, 0)
        fingerprint = (
            INVENTORY_INDEPENDENT if row.input_fingerprint == INVENTORY_INDEPENDENT else fingerprints.get(owner_id)
        )
        changed = fingerprint != row.input_fingerprint
        evidence_generation, evidence_fingerprint = evidence_snapshot(evidence, owner_id, row.candidate_tokens)
        progressed = evidence_fingerprint != row.evidence_fingerprint
        row.evidence_generation = evidence_generation
        row.evidence_fingerprint = evidence_fingerprint
        if row.state in ("complete", "degraded") and not changed and not (row.state == "degraded" and progressed):
            row.consumed_generation = generation
            row.updated_at = now
            continue
        if changed or (row.state == "degraded" and progressed):
            row.state = "pending"
            row.reason = "asset_inputs_changed"
            row.input_fingerprint = fingerprint
            row.attempts = 0
            row.next_attempt_at = None
        if not generation and row.effect_family != "candidate_selection" and row.reason == "balance_inputs_pending":
            # Rotate the fair scan without spending an attempt on absent evidence.
            row.updated_at = now
            continue
        if row.next_attempt_at and row.next_attempt_at > now:
            row.updated_at = now
            continue
        job_id = uuid.uuid4()
        request = {
            "address": row.deployment_address,
            "chain": chain_by_id(row.chain_id).name,
            "protocol_id": row.protocol_id,
            "effects_resume_work_id": row.id,
            "effects_function_ids": [row.function_id],
        }
        job = Job(
            id=job_id,
            address=row.deployment_address,
            chain_id=row.chain_id,
            protocol_id=row.protocol_id,
            stage=JobStage.effects,
            status=JobStatus.queued,
            request=request,
            detail="Retrying incomplete balance-dependent effects",
        )
        session.add(job)
        session.flush([job])  # satisfy the FK before the pending-row update
        row.queued_job_id = job_id
        row.required_generation = generation
        row.state = "queued"
        row.updated_at = now
        count += 1
    if count:
        logger.info("effects balance recovery queued=%d protocol_id=%s", count, protocol_id)
    return count


def with_relevant_tokens(session, candidate, ctx, covered=(), cache=None):
    """Resolve function-named token getters on THIS chain/deployment/block.

    This is the same bounded identity operation seeding uses. A source literal,
    discovery match, or unsolicited unpriced holding is never relevance evidence.
    Resolved getter identities need no price or present positive balance: future
    deposits and minting remain valid security questions.
    """
    from eth_utils.crypto import keccak

    from services.effects.calldata.facts import load_contract_facts, resolve_function
    from services.effects.calldata.seeding import input_token_hints
    from services.effects.seeding import budget_of
    from services.effects.simulate import SimCall

    cache = cache if cache is not None else {}
    facts = load_contract_facts(session, candidate.contract_address)
    fn = resolve_function(facts, candidate.selector) if facts is not None else None
    required = set(h for h in input_token_hints(fn, include_default_asset=False) if h.endswith("()")) if fn else set()
    getters = tuple(h for h in input_token_hints(fn) if h.endswith("()")) if fn else ()
    key = (ctx.chain_id, candidate.probe_target.lower(), ctx.block, getters, tuple(sorted(required)))
    cached = cache.get(key)
    if cached is None:
        relevant = []
        incomplete = False
        budget = budget_of(ctx.effective_seeder())
        permitted = not getters or (
            budget.take_identity(candidate.probe_target) if budget is not None else len(cache) < 8
        )
        if getters and ctx.block > 0 and permitted:
            calls = [SimCall(to=candidate.probe_target, data="0x" + keccak(text=sig)[:4].hex()) for sig in getters[:8]]
            incomplete = bool(required - set(getters[:8]))
            try:
                if ctx.on_requests:
                    ctx.on_requests(1)
                if ctx.simulate_supported:
                    results = ctx.simulate(calls, hex(ctx.block), None).calls
                elif getattr(ctx, "call_batch", None) is not None:
                    results = ctx.call_batch([{"to": c.to, "data": c.data} for c in calls], hex(ctx.block))
                else:
                    results = ()
                for index, sig in enumerate(getters[:8]):
                    item = results[index] if index < len(results) else None
                    raw = item.return_data.removeprefix("0x") if item else ""
                    try:
                        valid = bool(
                            item and item.success and len(raw) == 64 and int(raw[:24], 16) == 0 and int(raw[24:], 16)
                        )
                    except ValueError:
                        valid = False
                    if valid:
                        relevant.append("0x" + raw[24:].lower())
                    elif sig in required:
                        incomplete = True
            except Exception:
                incomplete = bool(required)
                logger.info(
                    "effects token getter unavailable chain=%s deployment=%s", ctx.chain_id, candidate.probe_target
                )
        elif getters:
            incomplete = bool(required)
        cache[key] = (relevant, incomplete)
    else:
        relevant, incomplete = cached
    arbitrary_inputs = (
        [*candidate.input_token_addresses, *sorted(covered)] if needs_token_inventory(session, candidate) else []
    )
    tokens = list(dict.fromkeys([*relevant, *arbitrary_inputs]))
    untried = [t for t in tokens if t not in covered]
    # A regular analysis with all identities covered still has normal useful inputs.
    selected = (untried or tokens)[:1]
    return replace(
        candidate,
        input_token_addresses=tuple(selected),
        deferred_token_addresses=tuple(untried[1:]),
        token_inputs_pending=incomplete,
    )
