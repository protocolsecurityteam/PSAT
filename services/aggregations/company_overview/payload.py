from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import and_, func, or_, select, tuple_
from sqlalchemy.orm import Session

from db.models import (
    ADMITTING_WITNESS_RULES,
    WITNESS_RULE_W2_STRUCTURAL,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    Job,
    JobStatus,
    PendingEffectsWork,
    Protocol,
    TvlSnapshot,
)
from schemas.api_responses import CompanyOverviewResponse, ReachBlock, TvlSummary
from schemas.control_tracking import MonitoredContractType
from services.clients.rpc import chain_id_for_chain_name
from services.discovery.membership_gate import membership_state, witness_is_heuristic
from services.discovery.probes import STATUS_NOT_ROUTABLE, STATUS_PROBED, UNRESOLVABLE_CHAIN_ID
from services.scoring.reach import REACH_MODEL, load_protocol_reach, merge_reach

from .entity_keys import _coalesce_chain, _entity_key
from .governance_view import build_governance_view
from .jobs import (
    CompanyNotFound,
    GovernanceView,
    _time_phase,
    prefetch_contracts,
    resolve_company_jobs,
    resolve_implementation_contracts,
)
from .principals import _MONITORED_TYPE_LOOKUP

logger = logging.getLogger("services.aggregations.company_overview")


def _protocol_inventory_filter(protocol_id: int):
    """Members plus this protocol's candidates/pruned rows.

    Another protocol's members never surface; unclaimed rows are outside the model (spec §3.1).
    """
    return or_(
        Contract.protocol_id == protocol_id,
        and_(Contract.protocol_id.is_(None), Contract.nominated_protocol_id == protocol_id),
    )


def _all_addresses_count(session: Session, protocol_row: Protocol) -> int:
    return int(
        session.execute(
            select(func.count()).select_from(Contract).where(_protocol_inventory_filter(protocol_row.id))
        ).scalar_one()
    )


def _witness_display_entry(row: ContractMembershipWitness) -> dict[str, Any]:
    entry: dict[str, Any] = {"rule": row.rule, "via_address": row.via_address}
    if row.rule == WITNESS_RULE_W2_STRUCTURAL and isinstance(row.evidence, dict):
        entry["edge_kind"] = row.evidence.get("edge_kind")
    # Never present heuristic membership as proven.
    entry["heuristic"] = witness_is_heuristic(row)
    return entry


def _candidate_reason(attempt: ContractProbeAttempt | None) -> dict[str, Any]:
    """Invariant 5: parked state named from the persisted probe row. ``no_probe_attempt`` means no row exists."""
    if attempt is None:
        return {"kind": "no_probe_attempt"}
    results = attempt.results if isinstance(attempt.results, dict) else {}
    status = results.get("status")
    if status == STATUS_PROBED:
        reads = results.get("reads")
        resolved: dict[str, str] = {}
        unresolved: list[str] = []
        if isinstance(reads, dict):
            for name in sorted(reads):
                read = reads.get(name)
                value = read.get("value") if isinstance(read, dict) else None
                if isinstance(value, str) and value:
                    resolved[name] = value
                else:
                    unresolved.append(name)
        return {
            "kind": "probe_unresolved",
            "probe_block": attempt.block_number,
            "resolved_reads": resolved,
            "unresolved_reads": unresolved,
        }
    if status == STATUS_NOT_ROUTABLE:
        return {"kind": "chain_not_routable", "chain": results.get("chain")}
    return {"kind": "probe_error"}


def _membership_fields(session: Session, rows: list[Contract]) -> dict[int, dict[str, Any]]:
    """Membership display fields (spec §5.2). One query per evidence table, never per row."""
    chain_ids = {cr.id: chain_id_for_chain_name(cr.chain) for cr in rows}
    code_pairs = sorted(
        {(cid, cr.address.lower()) for cr in rows if cr.address and (cid := chain_ids.get(cr.id)) is not None}
    )
    code_facts: dict[tuple[int, str], ContractCreationWitness] = {}
    if code_pairs:
        for fact in session.execute(
            select(ContractCreationWitness).where(
                tuple_(ContractCreationWitness.chain_id, ContractCreationWitness.address).in_(code_pairs)
            )
        ).scalars():
            code_facts[(fact.chain_id, fact.address)] = fact

    states: dict[int, str] = {}
    for cr in rows:
        code_absent: bool | None = None
        chain_id = chain_ids.get(cr.id)
        if chain_id is not None and cr.address:
            fact = code_facts.get((chain_id, cr.address.lower()))
            if fact is not None:
                code_absent = fact.code_absent_at_probe
        states[cr.id] = membership_state(cr, code_absent_at_probe=code_absent)

    member_protocol: dict[int, int] = {
        cr.id: cr.protocol_id for cr in rows if states[cr.id] == "member" and cr.protocol_id is not None
    }
    witnesses_by_contract: dict[int, list[dict[str, Any]]] = {}
    if member_protocol:
        for w in session.execute(
            select(ContractMembershipWitness)
            .where(
                ContractMembershipWitness.contract_id.in_(sorted(member_protocol)),
                ContractMembershipWitness.revoked_at.is_(None),
                ContractMembershipWitness.rule.in_(sorted(ADMITTING_WITNESS_RULES)),
            )
            .order_by(
                ContractMembershipWitness.rule, ContractMembershipWitness.via_address, ContractMembershipWitness.id
            )
        ).scalars():
            if w.protocol_id == member_protocol.get(w.contract_id):
                witnesses_by_contract.setdefault(w.contract_id, []).append(_witness_display_entry(w))

    candidate_ids = sorted(cid for cid, state in states.items() if state == "candidate")
    attempts: dict[tuple[int, int], ContractProbeAttempt] = {}
    if candidate_ids:
        for attempt in session.execute(
            select(ContractProbeAttempt).where(ContractProbeAttempt.contract_id.in_(candidate_ids))
        ).scalars():
            attempts[(attempt.contract_id, attempt.chain_id)] = attempt

    out: dict[int, dict[str, Any]] = {}
    for cr in rows:
        state = states[cr.id]
        reason: dict[str, Any] | None = None
        if state == "candidate":
            key_chain = chain_ids.get(cr.id)
            reason = _candidate_reason(attempts.get((cr.id, UNRESOLVABLE_CHAIN_ID if key_chain is None else key_chain)))
        elif state == "pruned":
            chain_id = chain_ids.get(cr.id)
            fact = code_facts.get((chain_id, cr.address.lower())) if chain_id is not None and cr.address else None
            reason = {"kind": "code_absent", "code_probe_block": fact.code_probe_block if fact else None}
        out[cr.id] = {
            "membership_state": state,
            "membership_witnesses": witnesses_by_contract.get(cr.id, []),
            "membership_reason": reason,
        }
    return out


def all_addresses_for_protocol(session: Session, protocol_row: Protocol) -> list[dict[str, Any]]:
    all_contract_rows = (
        session.execute(select(Contract).where(_protocol_inventory_filter(protocol_row.id))).scalars().all()
    )

    # Composite keys so another chain's twin's name isn't shown.
    impl_name_by_entity = {
        _entity_key(c.chain, c.address): c.contract_name for c in all_contract_rows if c.address and c.contract_name
    }
    job_ids = {cr.job_id for cr in all_contract_rows if cr.job_id is not None}
    completed_job_ids: set = set()
    if job_ids:
        completed_job_ids = set(
            session.execute(select(Job.id).where(Job.id.in_(job_ids), Job.status == JobStatus.completed))
            .scalars()
            .all()
        )
    membership = _membership_fields(session, list(all_contract_rows))

    return sorted(
        [
            {
                "address": cr.address,
                "name": cr.contract_name,
                **membership[cr.id],
                "source_verified": cr.source_verified,
                "is_proxy": cr.is_proxy,
                "analyzed": cr.job_id is not None and cr.job_id in completed_job_ids,
                "discovery_sources": list(cr.discovery_sources or []),
                "discovery_url": cr.discovery_url,
                "chain": cr.chain,
                "rank_score": (float(cr.rank_score) if cr.rank_score is not None else None),
                "implementation_address": cr.implementation if cr.is_proxy else None,
                "implementation_name": (
                    impl_name_by_entity.get(_entity_key(cr.chain, cr.implementation)) if cr.is_proxy else None
                ),
            }
            for cr in all_contract_rows
        ],
        key=lambda x: (not x["analyzed"], x["name"] or "zzz"),
    )


def _latest_tvl(session: Session, protocol_row: Protocol) -> TvlSummary | None:
    latest_tvl = session.execute(
        select(TvlSnapshot)
        .where(TvlSnapshot.protocol_id == protocol_row.id)
        .order_by(TvlSnapshot.timestamp.desc())
        .limit(1)
    ).scalar_one_or_none()
    if latest_tvl is None:
        return None
    from services.aggregations.tvl import snapshot_payload

    return snapshot_payload(latest_tvl)


def _company_reach(session: Session, contracts_by_job_id: dict[Any, Contract]) -> ReachBlock:
    """Scorer reach claims.

    Computed here, not in ``build_governance_view``, because the monitoring reconciler also calls that and can't afford
    the scorer planes in 512 MB.
    """
    protocol_ids = {c.protocol_id for c in contracts_by_job_id.values() if c is not None and c.protocol_id is not None}
    return {
        "model": REACH_MODEL,
        "entities": merge_reach(load_protocol_reach(session, pid) for pid in sorted(protocol_ids)),
    }


def _balance_effects_coverage(session: Session, protocol: Protocol) -> dict[str, int]:
    states: dict[str, int] = {
        state: count
        for state, count in session.execute(
            select(PendingEffectsWork.state, func.count())
            .where(PendingEffectsWork.protocol_id == protocol.id, PendingEffectsWork.state != "complete")
            .group_by(PendingEffectsWork.state)
        ).all()
    }
    return {"incomplete": sum(states.values()), "degraded": states.get("degraded", 0)}


def assemble_company_payload(
    session: Session,
    name: str,
    protocol_row: Protocol,
    governance: GovernanceView,
    reach: ReachBlock,
    *,
    include_summary: bool = True,
) -> CompanyOverviewResponse:
    payload: CompanyOverviewResponse = {
        "company": name,
        "protocol_id": protocol_row.id,
        "contract_count": len(governance.contracts),
        "contracts": governance.contracts,
        "principals": governance.principals,
        "ownership_hierarchy": governance.hierarchy,
        "fund_flows": governance.fund_flows,
        "reach": reach,
        # The full inventory (~167 KB) is served lazily by /api/company/{name}/addresses.
        "all_addresses_count": _all_addresses_count(session, protocol_row),
    }

    if include_summary:
        payload["tvl"] = _latest_tvl(session, protocol_row)
        payload["analysis_pending_balance_effects"] = _balance_effects_coverage(session, protocol_row)
    return payload


def build_company_summary(session: Session, name: str) -> dict[str, Any]:
    protocol = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if protocol is None:
        raise CompanyNotFound(name)
    return {
        "tvl": _latest_tvl(session, protocol),
        "analysis_pending_balance_effects": _balance_effects_coverage(session, protocol),
    }


def build_company_overview(session: Session, name: str, *, include_summary: bool = True) -> CompanyOverviewResponse:
    timings_ms: dict[str, int] = {}
    start = time.monotonic()

    with _time_phase(timings_ms, "resolve_jobs"):
        protocol_row, jobs = resolve_company_jobs(session, name)
    if protocol_row is None or not jobs:
        raise CompanyNotFound(name)
    with _time_phase(timings_ms, "prefetch_contracts"):
        contracts_by_job_id = prefetch_contracts(session, jobs)
    with _time_phase(timings_ms, "resolve_implementation_contracts"):
        impl_job_by_entity, contracts_by_job_id = resolve_implementation_contracts(session, jobs, contracts_by_job_id)
    with _time_phase(timings_ms, "build_governance_view"):
        governance = build_governance_view(session, jobs, contracts_by_job_id, impl_job_by_entity)
    with _time_phase(timings_ms, "compute_reach"):
        reach = _company_reach(session, contracts_by_job_id)
    with _time_phase(timings_ms, "assemble_payload"):
        payload = assemble_company_payload(
            session, name, protocol_row, governance, reach, include_summary=include_summary
        )

    total_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "Company overview built: company=%s jobs=%d contracts=%d total_ms=%d",
        name,
        len(jobs),
        len(payload.get("contracts") or []),
        total_ms,
        extra={
            "phase": "build_company_overview",
            "duration_ms": total_ms,
            "company": name,
            "job_count": len(jobs),
            "contract_count": len(payload.get("contracts") or []),
            "timings_ms": timings_ms,
        },
    )
    return payload


def controllers_for_protocol(session: Session, protocol_id: int) -> dict[tuple[str, str], MonitoredContractType]:
    """``(principal, chain) -> MonitoredContract.contract_type`` for primary controllers union privileged
    co-controllers.

    Chain is where the governed contracts live (``controls_chains``). The canvas groups by ``primary_for`` only, but
    monitoring watches the union: a guardian Safe or withdrawal timelock emits its own governance events. EOAs are
    dropped; ``proxy_admin`` maps to ``'proxy'``.
    """
    protocol = session.get(Protocol, protocol_id)
    if protocol is None:
        return {}
    _protocol_row, jobs = resolve_company_jobs(session, protocol.name)
    if not jobs:
        return {}
    contracts_by_job_id = prefetch_contracts(session, jobs)
    impl_job_by_entity, contracts_by_job_id = resolve_implementation_contracts(session, jobs, contracts_by_job_id)
    governance = build_governance_view(session, jobs, contracts_by_job_id, impl_job_by_entity)

    controllers: dict[tuple[str, str], MonitoredContractType] = {}
    for principal in governance.principals:
        if not (principal.get("primary_for") or principal.get("co_controls")):
            continue
        ptype = principal.get("type")
        monitored_type = _MONITORED_TYPE_LOOKUP.get(ptype) if isinstance(ptype, str) else None
        if monitored_type is None:
            continue
        addr = (principal.get("address") or "").lower()
        if not addr:
            continue
        for chain_token in principal.get("controls_chains") or [_coalesce_chain(None)]:
            controllers[(addr, chain_token)] = monitored_type
    return controllers
