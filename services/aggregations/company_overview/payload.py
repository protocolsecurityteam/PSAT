"""Protocol-wide views + final payload assembly (``build_company_overview``)."""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStatus, Protocol, TvlSnapshot
from schemas.api_responses import CompanyOverviewResponse, ReachBlock, TvlSummary
from schemas.control_tracking import MonitoredContractType
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


def _all_addresses_count(session: Session, protocol_row: Protocol | None, jobs: list[Job]) -> int:
    if protocol_row:
        return int(
            session.execute(
                select(func.count()).select_from(Contract).where(Contract.protocol_id == protocol_row.id)
            ).scalar_one()
        )
    fallback_job_ids = [j.id for j in jobs]
    if not fallback_job_ids:
        return 0
    return int(
        session.execute(
            select(func.count()).select_from(Contract).where(Contract.job_id.in_(fallback_job_ids))
        ).scalar_one()
    )


def all_addresses_for_protocol(
    session: Session, protocol_row: Protocol | None, jobs: list[Job]
) -> list[dict[str, Any]]:
    if protocol_row:
        all_contract_rows = (
            session.execute(select(Contract).where(Contract.protocol_id == protocol_row.id)).scalars().all()
        )
    else:
        fallback_job_ids = [j.id for j in jobs]
        if fallback_job_ids:
            all_contract_rows = list(
                session.execute(select(Contract).where(Contract.job_id.in_(fallback_job_ids))).scalars()
            )
        else:
            all_contract_rows = []

    # Prefetch impl-name lookup so proxy rows can expose the implementation
    # contract name alongside their own generic "UUPSProxy"/"ERC1967Proxy"
    # template name. Keyed by the composite entity token (a proxy's impl is on
    # the proxy's own chain) so a same-address twin on another chain doesn't
    # display the other chain's name.
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

    return sorted(
        [
            {
                "address": cr.address,
                "name": cr.contract_name,
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


def _latest_tvl(session: Session, protocol_row: Protocol | None) -> TvlSummary | None:
    if protocol_row is None:
        return None
    latest_tvl = session.execute(
        select(TvlSnapshot)
        .where(TvlSnapshot.protocol_id == protocol_row.id)
        .order_by(TvlSnapshot.timestamp.desc())
        .limit(1)
    ).scalar_one_or_none()
    if latest_tvl is None:
        return None
    return {
        "total_usd": float(latest_tvl.total_usd) if latest_tvl.total_usd else None,
        "defillama_tvl": float(latest_tvl.defillama_tvl) if latest_tvl.defillama_tvl else None,
        "source": latest_tvl.source,
        "timestamp": latest_tvl.timestamp.isoformat(),
    }


def _company_reach(session: Session, contracts_by_job_id: dict[Any, Contract]) -> ReachBlock:
    """The scorer-computed reach claims (services.scoring.reach) for the payload.

    Computed HERE and not in ``build_governance_view``: the governance view's
    other caller is the monitoring reconciler (``governance_controllers_for_
    protocol``), which reads only ``principals`` and must not pay for three
    scorer planes and the signal population on a 512 MB process. The block is
    always present, and an entity absent from it holds no reach claim at all.
    """
    protocol_ids = {c.protocol_id for c in contracts_by_job_id.values() if c is not None and c.protocol_id is not None}
    return {
        "model": REACH_MODEL,
        "entities": merge_reach(load_protocol_reach(session, pid) for pid in sorted(protocol_ids)),
    }


def assemble_company_payload(
    session: Session,
    name: str,
    protocol_row: Protocol | None,
    jobs: list[Job],
    governance: GovernanceView,
    reach: ReachBlock,
) -> CompanyOverviewResponse:
    return {
        "company": name,
        "protocol_id": protocol_row.id if protocol_row else None,
        "contract_count": len(governance.contracts),
        "tvl": _latest_tvl(session, protocol_row),
        "contracts": governance.contracts,
        "principals": governance.principals,
        "ownership_hierarchy": governance.hierarchy,
        "fund_flows": governance.fund_flows,
        "reach": reach,
        # Just the count here — the full inventory (~167 KB for ether.fi) is
        # served by /api/company/{name}/addresses and fetched lazily by
        # AddressesModal when the user opens it.
        "all_addresses_count": _all_addresses_count(session, protocol_row, jobs),
    }


def build_company_overview(session: Session, name: str) -> CompanyOverviewResponse:
    timings_ms: dict[str, int] = {}
    start = time.monotonic()

    with _time_phase(timings_ms, "resolve_jobs"):
        protocol_row, jobs = resolve_company_jobs(session, name)
    if not jobs:
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
        payload = assemble_company_payload(session, name, protocol_row, jobs, governance, reach)

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
    """Map ``(principal_address_lc, chain) -> MonitoredContract.contract_type``
    for every principal that holds governing authority over at least one
    contract in the protocol — its **primary controllers union its privileged
    co-controllers**, keyed per chain.

    The chain half of the key is the chain of the CONTRACTS the principal
    governs (``controls_chains``, from the per-chain primary contests), not a
    caller default: chain-as-island means a controller's monitoring row
    belongs on each chain where it actually controls something, and a Safe
    deployed at the same address on two chains gets one row per chain it
    governs on.

    Both sets come from the single source of truth
    (:mod:`services.governance.primary_controller`) via the same loaders +
    :func:`build_governance_view` the ``/company`` endpoint uses:

    * ``primary_for`` — the winner-take-all set the Surface canvas groups by.
    * ``co_controls`` — principals that hold real authority on a contract they
      *lost* the primary contest for, restricted to privileged or tightly-gated
      functions (:func:`assign_co_controllers`). This is what keeps a
      pause / fund-recovery guardian Safe, or a withdrawal-ops timelock, from
      going unmonitored just because a bigger governance Safe won the same
      contracts. Permissionless callers (whitelisted auction bidders sharing
      ``createBid``) and fund-destination Safes hold neither, so they stay out.

    The canvas renders only ``primary_for`` (groups) and shows ``co_controls`` as
    secondary annotations; monitoring intentionally watches the **union**,
    because each controller — primary or co — emits its own governance events.

    EOAs are dropped (no contract events / state to monitor) and ``proxy_admin``
    maps to the historical ``'proxy'`` contract_type. Read-only.
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
