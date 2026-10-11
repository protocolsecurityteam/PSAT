from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from db.models import Contract, Job, JobStatus, Protocol, derive_job_chain_id
from services.company_page_dependencies import track
from utils.chains import UnknownChainError, chain_by_id, chain_by_name

from .entity_keys import _entity_key


@contextmanager
def _time_phase(timings_ms: dict[str, int], name: str) -> Iterator[None]:
    """Bundled timings: one log line per request keeps volume bounded."""
    start = time.monotonic()
    try:
        yield
    finally:
        timings_ms[name] = int((time.monotonic() - start) * 1000)


class CompanyNotFound(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


@dataclass
class GovernanceView:
    contracts: list[dict[str, Any]] = field(default_factory=list)
    principals: list[dict[str, Any]] = field(default_factory=list)
    hierarchy: list[dict[str, Any]] = field(default_factory=list)
    fund_flows: list[dict[str, Any]] = field(default_factory=list)


def _contract_chain_id(contract_chain: str | None) -> int:
    """Resolve the overview's legacy/alias contract chain semantics."""
    try:
        return chain_by_name(contract_chain).chain_id if contract_chain else 1
    except UnknownChainError:
        return 1


def _job_matches_contract_chain(job: Job, contract_chain: str | None) -> bool:
    """Both sides resolve to a registry chain id, so aliases and NULL (legacy mainnet) agree."""
    job_cid = job.chain_id if isinstance(job.chain_id, int) else None
    if job_cid is None:
        request = job.request if isinstance(job.request, dict) else {}
        job_cid = derive_job_chain_id(request.get("chain"), job.address) or 1
    return job_cid == _contract_chain_id(contract_chain)


def eligible_company_protocol_ids(session: Session) -> list[int]:
    """Find company pages using the live resolver's membership rules.

    Reanalysis may repoint Contract.job_id before it completes. Match historical
    completed jobs by address and chain instead. Address-bearing jobs have a
    non-null chain_id enforced by ck_jobs_chain_id_required_for_address.
    Project distinct scalar chain pairs, never job requests or ORM graphs.
    """
    rows = session.execute(
        select(Contract.protocol_id, Contract.chain, Job.chain_id)
        .join(Job, Contract.address == func.lower(Job.address))
        .where(
            Contract.protocol_id.is_not(None),
            Job.status == JobStatus.completed,
            Job.address.is_not(None),
            Job.request["effects_resume_work_id"].astext.is_(None),
        )
        .distinct()
    )
    return sorted({pid for pid, chain, job_chain_id in rows if job_chain_id == _contract_chain_id(chain)})


def eligible_company_names(session: Session) -> dict[str, int]:
    """Company name -> protocol id. A company is a Protocol row; a Job.company
    string alone (a run before discovery creates the row, or an alias spelling
    of an existing protocol) never identifies one."""
    return {
        name: pid
        for name, pid in session.execute(
            select(Protocol.name, Protocol.id).where(Protocol.id.in_(eligible_company_protocol_ids(session)))
        )
    }


def _job_chain_name(job: Job) -> str:
    """Job chain as a registry name for composite keys; unknown ids fold to ``ethereum``."""
    job_cid = job.chain_id if isinstance(job.chain_id, int) else None
    if job_cid is None:
        request = job.request if isinstance(job.request, dict) else {}
        job_cid = derive_job_chain_id(request.get("chain"), job.address) or 1
    try:
        return chain_by_id(job_cid).name
    except UnknownChainError:
        return "ethereum"


def _job_recency(job: Job) -> datetime:
    return job.updated_at or job.created_at or datetime.min.replace(tzinfo=timezone.utc)


def resolve_company_jobs(session: Session, name: str) -> tuple[Protocol | None, list[Job]]:
    """Find the protocol row + jobs for ``name``.

    Filters on ``Contract.protocol_id``, not ``Job.protocol_id``: jobs inherit protocol_id from their parent at spawn,
    so a dependency job (WstETH under etherfi) carries it though its Contract is a non-member. Only the membership gate
    writes ``Contract.protocol_id``. No Protocol row means no company.
    """
    protocol_row = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if protocol_row is None:
        return None, []

    track(session, "protocol", [protocol_row.id])
    # Address-only SQL join (name vs int chain can't compare in SQL); chain agreement is enforced in Python so a
    # mainnet job never pairs with an L2 contract.
    rows = session.execute(
        select(Job, Contract.chain)
        .join(Contract, Contract.address == func.lower(Job.address))
        .where(
            Contract.protocol_id == protocol_row.id,
            Job.status == JobStatus.completed,
            Job.request["effects_resume_work_id"].astext.is_(None),
            Job.address.isnot(None),
        )
    ).all()
    # Duplicate jobs per entity are legal (re-analysis, spawn races); collapse to the newest for one card per entity.
    best_by_entity: dict[str, Job] = {}
    for job, contract_chain in rows:
        if not _job_matches_contract_chain(job, contract_chain):
            continue
        key = _entity_key(contract_chain, job.address)
        prev = best_by_entity.get(key)
        if prev is None or _job_recency(job) > _job_recency(prev):
            best_by_entity[key] = job
    return protocol_row, list(best_by_entity.values())


def prefetch_contracts(session: Session, jobs: list[Job]) -> dict[Any, Contract]:
    """``{job_id: Contract}``, matching ``copy_static_cache``-reassigned rows by ``(address, chain)``."""
    track(session, "address", (job.address for job in jobs))
    company_job_ids = [j.id for j in jobs]
    contracts_by_job_id: dict[Any, Contract] = {}
    if company_job_ids:
        for c in session.execute(
            select(Contract).where(Contract.job_id.in_(company_job_ids)).options(selectinload(Contract.summary))
        ).scalars():
            contracts_by_job_id[c.job_id] = c

    unresolved_addrs_by_chain: dict[str | None, set[str]] = {}
    for j in jobs:
        if contracts_by_job_id.get(j.id) is not None or not j.address:
            continue
        req = j.request if isinstance(j.request, dict) else {}
        unresolved_addrs_by_chain.setdefault(req.get("chain"), set()).add(j.address.lower())
    contracts_by_addr_chain: dict[tuple[str, str | None], Contract] = {}
    all_unresolved_addrs = {a for addrs in unresolved_addrs_by_chain.values() for a in addrs}
    if all_unresolved_addrs:
        for c in session.execute(
            select(Contract)
            .where(Contract.address.in_(list(all_unresolved_addrs)))
            .options(selectinload(Contract.summary))
        ).scalars():
            addr_lc = (c.address or "").lower()
            for chain_key, addrs in unresolved_addrs_by_chain.items():
                if addr_lc in addrs and (chain_key is None or c.chain == chain_key):
                    contracts_by_addr_chain[(addr_lc, chain_key)] = c

    out = dict(contracts_by_job_id)
    for j in jobs:
        if out.get(j.id) is not None or not j.address:
            continue
        req = j.request if isinstance(j.request, dict) else {}
        fallback = contracts_by_addr_chain.get((j.address.lower(), req.get("chain")))
        if fallback is not None:
            # Another job's row may legitimately point at this Contract.
            out[j.id] = fallback
    return out


def resolve_implementation_contracts(
    session: Session, jobs: list[Job], contracts_by_job_id: dict[Any, Contract]
) -> tuple[dict[str, Job], dict[Any, Contract]]:
    """``(impl_job_by_entity, contracts_by_job_id)``.

    Keyed by the impl's own composite entity so twins don't collapse across chains. Mutates ``contracts_by_job_id`` to
    add impl rows.
    """
    impl_addrs_needed: set[str] = set()
    proxy_addrs: set[str] = set()
    for j in jobs:
        cr = contracts_by_job_id.get(j.id)
        if not (cr and cr.is_proxy):
            continue
        if cr.address:
            proxy_addrs.add(cr.address.lower())
        for impl in [cr.implementation, *(cr.secondary_implementations or [])]:
            if impl:
                impl_addrs_needed.add(impl.lower())

    impl_job_by_entity: dict[str, Job] = {}
    track(session, "address", impl_addrs_needed)
    if impl_addrs_needed:
        # Newest completed per impl entity, preferring one linked to a rendered proxy; without ordering, re-analyses
        # attached arbitrarily.
        candidates: dict[str, list[Job]] = {}
        for ij in session.execute(
            select(Job)
            .where(
                Job.address.in_(list(impl_addrs_needed)),
                Job.status == JobStatus.completed,
                Job.request["effects_resume_work_id"].astext.is_(None),
            )
            .order_by(Job.updated_at.desc(), Job.created_at.desc(), Job.id.desc())
        ).scalars():
            if not ij.address:
                continue
            candidates.setdefault(_entity_key(_job_chain_name(ij), ij.address), []).append(ij)
        for token, addr_jobs in candidates.items():
            linked = [
                ij
                for ij in addr_jobs
                if isinstance(ij.request, dict) and str(ij.request.get("proxy_address") or "").lower() in proxy_addrs
            ]
            impl_job_by_entity[token] = (linked or addr_jobs)[0]

    impl_job_ids_needed = [ij.id for ij in impl_job_by_entity.values()]
    if impl_job_ids_needed:
        for c in session.execute(
            select(Contract).where(Contract.job_id.in_(impl_job_ids_needed)).options(selectinload(Contract.summary))
        ).scalars():
            contracts_by_job_id[c.job_id] = c

    # Includes borrowed implementations and their protocol-wide reach inputs.
    # Missing implementations were registered above, so their later insertion
    # also invalidates the page that previously could not resolve them.
    track(session, "contract", (c.id for c in contracts_by_job_id.values()))
    track(session, "address", (c.address for c in contracts_by_job_id.values()))
    track(session, "protocol", (c.protocol_id for c in contracts_by_job_id.values()))
    return impl_job_by_entity, contracts_by_job_id


def _secondary_impl_contracts(
    contract_row: Contract | None,
    impl_job_by_entity: dict[str, Job],
    contracts_by_job_id: dict[Any, Contract],
) -> list[Contract]:
    """Resolved rows for a proxy's secondary implementations, whose functions attribute to the proxy node."""
    if not (contract_row and contract_row.is_proxy and contract_row.secondary_implementations):
        return []
    out: list[Contract] = []
    for saddr in contract_row.secondary_implementations:
        impl_job = impl_job_by_entity.get(_entity_key(contract_row.chain, saddr))
        sc = contracts_by_job_id.get(impl_job.id) if impl_job else None
        if sc is not None:
            out.append(sc)
    return out


# A member with no completed analysis is not_determined, never dropped and never shown as analyzed. The token follows
# the statuses the company-page jobs trigger publishes (completed, failed, failed_terminal), so a queued or running
# retry never changes it.
MEMBER_ANALYSIS_FAILED = "analysis_failed"
MEMBER_ANALYSIS_NOT_COMPLETED = "analysis_not_completed"
_FAILED_STATUSES = frozenset({JobStatus.failed, JobStatus.failed_terminal})


def members_without_analysis(session: Session, protocol_id: int) -> tuple[int, list[dict[str, Any]]]:
    """``(member_count, members with no completed analysis job)``, each with its witness token and last failed job."""
    members = session.execute(
        select(Contract.id, Contract.address, Contract.chain, Contract.contract_name)
        .where(Contract.protocol_id == protocol_id, Contract.address.is_not(None))
        .order_by(Contract.id)
    ).all()
    if not members:
        return 0, []
    addresses = sorted({address.lower() for _, address, _, _ in members})
    track(session, "address", addresses)
    jobs_by_entity: dict[str, list[tuple[Any, JobStatus, datetime]]] = {}
    for job_id, address, status, chain_id, request_chain, updated_at, created_at in session.execute(
        select(
            Job.id,
            Job.address,
            Job.status,
            Job.chain_id,
            Job.request["chain"].astext,
            Job.updated_at,
            Job.created_at,
        ).where(
            func.lower(Job.address).in_(addresses),
            Job.request["effects_resume_work_id"].astext.is_(None),
        )
    ):
        job_chain_id = chain_id if isinstance(chain_id, int) else derive_job_chain_id(request_chain, address) or 1
        try:
            chain_name = chain_by_id(job_chain_id).name
        except UnknownChainError:
            continue
        recency = updated_at or created_at or datetime.min.replace(tzinfo=timezone.utc)
        jobs_by_entity.setdefault(_entity_key(chain_name, address), []).append((job_id, status, recency))

    out: list[dict[str, Any]] = []
    for contract_id, address, chain, name in members:
        jobs = jobs_by_entity.get(_entity_key(_canonical_chain_name(chain), address), [])
        if any(status == JobStatus.completed for _, status, _ in jobs):
            continue
        # Only finished attempts are named: a queued or running job changes nothing the page republishes on.
        failed = [job for job in jobs if job[1] in _FAILED_STATUSES]
        last_failed = max(failed, key=lambda job: job[2]) if failed else None
        out.append(
            {
                "contract_id": contract_id,
                "address": address.lower(),
                "chain": chain,
                "name": name,
                "analysis_state": MEMBER_ANALYSIS_FAILED if failed else MEMBER_ANALYSIS_NOT_COMPLETED,
                "last_failed_job_id": str(last_failed[0]) if last_failed else None,
                "last_failed_job_status": last_failed[1].value if last_failed else None,
            }
        )
    return len(members), sorted(out, key=lambda m: (m["analysis_state"], m["chain"] or "", m["address"]))


def _canonical_chain_name(contract_chain: str | None) -> str:
    """The contract's chain as the registry name a job's chain id resolves to (aliases and NULL mainnet agree)."""
    return chain_by_id(_contract_chain_id(contract_chain)).name
