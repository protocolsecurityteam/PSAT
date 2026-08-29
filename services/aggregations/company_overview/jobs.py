"""Job / contract resolution stages of the company overview."""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from db.models import Contract, Job, JobStatus, Protocol, derive_job_chain_id
from utils.chains import UnknownChainError, chain_by_id, chain_by_name

from .entity_keys import _entity_key


@contextmanager
def _time_phase(timings_ms: dict[str, int], name: str) -> Iterator[None]:
    """Record the elapsed ms of the wrapped block into ``timings_ms[name]``.

    Mirrors the ``_phase`` helper in
    ``services.static.contract_analysis_pipeline.core``; the bundled-timing
    style (single log line per request with every stage as a field) keeps
    log volume bounded and groups well in Loki.
    """
    start = time.monotonic()
    try:
        yield
    finally:
        timings_ms[name] = int((time.monotonic() - start) * 1000)


class CompanyNotFound(Exception):
    """Raised when no jobs / protocol match the given company name."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


@dataclass
class GovernanceView:
    contracts: list[dict[str, Any]] = field(default_factory=list)
    principals: list[dict[str, Any]] = field(default_factory=list)
    hierarchy: list[dict[str, Any]] = field(default_factory=list)
    fund_flows: list[dict[str, Any]] = field(default_factory=list)


def _job_matches_contract_chain(job: Job, contract_chain: str | None) -> bool:
    """Whether ``job`` and a Contract row (its ``chain`` name) are on the same
    chain. Both sides resolve to a registry chain id — the job from its
    first-class ``chain_id`` (else derived from ``request["chain"]``), the
    contract from its name string — so aliases (``"mainnet"``≡``"ethereum"``) and
    a NULL contract chain (legacy mainnet) fold to mainnet and agree, keeping
    mainnet output identical."""
    job_cid = job.chain_id if isinstance(job.chain_id, int) else None
    if job_cid is None:
        request = job.request if isinstance(job.request, dict) else {}
        job_cid = derive_job_chain_id(request.get("chain"), job.address) or 1
    try:
        contract_cid = chain_by_name(contract_chain).chain_id if contract_chain else 1
    except UnknownChainError:
        contract_cid = 1
    return job_cid == contract_cid


def _job_chain_name(job: Job) -> str:
    """Coalesced chain NAME for a job — the job side of
    :func:`_job_matches_contract_chain` resolved to a registry name so it can
    build a composite entity token (:func:`_entity_key`). First-class
    ``chain_id``, else derived from ``request["chain"]``/address, else mainnet;
    an unknown id folds to ``"ethereum"`` (the NULL≡mainnet legacy-read
    convention). A proxy's impl resolves on this chain, so a same-address twin on
    another chain no longer collapses last-wins."""
    job_cid = job.chain_id if isinstance(job.chain_id, int) else None
    if job_cid is None:
        request = job.request if isinstance(job.request, dict) else {}
        job_cid = derive_job_chain_id(request.get("chain"), job.address) or 1
    try:
        return chain_by_id(job_cid).name
    except UnknownChainError:
        return "ethereum"


def _job_recency(job: Job) -> datetime:
    """Sort key for picking the surviving job of a duplicated entity."""
    return job.updated_at or job.created_at or datetime.min.replace(tzinfo=timezone.utc)


def resolve_company_jobs(session: Session, name: str) -> tuple[Protocol | None, list[Job]]:
    """Find the protocol row + jobs that belong to ``name``.

    Modern data: ``Protocol`` row exists, every job carries ``protocol_id``,
    AND its subject ``Contract`` row carries the same id. We filter on
    Contract.protocol_id (not Job.protocol_id) because the Contract row is
    the authoritative membership signal — ``protocol_id`` is written only
    by the membership gate (services/discovery/membership_gate) against
    recorded witnesses. Jobs inherit protocol_id from their parent at
    spawn time (selection / resolution / static), which means a
    dependency-expansion job for WstETH spawned while analyzing an
    etherfi contract carries Job.protocol_id=etherfi even though the
    WstETH Contract row is correctly a non-member. Filtering by
    Contract.protocol_id keeps the surface page consistent with the
    gate's witnessed member set.

    Legacy fallback: no Protocol row but a Job has ``company == name``;
    we walk ``request.parent_job_id`` chains across all completed jobs to
    backfill the company graph.
    """
    protocol_row = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()

    if protocol_row:
        # Join Jobs to Contracts on the natural key. The address column on
        # contracts is already stored lowercased (see db/queue/discovery.py); jobs
        # store the address as-provided, so lowercase the job side for the
        # join. The SQL join stays address-only (a name-string ``Contract.chain``
        # can't be compared to the int ``Job.chain_id`` in SQL without a mapping,
        # and a raw string compare would drop legitimate rows on alias / NULL
        # mismatch); chain agreement is enforced in Python below via the registry
        # so a mainnet job never pairs with a same-address L2 contract.
        # On mainnet-only data every pair agrees, so output is unchanged.
        rows = session.execute(
            select(Job, Contract.chain)
            .join(Contract, Contract.address == func.lower(Job.address))
            .where(
                Contract.protocol_id == protocol_row.id,
                Job.status == JobStatus.completed,
                Job.address.isnot(None),
            )
        ).all()
        # One job per (chain, address) entity — newest wins. Duplicate jobs at
        # one entity are legal (an admin re-analysis, or a cascade child that
        # raced the spawn dedup); every downstream pass renders per JOB, so
        # collapsing here is what keeps the surface at one card per entity.
        best_by_entity: dict[str, Job] = {}
        for job, contract_chain in rows:
            if not _job_matches_contract_chain(job, contract_chain):
                continue
            key = _entity_key(contract_chain, job.address)
            prev = best_by_entity.get(key)
            if prev is None or _job_recency(job) > _job_recency(prev):
                best_by_entity[key] = job
        return protocol_row, list(best_by_entity.values())

    company_job = session.execute(
        select(Job).where(Job.company == name).order_by(Job.updated_at.desc()).limit(1)
    ).scalar_one_or_none()
    if company_job is None:
        return None, []

    company_job_id = str(company_job.id)
    all_completed = session.execute(select(Job).where(Job.status == JobStatus.completed)).scalars().all()
    jobs_by_id = {str(j.id): j for j in all_completed}
    jobs_by_id[company_job_id] = company_job

    def belongs_to_company(job: Job) -> bool:
        seen: set[str] = set()
        current: Job | None = job
        while current is not None:
            if current.company == name:
                return True
            request = current.request if isinstance(current.request, dict) else {}
            parent_id = request.get("parent_job_id")
            if not isinstance(parent_id, str) or parent_id in seen:
                return False
            seen.add(parent_id)
            current = jobs_by_id.get(parent_id)
        return False

    # Same one-job-per-entity collapse as the protocol path (newest wins).
    legacy_best: dict[str, Job] = {}
    for j in all_completed:
        if not j.address or not belongs_to_company(j):
            continue
        key = _entity_key(_job_chain_name(j), j.address)
        prev = legacy_best.get(key)
        if prev is None or _job_recency(j) > _job_recency(prev):
            legacy_best[key] = j
    return None, list(legacy_best.values())


def prefetch_contracts(session: Session, jobs: list[Job]) -> dict[Any, Contract]:
    """Return ``{job_id: Contract}``, with address/chain fallback.

    Jobs whose Contract row was reassigned to a newer job by
    ``copy_static_cache`` are matched by ``(address, chain)``.
    """
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

    # Combine — fallback contracts get keyed by job_id too so the rest of
    # the pipeline can pretend it always had a job_id match.
    out = dict(contracts_by_job_id)
    for j in jobs:
        if out.get(j.id) is not None or not j.address:
            continue
        req = j.request if isinstance(j.request, dict) else {}
        fallback = contracts_by_addr_chain.get((j.address.lower(), req.get("chain")))
        if fallback is not None:
            # Don't overwrite the source-of-truth dict when another job's row
            # legitimately points at this Contract; key by the job_id we want
            # the resolver to find under.
            out[j.id] = fallback
    return out


def resolve_implementation_contracts(
    session: Session, jobs: list[Job], contracts_by_job_id: dict[Any, Contract]
) -> tuple[dict[str, Job], dict[Any, Contract]]:
    """Return ``(impl_job_by_entity, contracts_by_job_id)`` with impls resolved.

    ``impl_job_by_entity`` is keyed by the composite entity token
    (:func:`_entity_key`, ``"<chain>::<addr>"``) of the impl job's OWN chain, so
    a proxy resolves its implementation on the proxy's own chain. A
    same-address impl twin on two of a protocol's chains no longer collapses
    last-wins across chains — each chain keeps its own impl job.

    Mutates the contracts_by_job_id dict to also include impl-contract rows
    keyed by their own job_id, so downstream code can look up impl
    contracts directly.
    """
    impl_addrs_needed: set[str] = set()
    proxy_addrs: set[str] = set()
    for j in jobs:
        cr = contracts_by_job_id.get(j.id)
        if not (cr and cr.is_proxy):
            continue
        if cr.address:
            proxy_addrs.add(cr.address.lower())
        # Primary EIP-1967 impl + any secondary logic contracts (the split-proxy
        # admin-impl pattern, Contract.secondary_implementations). Both are
        # resolved + attached so the proxy node absorbs every logic contract.
        for impl in [cr.implementation, *(cr.secondary_implementations or [])]:
            if impl:
                impl_addrs_needed.add(impl.lower())

    impl_job_by_entity: dict[str, Job] = {}
    if impl_addrs_needed:
        # Deterministic pick: newest completed job per impl (chain, address),
        # preferring the one linked to a proxy we're rendering
        # (request.proxy_address points back at a proxy in this set). Grouping by
        # the composite token keeps each chain's twin separate; without the
        # ORDER BY a re-analysis that left >1 completed impl job for one token
        # attached arbitrarily (1C).
        candidates: dict[str, list[Job]] = {}
        for ij in session.execute(
            select(Job)
            .where(Job.address.in_(list(impl_addrs_needed)), Job.status == JobStatus.completed)
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

    return impl_job_by_entity, contracts_by_job_id


def _secondary_impl_contracts(
    contract_row: Contract | None,
    impl_job_by_entity: dict[str, Job],
    contracts_by_job_id: dict[Any, Contract],
) -> list[Contract]:
    """Resolved Contract rows for a proxy's secondary implementations (the
    split-proxy admin-impl set, ``Contract.secondary_implementations``), in
    declared order. Empty unless the row is a proxy carrying secondaries.

    These logic contracts' EffectiveFunction / FunctionPrincipal rows attribute
    to the proxy node alongside the EIP-1967 impl's, so the proxy surfaces every
    function it routes — and the secondary never renders as a standalone
    ownerless contract.
    """
    if not (contract_row and contract_row.is_proxy and contract_row.secondary_implementations):
        return []
    out: list[Contract] = []
    for saddr in contract_row.secondary_implementations:
        impl_job = impl_job_by_entity.get(_entity_key(contract_row.chain, saddr))
        sc = contracts_by_job_id.get(impl_job.id) if impl_job else None
        if sc is not None:
            out.append(sc)
    return out
