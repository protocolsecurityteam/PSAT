"""Company-level governance overview.

Decomposed from a single ~700-line endpoint into stages so each step is
testable on its own. ``build_company_overview`` is the orchestrator
called by the router.

Stages (each returns plain Python data, not ORM rows that pin a session):

1. ``resolve_company_jobs`` — protocol lookup with legacy-company fallback
   that walks ``parent_job_id`` chains for older jobs that don't carry a
   protocol_id.
2. ``prefetch_contracts`` — batch fetch ``Contract`` rows by ``job_id``,
   with an address+chain fallback for jobs whose Contract row was
   reassigned by ``copy_static_cache`` to a newer job.
3. ``resolve_implementation_contracts`` — for proxy contracts in the
   inventory, locate the impl Contract row keyed by impl address.
4. ``build_governance_view`` — merges the above with prefetched child
   tables to produce the contract entries, ownership hierarchy,
   non-contract principals, and inter-contract fund-flow edges.
5. ``assemble_company_payload`` — adds the protocol-wide views
   (all_addresses, latest TVL) and shapes the final dict.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session, aliased, selectinload

from db.jsonb import jsonb_has_payload
from db.models import (
    CONTROL_EDGE_RELATIONS,
    Contract,
    ContractBalanceLatest,
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStatus,
    PrincipalLabel,
    Protocol,
    TvlSnapshot,
    UpgradeEvent,
    derive_job_chain_id,
)
from services.governance.primary_controller import assign_co_controllers, assign_primary_controllers
from services.governance.principals import _build_company_function_entry
from services.scoring.planes import CONTROL_RELATIONS as SCORER_REACH_RELATIONS
from utils.chains import UnknownChainError, chain_by_id, chain_by_name
from utils.etherscan import TOKEN_BALANCE_PAGE_SIZE, token_balances_may_be_truncated

logger = logging.getLogger("services.aggregations.company_overview")


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
    the authoritative ownership signal — gated by
    services/discovery/source_confidence on every write. Jobs inherit
    protocol_id from their parent at spawn time (selection / resolution /
    static), which means a dependency-expansion job for WstETH spawned
    while analyzing an etherfi contract carries Job.protocol_id=etherfi
    even though the WstETH Contract row is correctly orphan. Filtering by
    Contract.protocol_id keeps the surface page consistent with what the
    discovery-source gate already enforces for ownership.

    Legacy fallback: no Protocol row but a Job has ``company == name``;
    we walk ``request.parent_job_id`` chains across all completed jobs to
    backfill the company graph.
    """
    protocol_row = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()

    if protocol_row:
        # Join Jobs to Contracts on the natural key. The address column on
        # contracts is already stored lowercased (see db/queue.py); jobs
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


# Read the pool sizing from the same env vars db.models reads, rather than
# importing the (private) constants. The fan-out cap derives from
# pool_size + max_overflow so prod (start_workers.sh tightens to 2+3=5) and
# dev (5+10=15) both stay below ~half the pool: one in-flight /api/company
# never claims more than ~half the engine's connections, leaving room for
# /functions, /audit_coverage, etc. on the same worker process. The hard
# ceiling of 4 caps perf returns since beyond that the SQL planner and the
# DB CPU become the bottleneck, not concurrency.
#   prod (pool=5):  (5 - 1) // 2 = 2 workers + 1 request session = 3/5
#   dev  (pool=15): min(4, (15-1)//2 = 7) = 4 workers + 1 = 5/15
_DB_POOL_SIZE = int(os.environ.get("PSAT_DB_POOL_SIZE", "5"))
_DB_MAX_OVERFLOW = int(os.environ.get("PSAT_DB_MAX_OVERFLOW", "10"))
_PREFETCH_MAX_WORKERS = max(1, min(4, (_DB_POOL_SIZE + _DB_MAX_OVERFLOW - 1) // 2))


def _prefetch_child_tables(
    session: Session,
    contract_ids: set[int],
    *,
    max_workers: int = _PREFETCH_MAX_WORKERS,
) -> dict[str, dict[int, Any]]:
    """Pre-load every per-contract child row used downstream.

    The full ``EffectiveFunction`` rows (and their FunctionPrincipal
    children) are no longer loaded on this path — they're served by
    ``/api/company/{name}/functions`` and fetched lazily by the frontend.
    Two narrow projections replace the heavy row+selectinload pair:

    * ``ef_effects`` — ``{contract_id: list[list[str]]}`` of per-function
      ``effect_labels`` arrays. Drives the contract entry's
      ``value_effects`` / ``capabilities`` / ``role`` fields.
    * ``fp_governance_rows`` — non-contract principals (safe/timelock/
      eoa/proxy_admin) from ``function_principals``, joined back to
      ``contract_id``. Drives the third-pass principal backfill in
      ``_build_flows_and_principals`` (function-only principals like the
      EtherFiTimelock Safe).

    ``controller_values`` runs first on the request session because the
    ``cv_principal_addrs_lc`` set it produces is needed in the CGN/CGE
    keep-predicate. The remaining stages fan out over a per-request
    ``ThreadPoolExecutor`` — sync SQLAlchemy releases the GIL inside the
    DB driver so threads give genuine wall-time parallelism. Each task
    opens its own ``Session`` on the same engine because Session is not
    thread-safe; ``max_workers`` is derived from the engine pool size so
    a single request never claims more than ~half the pool (see the
    ``_PREFETCH_MAX_WORKERS`` comment above for the math). Tests pass
    ``max_workers=1`` to validate the sequential path against the
    parallel merge.
    """
    out: dict[str, dict[int, Any]] = {
        "controller_values": {},
        "ef_effects": {},
        "fp_governance_rows": {},
        "fp_in_contract_principals": {},
        "fp_all_addrs": {},
        "fp_function_detail": {},
        "upgrade_events_count": {},
        "upgrade_events_last": {},
        "balances": {},
        "cgn": {},
        "cge": {},
        "terminal_walk": {},
    }
    if not contract_ids:
        return out

    id_list = list(contract_ids)
    timings_ms: dict[str, int] = {}
    counts: dict[str, int] = {}

    with _time_phase(timings_ms, "controller_values"):
        cv_rows = 0
        for cv in session.execute(select(ControllerValue).where(ControllerValue.contract_id.in_(id_list))).scalars():
            out["controller_values"].setdefault(cv.contract_id, []).append(cv)
            cv_rows += 1
        counts["controller_values"] = cv_rows

    # The control_graph queries push the _trim_control_graph rule into the
    # WHERE clause. Without the prefilter, ether.fi loads ~7.1 K CGN + ~8.5 K
    # CGE rows just to drop ~78% / ~66% of them at serialization time. The
    # filter must be a strict superset of the Python trim because the trim
    # uses the *post-lookup* node type, so addresses whose CGN.resolved_type
    # is non-principal but whose principal_lookup entry upgrades them
    # (analyzed contracts, CV principals, cross-contract CGN principals,
    # timelock-delay details) must still be loaded. _trim_control_graph is
    # kept as a final no-op-on-the-happy-path pass that handles the cases
    # where SQL keeps more than Python would (cross-contract edge sources,
    # JSONB delay keys with non-positive values).
    cv_principal_addrs_lc: set[str] = set()
    for cv_list in out["controller_values"].values():
        for cv in cv_list:
            value = cv.value
            if not value or not value.startswith("0x"):
                continue
            details_dict = cv.details if isinstance(cv.details, dict) else {}
            if _principal_lookup_type(cv.resolved_type, details_dict):
                cv_principal_addrs_lc.add(value.lower())

    contract_addr_subq = (
        select(func.lower(Contract.address))
        .where(Contract.id.in_(id_list), Contract.address.is_not(None))
        .scalar_subquery()
    )
    edge_source_addr_subq = (
        select(func.lower(func.replace(ControlGraphEdge.from_node_id, "address:", "")))
        .where(ControlGraphEdge.contract_id.in_(id_list))
        .distinct()
        .scalar_subquery()
    )
    # Distinct aliases for the two roles the CGN table plays inside the
    # control_graph queries:
    #   * ``cgn_principal_lookup`` — the inner subquery that returns every
    #     address with a principal-typed or timelock-delay CGN row anywhere
    #     in the batch. Drives the cross-contract lookup upgrade case.
    #   * ``cge_target_cgn`` — the correlated CGN reference inside the CGE
    #     NOT EXISTS, joined to the edge's target.
    # Sharing one alias caused inner subquery references to shadow the outer
    # correlated reference inside the CGE query, which Postgres tolerates
    # but reads as a footgun.
    cgn_principal_lookup = aliased(ControlGraphNode, name="cgn_principal_lookup")
    cge_target_cgn = aliased(ControlGraphNode, name="cge_target_cgn")
    # ``jsonb_has_payload``, not a SQL null test, on both timelock-delay clauses
    # here and in ``_node_keep_predicate``: a JSONB column written from a Python
    # ``None`` holds the jsonb scalar null, which passes a null test. The
    # ``has_key`` checks that follow are false on that value, so the pair reads
    # as one contradictory row rather than a node with no resolved details.
    cgn_principal_addr_subq = (
        select(func.lower(cgn_principal_lookup.address))
        .where(
            cgn_principal_lookup.contract_id.in_(id_list),
            or_(
                cgn_principal_lookup.resolved_type.in_(_PRINCIPAL_TYPES_SQL),
                and_(
                    jsonb_has_payload(cgn_principal_lookup.details),
                    or_(
                        cgn_principal_lookup.details.has_key("delay"),
                        cgn_principal_lookup.details.has_key("delay_seconds"),
                        cgn_principal_lookup.details.has_key("min_delay"),
                    ),
                ),
            ),
        )
        .distinct()
        .scalar_subquery()
    )

    def _node_keep_predicate(node_ref: Any) -> Any:
        clauses = [
            node_ref.resolved_type.in_(_PRINCIPAL_TYPES_SQL),
            func.lower(node_ref.address).in_(contract_addr_subq),
            func.lower(node_ref.address).in_(cgn_principal_addr_subq),
            func.lower(node_ref.address).in_(edge_source_addr_subq),
            and_(
                jsonb_has_payload(node_ref.details),
                or_(
                    node_ref.details.has_key("delay"),
                    node_ref.details.has_key("delay_seconds"),
                    node_ref.details.has_key("min_delay"),
                ),
            ),
        ]
        if cv_principal_addrs_lc:
            clauses.append(func.lower(node_ref.address).in_(list(cv_principal_addrs_lc)))
        return or_(*clauses)

    def _ef_effects(s: Session) -> tuple[dict[int, list[dict[str, list[str]]]], int]:
        # Per function: legacy labels (drive value_effects) + Plane-1 claim_ids
        # (drive the capability chips, claims-first). One record per function so
        # the claims-vs-legacy choice stays per-function through aggregation.
        local: dict[int, list[dict[str, list[str]]]] = {}
        rows = 0
        for cid, labels, claims in s.execute(
            select(
                EffectiveFunction.contract_id,
                EffectiveFunction.effect_labels,
                EffectiveFunction.claims,
            ).where(EffectiveFunction.contract_id.in_(id_list))
        ).all():
            local.setdefault(cid, []).append({"labels": list(labels or []), "claims": _claim_ids_list(claims)})
            rows += 1
        return local, rows

    def _fp_governance(s: Session) -> tuple[dict[int, list[dict[str, Any]]], int]:
        local: dict[int, list[dict[str, Any]]] = {}
        rows = 0
        for row in s.execute(
            select(
                EffectiveFunction.contract_id,
                FunctionPrincipal.address,
                FunctionPrincipal.resolved_type,
                FunctionPrincipal.details,
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.resolved_type.in_(("safe", "timelock", "eoa", "proxy_admin")),
            )
        ).all():
            cid, address, resolved_type, details = row
            local.setdefault(cid, []).append(
                {
                    "address": address,
                    "resolved_type": resolved_type,
                    "details": details,
                }
            )
            rows += 1
        return local, rows

    def _fp_in_contract_principals(s: Session) -> tuple[dict[int, set[str]], int]:
        """Per-contract set of in-protocol-contract addresses that hold
        call authority on at least one ``EffectiveFunction``.

        Replaces the bare ``ControlGraphNode`` walk that previously drove
        in-contract ``type=principal`` flows. CGN rows include the full
        recursive graph (transitive lineage like
        ``WithdrawalQueueERC721 -> WstETH -> Lido stETH``), so emitting a
        principal flow for every in-protocol CGN match falsely surfaced
        tokens that EtherFi composes with as principals controlling
        EtherFi contracts. ``FunctionPrincipal`` is the authoritative
        per-function access-control record — an address only appears here
        if the capability resolver determined it can actually call a
        function.

        ``signature_witness`` is excluded because a signer of a message
        is not a caller. NULL ``principal_type`` is included so legacy
        rows pre-dating the typed writer still count.
        """
        local: dict[int, set[str]] = {}
        rows = 0
        for cid, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                func.lower(FunctionPrincipal.address),
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.address.is_not(None),
                func.lower(FunctionPrincipal.address).in_(contract_addr_subq),
                or_(
                    FunctionPrincipal.principal_type != "signature_witness",
                    FunctionPrincipal.principal_type.is_(None),
                ),
            )
            .distinct()
        ).all():
            if not addr:
                continue
            local.setdefault(cid, set()).add(addr)
            rows += 1
        return local, rows

    def _fp_all_addrs(s: Session) -> tuple[dict[int, set[str]], int]:
        """Per-contract set of every FP address (lower-cased), no contract
        filter. Drives ``services.governance.primary_controller`` which
        needs to ask "is this non-contract principal (Safe/Timelock/EOA/
        proxy_admin) in FP for any function on this contract?".

        ``_fp_in_contract_principals`` intersects with the in-protocol
        contract set so it can't answer that question — by construction
        it filters out the very addresses (Safes / EOAs) we want to
        check. ``signature_witness`` rows are excluded for the same
        reason as there: signers of a message aren't callers.
        """
        local: dict[int, set[str]] = {}
        rows = 0
        for cid, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                func.lower(FunctionPrincipal.address),
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.address.is_not(None),
                or_(
                    FunctionPrincipal.principal_type != "signature_witness",
                    FunctionPrincipal.principal_type.is_(None),
                ),
            )
            .distinct()
        ).all():
            if not addr:
                continue
            local.setdefault(cid, set()).add(addr)
            rows += 1
        return local, rows

    def _fp_function_detail(s: Session) -> tuple[dict[int, list[dict[str, Any]]], int]:
        """Per-contract, per-function ``{"function": str, "callers": set,
        "labels": set, "claims": list[claim_id]}``. Drives two things:

        * the co-controller rule in
          :func:`services.governance.primary_controller.assign_co_controllers`,
          which keeps a non-primary principal only when it holds authority on a
          function that is privileged (a strong effect label) or tightly gated
          (few authorized callers) — separating a real guardian/admin from a
          permissionless caller (``createBid``, shared by dozens of bidders);
        * the per-(controller, contract) capability detail surfaced on the
          canvas (which concrete functions / effect categories each controller
          can actually call), so a relationship reads as "pause · recover"
          rather than a generic "controlled". ``function_name`` is carried for
          that — effect labels alone are too coarse (``setCapacity`` is only
          ``external_contract_call``).

        ``signature_witness`` rows are excluded for the same reason as the
        sibling FP projections: a signer of a message isn't a caller."""
        by_ef: dict[int, dict[str, Any]] = {}
        rows = 0
        for cid, ef_id, fname, labels, claims, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                EffectiveFunction.id,
                EffectiveFunction.function_name,
                EffectiveFunction.effect_labels,
                EffectiveFunction.claims,
                func.lower(FunctionPrincipal.address),
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.address.is_not(None),
                or_(
                    FunctionPrincipal.principal_type != "signature_witness",
                    FunctionPrincipal.principal_type.is_(None),
                ),
            )
        ).all():
            if not addr:
                continue
            entry = by_ef.get(ef_id)
            if entry is None:
                entry = {
                    "contract_id": cid,
                    "function": fname,
                    "labels": set(labels or ()),
                    "claims": _claim_ids_list(claims),
                    "callers": set(),
                }
                by_ef[ef_id] = entry
            entry["callers"].add(addr)
            rows += 1
        local: dict[int, list[dict[str, Any]]] = {}
        for entry in by_ef.values():
            local.setdefault(entry["contract_id"], []).append(
                {
                    "function": entry["function"],
                    "labels": entry["labels"],
                    "claims": entry["claims"],
                    "callers": entry["callers"],
                }
            )
        return local, rows

    def _upgrade_count(s: Session) -> tuple[dict[int, dict[str, Any]], int]:
        """Upgrade ACTIONS per contract, not Upgraded logs — with the basis.

        The payload's ``upgrade_count`` renders as literal "N upgrades" text,
        so the unit must be exercises of upgrade authority. Distinct
        ``tx_hash`` is the honest cardinality the persisted rows can support:
        one transaction can emit several ``Upgraded`` logs against the same
        proxy (a within-tx swap-and-restore emits two), and counting distinct
        *resting-implementation changes* instead would need old→new impl
        continuity, which ``old_impl`` (NULL on every backfill-written row)
        cannot give. Rows with NULL ``tx_hash`` (the poll writer detects a slot
        change without a tx) are each their own observed upgrade: they cannot
        be grouped by transaction, and folding them together would undercount.

        What the distinct-tx count still could not see is that **a proxy's own
        deployment emits ``Upgraded``**, so its creation was published as an
        upgrade. ``upgrade_action_counts`` excludes an event only where the
        deployment is PROVEN (see ``services/discovery/upgrade_history.py``),
        leaves every unproven one counted, and refuses to publish a
        post-exclusion zero as a proven zero. The sidecar carries the basis so
        a consumer can see the coverage behind the number rather than reading
        it as complete.
        """
        from services.discovery.upgrade_history import upgrade_action_counts

        local: dict[int, dict[str, Any]] = upgrade_action_counts(s, id_list)
        return local, len(local)

    def _upgrade_last(s: Session) -> tuple[dict[int, dict[str, Any]], int]:
        """Block + timestamp of THE last upgrade event — one row, both fields.

        Formerly two independent ``MAX`` aggregates over the same group, which
        can name two different events the moment a poll-detected row (NULL
        ``block_number`` by design) coexists with a block-carrying one. The
        published pair describes "the last upgrade", so both halves must come
        from the same qualifying row. Ordering mirrors the chat plane's
        documented total order (services/chat/data.py): timestamp leads
        because every writer sets it; block NULLS FIRST under DESC so a
        poll-detected latest row wins over an older block-carrying one; ``id``
        makes the order total.
        """
        local: dict[int, dict[str, Any]] = {}
        for cid, last_block, last_ts in s.execute(
            select(
                UpgradeEvent.contract_id,
                UpgradeEvent.block_number,
                UpgradeEvent.timestamp,
            )
            .where(UpgradeEvent.contract_id.in_(id_list))
            .order_by(
                UpgradeEvent.contract_id,
                UpgradeEvent.timestamp.desc().nullslast(),
                UpgradeEvent.block_number.desc().nullsfirst(),
                UpgradeEvent.id.desc(),
            )
            .distinct(UpgradeEvent.contract_id)
        ).all():
            local[cid] = {"block": last_block, "timestamp": last_ts}
        return local, len(local)

    def _balances(s: Session) -> tuple[dict[int, list[Any]], int]:
        # ``contract_balances_latest``, not the base table: both writers are
        # insert-only now, so the base table carries every past cycle and this
        # would list the same holding once per refresh.
        local: dict[int, list[Any]] = {}
        rows = 0
        for b in s.execute(
            select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id.in_(id_list))
        ).scalars():
            local.setdefault(b.contract_id, []).append(b)
            rows += 1
        return local, rows

    def _cgn(s: Session) -> tuple[dict[int, list[ControlGraphNode]], int]:
        local: dict[int, list[ControlGraphNode]] = {}
        rows = 0
        for n in s.execute(
            select(ControlGraphNode).where(
                ControlGraphNode.contract_id.in_(id_list),
                _node_keep_predicate(ControlGraphNode),
            )
        ).scalars():
            local.setdefault(n.contract_id, []).append(n)
            rows += 1
        return local, rows

    def _terminal_walk(s: Session) -> tuple[dict[str, dict[str, Any]], int]:
        """``{lower(address): terminal_principal record}`` from ``principal_labels``.

        The terminal-controller walk (``services/governance/principals.resolve_terminal_principal``)
        is persisted ONLY on ``principal_labels.details`` — 1,556 rows written, and
        the one consumer that handles its whole status vocabulary correctly,
        ``claimsVocab.terminalControllerNote``, could never receive it because
        ``_build_principal_lookup`` never joined the table. A permanently
        disconnected plane, not a rare shape.

        Keyed by address, not by ``(contract_id, address)``: the walk answers "what
        ultimately controls THIS address", and the local corpus has 0 addresses
        whose record differs between the subject contracts that recorded it (22
        distinct addresses across 180 rows). A narrow projection with the jsonb
        ``has_key`` filter in the WHERE clause, so contracts with no walk cost
        nothing.

        CHAIN SCOPE, stated rather than claimed: the read is scoped by
        ``contract_id`` (chain-scoped through ``contracts.chain``) but the returned
        MAP is keyed by a bare lowercase address, which is the pre-existing shape of
        the whole ``principal_lookup`` plane — ``principal_labels`` /
        ``control_graph_nodes`` / ``controller_values`` carry no chain column at all,
        and ``_build_principal_lookup`` already merges every source into one
        bare-address dict. So a protocol spanning two chains could in
        principle have one chain's walk annotate the other's node. Not realised: the
        control/policy plane is 100% ethereum, and 0 addresses carry differing
        records. Closing it means giving that plane a chain key, which is a
        producer-side schema change, not a consumer split.
        """
        local: dict[str, dict[str, Any]] = {}
        rows = 0
        for address, details in s.execute(
            select(PrincipalLabel.address, PrincipalLabel.details).where(
                PrincipalLabel.contract_id.in_(id_list),
                jsonb_has_payload(PrincipalLabel.details),
                PrincipalLabel.details.has_key("terminal_principal"),
            )
        ).all():
            record = (details or {}).get("terminal_principal")
            if not isinstance(record, dict) or not address:
                continue
            local.setdefault(address.lower(), record)
            rows += 1
        return local, rows

    def _cge(s: Session) -> tuple[dict[int, list[ControlGraphEdge]], int]:
        # Drop an edge iff there exists a CGN row at its target address in
        # the same contract that the keep-clause would not retain — i.e., a
        # Python-trim-dropped node. Targets outside this contract's CGN are
        # always kept (no CGN row means no dropped row).
        keep_edge_clause = ~exists().where(
            and_(
                cge_target_cgn.contract_id == ControlGraphEdge.contract_id,
                func.lower(cge_target_cgn.address)
                == func.lower(func.replace(ControlGraphEdge.to_node_id, "address:", "")),
                ~_node_keep_predicate(cge_target_cgn),
            )
        )
        local: dict[int, list[ControlGraphEdge]] = {}
        rows = 0
        for e in s.execute(
            select(ControlGraphEdge).where(ControlGraphEdge.contract_id.in_(id_list), keep_edge_clause)
        ).scalars():
            local.setdefault(e.contract_id, []).append(e)
            rows += 1
        return local, rows

    # (timing_key, out_key, runner). Order matters under bounded max_workers:
    # the slowest stage gets submitted first so it lands on an idle worker
    # immediately and runs alongside the queue of shorter stages.
    parallel_stages: list[tuple[str, str, Callable[[Session], tuple[Any, int]]]] = [
        ("control_graph_edges", "cge", _cge),
        ("control_graph_nodes", "cgn", _cgn),
        ("balances", "balances", _balances),
        ("ef_effects", "ef_effects", _ef_effects),
        ("fp_governance_rows", "fp_governance_rows", _fp_governance),
        ("fp_in_contract_principals", "fp_in_contract_principals", _fp_in_contract_principals),
        ("fp_all_addrs", "fp_all_addrs", _fp_all_addrs),
        ("fp_function_detail", "fp_function_detail", _fp_function_detail),
        ("upgrade_events_count", "upgrade_events_count", _upgrade_count),
        ("upgrade_events_last", "upgrade_events_last", _upgrade_last),
        ("terminal_walk", "terminal_walk", _terminal_walk),
    ]

    engine = session.get_bind()

    def _run_stage(
        timing_key: str, out_key: str, runner: Callable[[Session], tuple[Any, int]]
    ) -> tuple[str, str, Any, int, int]:
        start = time.monotonic()
        with Session(bind=engine, expire_on_commit=False) as s:
            data, rows = runner(s)
        return timing_key, out_key, data, rows, int((time.monotonic() - start) * 1000)

    parallel_wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futures = [ex.submit(_run_stage, tk, ok, fn) for tk, ok, fn in parallel_stages]
        for fut in as_completed(futures):
            timing_key, out_key, data, rows, ms = fut.result()
            out[out_key] = data
            timings_ms[timing_key] = ms
            counts[timing_key] = rows
    parallel_wall_ms = int((time.monotonic() - parallel_wall_start) * 1000)

    total_ms = sum(timings_ms.values())
    logger.info(
        "Prefetched per-contract child tables: contracts=%d total_ms=%d parallel_wall_ms=%d",
        len(contract_ids),
        total_ms,
        parallel_wall_ms,
        extra={
            "phase": "prefetch_child_tables",
            "duration_ms": total_ms,
            "parallel_wall_ms": parallel_wall_ms,
            "contract_count": len(contract_ids),
            "timings_ms": timings_ms,
            "row_counts": counts,
        },
    )
    return out


_PRINCIPAL_TYPES = frozenset({"contract", "safe", "timelock", "eoa", "proxy_admin"})
_PRINCIPAL_TYPES_SQL = ("contract", "safe", "timelock", "eoa", "proxy_admin")

# ControllerValue.controller_id values that denote a contract's *active*
# owner. The substring heuristic ``"owner" in controller_id.lower()`` used
# to drive this and false-positives on ``pendingOwner``, ``previousOwner``,
# ``roleOwner``, ``ownerFee``, etc. Combined with last-write-wins
# assignment in the CV iteration, OZ Ownable2Step contracts (both
# ``owner()`` and ``pendingOwner()`` tracked) routinely latched the
# not-yet-accepted pending owner — and the wrong owner cascaded into the
# ownership hierarchy and the controls/controls_value fund flow.
#
# Exact whitelist instead. Covers the canonical Ownable variants: bare
# state-var name (``owner`` / ``_owner``) and the prefixed
# ``state_variable:`` form the tracker emits today.
_ACTIVE_OWNER_CONTROLLER_IDS = frozenset(
    {
        "owner",
        "_owner",
        "state_variable:owner",
        "state_variable:_owner",
    }
)


def _is_active_owner_controller(controller_id: str | None) -> bool:
    return (controller_id or "").lower() in _ACTIVE_OWNER_CONTROLLER_IDS


def _trim_control_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Drop mapping-entry leaf nodes (and edges pointing at them) from a
    contract's local control_graph.

    The frontend walker in ``site/src/surface/layout/controlGraph.js``
    emits any non-contract ``to`` of an edge from a reachable source as
    an "indirect principal" in the function inspector. Contracts like
    ``EtherFiNodesManager`` store hundreds of validator addresses in a
    mapping; those addresses end up as nodes of ``type:"unknown"`` with
    labels like ``"deployedEtherFiNodes"``. They are not principals —
    they are stored EVM data — and they balloon the payload (~900 KB
    on ether.fi) while filling the inspector with noise.

    A node is dropped iff its type is not a recognised principal AND it
    never appears as the source of any edge in this contract's local
    edges list (so the walker can never recurse out of it). All edges
    targeting a dropped node are dropped with it so the walker never
    emits a ghost entry.
    """
    sources = {(e.get("from") or "").lower() for e in edges}
    dropped: set[str] = set()
    kept_nodes: list[dict[str, Any]] = []
    for n in nodes:
        addr = (n.get("address") or "").lower()
        if (n.get("type") in _PRINCIPAL_TYPES) or (addr in sources):
            kept_nodes.append(n)
        else:
            dropped.add(addr)
    if not dropped:
        return {"nodes": nodes, "edges": edges}
    kept_edges = [e for e in edges if (e.get("to") or "").lower() not in dropped]
    return {"nodes": kept_nodes, "edges": kept_edges}


def _has_timelock_delay(details: Any) -> bool:
    if not isinstance(details, dict):
        return False
    for key in ("delay", "delay_seconds", "min_delay"):
        value = details.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and value > 0:
            return True
        if isinstance(value, str) and value.isdigit() and int(value) > 0:
            return True
    return False


def _principal_lookup_type(resolved_type: str | None, details: Any) -> str | None:
    normalized = (resolved_type or "").lower()
    if normalized == "gnosis_safe":
        normalized = "safe"
    if normalized in {"safe", "timelock", "eoa", "proxy_admin"}:
        return normalized
    if _has_timelock_delay(details):
        return "timelock"
    if normalized == "contract":
        return "contract"
    return None


def _principal_type_priority(resolved_type: str | None) -> int:
    if resolved_type in {"safe", "timelock", "eoa", "proxy_admin"}:
        return 3
    if resolved_type == "contract":
        return 1
    return 0


def _record_principal_lookup(
    lookup: dict[str, dict[str, Any]],
    *,
    address: str | None,
    resolved_type: str | None,
    label: str | None,
    details: Any,
) -> None:
    if not address or not address.startswith("0x"):
        return
    details_dict = dict(details) if isinstance(details, dict) else {}
    principal_type = _principal_lookup_type(resolved_type, details_dict)
    if not principal_type:
        return

    addr = address.lower()
    current = lookup.setdefault(addr, {"resolved_type": principal_type, "details": {}})
    current_priority = _principal_type_priority(current.get("resolved_type"))
    principal_priority = _principal_type_priority(principal_type)
    if principal_priority > current_priority:
        current["resolved_type"] = principal_type
    if label and not current.get("label"):
        current["label"] = label

    merged_details = dict(current.get("details") or {})
    if principal_priority >= current_priority:
        merged_details.update(details_dict)
    merged_details.setdefault("address", addr)
    current["details"] = merged_details


def _build_principal_lookup(
    contracts_by_job_id: dict[Any, Contract],
    controller_values_by_cid: dict[int, list[ControllerValue]],
    cgn_by_cid: dict[int, list[ControlGraphNode]],
    terminal_walk_by_address: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    seen_contract_ids: set[int] = set()

    for contract in contracts_by_job_id.values():
        if not contract or contract.id in seen_contract_ids:
            continue
        seen_contract_ids.add(contract.id)
        summary = contract.summary
        # ``is True``: the column is three-state, and only a proven timelock earns
        # the strong ``timelock`` type (priority 3, a settled key for
        # ``terminalControllerNote``). A NULL or a missing row falls to
        # ``contract`` — the WEAK, non-terminal way-point type — so the
        # not-determined case cannot be promoted into a settled controller.
        contract_type = "timelock" if summary is not None and summary.has_timelock is True else "contract"
        _record_principal_lookup(
            lookup,
            address=contract.address,
            resolved_type=contract_type,
            label=contract.contract_name,
            details={},
        )

    for values in controller_values_by_cid.values():
        for cv in values:
            _record_principal_lookup(
                lookup,
                address=cv.value,
                resolved_type=cv.resolved_type,
                label=cv.source or cv.controller_id,
                details=cv.details,
            )

    for nodes in cgn_by_cid.values():
        for node in nodes:
            _record_principal_lookup(
                lookup,
                address=node.address,
                resolved_type=node.resolved_type,
                label=node.contract_name or node.label,
                details=node.details,
            )

    # The terminal-controller walk, forwarded from ``principal_labels`` — the only
    # place it is persisted. Its one correct consumer,
    # ``claimsVocab.terminalControllerNote`` (rendered by ``InspectorCard``),
    # handles all six statuses and could never receive the data.
    #
    # Deliberately narrow, and it is the narrowness that keeps this attributable:
    #
    # * ONLY ``terminal_principal`` is forwarded. ``principal_labels.details`` also
    #   carries ``terminal``, ``signer_overlap`` and ``shared_deployer``, and
    #   forwarding ``terminal`` would let one plane's typing publish a SETTLED key
    #   (``terminalControllerNote`` returns null on ``terminal === true``) beside a
    #   ``resolved_type`` from another plane that still says ``contract`` — an
    #   inconsistent record, and in the reassuring direction. The other two are
    #   attribution facts with their own hedged copy and their own review.
    # * only addresses the lookup ALREADY carries are annotated. Admitting new
    #   addresses would widen the published principal set, which is a different
    #   change from connecting the renderer.
    # * ``setdefault``, so a record already merged in from a CGN/CV ``details``
    #   payload wins — this pass adds the fact where it is missing, never
    #   overwrites one that arrived with the row.
    #
    # Status vocabulary: see ``services.governance.principals`` (the single
    # declaration point). Non-terminated statuses all render through
    # ``terminalControllerNote``'s honest "unresolved (<status>)" fall-through,
    # including ``controllers_not_determined`` — the canonical-getter-silence
    # state that replaced the refuted ``no_controller`` proven-absence claim
    # (persisted pre-fix rows may still carry the old token until the next
    # policy run rewrites them; the renderer folds it into the same unresolved
    # copy, so no reader can mistake either for a settled key).
    for address, record in (terminal_walk_by_address or {}).items():
        entry = lookup.get(address)
        if entry is None:
            continue
        details = dict(entry.get("details") or {})
        details.setdefault("terminal_principal", record)
        entry["details"] = details

    return lookup


def _principal_lookup_meta(
    principal_lookup: dict[str, dict[str, Any]],
    address: str | None,
    details: Any = None,
) -> dict[str, Any]:
    lookup = principal_lookup.get((address or "").lower(), {})
    merged_details = dict(lookup.get("details") or {})
    if isinstance(details, dict):
        merged_details.update(details)
    return {
        "resolved_type": lookup.get("resolved_type"),
        "label": lookup.get("label"),
        "details": merged_details,
    }


# THE single capability vocabulary, shared by both the per-contract
# ``capabilities`` field (the contract card / contract-click chips) and the
# per-(controller, contract) detail (guardian / co-controller chips, sidebar
# "Can Call"). One map means the same power reads the same word no matter what
# you click — a Safe's "fund-out" on EETH matches the chip you'd see clicking
# EETH itself.
#
# ``_CLAIM_CAPABILITY`` is the Plane-1 vocabulary, authoritative per function.
# It adds the ``timelock`` / ``safe`` chips (no legacy label ever mapped to
# them) and finally produces ``arbitrary-call`` (its ``arbitrary_external_call``
# legacy source was corpus-dead). The hook/external exclusion is now structural:
# ``external_contract_call`` isn't representable as a claim at all, and
# ``callee_pointer.rotate`` (the precise hook-pointer rotation) is deliberately
# unmapped, so those functions are still shown by name.
_CLAIM_CAPABILITY: dict[str, str] = {
    "pause.set": "pause",
    "pause.unset": "pause",
    "ownership.transfer": "ownership",
    "ownership.renounce": "ownership",
    "ownership.accept": "ownership",
    "authorized_caller.rotate": "authority",
    "authority.replace": "authority",
    "roles.grant": "roles",
    "roles.revoke": "roles",
    "roles.configure": "roles",
    "upgrade.implementation": "upgrade",
    "proxy.admin_change": "upgrade",
    "timelock.schedule": "timelock",
    "timelock.execute": "timelock",
    "timelock.cancel": "timelock",
    "timelock.set_delay": "timelock",
    "safe.signer_mgmt": "safe",
    "safe.module_mgmt": "safe",
    "safe.set_guard": "safe",
    "flow.out": "fund-out",
    "flow.in": "fund-in",
    "supply.mint": "mint",
    "supply.burn": "burn",
    "exec.arbitrary": "arbitrary-call",
    "contract_deployment": "deploy",
}

# Legacy effect_labels → chip, the fallback for claim-less rows (stale data /
# degraded artifact). ``delegatecall_execution`` is a Plane-0 fact with no claim
# projection, so it only ever surfaces a chip through this path.
_EFFECT_CAPABILITY: dict[str, str] = {
    "pause_toggle": "pause",
    "ownership_transfer": "ownership",
    "role_management": "roles",
    "implementation_update": "upgrade",
    "asset_send": "fund-out",
    "asset_pull": "fund-in",
    "mint": "mint",
    "burn": "burn",
    "delegatecall_execution": "delegatecall",
    "authority_update": "authority",
    "contract_deployment": "deploy",
    "arbitrary_external_call": "arbitrary-call",
}


def _claim_ids_list(claims: Any) -> list[str]:
    """``claim_id`` strings from a stored ``EffectiveFunction.claims`` JSONB list
    (``[{claim_id, tier, witness}, ...]``); anything else reads as empty."""
    if not isinstance(claims, list):
        return []
    out: list[str] = []
    for claim in claims:
        if isinstance(claim, dict):
            cid = claim.get("claim_id")
            if isinstance(cid, str) and cid:
                out.append(cid)
    return out


def _function_capabilities(labels: Iterable[str], claim_ids: Iterable[str]) -> set[str]:
    """Capability chips for ONE function. Plane-1 claims are authoritative when
    present; a claim-less function falls back to the legacy effect_labels map.
    Coarse effects with no clean chip drop out — their functions are shown by
    name instead."""
    claim_id_set = set(claim_ids)
    if claim_id_set:
        return {_CLAIM_CAPABILITY[cid] for cid in claim_id_set if cid in _CLAIM_CAPABILITY}
    return {_EFFECT_CAPABILITY[label] for label in labels if label in _EFFECT_CAPABILITY}


def build_governance_view(
    session: Session,
    jobs: list[Job],
    contracts_by_job_id: dict[Any, Contract],
    impl_job_by_entity: dict[str, Job],
) -> GovernanceView:
    """Build the contracts list + ownership hierarchy + fund flows + principals."""
    relevant_contract_ids: set[int] = {c.id for c in contracts_by_job_id.values() if c is not None}
    children = _prefetch_child_tables(session, relevant_contract_ids)
    controller_values_by_cid: dict[int, list[ControllerValue]] = children["controller_values"]
    ef_effects_by_cid: dict[int, list[dict[str, list[str]]]] = children["ef_effects"]
    fp_governance_by_cid: dict[int, list[dict[str, Any]]] = children["fp_governance_rows"]
    upgrade_events_count_by_cid: dict[int, dict[str, Any]] = children["upgrade_events_count"]
    last_upgrade_by_cid: dict[int, dict[str, Any]] = children["upgrade_events_last"]
    balances_by_cid: dict[int, list[Any]] = children["balances"]
    cgn_by_cid: dict[int, list[ControlGraphNode]] = children["cgn"]
    cge_by_cid: dict[int, list[ControlGraphEdge]] = children["cge"]
    fp_in_contract_by_cid: dict[int, set[str]] = children["fp_in_contract_principals"]
    fp_all_addrs_by_cid: dict[int, set[str]] = children["fp_all_addrs"]
    fp_function_detail_by_cid: dict[int, list[dict[str, Any]]] = children["fp_function_detail"]
    # Keyed by ADDRESS, unlike every sibling stage's contract_id map — the walk is a
    # fact about the address, not about the subject contract that recorded it.
    terminal_walk_by_address: dict[str, dict[str, Any]] = children["terminal_walk"]  # type: ignore[assignment]

    # Fold each proxy's secondary-impl child rows into its PRIMARY impl's
    # contract_id buckets. The flow/principal passes key on the primary impl
    # (the proxy's lookup contract), so a governor/admin Safe that holds
    # authority only on the secondary (admin) impl's functions still surfaces as
    # a controller of the proxy node.
    for job in jobs:
        cr = contracts_by_job_id.get(job.id)
        secondaries = _secondary_impl_contracts(cr, impl_job_by_entity, contracts_by_job_id)
        if not secondaries:
            continue
        impl_job = (
            impl_job_by_entity.get(_entity_key(cr.chain, cr.implementation)) if cr and cr.implementation else None
        )
        primary_impl = contracts_by_job_id.get(impl_job.id) if impl_job else None
        primary_cid = primary_impl.id if primary_impl else (cr.id if cr else None)
        if primary_cid is None:
            continue
        for sc in secondaries:
            if sc.id == primary_cid:
                continue
            cv_extra = controller_values_by_cid.get(sc.id)
            if cv_extra:
                controller_values_by_cid[primary_cid] = list(controller_values_by_cid.get(primary_cid) or []) + cv_extra
            fpg_extra = fp_governance_by_cid.get(sc.id)
            if fpg_extra:
                fp_governance_by_cid[primary_cid] = list(fp_governance_by_cid.get(primary_cid) or []) + fpg_extra
            extra_addrs = fp_in_contract_by_cid.get(sc.id)
            if extra_addrs:
                fp_in_contract_by_cid[primary_cid] = set(fp_in_contract_by_cid.get(primary_cid) or set()) | set(
                    extra_addrs
                )
            # The second-pass CGN principal gate (:_build_flows_and_principals)
            # admits a Safe/EOA/timelock only if it holds FP authority on the
            # PRIMARY impl's cid. A governor that gates only the secondary impl's
            # functions lives in fp_all_addrs under the secondary cid, so fold it
            # up too — the sibling projections above already do.
            extra_all = fp_all_addrs_by_cid.get(sc.id)
            if extra_all:
                fp_all_addrs_by_cid[primary_cid] = set(fp_all_addrs_by_cid.get(primary_cid) or set()) | set(extra_all)

    principal_lookup = _build_principal_lookup(
        contracts_by_job_id, controller_values_by_cid, cgn_by_cid, terminal_walk_by_address
    )

    contracts: list[dict[str, Any]] = []
    owner_groups: dict[str, list[dict]] = {}

    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue

        contract_row = contracts_by_job_id.get(job.id)
        is_proxy = contract_row.is_proxy if contract_row else False
        proxy_type = contract_row.proxy_type if contract_row else None
        impl_addr = contract_row.implementation if contract_row else None

        impl_job = (
            impl_job_by_entity.get(_entity_key(contract_row.chain, impl_addr)) if contract_row and impl_addr else None
        )
        impl_job_id = str(impl_job.id) if impl_job else None
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None

        # Split-proxy secondary logic contracts (admin-impl set). Their
        # functions + principals attribute to this proxy node too.
        secondary_impl_contracts = _secondary_impl_contracts(contract_row, impl_job_by_entity, contracts_by_job_id)

        summary_row = impl_contract.summary if impl_contract else None
        if not summary_row and contract_row:
            summary_row = contract_row.summary

        # Prefer a logic contract's controller snapshot for proxies — the impl
        # (or a secondary impl) read against proxy storage, whichever has rows.
        lookup_contract = contract_row
        if is_proxy:
            for candidate in [impl_contract, *secondary_impl_contracts]:
                if candidate and controller_values_by_cid.get(candidate.id):
                    lookup_contract = candidate
                    break

        owner = None
        controllers: dict[str, Any] = {}
        if lookup_contract:
            for cv in controller_values_by_cid.get(lookup_contract.id, []):
                controllers[cv.controller_id] = cv.value
                if _is_active_owner_controller(cv.controller_id) and cv.value and cv.value.startswith("0x"):
                    owner = cv.value.lower()

        upgrade_entry = (upgrade_events_count_by_cid.get(contract_row.id) if contract_row else None) or {}
        # ``count`` is None whenever the rows support no PROVEN upgrade action —
        # including the post-exclusion zero, which the UI would otherwise render
        # as the earned negative "0 upgrades".
        upgrade_count = upgrade_entry.get("count")
        upgrade_count_basis = upgrade_entry.get("basis")
        last_upgrade_entry = (last_upgrade_by_cid.get(contract_row.id) if contract_row else None) or {}
        last_upgrade_block = last_upgrade_entry.get("block")
        last_ts = last_upgrade_entry.get("timestamp")
        last_upgrade_timestamp = last_ts.isoformat() if last_ts is not None else None

        # Effects from every logic contract of this node: the impl (or the row
        # itself for non-proxies) plus any secondary impls.
        primary_ef_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        ef_contract_ids = [primary_ef_cid] if primary_ef_cid else []
        ef_contract_ids += [sc.id for sc in secondary_impl_contracts]

        # ``value_effects`` stays a Plane-0 fact off legacy labels (it drives the
        # role classification + fund-flow lane); the capability chips key off
        # Plane-1 claims per function, legacy labels the claim-less fallback.
        value_effects: list[str] = []
        caps_set: set[str] = set()
        for cid in ef_contract_ids:
            for rec in ef_effects_by_cid.get(cid, []):
                for label in rec["labels"]:
                    if label in ("asset_pull", "asset_send", "mint", "burn") and label not in value_effects:
                        value_effects.append(label)
                caps_set |= _function_capabilities(rec["labels"], rec["claims"])

        # Two non-label extras layered on: ``upgradeable`` (it's a proxy shell)
        # and ``pause`` from the summary flag (a contract can be pausable without
        # a pause_toggle EffectiveFunction surfacing).
        if is_proxy:
            caps_set.add("upgradeable")
        # ``is True``, not truthiness: the column is three-state and a ``None``
        # means the pause detector did not answer (or there is no summary row at
        # all). A capability chip is a positive claim — "this contract can be
        # paused" — so only a proven ``True`` earns one. Absence of the chip is
        # NOT published as proof of the opposite; the three-state flag below is
        # where a consumer reads that.
        if summary_row is not None and summary_row.is_pausable is True:
            caps_set.add("pause")
        capabilities: list[str] = sorted(caps_set)

        contract_name = None
        if is_proxy and impl_job:
            if impl_contract and impl_contract.contract_name:
                contract_name = impl_contract.contract_name
            elif impl_job.name:
                contract_name = impl_job.name
        if not contract_name:
            contract_name = (contract_row.contract_name if contract_row else None) or job.name or ""
        standards = list(summary_row.standards or []) if summary_row else []
        # Three states through the payload. ``False`` used to be published for a
        # contract that HAS NO SUMMARY ROW — 3 of the 56 entries the endpoint
        # serves on the local corpus (lower bound; every dependency-only contract
        # without a summary takes this path) — so "this contract cannot be paused
        # / has no timelock / is not
        # a factory" was asserted on the strength of never having looked. The
        # producer's own columns are three-state (``bool | None``), and a row
        # whose column is NULL means the detector ran and could not tell; both
        # routes to "nobody answered" publish ``None`` here, and
        # ``summary_evidence`` below names WHICH route it was — the two are
        # different questions for whoever wants to fix it (re-run the stage vs
        # improve the detector), and the same answer for anyone reading the flag.
        is_factory = summary_row.is_factory if summary_row else None
        has_timelock = summary_row.has_timelock if summary_row else None
        is_pausable = summary_row.is_pausable if summary_row else None
        control_model = summary_row.control_model if summary_row else None

        name_lower = contract_name.lower()
        if "bridge" in name_lower or "gateway" in name_lower:
            role = "bridge"
        elif any(e in value_effects for e in ("asset_pull", "asset_send")):
            role = "value_handler"
        elif any(s in standards for s in ("ERC20", "ERC721", "ERC1155")):
            role = "token"
        elif has_timelock is True or control_model == "governance":
            role = "governance"
        elif is_factory is True:
            role = "factory"
        else:
            role = "utility"

        # ``role`` has no not-determined member and every consumer needs one:
        # each branch above except the last fires on a POSITIVE fact (a name, an
        # observed value effect, a declared standard, a proven timelock/factory),
        # so only the ``utility`` fall-through can be reached by a chain of
        # not-determined inputs. Published as its own key rather than folded into
        # ``role`` so the existing role vocabulary — read by the canvas, the
        # layout bands and ``protocolScore`` — keeps its meaning, and a consumer
        # that cares can refuse to treat this row's ``utility`` as evidence.
        role_evidence = (
            "witnessed"
            if role != "utility" or (summary_row is not None and has_timelock is not None and is_factory is not None)
            else "not_determined"
        )

        balance_contract = lookup_contract or contract_row
        balances_list = []
        total_usd = 0.0
        unvalued_rows = 0
        if balance_contract:
            for b in balances_by_cid.get(balance_contract.id, []):
                usd = float(b.usd_value) if b.usd_value is not None else None
                if usd is None:
                    unvalued_rows += 1
                balances_list.append(
                    {
                        "token_symbol": b.token_symbol,
                        "token_name": b.token_name,
                        "token_address": b.token_address,
                        "raw_balance": b.raw_balance,
                        "decimals": b.decimals,
                        "usd_value": usd,
                        # ``usd_value: null`` and ``usd_value: 0`` are one
                        # truthiness test apart in JS and mean opposite things —
                        # "we do not know what this holding is worth" (1,001 of
                        # 1,376 local rows) versus "priced, and worth less than
                        # half a cent" (100 rows). The state is published rather
                        # than left to be inferred from the value's shape.
                        #
                        # ``not_determined`` deliberately does not name a CAUSE:
                        # ``utils/etherscan`` distinguishes "no price returned"
                        # from "no token divisor returned" (which would make any
                        # USD figure wrong by 10^n), but neither writer persists
                        # ``decimals_reported``, so the DB cannot tell them apart
                        # and this payload must not pretend otherwise.
                        "usd_value_state": "measured" if usd is not None else "not_determined",
                        # Kept for continuity, and NOT a money fact: the producer
                        # writes 0 for "no price known" on 1,001 local rows (a
                        # further 6 rows hold a real sub-1e-8 price truncated to
                        # 0 by Numeric(20,8) — 0 is ambiguous even between those
                        # two), so a consumer reading this column directly reads
                        # them as worthless. Read ``usd_value`` / ``usd_value_state``.
                        "price_usd": float(b.price_usd) if b.price_usd is not None else None,
                    }
                )
                if usd:
                    total_usd += usd
        # Whether this contract's holdings list is the whole set. There is no
        # ``complete`` member ON PURPOSE: the Etherscan holdings fetch returns ONE
        # page capped at ``TOKEN_BALANCE_PAGE_SIZE`` and neither writer persists
        # the raw page length, so nothing here can prove a short list was not a
        # truncated one (the loop that stores rows drops zero-balance entries, so
        # a full page can store fewer than the cap). At-the-cap is therefore the
        # only positive statement available — ``token_balances_may_be_truncated``'s
        # own one-directional contract — and the other arm is not-determined,
        # never "whole".
        holdings_coverage = {
            "rows": len(balances_list),
            "page_cap": TOKEN_BALANCE_PAGE_SIZE,
            "state": ("may_be_incomplete" if token_balances_may_be_truncated(len(balances_list)) else "not_determined"),
            # Rows inside the stored set whose USD value was never determined.
            # ``total_usd`` skips them, so any non-zero total is a lower bound
            # whenever this is non-zero — independently of truncation.
            "unvalued_rows": unvalued_rows,
        }

        entry: dict[str, Any] = {
            # Canonical lowercase: node ids and selection keys downstream
            # assume one form, but a legacy job row can hold a checksummed
            # address (ingress normalizes only since the AnalyzeRequest
            # validator landed).
            "address": (job.address or "").lower(),
            "name": contract_name,
            "contract_id": contract_row.id if contract_row else None,
            "job_id": str(job.id),
            "impl_job_id": impl_job_id,
            "is_proxy": is_proxy,
            "proxy_type": proxy_type,
            "implementation": impl_addr,
            "secondary_implementations": (
                [s.lower() for s in (contract_row.secondary_implementations or [])] if contract_row else []
            ),
            "deployer": contract_row.deployer if contract_row else None,
            "owner": owner,
            "controllers": controllers,
            "control_model": control_model,
            "source_verified": summary_row.source_verified if summary_row else None,
            "chain": contract_row.chain if contract_row else None,
            "upgrade_count": upgrade_count,
            # Never a proven-complete count: it is an upper bound whose coverage
            # (how many of the events carry a receipt fact, how many proven
            # deployments were removed) is stated rather than implied, together
            # with the three refusals — signer set, decoy verdict, and whether
            # the recording surface saw everything — that this plane cannot
            # answer at all.
            "upgrade_count_basis": upgrade_count_basis,
            "last_upgrade_block": last_upgrade_block,
            "last_upgrade_timestamp": last_upgrade_timestamp,
            "role": role,
            "role_evidence": role_evidence,
            "standards": standards,
            "value_effects": value_effects,
            "is_pausable": is_pausable,
            "has_timelock": has_timelock,
            "is_factory": is_factory,
            # Which route a ``None`` on the three flags above took: ``absent``
            # means no ContractSummary row exists for this entry (nor for its
            # implementation), ``present`` means the row exists and the column
            # itself is NULL. Never omitted, so key-absence marks a pre-fix
            # payload rather than either state.
            "summary_evidence": "present" if summary_row is not None else "absent",
            "capabilities": capabilities,
            "balances": balances_list,
            "total_usd": round(total_usd, 2) if total_usd > 0 else None,
            "holdings_coverage": holdings_coverage,
        }

        graph_contract = lookup_contract or contract_row
        if graph_contract:
            cg_nodes = cgn_by_cid.get(graph_contract.id, [])
            cg_edges = cge_by_cid.get(graph_contract.id, [])
            node_meta = {n.address: _principal_lookup_meta(principal_lookup, n.address, n.details) for n in cg_nodes}
            nodes_payload = [
                {
                    "address": n.address,
                    "type": node_meta[n.address].get("resolved_type") or n.resolved_type,
                    "label": node_meta[n.address].get("label") or n.contract_name or n.label,
                    "details": node_meta[n.address]["details"],
                }
                for n in cg_nodes
            ]
            edges_payload = [
                {
                    "from": e.from_node_id.replace("address:", ""),
                    "to": e.to_node_id.replace("address:", ""),
                    "relation": e.relation,
                }
                for e in cg_edges
            ]
            entry["control_graph"] = _trim_control_graph(nodes_payload, edges_payload)
        contracts.append(entry)

        if owner:
            owner_groups.setdefault(owner, []).append(entry)

    # Deduplicate: remove standalone impl contracts already represented via a
    # proxy — both the EIP-1967 impl and any split-proxy secondary impls (the
    # latter were analysed standalone in older runs). Keyed by the composite
    # entity token (a proxy's impl is on the proxy's own chain) so a same-address
    # standalone on ANOTHER chain isn't collapsed away.
    impl_entities = {_entity_key(c.get("chain"), c["implementation"]) for c in contracts if c.get("implementation")}
    for c in contracts:
        for saddr in c.get("secondary_implementations") or []:
            impl_entities.add(_entity_key(c.get("chain"), saddr))
    contracts = [
        c
        for c in contracts
        if not c["address"] or _entity_key(c.get("chain"), c["address"]) not in impl_entities or c["is_proxy"]
    ]

    remaining_addrs = {c["address"] for c in contracts if c["address"]}
    for owner_addr in list(owner_groups):
        owner_groups[owner_addr] = [e for e in owner_groups[owner_addr] if e["address"] in remaining_addrs]
        if not owner_groups[owner_addr]:
            del owner_groups[owner_addr]

    hierarchy = _build_ownership_hierarchy(contracts, owner_groups)
    protocol_ids = {c.protocol_id for c in contracts_by_job_id.values() if c is not None and c.protocol_id is not None}
    reach_edges = _protocol_reach_edges(session, protocol_ids)
    fund_flows, principals = _build_flows_and_principals(
        contracts,
        contracts_by_job_id,
        controller_values_by_cid,
        fp_governance_by_cid,
        cgn_by_cid,
        cge_by_cid,
        fp_in_contract_by_cid,
        fp_all_addrs_by_cid,
        principal_lookup,
        reach_edges,
    )

    # Reshape FP-by-contract-id into FP-by-contract-address so each principal
    # gets a ``primary_for`` list — the contracts it canonically governs,
    # consumed by Surface group containment (see
    # ``services.governance.primary_controller``). Two transforms make this
    # correct across protocols, not just for directly-Safe-owned contracts:
    #
    #   1. Proxy→impl keying. EffectiveFunction / FunctionPrincipal rows live
    #      on the *implementation* contract, but the canvas renders and groups
    #      by the *proxy* address. Map impl→proxy so a principal's primary_for
    #      lands on the address the frontend actually draws; without this every
    #      proxied contract silently drops out of all groups.
    #
    #   2. Governance pass-through. When a protocol is governed via an
    #      in-protocol Timelock / ProxyAdmin, the governed contracts' direct FP
    #      caller resolves to that governance contract — which is itself
    #      in-protocol and therefore never a principal. We hand the set of such
    #      contracts to ``assign_primary_controllers`` so it resolves authority
    #      one hop further, to the terminal Safe/EOA. Only FP (call-authority)
    #      edges are followed, so fund-destination Safes (which hold no FP row)
    #      cannot be re-introduced.
    # cid → the composite entity token of the contract's OWN (chain, address).
    # The whole attribution fold below stays in composite-entity space so a
    # same-address twin on another chain never merges into this chain's
    # authority sets: two standalone CREATE2 twins render to distinct
    # ``<chain>::<address>`` keys, so ``assign_primary_controllers`` runs a
    # separate contest per chain. The per-principal OUTPUT fields (primary_for /
    # co_controls / controls_detail / other_callers) are rendered back to BARE
    # addresses at the landing points — the frontend composes those with the
    # active chain (site/src/surface/layout/elkLayout.js), so the serialized
    # values must stay bare.
    contract_entity_by_cid: dict[int, str] = {
        c.id: _entity_key(c.chain, c.address) for c in contracts_by_job_id.values() if c is not None and c.address
    }
    impl_entity_to_proxy_entity: dict[str, str] = {}
    for c in contracts:
        if not (c.get("is_proxy") and c.get("address")):
            continue
        # An impl renders under its proxy only on the proxy's own chain.
        proxy_entity = _entity_key(c.get("chain"), c["address"])
        if c.get("implementation"):
            impl_entity_to_proxy_entity[_entity_key(c.get("chain"), c["implementation"])] = proxy_entity
        # Secondary impls render under the proxy too, so their FunctionPrincipal
        # authority (e.g. a governor over admin functions) attributes here.
        for saddr in c.get("secondary_implementations") or []:
            impl_entity_to_proxy_entity[_entity_key(c.get("chain"), saddr)] = proxy_entity

    def _rendered_entity(cid: int) -> str | None:
        own_entity = contract_entity_by_cid.get(cid)
        if not own_entity:
            return None
        # Fold onto the proxy (its own chain) if this cid is a proxy's impl; else
        # render under the contract's own entity.
        return impl_entity_to_proxy_entity.get(own_entity) or own_entity

    # ``{contract_entity: {caller_entity}}`` — the FP authority graph the
    # primary-controller contest walks. Callers are composited with the chain of
    # the contract they call (a caller and its target are always same-chain), so
    # an in-protocol governance contract is one node whether it appears as a
    # contract key or as a passthrough caller — the graph stays connected.
    fp_addrs_by_contract_entity: dict[str, set[str]] = {}
    for cid, addrs in fp_all_addrs_by_cid.items():
        rendered = _rendered_entity(cid)
        if not rendered:
            continue
        chain_tok = _entity_chain(rendered)
        bucket = fp_addrs_by_contract_entity.setdefault(rendered, set())
        bucket.update(_entity_key(chain_tok, a) for a in addrs)

    governance_passthrough = {
        entity
        for entity in fp_addrs_by_contract_entity
        if principal_lookup.get(_entity_addr(entity), {}).get("resolved_type") in {"timelock", "proxy_admin"}
    }
    # Bare-address mirror for the caller_detail capability walk below, whose inner
    # caller keys stay bare addresses.
    governance_passthrough_addrs = {_entity_addr(e) for e in governance_passthrough}

    primary_for = assign_primary_controllers(
        principals,
        fp_addrs_by_contract_entity,
        governance_passthrough=governance_passthrough,
    )

    # Co-controllers: principals holding real (privileged or tightly-gated)
    # authority on a contract they lost the primary contest for. Surfaced as
    # their own guardian-rail nodes (not group containers) and enrolled in
    # monitoring, so a pause / fund-recovery guardian Safe isn't invisible just
    # because a bigger governance Safe won the same contracts. Built from
    # per-function caller sets + effect labels keyed to the rendered (proxy)
    # address — same keying as ``primary_for``; see
    # ``services.governance.primary_controller.assign_co_controllers``.
    fp_function_detail_by_entity: dict[str, list[dict[str, Any]]] = {}
    for cid, functions in fp_function_detail_by_cid.items():
        rendered = _rendered_entity(cid)
        if not rendered:
            continue
        fp_function_detail_by_entity.setdefault(rendered, []).extend(functions)
    co_controls = assign_co_controllers(principals, fp_function_detail_by_entity, primary_for)

    principal_meta = {(p.get("address") or "").lower(): p for p in principals if p.get("address")}

    # Per-(controller, contract) capability detail: the concrete functions — and
    # effect-category tags — each FP caller can actually invoke. Lets the canvas
    # show "pause · recover" instead of a generic "controlled", from verified
    # call rights (FunctionPrincipal), not the CGN-derived ``controls`` list.
    # ``caller_detail[contract_entity][caller_lc] = {functions, labels}`` — the
    # contract key is the composite ``<chain>::<address>`` entity (so twins stay
    # separate), the caller key a bare address. EVERY FP caller is kept here,
    # including in-protocol governance *contracts* (timelocks / proxy-admins) —
    # they're the passthrough hop a governance Safe reaches its contracts
    # through, so the capability resolution below needs them. Non-principal
    # callers are filtered out at the consumption points.
    caller_detail: dict[str, dict[str, dict[str, set[str]]]] = {}
    for caddr, functions in fp_function_detail_by_entity.items():
        for fn in functions:
            fname = fn.get("function")
            # Capability chips are computed per function (claims-first) then
            # unioned, so the claims-vs-legacy choice stays per-function.
            fn_caps = _function_capabilities(fn.get("labels") or (), fn.get("claims") or ())
            for a in fn.get("callers", ()):
                la = (a or "").lower()
                if not la:
                    continue
                detail = caller_detail.setdefault(caddr, {}).setdefault(la, {"functions": set(), "capabilities": set()})
                if fname:
                    detail["functions"].add(fname)
                detail["capabilities"].update(fn_caps)

    # Invert to per-principal: the contracts it can call, with functions +
    # capability tags. Drives the sidebar "Can Call" and the on-select chips for
    # BOTH co-controllers and primaries. Two sources merged:
    #   1. Direct FP authority (caller_detail).
    #   2. Passthrough — capabilities held via an in-protocol governance
    #      contract (timelock / proxy-admin) the principal controls, the same
    #      hop assign_primary_controllers used to award primary_for. Without
    #      this the governance Safe that acts only through its timelock would
    #      show no capabilities on the 20 contracts it governs (just
    #      "controlled"). One hop — covers Safe → Timelock → contracts.
    detail_acc: dict[str, dict[str, dict[str, set[str]]]] = {}

    def _accumulate(principal_lc: str, contract_lc: str, src: dict[str, set[str]]) -> None:
        slot = detail_acc.setdefault(principal_lc, {}).setdefault(
            contract_lc, {"functions": set(), "capabilities": set()}
        )
        slot["functions"].update(src.get("functions", ()))
        slot["capabilities"].update(src.get("capabilities", ()))

    # detail_acc keys: principal (bare address) → contract (composite entity).
    for caddr, callers_map in caller_detail.items():
        for la, detail in callers_map.items():
            if la in principal_meta:  # direct rights belong to principals, not contract callers
                _accumulate(la, caddr, detail)
    for la, owned in primary_for.items():
        for caddr in owned:
            # The governance contract's own entity shares the governed contract's
            # chain (control is intra-chain), so rebuild it from the bare caller.
            caddr_chain = _entity_chain(caddr)
            for gov_addr, gov_detail in caller_detail.get(caddr, {}).items():
                gov_entity = _entity_key(caddr_chain, gov_addr)
                if gov_addr in governance_passthrough_addrs and la in caller_detail.get(gov_entity, {}):
                    _accumulate(la, caddr, gov_detail)

    detail_by_principal: dict[str, list[dict[str, Any]]] = {}
    for la, by_contract in detail_acc.items():
        # Render the contract entity back to a bare address for the payload.
        rows = [
            {
                "address": _entity_addr(caddr),
                "chain": _entity_chain(caddr),
                "functions": sorted(d["functions"]),
                "capabilities": sorted(d["capabilities"]),
            }
            for caddr, d in by_contract.items()
        ]
        rows.sort(key=lambda e: (e["address"], e["chain"]))
        detail_by_principal[la] = rows

    for p in principals:
        p_addr_lc = (p.get("address") or "").lower()
        # primary_for / co_controls carry composite contract entities internally;
        # the serialized fields are bare addresses (the frontend re-composes them
        # with the active chain).
        p["primary_for"] = sorted({_entity_addr(e) for e in primary_for.get(p_addr_lc, [])})
        p["co_controls"] = sorted({_entity_addr(e) for e in co_controls.get(p_addr_lc, [])})
        # The chains the flattening above discards, kept as their own field:
        # the per-chain contests already ran, so the set of chains this
        # principal won or co-controls ON is a computed fact — enrollment needs
        # it to put a controller's MonitoredContract row on the chain of the
        # contracts it governs instead of a caller-supplied default.
        p["controls_chains"] = sorted(
            {_entity_chain(e) for e in primary_for.get(p_addr_lc, [])}
            | {_entity_chain(e) for e in co_controls.get(p_addr_lc, [])}
        )
        p["controls_detail"] = detail_by_principal.get(p_addr_lc, [])

    # Per-edge ``capabilities``: what THE SOURCE can do to THE TARGET, from
    # the same FunctionPrincipal-derived machinery that feeds
    # ``controls_detail`` — so an edge chip and the principal's own detail
    # panel can never disagree about the same (source, target) pair.
    # ``detail_acc`` (principal sources; includes the one-hop governance
    # passthrough) is consulted first, then ``caller_detail`` (contract
    # sources with direct FP rights). A source with no witnessed rights on
    # the target publishes ``[]`` — same convention as the contract-level
    # list: a capability chip is a positive claim, and its absence is not
    # published as proof of inability (the edge itself still states the
    # ownership/controller relationship via ``type``).
    for flow in fund_flows:
        src_lc = (flow.get("from") or "").lower()
        target_entity = _entity_key(flow.get("to_chain"), flow.get("to"))
        detail = detail_acc.get(src_lc, {}).get(target_entity)
        if detail is None:
            detail = caller_detail.get(target_entity, {}).get(src_lc)
        flow["capabilities"] = sorted(detail["capabilities"]) if detail else []

    # Per-contract "other callers": principal-callers holding FP authority that
    # are neither the contract's primary owner nor a co-controller of it — the
    # permissionless / lower-privilege long tail (e.g. AuctionManager's
    # whitelisted ``createBid`` bidders). The canvas renders these in aggregate
    # as a "+N callers" affordance per contract, so an authorized caller is
    # never silently invisible, without drawing 30+ cross-group edges or minting
    # a node per bidder. Each carries its own functions / capabilities so the
    # sidebar list says what each caller can do. Restricted to FP-typed
    # principals, so state-variable destinations / CGN noise don't leak in.
    # Keyed by composite contract entity (primary_for / co_controls carry those);
    # the principal values stay bare addresses.
    primary_by_contract: dict[str, str] = {c: paddr for paddr, owned in primary_for.items() for c in owned}
    co_by_contract: dict[str, set[str]] = {}
    for paddr, owned in co_controls.items():
        for c in owned:
            co_by_contract.setdefault(c, set()).add(paddr)
    for entry in contracts:
        addr = (entry.get("address") or "").lower()
        entity = _entity_key(entry.get("chain"), addr)
        cd = caller_detail.get(entity, {})
        callers = {a for a in cd if a in principal_meta}  # contract callers aren't "other callers"
        callers.discard(addr)
        callers.discard(primary_by_contract.get(entity, ""))
        callers -= co_by_contract.get(entity, set())
        entry["other_callers"] = [
            {
                "address": a,
                "type": (principal_meta.get(a) or {}).get("type"),
                "label": (principal_meta.get(a) or {}).get("label"),
                "functions": sorted(cd[a]["functions"]),
                "capabilities": sorted(cd[a]["capabilities"]),
            }
            for a in sorted(callers)
        ]

    return GovernanceView(
        contracts=contracts,
        principals=principals,
        hierarchy=hierarchy,
        fund_flows=fund_flows,
    )


def _build_ownership_hierarchy(
    contracts: list[dict[str, Any]], owner_groups: dict[str, list[dict]]
) -> list[dict[str, Any]]:
    hierarchy: list[dict[str, Any]] = []
    assigned: set[str | None] = set()
    for owner_addr, owned in sorted(owner_groups.items(), key=lambda x: -len(x[1])):
        owner_contract = next((c for c in contracts if c["address"] and c["address"].lower() == owner_addr), None)
        hierarchy.append(
            {
                "owner": owner_addr,
                "owner_name": owner_contract["name"] if owner_contract else None,
                "owner_is_contract": owner_contract is not None,
                "contracts": [{"address": c["address"], "name": c["name"]} for c in owned],
            }
        )
        assigned.update(c["address"] for c in owned)

    unowned = [c for c in contracts if c["address"] not in assigned]
    if unowned:
        hierarchy.append(
            {
                "owner": None,
                "owner_name": "No owner detected",
                "owner_is_contract": False,
                "contracts": [{"address": c["address"], "name": c["name"]} for c in unowned],
            }
        )
    return hierarchy


_ZERO_ADDR = "0x0000000000000000000000000000000000000000"


def _protocol_reach_edges(
    session: Session, protocol_ids: set[int]
) -> list[tuple[str, str, str, str | None, str | None]]:
    """The control edges the scorer's closure walks, protocol-wide.

    Mirrors ``services.scoring.planes.load_control_closure`` exactly: every
    ``ControlGraphEdge`` row of the protocol whose relation is in
    ``SCORER_REACH_RELATIONS`` (reversed to authority direction), plus the
    ``Contract.admin`` column pairs. Deliberately NOT restricted to the
    contracts that make this payload's list — the scorer isn't either, so a
    score-document reach can route through an implementation or an orphaned
    contract row this page never renders, and the surface graph must carry
    those hops to route the path. Rows are ``(chain_tok, holder, subject,
    relation, label)``; admin pairs carry ``relation=None`` (the column is the
    witness — inventing a relation name for it would overclaim).

    ``safe_owner`` and ``capability_principal`` witnesses never appear here:
    the scorer excludes both from reach, and admitting them would draw routes
    the score document does not vouch for. Zero-address ends are skipped —
    a renounced owner holds nothing, and no host-seeded path routes through
    the zero address.
    """
    rows: list[tuple[str, str, str, str | None, str | None]] = []
    if not protocol_ids:
        return rows
    id_list = sorted(protocol_ids)
    edge_rows = (
        session.query(ControlGraphEdge, Contract.chain)
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id.in_(id_list), ControlGraphEdge.relation.in_(SCORER_REACH_RELATIONS))
        .order_by(ControlGraphEdge.id)
        .all()
    )
    for edge, chain in edge_rows:
        subject = (edge.from_node_id or "").replace("address:", "").lower()
        holder = (edge.to_node_id or "").replace("address:", "").lower()
        if not subject or not holder or subject == holder or _ZERO_ADDR in (subject, holder):
            continue
        rows.append((_coalesce_chain(chain), holder, subject, edge.relation, edge.label or None))
    for contract in session.query(Contract).filter(Contract.protocol_id.in_(id_list)).order_by(Contract.id).all():
        address = (contract.address or "").lower()
        admin = (contract.admin or "").lower()
        if address and admin and admin != address and _ZERO_ADDR not in (address, admin):
            rows.append((_coalesce_chain(contract.chain), admin, address, None, None))
    return rows


def _control_edge_witness(
    contracts: list[dict[str, Any]],
    lookup_contract_by_entity: dict[str, Contract | None],
    cge_by_cid: dict[int, list[ControlGraphEdge]],
    reach_edges: Iterable[tuple[str, str, str, str | None, str | None]] = (),
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """``(chain, flow_from, flow_to)`` → the witnessed claims on that control edge.

    A ``control_graph_edges`` row is written subject-first: ``from_node_id`` is
    the contract the row was recorded against and ``to_node_id`` the related
    address, and for the relations in ``CONTROL_EDGE_RELATIONS`` that reads
    "the to-node has authority over the from-node" (see ``db.models``). A
    fund-flow control edge runs the other way — authority holder → contract —
    so rows are indexed reversed. Only those relations are indexed: reversing
    an ``external_call_target`` would assert an authority nobody proved.

    ``reach_edges`` (from :func:`_protocol_reach_edges`) contributes the same
    claims for pairs whose carrying row lives on a contract outside this
    payload — an edge admitted from that plane must be nameable too.

    One pair can carry several distinct claims at once (a Teller both holds
    ``roles 2,3`` on a vault and is its ``hook`` controller-value). Collapsing
    them to one would publish an arbitrary pick, so the single-claim case gets
    the scalar ``relation`` / ``label`` and the multi-claim case gets the whole
    witnessed set as ``relations``. A pair with no control-graph row at all gets
    neither, and the edge is published with its flow type alone.
    """
    claims: dict[tuple[str, str, str], set[tuple[str, str | None]]] = {}
    for entry in contracts:
        if not entry.get("address"):
            continue
        lookup_c = lookup_contract_by_entity.get(_entity_key(entry.get("chain"), entry["address"]))
        if not lookup_c:
            continue
        chain_tok = _coalesce_chain(entry.get("chain"))
        for edge in cge_by_cid.get(lookup_c.id, []):
            if edge.relation not in CONTROL_EDGE_RELATIONS:
                continue
            subject = (edge.from_node_id or "").replace("address:", "").lower()
            holder = (edge.to_node_id or "").replace("address:", "").lower()
            if not subject or not holder or subject == holder:
                continue
            claims.setdefault((chain_tok, holder, subject), set()).add((edge.relation, edge.label or None))
    for chain_tok, holder, subject, relation, label in reach_edges:
        if relation is not None:
            claims.setdefault((chain_tok, holder, subject), set()).add((relation, label))

    witness: dict[tuple[str, str, str], dict[str, Any]] = {}
    for key, pairs in claims.items():
        ordered = sorted(pairs, key=lambda p: (p[0], p[1] or ""))
        if len(ordered) == 1:
            relation, label = ordered[0]
            witness[key] = {"relation": relation, **({"label": label} if label else {})}
        else:
            witness[key] = {
                "relations": [{"relation": r, **({"label": lb} if lb else {})} for r, lb in ordered],
            }
    return witness


def _build_flows_and_principals(
    contracts: list[dict[str, Any]],
    contracts_by_job_id: dict[Any, Contract],
    controller_values_by_cid: dict[int, list[ControllerValue]],
    fp_governance_by_cid: dict[int, list[dict[str, Any]]],
    cgn_by_cid: dict[int, list[ControlGraphNode]],
    cge_by_cid: dict[int, list[ControlGraphEdge]],
    fp_in_contract_by_cid: dict[int, set[str]],
    fp_all_addrs_by_cid: dict[int, set[str]],
    principal_lookup: dict[str, dict[str, Any]],
    reach_edges: list[tuple[str, str, str, str | None, str | None]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    contract_addrs = {c["address"].lower() for c in contracts if c["address"]}
    # Control relations are intra-chain, so every flow carries a single chain
    # (from_chain == to_chain). Dedup is per-chain so a same-address twin on
    # another chain keeps its own edge instead of colliding on the bare pair.
    flow_seen: set[tuple[str, str, str]] = set()
    fund_flows: list[dict[str, Any]] = []
    # Filled once the contract→Contract lookup exists (below), before the first
    # add_flow call. Absent keys are the normal case: an edge the control graph
    # never witnessed a relation for carries no relation/label at all.
    edge_witness: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_flow(from_addr: str, to_addr: str, flow_type: str, chain: str | None, lane: str = "control") -> None:
        chain_tok = _coalesce_chain(chain)
        key = (chain_tok, (from_addr or "").lower(), (to_addr or "").lower())
        if key in flow_seen:
            return
        flow_seen.add(key)
        fund_flows.append(
            {
                "from": from_addr,
                "to": to_addr,
                "type": flow_type,
                "lane": lane,
                # Additive, and present only where a control-graph row witnesses
                # this exact pair (see _control_edge_witness) — the frontend's
                # reach-path inspector names the hop's relation/role from it and
                # shows the type alone when it is absent.
                **edge_witness.get(key, {}),
                # Filled by build_governance_view once caller_detail exists:
                # the SOURCE's witnessed rights on the target, never the
                # target's own capability union — an edge is a claim about the
                # relationship, and the frontend renders it as a per-edge chip.
                "capabilities": [],
                "from_chain": chain_tok,
                "to_chain": chain_tok,
            }
        )

    def _lookup_contract_for(entry: dict[str, Any]) -> Contract | None:
        import uuid as _uuid

        lookup_job_id = entry.get("impl_job_id") or entry["job_id"]
        try:
            key_id = _uuid.UUID(lookup_job_id) if isinstance(lookup_job_id, str) else lookup_job_id
        except (TypeError, ValueError):
            key_id = lookup_job_id
        return contracts_by_job_id.get(key_id)

    # Keyed by composite ``<chain>::<address>`` entity, not bare address: two
    # standalone twins share an address, so a bare key would resolve both to one
    # chain's Contract row and collapse the other chain's principals.
    lookup_contract_by_entity: dict[str, Contract | None] = {}
    for entry in contracts:
        if entry.get("address"):
            lookup_contract_by_entity[_entity_key(entry.get("chain"), entry["address"])] = _lookup_contract_for(entry)

    edge_witness.update(_control_edge_witness(contracts, lookup_contract_by_entity, cge_by_cid, reach_edges))

    for c in contracts:
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        lookup_c = lookup_contract_by_entity.get(_entity_key(chain, target))
        # In-protocol contract addresses that hold actual call authority
        # on this target's EffectiveFunctions. Same authoritative signal
        # (FunctionPrincipal) drives both the controller-flow gate and
        # the principal-flow emit below.
        fp_principals: set[str] = fp_in_contract_by_cid.get(lookup_c.id, set()) if lookup_c else set()

        if c.get("owner") and c["owner"] in contract_addrs:
            flow_type = (
                "controls_value"
                if any(e in c.get("value_effects", []) for e in ("asset_pull", "asset_send"))
                else "controls"
            )
            add_flow(c["owner"], target, flow_type, chain)

        # The ``controllers`` dict at the contract entry is populated
        # unfiltered from every tracked address-typed ControllerValue
        # row, which includes integration/composability references
        # (``weth``, ``oracle``, ``treasury``, ``swapRouter``, ``stEth``)
        # alongside real authorizers. Emitting type=controller for the
        # former asserts a control relationship that doesn't exist.
        # Gate on FunctionPrincipal membership so only CV values that
        # the capability resolver also identified as call-authority
        # principals produce a controller flow.
        for cid, val in c.get("controllers", {}).items():
            if isinstance(val, str) and val.startswith("0x"):
                val_lower = val.lower()
                if val_lower in contract_addrs and val_lower != (c.get("owner") or "") and val_lower in fp_principals:
                    add_flow(val_lower, target, "controller", chain)

        # In-protocol contract principals come from FunctionPrincipal —
        # the per-function access-control record produced by the
        # capability resolver. A bare ControlGraphNode match used to
        # drive this and over-reported transitive lineage (e.g. a token
        # mid-chain like ``WithdrawalQueueERC721 -> WstETH -> Lido stETH``
        # was flagged as a principal of every EtherFi contract whose
        # graph traversed it). FP is the authoritative signal: an
        # address only appears here if it can actually call a function.
        if lookup_c:
            for node_addr in fp_principals:
                if not node_addr or node_addr == target:
                    continue
                if node_addr not in contract_addrs:
                    continue
                add_flow(node_addr, target, "principal", chain)

    # Collect non-contract principals from control graph + function principals.
    # First pass: find safe_owner edges so we can nest Safe owners later.
    principal_map: dict[str, dict[str, Any]] = {}
    safe_owners_map: dict[str, list[str]] = {}
    owner_of_safe: set[str] = set()

    for c in contracts:
        if not c["address"]:
            continue
        lookup_c = lookup_contract_by_entity.get(_entity_key(c.get("chain"), c["address"]))
        if not lookup_c:
            continue
        for edge in cge_by_cid.get(lookup_c.id, []):
            if edge.relation != "safe_owner":
                continue
            safe_addr = edge.from_node_id.replace("address:", "").lower()
            owner_addr = edge.to_node_id.replace("address:", "").lower()
            safe_owners_map.setdefault(safe_addr, [])
            if owner_addr not in safe_owners_map[safe_addr]:
                safe_owners_map[safe_addr].append(owner_addr)
            owner_of_safe.add(owner_addr)

    # Second pass: collect direct controllers (skip Safe owners — they're nested)
    for c in contracts:
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        lookup_c = lookup_contract_by_entity.get(_entity_key(chain, target))
        if not lookup_c:
            continue

        for cgn in cgn_by_cid.get(lookup_c.id, []):
            node_addr = (cgn.address or "").lower()
            if not node_addr or node_addr in contract_addrs:
                continue
            if node_addr in owner_of_safe:
                continue
            lookup_meta = principal_lookup.get(node_addr, {})
            resolved_type = lookup_meta.get("resolved_type") or cgn.resolved_type
            if resolved_type not in ("safe", "timelock", "proxy_admin", "eoa"):
                continue
            if node_addr == "0x0000000000000000000000000000000000000000":
                continue
            # Gate on FunctionPrincipal authority: a safe/eoa/timelock/
            # proxy_admin CGN node earns a principal + controls edge only if it
            # can actually call a function on this contract. Without it, a
            # zero-authority beneficiary stored in a state var (treasury /
            # feeRecipient / _owner / payoutAddress) becomes a spurious
            # principal claiming control it doesn't hold. Mirrors the
            # controller-flow gate above and the FP third pass below;
            # cgn_by_cid and fp_all_addrs_by_cid are both keyed by lookup_c.id.
            if node_addr not in fp_all_addrs_by_cid.get(lookup_c.id, set()):
                continue

            if node_addr not in principal_map:
                # Seed details with the CGN's own introspection result
                # (getOwners/getThreshold for safes, getMinDelay for
                # timelocks). This is the authoritative source for the
                # principal's intrinsic config — ControllerValue rows
                # describe the relationship FROM a consumer, not the
                # Safe's own threshold, so prior code that only merged
                # CV details missed the threshold and fell back to
                # len(owners).
                details: dict[str, Any] = dict(lookup_meta.get("details") or {})
                if isinstance(cgn.details, dict):
                    details.update(cgn.details)
                for cv in controller_values_by_cid.get(lookup_c.id, []):
                    if (cv.value or "").lower() != node_addr:
                        continue
                    if cv.details and isinstance(cv.details, dict):
                        for k, v in cv.details.items():
                            details.setdefault(k, v)

                if resolved_type == "safe":
                    if not details.get("owners"):
                        details["owners"] = safe_owners_map.get(node_addr, [])
                    if "threshold" not in details and details.get("owners"):
                        details["threshold"] = len(details["owners"])

                principal_map[node_addr] = {
                    "address": node_addr,
                    "type": resolved_type,
                    "label": lookup_meta.get("label") or cgn.contract_name or cgn.label or resolved_type,
                    "details": details,
                    "controls": [],
                    "chains": set(),
                }

            principal_map[node_addr]["controls"].append(target)
            principal_map[node_addr]["chains"].add(_coalesce_chain(chain))
            add_flow(node_addr, target, "principal", chain)

    # Third pass: pull principals out of FunctionPrincipal rows. Some
    # role-gated functions (e.g. EtherFiTimelock.cancel / .execute) have
    # their controlling Safe/EOA stored *only* on the per-function
    # principal row — the Safe never gets a top-level ControlGraphNode
    # entry for that contract, so the prior CGN-only pass misses the
    # Safe→Contract edge entirely. This pass backfills, reading from the
    # narrow ``fp_governance_rows`` projection (already filtered to
    # safe/timelock/eoa/proxy_admin) instead of walking full EF rows.
    for c in contracts:
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        lookup_c = lookup_contract_by_entity.get(_entity_key(chain, target))
        if not lookup_c:
            continue
        for fp in fp_governance_by_cid.get(lookup_c.id, []):
            pa = (fp.get("address") or "").lower()
            if not pa or pa == target:
                continue
            if pa == "0x0000000000000000000000000000000000000000":
                continue
            if pa in owner_of_safe:
                continue
            lookup_meta = principal_lookup.get(pa, {})
            resolved_type = fp.get("resolved_type")
            if lookup_meta.get("resolved_type") and resolved_type in (None, "", "unknown", "contract"):
                resolved_type = lookup_meta["resolved_type"]
            if resolved_type not in ("safe", "timelock", "eoa", "proxy_admin"):
                continue
            if pa in contract_addrs:
                continue
            if pa not in principal_map:
                fp_details = dict(lookup_meta.get("details") or {})
                fp_raw_details = fp.get("details")
                if isinstance(fp_raw_details, dict):
                    fp_details.update(fp_raw_details)
                if resolved_type == "safe":
                    if not fp_details.get("owners"):
                        fp_details["owners"] = safe_owners_map.get(pa, [])
                    if "threshold" not in fp_details and fp_details.get("owners"):
                        fp_details["threshold"] = len(fp_details["owners"])
                principal_map[pa] = {
                    "address": pa,
                    "type": resolved_type,
                    "label": lookup_meta.get("label") or resolved_type,
                    "details": fp_details,
                    "controls": [],
                    "chains": set(),
                }
            if target not in principal_map[pa]["controls"]:
                principal_map[pa]["controls"].append(target)
            principal_map[pa]["chains"].add(_coalesce_chain(chain))
            add_flow(pa, target, "principal", chain)

    # The authority edges the scorer's control closure walks (see
    # _protocol_reach_edges), carried verbatim: the score document publishes
    # reach over exactly these pairs, and one this graph drops is a route the
    # frontend can only report as "not carried". No holder gate — the closure
    # routes through whatever the witnessed rows name, including a
    # RolesAuthority that gates functions without ever being a
    # FunctionPrincipal, an implementation row the page does not render, and
    # contracts never enrolled in the inventory at all. The relations admitted
    # here all carry established authority provenance (an unattributed value
    # lands on controller_value_unattributed, which neither the scorer nor
    # this pass walks), so a beneficiary state-var cannot ride in — and the
    # FP-gated passes stay authoritative for which addresses become principal
    # CARDS; this pass emits edges only. It runs LAST so add_flow's
    # first-writer-wins dedup lets every pass above keep its richer type
    # (``principal``, gate-derived ``controller``) — reach edges only fill
    # pairs no other witness emitted.
    for chain_tok, holder, subject, _relation, _label in reach_edges:
        add_flow(holder, subject, "controller", chain_tok)

    # ``chains`` accumulates as a set during collection (a principal may govern
    # on several chains); the payload carries a sorted list. It stays additive —
    # a single-chain protocol reports ``["ethereum"]`` and nothing else moves.
    principals_out = list(principal_map.values())
    for pr in principals_out:
        pr["chains"] = sorted(pr["chains"])
    return fund_flows, principals_out


def _coalesce_chain(chain: str | None) -> str:
    """Chain token matching the frontend's ``coalesceChain`` (site/src/surface/
    entityKey.js): NULL/empty/``"mainnet"`` fold to ``"ethereum"`` (the
    NULL≡ethereum legacy-read convention), everything else lowercases as-is.

    Deliberately NOT :func:`utils.chains.canonical_chain` — that folds extra
    aliases (``eth``→``ethereum``, ``avax``→``avalanche``) the frontend key does
    not, so a token built here must mirror the JS exactly or the frontend's
    lookup can never match it. Contract ``chain`` strings are already stored
    canonical, so the two agree in practice.
    """
    c = str(chain or "").strip().lower()
    if not c or c == "mainnet":
        return "ethereum"
    return c


def _entity_key(chain: str | None, address: str | None) -> str:
    """Composite ``"<chain>::<address>"`` entity key, byte-identical to the
    frontend ``entityKey`` (site/src/surface/entityKey.js) so a backend-built
    functions map aligns with the frontend's per-(chain, address) lookups.
    ``"::"`` appears in neither a chain name nor a ``0x`` address, so the
    composite is collision-free."""
    return f"{_coalesce_chain(chain)}::{str(address or '').lower()}"


def _entity_addr(entity: str) -> str:
    """Bare lowercased address of a composite ``<chain>::<address>`` entity —
    the inverse of :func:`_entity_key`'s address half. A token without ``"::"``
    (a plain address) passes through unchanged."""
    return entity.rsplit("::", 1)[-1]


def _entity_chain(entity: str) -> str:
    """Coalesced chain token of a composite ``<chain>::<address>`` entity."""
    return entity.split("::", 1)[0] if "::" in entity else _coalesce_chain(None)


def build_functions_for_protocol(session: Session, name: str) -> dict[str, list[dict[str, Any]]]:
    """Return ``{"<chain>::<address>": [function_entries]}`` for every contract
    in the protocol, keyed by the composite entity token (:func:`_entity_key`,
    mirroring the frontend's ``entityKey``).

    Split out of ``build_company_overview`` so the heavy
    ``effective_functions`` query (1469 rows × per-function principal
    expansion, 120-290ms + 2.13 MB of payload on ether.fi) doesn't block
    the main /company TTFB and JSON parse. The frontend mounts the
    Surface canvas off the lighter main payload and fetches this in
    parallel; the function inspector renders a loading state until it
    lands.
    """
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

    # Entities that are a secondary impl of some proxy are absorbed into that
    # proxy node (their functions surface there), so they get no standalone
    # entry — mirrors the canvas dedup for split-proxy admin impls. Keyed by the
    # composite entity token (the secondary is on its proxy's chain) so a
    # same-address standalone on another chain isn't suppressed.
    secondary_impl_entities = {
        _entity_key(cr.chain, s)
        for cr in contracts_by_job_id.values()
        if cr is not None and cr.is_proxy
        for s in (cr.secondary_implementations or [])
    }

    # Map each job's (chain, address) to the contract_ids whose EF rows it
    # should show — for a proxy: its EIP-1967 impl plus any split-proxy secondary
    # impls; for a plain contract: its own row. The key is the composite entity
    # token so a CREATE2 twin at the same address on two chains keeps each
    # chain's own analysis instead of collapsing last-wins.
    entity_key_to_ef_cids: dict[str, list[int]] = {}
    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue
        if not job.address:
            continue
        contract_row = contracts_by_job_id.get(job.id)
        entity_chain = contract_row.chain if contract_row else None
        if _entity_key(entity_chain, job.address) in secondary_impl_entities:
            continue
        impl_addr = contract_row.implementation if (contract_row and contract_row.is_proxy) else None
        impl_job = impl_job_by_entity.get(_entity_key(entity_chain, impl_addr)) if impl_addr else None
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None
        primary_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        cids = [primary_cid] if primary_cid is not None else []
        cids += [
            sc.id
            for sc in _secondary_impl_contracts(contract_row, impl_job_by_entity, contracts_by_job_id)
            if sc.id != primary_cid
        ]
        if cids:
            entity_key_to_ef_cids[_entity_key(entity_chain, job.address)] = cids

    relevant_cids = {cid for cids in entity_key_to_ef_cids.values() for cid in cids}
    ef_rows_by_cid: dict[int, list[EffectiveFunction]] = {}
    if relevant_cids:
        with _time_phase(timings_ms, "effective_functions"):
            ef_row_count = 0
            for ef in session.execute(
                select(EffectiveFunction)
                .where(EffectiveFunction.contract_id.in_(list(relevant_cids)))
                .options(selectinload(EffectiveFunction.principals))
            ).scalars():
                ef_rows_by_cid.setdefault(ef.contract_id, []).append(ef)
                ef_row_count += 1

    # Reuse the same principal_lookup the main path builds so labels and
    # resolved_type carry through to per-function principal entries.
    relevant_contract_ids: set[int] = {c.id for c in contracts_by_job_id.values() if c is not None}
    controller_values_by_cid: dict[int, list[ControllerValue]] = {}
    cgn_by_cid: dict[int, list[ControlGraphNode]] = {}
    terminal_walk_by_address: dict[str, dict[str, Any]] = {}
    if relevant_contract_ids:
        id_list = list(relevant_contract_ids)
        with _time_phase(timings_ms, "principal_lookup_inputs"):
            for cv in session.execute(
                select(ControllerValue).where(ControllerValue.contract_id.in_(id_list))
            ).scalars():
                controller_values_by_cid.setdefault(cv.contract_id, []).append(cv)
            for n in session.execute(
                select(ControlGraphNode).where(ControlGraphNode.contract_id.in_(id_list))
            ).scalars():
                cgn_by_cid.setdefault(n.contract_id, []).append(n)
            # Same terminal-walk forwarding as the main path: the per-function
            # principal payload built below is what ``InspectorCard`` renders
            # ``terminalControllerNote`` from, so wiring only ``build_governance_view``
            # would connect the plane on one endpoint and leave it dark on the other.
            for address, details in session.execute(
                select(PrincipalLabel.address, PrincipalLabel.details).where(
                    PrincipalLabel.contract_id.in_(id_list),
                    jsonb_has_payload(PrincipalLabel.details),
                    PrincipalLabel.details.has_key("terminal_principal"),
                )
            ).all():
                record = (details or {}).get("terminal_principal")
                if isinstance(record, dict) and address:
                    terminal_walk_by_address.setdefault(address.lower(), record)
    principal_lookup = _build_principal_lookup(
        contracts_by_job_id, controller_values_by_cid, cgn_by_cid, terminal_walk_by_address
    )

    out: dict[str, list[dict[str, Any]]] = {}
    with _time_phase(timings_ms, "serialize"):
        for key, ef_cids in entity_key_to_ef_cids.items():
            ef_rows = [ef for cid in ef_cids for ef in ef_rows_by_cid.get(cid, [])]
            out[key] = [
                _build_company_function_entry(ef, ef.principals or [], principal_lookup=principal_lookup)
                for ef in ef_rows
            ]

    total_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "Functions payload built: company=%s contracts=%d functions=%d total_ms=%d",
        name,
        len(out),
        sum(len(v) for v in out.values()),
        total_ms,
        extra={
            "phase": "build_functions_for_protocol",
            "duration_ms": total_ms,
            "company": name,
            "contract_count": len(out),
            "function_count": sum(len(v) for v in out.values()),
            "timings_ms": timings_ms,
        },
    )
    return out


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


def _latest_tvl(session: Session, protocol_row: Protocol | None) -> dict[str, Any] | None:
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


def assemble_company_payload(
    session: Session,
    name: str,
    protocol_row: Protocol | None,
    jobs: list[Job],
    governance: GovernanceView,
) -> dict[str, Any]:
    return {
        "company": name,
        "protocol_id": protocol_row.id if protocol_row else None,
        "contract_count": len(governance.contracts),
        "tvl": _latest_tvl(session, protocol_row),
        "contracts": governance.contracts,
        "principals": governance.principals,
        "ownership_hierarchy": governance.hierarchy,
        "fund_flows": governance.fund_flows,
        # Just the count here — the full inventory (~167 KB for ether.fi) is
        # served by /api/company/{name}/addresses and fetched lazily by
        # AddressesModal when the user opens it.
        "all_addresses_count": _all_addresses_count(session, protocol_row, jobs),
    }


def build_company_overview(session: Session, name: str) -> dict[str, Any]:
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
    with _time_phase(timings_ms, "assemble_payload"):
        payload = assemble_company_payload(session, name, protocol_row, jobs, governance)

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


def controllers_for_protocol(session: Session, protocol_id: int) -> dict[tuple[str, str], str]:
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

    controllers: dict[tuple[str, str], str] = {}
    for principal in governance.principals:
        if not (principal.get("primary_for") or principal.get("co_controls")):
            continue
        ptype = principal.get("type")
        if ptype not in ("safe", "timelock", "proxy_admin"):
            continue
        addr = (principal.get("address") or "").lower()
        if not addr:
            continue
        monitored_type = "proxy" if ptype == "proxy_admin" else ptype
        for chain_token in principal.get("controls_chains") or [_coalesce_chain(None)]:
            controllers[(addr, chain_token)] = monitored_type
    return controllers
