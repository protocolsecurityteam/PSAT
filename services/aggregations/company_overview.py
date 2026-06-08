"""Company-level governance overview.

Decomposed from a single ~700-line endpoint into stages so each step is
testable on its own. ``build_company_overview`` is the orchestrator
called by the router.

Stages (each returns plain Python data, not ORM rows that pin a session):

1. ``resolve_company_jobs`` — protocol lookup keyed by ``Protocol`` plus
   canonical ``Contract.protocol_id`` ownership.
2. ``prefetch_contracts`` — batch fetch canonical ``Contract`` rows by each
   job's ``(address, chain_id)`` identity.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session, aliased, selectinload

from db.models import (
    Contract,
    ContractBalance,
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStatus,
    Protocol,
    TvlSnapshot,
    UpgradeEvent,
)
from schemas.aggregation_schemas import (
    ContractControlGraph,
    ContractControlGraphEdge,
    ContractControlGraphNode,
    GovernanceContract,
    GovernanceFundFlow,
    GovernanceHierarchyEntry,
    GovernanceView,
    TokenBalanceEntry,
)
from schemas.common import Contract as ContractSchema
from schemas.common import make_contract
from schemas.governance_schemas import GovernanceControlDetail, GovernanceFunctionEntry, GovernancePrincipal
from services.governance.primary_controller import assign_co_controllers, assign_primary_controllers
from services.governance.principals import _build_company_function_entry
from utils.rpc import require_supported_chain_id

logger = logging.getLogger("services.aggregations.company_overview")

ImplJobKey = tuple[str, int]


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


def _contract_ref_from_row(
    contract_row: Contract | None,
    *,
    address: str | None,
    chain_id: int | None = None,
    label: str | None = None,
) -> ContractSchema:
    if contract_row is None:
        if chain_id is None:
            raise RuntimeError(f"address-only company overview contract requires chain_id: {address}")
        if not address:
            raise RuntimeError("address-only company overview contract requires address")
        return make_contract(address=address, chain_id=chain_id, name=None, label=label)
    implementations = [
        item for item in [contract_row.implementation, *(contract_row.secondary_implementations or [])] if item
    ]
    if contract_row.chain_id is None:
        raise RuntimeError(f"contract {contract_row.id} requires chain_id for company overview")
    return make_contract(
        address=contract_row.address,
        chain_id=contract_row.chain_id,
        name=contract_row.contract_name,
        label=label,
        is_proxy=bool(contract_row.is_proxy),
        proxy_address=contract_row.address if contract_row.is_proxy else None,
        implementation_addresses=implementations,
        admin_addresses=[contract_row.admin] if contract_row.admin else [],
        beacon_addresses=[contract_row.beacon] if contract_row.beacon else [],
        deployer_address=contract_row.deployer,
        proxy_type=contract_row.proxy_type,
    )


def resolve_company_jobs(session: Session, name: str) -> tuple[Protocol, list[Job]]:
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

    Missing protocol rows are hard failures. The company surface is multichain
    by construction only when ownership comes from ``Protocol`` and
    ``Contract.protocol_id`` rather than historical job ancestry.
    """
    protocol_row = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()

    if protocol_row is None:
        logger.error("Company overview requires Protocol row: company=%s", name)
        raise CompanyNotFound(name)

    # Join Jobs to Contracts on the natural key. The address column on
    # contracts is already stored lowercased (see db/queue.py); jobs
    # store the address as-provided, so lowercase the job side for the join.
    company_jobs = (
        session.execute(
            select(Job)
            .join(
                Contract,
                and_(
                    Contract.address == func.lower(Job.address),
                    Contract.chain_id == Job.chain_id,
                ),
            )
            .where(
                Contract.protocol_id == protocol_row.id,
                Job.status == JobStatus.completed,
                Job.address.isnot(None),
            )
        )
        .scalars()
        .all()
    )
    return protocol_row, list(company_jobs)


def prefetch_contracts(session: Session, jobs: list[Job]) -> dict[Any, Contract]:
    """Return ``{job_id: Contract}`` using each job's canonical ``(address, chain_id)``."""
    contracts_by_job_id: dict[Any, Contract] = {}

    addresses: set[str] = set()
    chain_ids: set[int] = set()
    for j in jobs:
        if not j.address:
            continue
        addresses.add(j.address.lower())
        chain_ids.add(
            require_supported_chain_id(
                chain_id=j.chain_id,
                context=f"company overview contract lookup for job {j.id}",
            )
        )
    if not addresses:
        return contracts_by_job_id

    contracts_by_addr_chain_id: dict[ImplJobKey, Contract] = {}
    for c in session.execute(
        select(Contract)
        .where(Contract.address.in_(list(addresses)), Contract.chain_id.in_(list(chain_ids)))
        .options(selectinload(Contract.summary))
    ).scalars():
        contracts_by_addr_chain_id[
            (
                c.address.lower(),
                require_supported_chain_id(chain_id=c.chain_id, context=f"company overview contract row {c.id}"),
            )
        ] = c

    for j in jobs:
        if not j.address:
            continue
        key = (
            j.address.lower(),
            require_supported_chain_id(chain_id=j.chain_id, context=f"company overview contract lookup for job {j.id}"),
        )
        contract = contracts_by_addr_chain_id.get(key)
        if contract is None:
            logger.error(
                "company overview missing Contract row for job_id=%s chain_id=%s address=%s",
                j.id,
                j.chain_id,
                j.address,
            )
            raise RuntimeError(f"company overview missing Contract row for job {j.id}")
        contracts_by_job_id[j.id] = contract
    return contracts_by_job_id


def resolve_implementation_contracts(
    session: Session, jobs: list[Job], contracts_by_job_id: dict[Any, Contract]
) -> tuple[dict[ImplJobKey, Job], dict[Any, Contract]]:
    """Return ``(impl_job_by_addr, contracts_by_job_id)`` with impls resolved.

    Mutates the contracts_by_job_id dict to also include impl-contract rows
    keyed by their own job_id, so downstream code can look up impl
    contracts directly.
    """
    impl_keys_needed: set[ImplJobKey] = set()
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
                impl_keys_needed.add(
                    (
                        impl.lower(),
                        require_supported_chain_id(
                            chain_id=cr.chain_id,
                            context=f"company overview implementation lookup for contract {cr.id}",
                        ),
                    )
                )

    impl_job_by_addr: dict[ImplJobKey, Job] = {}
    if impl_keys_needed:
        # Deterministic pick: newest completed job per impl address, preferring
        # the one linked to a proxy we're rendering (request.proxy_address points
        # back at a proxy in this set). Without the ORDER BY a re-analysis that
        # left >1 completed impl job for an address attached arbitrarily (1C).
        needed_addrs = {address for address, _chain_id in impl_keys_needed}
        needed_chain_ids = {chain_id for _address, chain_id in impl_keys_needed}
        candidates: dict[ImplJobKey, list[Job]] = {}
        stmt = select(Job).where(Job.address.in_(list(needed_addrs)), Job.status == JobStatus.completed)
        stmt = stmt.where(Job.chain_id.in_(list(needed_chain_ids)))
        for ij in session.execute(
            stmt.order_by(Job.updated_at.desc(), Job.created_at.desc(), Job.id.desc())
        ).scalars():
            key = (
                (ij.address or "").lower(),
                require_supported_chain_id(
                    chain_id=ij.chain_id,
                    context=f"company overview implementation job {ij.id}",
                ),
            )
            if key in impl_keys_needed:
                candidates.setdefault(key, []).append(ij)
        for key, addr_jobs in candidates.items():
            linked = [
                ij
                for ij in addr_jobs
                if isinstance(ij.request, dict) and str(ij.request.get("proxy_address") or "").lower() in proxy_addrs
            ]
            impl_job_by_addr[key] = (linked or addr_jobs)[0]

    impl_jobs = list({ij.id: ij for ij in impl_job_by_addr.values()}.values())
    if impl_jobs:
        contracts_by_job_id.update(prefetch_contracts(session, impl_jobs))

    return impl_job_by_addr, contracts_by_job_id


def _secondary_impl_contracts(
    contract_row: Contract | None,
    impl_job_by_addr: dict[ImplJobKey, Job],
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
        impl_job = impl_job_by_addr.get(((saddr or "").lower(), contract_row.chain_id))
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
    cgn_principal_addr_subq = (
        select(func.lower(cgn_principal_lookup.address))
        .where(
            cgn_principal_lookup.contract_id.in_(id_list),
            or_(
                cgn_principal_lookup.resolved_type.in_(_PRINCIPAL_TYPES_SQL),
                and_(
                    cgn_principal_lookup.details.is_not(None),
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
                node_ref.details.is_not(None),
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

    def _ef_effects(s: Session) -> tuple[dict[int, list[list[str]]], int]:
        local: dict[int, list[list[str]]] = {}
        rows = 0
        for cid, labels in s.execute(
            select(EffectiveFunction.contract_id, EffectiveFunction.effect_labels).where(
                EffectiveFunction.contract_id.in_(id_list)
            )
        ).all():
            local.setdefault(cid, []).append(list(labels or []))
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
        "labels": set}``. Drives two things:

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
        for cid, ef_id, fname, labels, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                EffectiveFunction.id,
                EffectiveFunction.function_name,
                EffectiveFunction.effect_labels,
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
                entry = {"contract_id": cid, "function": fname, "labels": set(labels or ()), "callers": set()}
                by_ef[ef_id] = entry
            entry["callers"].add(addr)
            rows += 1
        local: dict[int, list[dict[str, Any]]] = {}
        for entry in by_ef.values():
            local.setdefault(entry["contract_id"], []).append(
                {"function": entry["function"], "labels": entry["labels"], "callers": entry["callers"]}
            )
        return local, rows

    def _upgrade_count(s: Session) -> tuple[dict[int, int], int]:
        local: dict[int, int] = {}
        for cid, count in s.execute(
            select(UpgradeEvent.contract_id, func.count(UpgradeEvent.id))
            .where(UpgradeEvent.contract_id.in_(id_list))
            .group_by(UpgradeEvent.contract_id)
        ).all():
            local[cid] = count
        return local, len(local)

    def _upgrade_last(s: Session) -> tuple[dict[int, dict[str, Any]], int]:
        local: dict[int, dict[str, Any]] = {}
        for cid, last_block, last_ts in s.execute(
            select(
                UpgradeEvent.contract_id,
                func.max(UpgradeEvent.block_number),
                func.max(UpgradeEvent.timestamp),
            )
            .where(UpgradeEvent.contract_id.in_(id_list))
            .group_by(UpgradeEvent.contract_id)
        ).all():
            local[cid] = {"block": last_block, "timestamp": last_ts}
        return local, len(local)

    def _balances(s: Session) -> tuple[dict[int, list[Any]], int]:
        local: dict[int, list[Any]] = {}
        rows = 0
        for b in s.execute(select(ContractBalance).where(ContractBalance.contract_id.in_(id_list))).scalars():
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


def _trim_control_graph(
    nodes: list[ContractControlGraphNode], edges: list[ContractControlGraphEdge]
) -> ContractControlGraph:
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
    kept_nodes: list[ContractControlGraphNode] = []
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
) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    seen_contract_ids: set[int] = set()

    for contract in contracts_by_job_id.values():
        if not contract or contract.id in seen_contract_ids:
            continue
        seen_contract_ids.add(contract.id)
        summary = contract.summary
        contract_type = "timelock" if summary and summary.has_timelock else "contract"
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
# EETH itself. ``external_contract_call`` / ``hook_update`` are intentionally
# unmapped — too coarse to name a power (they cover everything from
# ``setCapacity`` to ``createBid``); those functions are shown by name instead.
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


def _capabilities_for(labels: set[str]) -> list[str]:
    """Sorted, de-duplicated human capability tags for a set of effect labels.
    Coarse labels with no clean tag drop out — concrete function names carry
    those instead."""
    return sorted({_EFFECT_CAPABILITY[label] for label in labels if label in _EFFECT_CAPABILITY})


def build_governance_view(
    session: Session,
    jobs: list[Job],
    contracts_by_job_id: dict[Any, Contract],
    impl_job_by_addr: dict[ImplJobKey, Job],
) -> GovernanceView:
    """Build the contracts list + ownership hierarchy + fund flows + principals."""
    relevant_contract_ids: set[int] = {c.id for c in contracts_by_job_id.values() if c is not None}
    children = _prefetch_child_tables(session, relevant_contract_ids)
    controller_values_by_cid: dict[int, list[ControllerValue]] = children["controller_values"]
    ef_effects_by_cid: dict[int, list[list[str]]] = children["ef_effects"]
    fp_governance_by_cid: dict[int, list[dict[str, Any]]] = children["fp_governance_rows"]
    upgrade_events_count_by_cid: dict[int, int] = children["upgrade_events_count"]
    last_upgrade_by_cid: dict[int, dict[str, Any]] = children["upgrade_events_last"]
    balances_by_cid: dict[int, list[Any]] = children["balances"]
    cgn_by_cid: dict[int, list[ControlGraphNode]] = children["cgn"]
    cge_by_cid: dict[int, list[ControlGraphEdge]] = children["cge"]
    fp_in_contract_by_cid: dict[int, set[str]] = children["fp_in_contract_principals"]
    fp_all_addrs_by_cid: dict[int, set[str]] = children["fp_all_addrs"]
    fp_function_detail_by_cid: dict[int, list[dict[str, Any]]] = children["fp_function_detail"]

    # Fold each proxy's secondary-impl child rows into its PRIMARY impl's
    # contract_id buckets. The flow/principal passes key on the primary impl
    # (the proxy's lookup contract), so a governor/admin Safe that holds
    # authority only on the secondary (admin) impl's functions still surfaces as
    # a controller of the proxy node.
    for job in jobs:
        cr = contracts_by_job_id.get(job.id)
        secondaries = _secondary_impl_contracts(cr, impl_job_by_addr, contracts_by_job_id)
        if not secondaries:
            continue
        impl_job = (
            impl_job_by_addr.get((cr.implementation.lower(), cr.chain_id))
            if cr and cr.implementation
            else None
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

    principal_lookup = _build_principal_lookup(contracts_by_job_id, controller_values_by_cid, cgn_by_cid)

    contracts: list[GovernanceContract] = []
    owner_groups: dict[str, list[GovernanceContract]] = {}

    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue

        contract_row = contracts_by_job_id.get(job.id)
        is_proxy = contract_row.is_proxy if contract_row else False
        proxy_type = contract_row.proxy_type if contract_row else None
        impl_addr = contract_row.implementation if contract_row else None

        impl_job = (
            impl_job_by_addr.get((impl_addr.lower(), contract_row.chain_id))
            if impl_addr and contract_row
            else None
        )
        implementation_analysis_job_id = str(impl_job.id) if impl_job else None
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None

        # Split-proxy secondary logic contracts (admin-impl set). Their
        # functions + principals attribute to this proxy node too.
        secondary_impl_contracts = _secondary_impl_contracts(contract_row, impl_job_by_addr, contracts_by_job_id)

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

        upgrade_count = upgrade_events_count_by_cid.get(contract_row.id) if contract_row else None
        last_upgrade_entry = (last_upgrade_by_cid.get(contract_row.id) if contract_row else None) or {}
        last_upgrade_block = last_upgrade_entry.get("block")
        last_ts = last_upgrade_entry.get("timestamp")
        last_upgrade_timestamp = last_ts.isoformat() if last_ts is not None else None

        # Effects from every logic contract of this node: the impl (or the row
        # itself for non-proxies) plus any secondary impls.
        primary_ef_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        ef_contract_ids = [primary_ef_cid] if primary_ef_cid else []
        ef_contract_ids += [sc.id for sc in secondary_impl_contracts]

        value_effects: list[str] = []
        all_effects: set[str] = set()
        for cid in ef_contract_ids:
            for label_list in ef_effects_by_cid.get(cid, []):
                for label in label_list:
                    all_effects.add(label)
                    if label in ("asset_pull", "asset_send", "mint", "burn") and label not in value_effects:
                        value_effects.append(label)

        # Contract capability tags, from the shared vocabulary (_EFFECT_CAPABILITY)
        # so a contract's chips use the same words as the per-controller chips.
        # Two non-label extras layered on: ``upgradeable`` (it's a proxy shell)
        # and ``pause`` from the summary flag (a contract can be pausable without
        # a pause_toggle EffectiveFunction surfacing).
        caps_set = set(_capabilities_for(all_effects))
        if is_proxy:
            caps_set.add("upgradeable")
        if summary_row and summary_row.is_pausable:
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
        is_factory = bool(summary_row.is_factory) if summary_row else False
        has_timelock = bool(summary_row.has_timelock) if summary_row else False
        is_pausable = bool(summary_row.is_pausable) if summary_row else False
        control_model = summary_row.control_model if summary_row else None

        name_lower = contract_name.lower()
        if "bridge" in name_lower or "gateway" in name_lower:
            role = "bridge"
        elif any(e in value_effects for e in ("asset_pull", "asset_send")):
            role = "value_handler"
        elif any(s in standards for s in ("ERC20", "ERC721", "ERC1155")):
            role = "token"
        elif has_timelock or control_model == "governance":
            role = "governance"
        elif is_factory:
            role = "factory"
        else:
            role = "utility"

        balance_contract = lookup_contract or contract_row
        balances_list: list[TokenBalanceEntry] = []
        total_usd = 0.0
        if balance_contract:
            for b in balances_by_cid.get(balance_contract.id, []):
                usd = float(b.usd_value) if b.usd_value is not None else None
                balances_list.append(
                    {
                        "token_symbol": b.token_symbol,
                        "token_name": b.token_name,
                        "token_address": b.token_address,
                        "raw_balance": b.raw_balance,
                        "decimals": b.decimals,
                        "usd_value": usd,
                        "price_usd": float(b.price_usd) if b.price_usd is not None else None,
                    }
                )
                if usd:
                    total_usd += usd

        entry: GovernanceContract = {
            "contract": _contract_ref_from_row(
                contract_row,
                address=job.address,
                chain_id=job.chain_id,
                label=contract_name,
            ),
            "address": job.address,
            "name": contract_name,
            "contract_id": contract_row.id if contract_row else None,
            "analysis_job_id": str(job.id),
            "implementation_analysis_job_id": implementation_analysis_job_id,
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
            "risk_level": summary_row.risk_level if summary_row else None,
            "source_verified": summary_row.source_verified if summary_row else None,
            "chain_id": contract_row.chain_id if contract_row else None,
            "upgrade_count": upgrade_count,
            "last_upgrade_block": last_upgrade_block,
            "last_upgrade_timestamp": last_upgrade_timestamp,
            "role": role,
            "standards": standards,
            "value_effects": value_effects,
            "is_pausable": is_pausable,
            "has_timelock": has_timelock,
            "capabilities": capabilities,
            "balances": balances_list,
            "total_usd": round(total_usd, 2) if total_usd > 0 else None,
        }

        graph_contract = lookup_contract or contract_row
        if graph_contract:
            cg_nodes = cgn_by_cid.get(graph_contract.id, [])
            cg_edges = cge_by_cid.get(graph_contract.id, [])
            node_meta = {n.address: _principal_lookup_meta(principal_lookup, n.address, n.details) for n in cg_nodes}
            nodes_payload: list[ContractControlGraphNode] = [
                {
                    "address": n.address,
                    "type": node_meta[n.address].get("resolved_type") or n.resolved_type,
                    "label": node_meta[n.address].get("label") or n.contract_name or n.label,
                    "details": node_meta[n.address]["details"],
                }
                for n in cg_nodes
            ]
            edges_payload: list[ContractControlGraphEdge] = [
                {
                    "from": e.from_node_id.replace("address:", ""),
                    "to": e.to_node_id.replace("address:", ""),
                    "relation": e.relation or "",
                }
                for e in cg_edges
            ]
            entry["control_graph"] = _trim_control_graph(nodes_payload, edges_payload)
        contracts.append(entry)

        if owner:
            owner_groups.setdefault(owner, []).append(entry)

    # Deduplicate: remove standalone impl contracts already represented via a
    # proxy — both the EIP-1967 impl and any split-proxy secondary impls (the
    # latter were analysed standalone in older runs, so drop them by address).
    impl_addresses = {impl.lower() for c in contracts if (impl := c.get("implementation"))}
    for c in contracts:
        for saddr in c.get("secondary_implementations") or []:
            impl_addresses.add(saddr.lower())
    contracts = [
        c for c in contracts if not c["address"] or c["address"].lower() not in impl_addresses or c["is_proxy"]
    ]

    remaining_addrs = {c["address"] for c in contracts if c["address"]}
    for owner_addr in list(owner_groups):
        owner_groups[owner_addr] = [e for e in owner_groups[owner_addr] if e["address"] in remaining_addrs]
        if not owner_groups[owner_addr]:
            del owner_groups[owner_addr]

    hierarchy = _build_ownership_hierarchy(contracts, owner_groups)
    fund_flows, principals = _build_flows_and_principals(
        contracts,
        contracts_by_job_id,
        controller_values_by_cid,
        fp_governance_by_cid,
        cgn_by_cid,
        cge_by_cid,
        fp_in_contract_by_cid,
        principal_lookup,
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
    contract_addr_by_cid: dict[int, str] = {
        c.id: c.address.lower() for c in contracts_by_job_id.values() if c is not None and c.address
    }
    impl_to_proxy: dict[str, str] = {}
    for c in contracts:
        if not (c.get("is_proxy") and c.get("address")):
            continue
        proxy_addr = c["address"]
        if proxy_addr is None:
            continue
        proxy_addr_lc = proxy_addr.lower()
        implementation = c.get("implementation")
        if implementation:
            impl_to_proxy[implementation.lower()] = proxy_addr_lc
        # Secondary impls render under the proxy too, so their FunctionPrincipal
        # authority (e.g. a governor over admin functions) attributes here.
        for saddr in c.get("secondary_implementations") or []:
            impl_to_proxy[saddr.lower()] = proxy_addr_lc
    fp_addrs_by_contract_addr: dict[str, set[str]] = {}
    for cid, addrs in fp_all_addrs_by_cid.items():
        own_addr = contract_addr_by_cid.get(cid)
        if not own_addr:
            continue
        rendered_addr = impl_to_proxy.get(own_addr, own_addr)
        fp_addrs_by_contract_addr.setdefault(rendered_addr, set()).update(addrs)

    governance_passthrough = {
        addr
        for addr in fp_addrs_by_contract_addr
        if principal_lookup.get(addr, {}).get("resolved_type") in {"timelock", "proxy_admin"}
    }

    primary_for = assign_primary_controllers(
        principals,
        fp_addrs_by_contract_addr,
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
    fp_function_detail_by_addr: dict[str, list[dict[str, Any]]] = {}
    for cid, functions in fp_function_detail_by_cid.items():
        own_addr = contract_addr_by_cid.get(cid)
        if not own_addr:
            continue
        rendered_addr = impl_to_proxy.get(own_addr, own_addr)
        fp_function_detail_by_addr.setdefault(rendered_addr, []).extend(functions)
    co_controls = assign_co_controllers(principals, fp_function_detail_by_addr, primary_for)

    principal_meta: dict[str, GovernancePrincipal] = {
        (p.get("address") or "").lower(): p for p in principals if p.get("address")
    }

    # Per-(controller, contract) capability detail: the concrete functions — and
    # effect-category tags — each FP caller can actually invoke. Lets the canvas
    # show "pause · recover" instead of a generic "controlled", from verified
    # call rights (FunctionPrincipal), not the CGN-derived ``controls`` list.
    # ``caller_detail[contract_lc][caller_lc] = {functions, labels}``. EVERY FP
    # caller is kept here, including in-protocol governance *contracts*
    # (timelocks / proxy-admins) — they're the passthrough hop a governance Safe
    # reaches its contracts through, so the capability resolution below needs
    # them. Non-principal callers are filtered out at the consumption points.
    caller_detail: dict[str, dict[str, dict[str, set[str]]]] = {}
    for caddr, functions in fp_function_detail_by_addr.items():
        for fn in functions:
            fname = fn.get("function")
            fn_labels = fn.get("labels") or set()
            for a in fn.get("callers", ()):
                la = (a or "").lower()
                if not la:
                    continue
                detail = caller_detail.setdefault(caddr, {}).setdefault(la, {"functions": set(), "labels": set()})
                if fname:
                    detail["functions"].add(fname)
                detail["labels"].update(fn_labels)

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
        slot = detail_acc.setdefault(principal_lc, {}).setdefault(contract_lc, {"functions": set(), "labels": set()})
        slot["functions"].update(src.get("functions", ()))
        slot["labels"].update(src.get("labels", ()))

    for caddr, callers_map in caller_detail.items():
        for la, detail in callers_map.items():
            if la in principal_meta:  # direct rights belong to principals, not contract callers
                _accumulate(la, caddr, detail)
    for la, owned in primary_for.items():
        for caddr in owned:
            for gov_addr, gov_detail in caller_detail.get(caddr, {}).items():
                if gov_addr in governance_passthrough and la in caller_detail.get(gov_addr, {}):
                    _accumulate(la, caddr, gov_detail)

    detail_by_principal: dict[str, list[GovernanceControlDetail]] = {}
    for la, by_contract in detail_acc.items():
        rows: list[GovernanceControlDetail] = [
            {"address": caddr, "functions": sorted(d["functions"]), "capabilities": _capabilities_for(d["labels"])}
            for caddr, d in by_contract.items()
        ]
        rows.sort(key=lambda e: e["address"])
        detail_by_principal[la] = rows

    for p in principals:
        p_addr_lc = (p.get("address") or "").lower()
        p["primary_for"] = primary_for.get(p_addr_lc, [])
        p["co_controls"] = co_controls.get(p_addr_lc, [])
        p["controls_detail"] = detail_by_principal.get(p_addr_lc, [])

    # Per-contract "other callers": principal-callers holding FP authority that
    # are neither the contract's primary owner nor a co-controller of it — the
    # permissionless / lower-privilege long tail (e.g. AuctionManager's
    # whitelisted ``createBid`` bidders). The canvas renders these in aggregate
    # as a "+N callers" affordance per contract, so an authorized caller is
    # never silently invisible, without drawing 30+ cross-group edges or minting
    # a node per bidder. Each carries its own functions / capabilities so the
    # sidebar list says what each caller can do. Restricted to FP-typed
    # principals, so state-variable destinations / CGN noise don't leak in.
    primary_by_contract: dict[str, str] = {c: paddr for paddr, owned in primary_for.items() for c in owned}
    co_by_contract: dict[str, set[str]] = {}
    for paddr, owned in co_controls.items():
        for c in owned:
            co_by_contract.setdefault(c, set()).add(paddr)
    for entry in contracts:
        addr = (entry.get("address") or "").lower()
        cd = caller_detail.get(addr, {})
        callers = {a for a in cd if a in principal_meta}  # contract callers aren't "other callers"
        callers.discard(addr)
        callers.discard(primary_by_contract.get(addr, ""))
        callers -= co_by_contract.get(addr, set())
        entry["other_callers"] = [
            {
                "address": a,
                "type": (principal_meta.get(a) or {}).get("type"),
                "label": (principal_meta.get(a) or {}).get("label"),
                "functions": sorted(cd[a]["functions"]),
                "capabilities": _capabilities_for(cd[a]["labels"]),
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
    contracts: list[GovernanceContract], owner_groups: dict[str, list[GovernanceContract]]
) -> list[GovernanceHierarchyEntry]:
    hierarchy: list[GovernanceHierarchyEntry] = []
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


def _build_flows_and_principals(
    contracts: list[GovernanceContract],
    contracts_by_job_id: dict[Any, Contract],
    controller_values_by_cid: dict[int, list[ControllerValue]],
    fp_governance_by_cid: dict[int, list[dict[str, Any]]],
    cgn_by_cid: dict[int, list[ControlGraphNode]],
    cge_by_cid: dict[int, list[ControlGraphEdge]],
    fp_in_contract_by_cid: dict[int, set[str]],
    principal_lookup: dict[str, dict[str, Any]],
) -> tuple[list[GovernanceFundFlow], list[GovernancePrincipal]]:
    contract_addrs = {c["address"].lower() for c in contracts if c["address"]}
    contract_by_addr = {c["address"].lower(): c for c in contracts if c["address"]}
    chain_id_by_contract_addr = {
        c["address"].lower(): int(c["chain_id"])
        for c in contracts
        if c.get("address") and c.get("chain_id") is not None
    }
    flow_seen: set[tuple[str, str]] = set()
    fund_flows: list[GovernanceFundFlow] = []

    def add_flow(from_addr: str, to_addr: str, flow_type: str, lane: str = "control") -> None:
        key = (from_addr, to_addr)
        if key in flow_seen:
            return
        flow_seen.add(key)
        target = contract_by_addr.get(to_addr, {})
        fund_flows.append(
            {
                "from": from_addr,
                "to": to_addr,
                "type": flow_type,
                "lane": lane,
                "capabilities": target.get("capabilities", []),
            }
        )

    def _lookup_contract_for(entry: GovernanceContract) -> Contract | None:
        import uuid as _uuid

        lookup_job_id = entry.get("implementation_analysis_job_id") or entry["analysis_job_id"]
        try:
            key_id = _uuid.UUID(lookup_job_id) if isinstance(lookup_job_id, str) else lookup_job_id
        except (TypeError, ValueError):
            key_id = lookup_job_id
        return contracts_by_job_id.get(key_id)

    lookup_contract_by_entry: dict[str, Contract | None] = {}
    for entry in contracts:
        entry_address = entry.get("address")
        if entry_address:
            lookup_contract_by_entry[entry_address.lower()] = _lookup_contract_for(entry)

    for c in contracts:
        if not c["address"]:
            continue
        target = c["address"].lower()
        lookup_c = lookup_contract_by_entry.get(target)
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
            add_flow(c["owner"], target, flow_type)

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
                    add_flow(val_lower, target, "controller")

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
                add_flow(node_addr, target, "principal")

    # Collect non-contract principals from control graph + function principals.
    # First pass: find safe_owner edges so we can nest Safe owners later.
    principal_map: dict[str, GovernancePrincipal] = {}
    safe_owners_map: dict[str, list[str]] = {}
    owner_of_safe: set[str] = set()

    for c in contracts:
        if not c["address"]:
            continue
        lookup_c = lookup_contract_by_entry.get(c["address"].lower())
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
        lookup_c = lookup_contract_by_entry.get(target)
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

            if node_addr not in principal_map:
                # Seed details with the CGN's own introspection result
                # (getOwners/getThreshold for safes, getMinDelay for
                # timelocks). This is the authoritative source for the
                # principal's intrinsic config — ControllerValue rows
                # describe the relationship FROM a consumer, not the
                # Safe's own threshold, so prior code that only merged
                # CV details missed the threshold and derived len(owners).
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
                }

            principal_map[node_addr]["controls"].append(target)
            add_flow(node_addr, target, "principal")

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
        lookup_c = lookup_contract_by_entry.get(target)
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
                }
            if target not in principal_map[pa]["controls"]:
                principal_map[pa]["controls"].append(target)
            add_flow(pa, target, "principal")

    for principal in principal_map.values():
        chain_ids = sorted(
            {
                chain_id_by_contract_addr[controlled.lower()]
                for controlled in principal.get("controls", [])
                if isinstance(controlled, str) and controlled.lower() in chain_id_by_contract_addr
            }
        )
        principal["chain_ids"] = chain_ids
        principal["chain_id"] = chain_ids[0] if len(chain_ids) == 1 else None

    return fund_flows, list(principal_map.values())


def build_functions_for_protocol(session: Session, name: str) -> dict[str, list[GovernanceFunctionEntry]]:
    """Return ``{address: [function_entries]}`` for every contract in the
    protocol.

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
        impl_job_by_addr, contracts_by_job_id = resolve_implementation_contracts(session, jobs, contracts_by_job_id)

    # Addresses that are a secondary impl of some proxy are absorbed into that
    # proxy node (their functions surface there), so they get no standalone
    # entry — mirrors the canvas dedup for split-proxy admin impls.
    secondary_impl_addrs = {
        s.lower()
        for cr in contracts_by_job_id.values()
        if cr is not None and cr.is_proxy
        for s in (cr.secondary_implementations or [])
    }

    # Map each job's address to the contract_ids whose EF rows it should show —
    # for a proxy: its EIP-1967 impl plus any split-proxy secondary impls; for a
    # plain contract: its own row.
    job_addr_to_ef_cids: dict[str, list[int]] = {}
    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue
        if not job.address:
            continue
        if job.address.lower() in secondary_impl_addrs:
            continue
        contract_row = contracts_by_job_id.get(job.id)
        impl_addr = contract_row.implementation if (contract_row and contract_row.is_proxy) else None
        impl_job = (
            impl_job_by_addr.get((impl_addr.lower(), contract_row.chain_id))
            if impl_addr and contract_row
            else None
        )
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None
        primary_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        cids = [primary_cid] if primary_cid is not None else []
        cids += [
            sc.id
            for sc in _secondary_impl_contracts(contract_row, impl_job_by_addr, contracts_by_job_id)
            if sc.id != primary_cid
        ]
        if cids:
            job_addr_to_ef_cids[job.address] = cids

    relevant_cids = {cid for cids in job_addr_to_ef_cids.values() for cid in cids}
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
    principal_lookup = _build_principal_lookup(contracts_by_job_id, controller_values_by_cid, cgn_by_cid)

    out: dict[str, list[GovernanceFunctionEntry]] = {}
    with _time_phase(timings_ms, "serialize"):
        for addr, ef_cids in job_addr_to_ef_cids.items():
            ef_rows = [ef for cid in ef_cids for ef in ef_rows_by_cid.get(cid, [])]
            out[addr] = [
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


def _all_addresses_count(session: Session, protocol_row: Protocol) -> int:
    return int(
        session.execute(
            select(func.count()).select_from(Contract).where(Contract.protocol_id == protocol_row.id)
        ).scalar_one()
    )


def all_addresses_for_protocol(session: Session, protocol_row: Protocol) -> list[dict[str, Any]]:
    all_contract_rows = session.execute(select(Contract).where(Contract.protocol_id == protocol_row.id)).scalars().all()

    # Prefetch impl-name lookup so proxy rows can expose the implementation
    # contract name alongside their own generic "UUPSProxy"/"ERC1967Proxy"
    # template name.
    impl_name_by_addr = {
        (
            (c.address or "").lower(),
            require_supported_chain_id(chain_id=c.chain_id, context=f"all addresses contract row {c.id}"),
        ): c.contract_name
        for c in all_contract_rows
        if c.address and c.contract_name
    }
    completed_job_keys: set[ImplJobKey] = set()
    contract_addrs = {(cr.address or "").lower() for cr in all_contract_rows if cr.address}
    contract_chain_ids = {
        require_supported_chain_id(chain_id=cr.chain_id, context=f"all addresses contract row {cr.id}")
        for cr in all_contract_rows
    }
    if contract_addrs and contract_chain_ids:
        completed_job_keys = {
            (
                str(addr).lower(),
                require_supported_chain_id(chain_id=job_chain_id, context="all addresses completed job lookup"),
            )
            for addr, job_chain_id in session.execute(
                select(func.lower(Job.address), Job.chain_id).where(
                    func.lower(Job.address).in_(list(contract_addrs)),
                    Job.chain_id.in_(list(contract_chain_ids)),
                    Job.status == JobStatus.completed,
                )
            )
        }

    return sorted(
        [
            {
                "address": cr.address,
                "name": cr.contract_name,
                "source_verified": cr.source_verified,
                "is_proxy": cr.is_proxy,
                "analyzed": (
                    (
                        (cr.address or "").lower(),
                        require_supported_chain_id(chain_id=cr.chain_id, context=f"all addresses contract row {cr.id}"),
                    )
                    in completed_job_keys
                ),
                "discovery_sources": list(cr.discovery_sources or []),
                "discovery_url": cr.discovery_url,
                "chain_id": cr.chain_id,
                "rank_score": (float(cr.rank_score) if cr.rank_score is not None else None),
                "implementation_address": cr.implementation if cr.is_proxy else None,
                "implementation_name": (
                    impl_name_by_addr.get(
                        (
                            (cr.implementation or "").lower(),
                            require_supported_chain_id(
                                chain_id=cr.chain_id,
                                context=f"all addresses contract row {cr.id}",
                            ),
                        )
                    )
                    if cr.is_proxy
                    else None
                ),
            }
            for cr in all_contract_rows
        ],
        key=lambda x: (not x["analyzed"], x["name"] or "zzz"),
    )


def _latest_tvl(session: Session, protocol_row: Protocol) -> dict[str, Any] | None:
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
    protocol_row: Protocol,
    jobs: list[Job],
    governance: GovernanceView,
) -> dict[str, Any]:
    return {
        "company": name,
        "protocol_id": protocol_row.id,
        "contract_count": len(governance.contracts),
        "tvl": _latest_tvl(session, protocol_row),
        "contracts": governance.contracts,
        "principals": governance.principals,
        "ownership_hierarchy": governance.hierarchy,
        "fund_flows": governance.fund_flows,
        # Just the count here — the full inventory (~167 KB for ether.fi) is
        # served by /api/company/{name}/addresses and fetched lazily by
        # AddressesModal when the user opens it.
        "all_addresses_count": _all_addresses_count(session, protocol_row),
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
        impl_job_by_addr, contracts_by_job_id = resolve_implementation_contracts(session, jobs, contracts_by_job_id)
    with _time_phase(timings_ms, "build_governance_view"):
        governance = build_governance_view(session, jobs, contracts_by_job_id, impl_job_by_addr)
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


def controllers_for_protocol(session: Session, protocol_id: int, *, chain_id: int) -> dict[str, str]:
    """Map ``principal_address_lc -> MonitoredContract.contract_type`` for every
    principal that holds governing authority over at least one contract in the
    protocol — its **primary controllers union its privileged co-controllers**.

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
    effective_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context=f"controllers for protocol {protocol_id}",
    )
    _protocol_row, jobs = resolve_company_jobs(session, protocol.name)
    if not jobs:
        return {}
    contracts_by_job_id = prefetch_contracts(session, jobs)
    jobs = [
        job
        for job in jobs
        if (contracts_by_job_id[job.id].chain_id if contracts_by_job_id.get(job.id) is not None else job.chain_id)
        == effective_chain_id
    ]
    if not jobs:
        return {}
    impl_job_by_addr, contracts_by_job_id = resolve_implementation_contracts(session, jobs, contracts_by_job_id)
    governance = build_governance_view(session, jobs, contracts_by_job_id, impl_job_by_addr)

    controllers: dict[str, str] = {}
    for principal in governance.principals:
        if not (principal.get("primary_for") or principal.get("co_controls")):
            continue
        ptype = principal.get("type")
        if ptype not in ("safe", "timelock", "proxy_admin"):
            continue
        addr = (principal.get("address") or "").lower()
        if addr:
            controllers[addr] = "proxy" if ptype == "proxy_admin" else ptype
    return controllers
