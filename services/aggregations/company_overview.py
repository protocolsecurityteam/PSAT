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
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
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
from services.governance.principals import _build_company_function_entry

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
        # join. Chain is not part of the join — a Contract row keyed by
        # (address, chain) belongs to the protocol regardless of which
        # chain the job ran on, and adding chain to the join would drop
        # legitimate rows when chain is NULL on one side.
        company_jobs = (
            session.execute(
                select(Job)
                .join(Contract, Contract.address == func.lower(Job.address))
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

    return None, [j for j in all_completed if j.address and belongs_to_company(j)]


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
    """Return ``(impl_job_by_addr, contracts_by_job_id)`` with impls resolved.

    Mutates the contracts_by_job_id dict to also include impl-contract rows
    keyed by their own job_id, so downstream code can look up impl
    contracts directly.
    """
    impl_addrs_needed: set[str] = set()
    for j in jobs:
        cr = contracts_by_job_id.get(j.id)
        if cr and cr.is_proxy and cr.implementation:
            impl_addrs_needed.add(cr.implementation.lower())

    impl_job_by_addr: dict[str, Job] = {}
    if impl_addrs_needed:
        for ij in session.execute(
            select(Job).where(
                Job.address.in_(list(impl_addrs_needed)),
                Job.status == JobStatus.completed,
            )
        ).scalars():
            key = (ij.address or "").lower()
            if key and key not in impl_job_by_addr:
                impl_job_by_addr[key] = ij

    impl_job_ids_needed = [ij.id for ij in impl_job_by_addr.values()]
    if impl_job_ids_needed:
        for c in session.execute(
            select(Contract).where(Contract.job_id.in_(impl_job_ids_needed)).options(selectinload(Contract.summary))
        ).scalars():
            contracts_by_job_id[c.job_id] = c

    return impl_job_by_addr, contracts_by_job_id


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


def build_governance_view(
    session: Session,
    jobs: list[Job],
    contracts_by_job_id: dict[Any, Contract],
    impl_job_by_addr: dict[str, Job],
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
    principal_lookup = _build_principal_lookup(contracts_by_job_id, controller_values_by_cid, cgn_by_cid)

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

        impl_job = impl_job_by_addr.get(impl_addr.lower()) if impl_addr else None
        impl_job_id = str(impl_job.id) if impl_job else None
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None

        summary_row = impl_contract.summary if impl_contract else None
        if not summary_row and contract_row:
            summary_row = contract_row.summary

        # Prefer the impl's controller snapshot for proxies if it has any.
        lookup_contract = contract_row
        if is_proxy and impl_contract and controller_values_by_cid.get(impl_contract.id):
            lookup_contract = impl_contract

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

        ef_contract_id = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)

        value_effects: list[str] = []
        all_effects: set[str] = set()
        ef_effects_for_contract = ef_effects_by_cid.get(ef_contract_id, []) if ef_contract_id else []
        for label_list in ef_effects_for_contract:
            for label in label_list:
                all_effects.add(label)
                if label in ("asset_pull", "asset_send", "mint", "burn"):
                    if label not in value_effects:
                        value_effects.append(label)

        capabilities: list[str] = []
        if is_proxy:
            capabilities.append("upgradeable")
        if "implementation_update" in all_effects:
            capabilities.append("upgrade")
        if "pause_toggle" in all_effects or (summary_row and summary_row.is_pausable):
            capabilities.append("pause")
        if "ownership_transfer" in all_effects:
            capabilities.append("ownership")
        if "role_management" in all_effects:
            capabilities.append("roles")
        if "asset_pull" in all_effects or "mint" in all_effects:
            capabilities.append("value-in")
        if "asset_send" in all_effects or "burn" in all_effects:
            capabilities.append("value-out")
        if "delegatecall_execution" in all_effects:
            capabilities.append("delegatecall")
        if "arbitrary_external_call" in all_effects:
            capabilities.append("arbitrary-call")

        contract_name = None
        if is_proxy and impl_job:
            if impl_contract and impl_contract.contract_name:
                contract_name = impl_contract.contract_name
            elif impl_job.name:
                contract_name = impl_job.name
        if not contract_name:
            contract_name = (contract_row.contract_name if contract_row else None) or job.name or ""
        standards = list(summary_row.standards or []) if summary_row else []
        is_factory = summary_row.is_factory if summary_row else False
        has_timelock = summary_row.has_timelock if summary_row else False
        is_pausable = summary_row.is_pausable if summary_row else False
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
        balances_list = []
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

        entry: dict[str, Any] = {
            "address": job.address,
            "name": contract_name,
            "contract_id": contract_row.id if contract_row else None,
            "job_id": str(job.id),
            "impl_job_id": impl_job_id,
            "is_proxy": is_proxy,
            "proxy_type": proxy_type,
            "implementation": impl_addr,
            "deployer": contract_row.deployer if contract_row else None,
            "owner": owner,
            "controllers": controllers,
            "control_model": control_model,
            "risk_level": summary_row.risk_level if summary_row else None,
            "source_verified": summary_row.source_verified if summary_row else None,
            "chain": contract_row.chain if contract_row else None,
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

    # Deduplicate: remove standalone impl contracts already represented via a proxy
    impl_addresses = {c["implementation"].lower() for c in contracts if c.get("implementation")}
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


def _build_flows_and_principals(
    contracts: list[dict[str, Any]],
    contracts_by_job_id: dict[Any, Contract],
    controller_values_by_cid: dict[int, list[ControllerValue]],
    fp_governance_by_cid: dict[int, list[dict[str, Any]]],
    cgn_by_cid: dict[int, list[ControlGraphNode]],
    cge_by_cid: dict[int, list[ControlGraphEdge]],
    fp_in_contract_by_cid: dict[int, set[str]],
    principal_lookup: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    contract_addrs = {c["address"].lower() for c in contracts if c["address"]}
    contract_by_addr = {c["address"].lower(): c for c in contracts if c["address"]}
    flow_seen: set[tuple[str, str]] = set()
    fund_flows: list[dict[str, Any]] = []

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

    def _lookup_contract_for(entry: dict[str, Any]) -> Contract | None:
        import uuid as _uuid

        lookup_job_id = entry.get("impl_job_id") or entry["job_id"]
        try:
            key_id = _uuid.UUID(lookup_job_id) if isinstance(lookup_job_id, str) else lookup_job_id
        except (TypeError, ValueError):
            key_id = lookup_job_id
        return contracts_by_job_id.get(key_id)

    lookup_contract_by_entry: dict[str, Contract | None] = {}
    for entry in contracts:
        if entry.get("address"):
            lookup_contract_by_entry[entry["address"].lower()] = _lookup_contract_for(entry)

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
    principal_map: dict[str, dict[str, Any]] = {}
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

    return fund_flows, list(principal_map.values())


def build_functions_for_protocol(session: Session, name: str) -> dict[str, list[dict[str, Any]]]:
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

    # Map each job's address to the contract_id whose EF rows it should
    # show — the impl's row for proxies, the job's own row otherwise.
    job_addr_to_ef_cid: dict[str, int] = {}
    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue
        if not job.address:
            continue
        contract_row = contracts_by_job_id.get(job.id)
        impl_addr = contract_row.implementation if (contract_row and contract_row.is_proxy) else None
        impl_job = impl_job_by_addr.get(impl_addr.lower()) if impl_addr else None
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None
        ef_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        if ef_cid is not None:
            job_addr_to_ef_cid[job.address] = ef_cid

    relevant_cids = set(job_addr_to_ef_cid.values())
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

    out: dict[str, list[dict[str, Any]]] = {}
    with _time_phase(timings_ms, "serialize"):
        for addr, ef_cid in job_addr_to_ef_cid.items():
            ef_rows = ef_rows_by_cid.get(ef_cid, [])
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
    # template name.
    impl_name_by_addr = {
        (c.address or "").lower(): c.contract_name for c in all_contract_rows if c.address and c.contract_name
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
                    impl_name_by_addr.get((cr.implementation or "").lower()) if cr.is_proxy else None
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
