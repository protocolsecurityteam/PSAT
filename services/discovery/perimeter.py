"""The analysis perimeter: which discovered contracts become analysis jobs.

One walker, two call sites, deliberately the SAME code path:

* the **resolution stage** spawns from the walk's first graph, and
* the **policy stage** spawns from the refreshed graph it rebuilds once
  ``effective_permissions`` exists — the refresh that projects
  ``role_principal`` nodes into the graph.

Until the second call site existed, every node FIRST discovered by the policy
refresh was permanently outside the perimeter even though it satisfied every
gate here. Measured on the PR-161 corpus: 32 addresses carry
``details->>'source' = 'semantic_capability:role_grant'`` with
``node_type='contract'``, of which **19 had no job** — all 19 ``analyzed=true``,
so all 19 pass the gates below unmodified.

**Every candidate that does not become a job is accounted for**, in one of three
declared dispositions. The three PARTITION the node list **only when the ledger
carries ``walked: true``** — see ``walked`` below; on a ``false`` they are a
PREFIX of it and nothing may be concluded from their emptiness:

* ``queued`` — a job was created;
* ``omitted`` — a candidate this stage COULD have analysed and chose not to
  (budget, depth, chain, unusable address). This is the ledger: a silently
  dropped candidate is precisely the C2 defect, so each one is persisted with
  its reason, not merely counted;
* ``out_of_population`` — never a candidate for this stage at all: the root
  itself, a node the walk did not analyse, a non-contract node, or an address
  that already has a job. These are the fail-closed gates and the dedup arm;
  they are NOT omissions and must not redden a population invariant.

``walked`` is the discriminator that makes those dispositions readable. The
ledger is constructed by the CALLER and persisted from a ``finally``, so it is
written on three different histories: the walk ran to the end, the walk raised
part-way through, and the walk never started at all (the policy stage skips it
when the refresh produced no graph). All three used to serialize identically
when nothing was queued, so an all-empty ledger asserted "walked, omitted
nothing" for two histories that had walked nothing. ``walked`` is set at LOOP
EXIT and nowhere else: ``true`` licenses the partition claim, ``false`` says
the ledger is a prefix — its contents are still true individually, but their
emptiness proves nothing.

A budget is spent at ``create_job`` and nowhere else, so a candidate rejected by
any earlier gate provably consumes none of it — the ordering of the gates in the
loop below cannot silently become load-bearing.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping, TypedDict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract, ContractDependency, Job, JobStage
from db.queue import _mainnet_coalesced_chain, create_job, find_existing_job_for_address
from utils.chains import chain_enabled

logger = logging.getLogger(__name__)

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

#: How many contracts ONE policy-stage refresh may spawn. The policy refresh is
#: recursive in a way the resolution walk is not: a newly-analysed manager runs
#: its own policy stage, projects its own role principals, and spawns again — so
#: without a cut it fans out until the graph is exhausted.
#:
#: This is a NAMED MODEL CHOICE, not a measured reliability: the 19-row jobless
#: population is far below the ~5-row floor at which calibrating a threshold on
#: observed data is admissible at all, so no number here is claimed to be
#: derived from it. Chosen so one refresh makes progress while a cut stays
#: visible; raise it in config, never by inferring a "right" value from a run.
PERIMETER_SPAWN_LIMIT = int(os.getenv("PSAT_PERIMETER_SPAWN_LIMIT", "8"))

#: How many spawn generations may chain off one root. Counts PERIMETER SPAWNS
#: ONLY and is carried in the child's request — it is NOT
#: ``control_graph_nodes.depth`` (the walk's BFS distance, which is 1 on all 19
#: jobless role-grant nodes) and the two must never be read for each other.
PERIMETER_SPAWN_DEPTH_CAP = int(os.getenv("PSAT_PERIMETER_SPAWN_DEPTH_CAP", "2"))

#: Request key carrying the spawn generation. Absent ⇒ generation 0.
PERIMETER_DEPTH_KEY = "perimeter_spawn_depth"


class OmissionRecord(TypedDict):
    address: str
    reason: str


class PerimeterSpawnResult(TypedDict):
    site: str
    budget: int | None
    budget_used: int
    spawn_depth: int
    queued: list[dict[str, Any]]
    omitted: list[OmissionRecord]
    out_of_population: list[OmissionRecord]
    # True only after the node loop ran to completion. See the module docstring:
    # this is what separates "walked, omitted nothing" from "never walked" and
    # from "raised on node 3 of 5", which are otherwise the same three lists.
    walked: bool


def spawn_depth_of(job: Job) -> int:
    """The perimeter generation *job* belongs to. A malformed or absent value is
    generation 0 — never a guess that skips the cap."""
    request = job.request if isinstance(job.request, dict) else {}
    raw = request.get(PERIMETER_DEPTH_KEY)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        return 0
    return raw


def _parent_company(session: Session, job: Job) -> str | None:
    """Walk up the parent chain for a company when this job has none."""
    if job.company:
        return job.company
    request = job.request if isinstance(job.request, dict) else {}
    seen: set[str] = set()
    current_req = request
    while True:
        parent_id = current_req.get("parent_job_id")
        if not isinstance(parent_id, str) or parent_id in seen:
            return None
        seen.add(parent_id)
        parent_job = session.get(Job, parent_id)
        if parent_job is None:
            return None
        if parent_job.company:
            return parent_job.company
        current_req = parent_job.request if isinstance(parent_job.request, dict) else {}


def _structural_ownership(session: Session, job: Job) -> tuple[bool, dict[str, str]]:
    """``(parent_owns_high, {dep_address: relationship})`` for structural
    same-protocol components of the parent.

    ``cd.relationship_type`` alone isn't sufficient — it's the classifier's
    verdict on what kind of contract the dep IS, not the edge semantics. A HIGH
    ether.fi contract calling Lido stETH has ``relationship_type='proxy'``
    because stETH is a proxy — that doesn't make stETH ether.fi's structural
    proxy. We require the proxy/impl/beacon fields on the Contract row to
    actually link the two.

    Best-effort: a failure falls back to "no propagation" (the safe default)
    rather than blocking discovery.
    """
    from services.discovery.source_confidence import asserts_ownership

    parent_owns_high = False
    structural_rel_by_addr: dict[str, str] = {}
    try:
        parent_contract = session.execute(
            select(Contract).where(Contract.job_id == job.id).limit(1)
        ).scalar_one_or_none()
    except Exception as exc:
        logger.debug("Job %s: structural-propagation parent lookup failed: %s", job.id, exc)
        return False, {}
    if parent_contract is None:
        return False, {}

    parent_sources = getattr(parent_contract, "discovery_sources", None)
    parent_owns_high = asserts_ownership(list(parent_sources) if parent_sources else None)
    parent_id = getattr(parent_contract, "id", None)
    parent_impl = (getattr(parent_contract, "implementation", None) or "").lower() or None
    parent_beacon = (getattr(parent_contract, "beacon", None) or "").lower() or None
    parent_addr_lower = (getattr(parent_contract, "address", None) or "").lower() or None
    parent_chain = _mainnet_coalesced_chain(getattr(parent_contract, "chain", None))
    if parent_id is None:
        return parent_owns_high, {}

    try:
        dep_rows = list(
            session.execute(select(ContractDependency).where(ContractDependency.contract_id == parent_id)).scalars()
        )
    except Exception as exc:
        logger.debug("Job %s: structural-propagation dep-rows lookup failed: %s", job.id, exc)
        return parent_owns_high, {}

    # For proxy-direction edges we need to verify the dep's Contract.implementation
    # back-links to the parent. Batch so the loop stays O(deps) not O(deps×SELECTs).
    proxy_edge_addrs = [row.dependency_address.lower() for row in dep_rows if row.relationship_type == "proxy"]
    dep_impl_by_addr: dict[str, str | None] = {}
    # Chain-scoped like ``is_known_proxy``: a back-link is only evidence on the
    # parent's own chain — a CREATE2 twin elsewhere satisfies the bare address
    # match. Mainnet-coalesced so legacy NULL-chain rows still match a mainnet
    # parent while a non-mainnet lookup stays isolated.
    if proxy_edge_addrs:
        try:
            dep_contract_rows = session.execute(
                select(Contract).where(
                    Contract.address.in_(proxy_edge_addrs),
                    func.lower(func.coalesce(Contract.chain, "ethereum")) == parent_chain,
                )
            ).scalars()
            for dc in dep_contract_rows:
                dep_impl_by_addr[dc.address.lower()] = (dc.implementation or "").lower() or None
        except Exception as exc:
            logger.debug("Job %s: structural-propagation dep back-link lookup failed: %s", job.id, exc)
            dep_impl_by_addr = {}

    for row in dep_rows:
        rel = row.relationship_type
        if rel not in ("implementation", "proxy", "beacon"):
            continue
        dep_addr = (row.dependency_address or "").lower()
        if not dep_addr:
            continue
        if rel == "implementation":
            structurally_linked = parent_impl is not None and parent_impl == dep_addr
        elif rel == "proxy":
            dep_impl = dep_impl_by_addr.get(dep_addr)
            structurally_linked = (
                dep_impl is not None and parent_addr_lower is not None and dep_impl == parent_addr_lower
            )
        else:  # beacon
            structurally_linked = parent_beacon is not None and parent_beacon == dep_addr
        if structurally_linked:
            structural_rel_by_addr[dep_addr] = rel
    return parent_owns_high, structural_rel_by_addr


def new_spawn_result(*, site: str, budget: int | None, spawn_depth: int = 0) -> PerimeterSpawnResult:
    """An empty ledger, constructed by the CALLER so it survives a raise.

    The walker fills this in place. If ``create_job`` raises on the third of
    five nodes, the caller's ``finally`` still holds — and can still persist —
    the two children that were already committed. Building the ledger inside
    the walker and returning it made a partial spawn indistinguishable from no
    spawn: the children were committed, the artifact was never written.

    ``walked`` starts ``False`` and only the walker's loop exit sets it, so a
    ledger that reaches ``_persist_spawn_summary`` without the walk having run
    to the end says so rather than reading as a completed empty walk.
    """
    return {
        "site": site,
        "budget": budget,
        "budget_used": 0,
        "spawn_depth": spawn_depth,
        "queued": [],
        "omitted": [],
        "out_of_population": [],
        "walked": False,
    }


def queue_discovered_contracts(
    session: Session,
    job: Job,
    resolved_graph: Mapping[str, Any],
    rpc_url: str,
    *,
    site: str,
    chain_name: str,
    budget: int | None = None,
    depth_cap: int | None = None,
    result: PerimeterSpawnResult | None = None,
) -> PerimeterSpawnResult:
    """Queue analysis jobs for contracts in *resolved_graph* that have none.

    ``budget=None`` (the resolution stage) means no cut: the walk's own
    ``max_depth`` already bounds it. An int (the policy stage) caps this
    stage's spawns and records every candidate it drops.

    Pass *result* (from :func:`new_spawn_result`) to keep the ledger reachable
    if this raises part-way through.
    """
    spawn_depth = spawn_depth_of(job)
    if result is None:
        result = new_spawn_result(site=site, budget=budget, spawn_depth=spawn_depth)
    result["spawn_depth"] = spawn_depth

    parent_company = _parent_company(session, job)
    parent_owns_high, structural_rel_by_addr = _structural_ownership(session, job)

    nodes = resolved_graph.get("nodes", []) or []
    root_address = str(resolved_graph.get("root_contract_address", "") or "").lower()

    def _omit(address: str, reason: str) -> None:
        result["omitted"].append({"address": address, "reason": reason})
        logger.info(
            "Perimeter spawn omitted a candidate",
            extra={
                "address": address,
                "chain": chain_name,
                "reason": reason,
                "site": site,
                "job_id": str(job.id),
            },
        )

    def _out(address: str, reason: str) -> None:
        result["out_of_population"].append({"address": address, "reason": reason})

    for node in nodes:
        addr = (node.get("address") or "").lower()
        if not addr or not addr.startswith("0x") or len(addr) != 42:
            _omit(addr or "", "invalid_address")
            continue
        if addr == ZERO_ADDRESS:
            # An unset controller/dependency resolves to the zero address;
            # queuing it spawns a discovery job that can only fail with
            # "No verified source code for 0x000…000".
            _omit(addr, "zero_address")
            continue
        if addr == root_address:
            _out(addr, "root_node")
            continue
        # Only queue contracts that were analyzed during the walk.
        if not node.get("analyzed"):
            _out(addr, "not_analyzed")
            continue
        if node.get("node_type") != "contract":
            _out(addr, "not_contract_node")
            continue
        # Skip if a job already exists for this address on THIS chain —
        # case-insensitive (a checksummed admin submission is the same
        # contract) and chain-scoped so a same-address twin on another chain
        # doesn't suppress this chain's child.
        if find_existing_job_for_address(session, addr, chain=chain_name) is not None:
            _out(addr, "existing_job")
            continue
        # Defense in depth: discovered contracts share the parent's chain
        # (chain-as-island), so a gated parent already implies a gated child —
        # but a disabled chain must never spawn analysis work.
        if not chain_enabled(chain_name):
            _omit(addr, "chain_not_enabled")
            continue
        if depth_cap is not None and spawn_depth >= depth_cap:
            _omit(addr, "depth_exhausted")
            continue
        if budget is not None and result["budget_used"] >= budget:
            _omit(addr, "budget_exhausted")
            continue

        contract_name = node.get("contract_name") or node.get("label") or addr
        child_request: dict[str, Any] = {
            "address": addr,
            "name": contract_name,
            "rpc_url": rpc_url,
            "parent_job_id": str(job.id),
            "discovered_by": site,
            "chain": chain_name,
        }
        if depth_cap is not None:
            child_request[PERIMETER_DEPTH_KEY] = spawn_depth + 1
        structural_rel = structural_rel_by_addr.get(addr)
        if structural_rel is not None:
            child_request["discovery_relationship"] = structural_rel
            child_request["parent_owns_high"] = parent_owns_high

        child_job = create_job(session, child_request, initial_stage=JobStage.discovery)
        if parent_company:
            child_job.company = parent_company
        if job.protocol_id:
            child_job.protocol_id = job.protocol_id
        session.commit()

        # Budget is spent HERE and only here, so every earlier gate provably
        # consumes none of it.
        result["budget_used"] += 1
        result["queued"].append({"address": addr, "name": contract_name, "job_id": str(child_job.id)})
        logger.info(
            "Job %s: queued discovered contract %s (%s) as job %s",
            job.id,
            contract_name,
            addr,
            child_job.id,
        )

    # Loop exit, and only loop exit: every node has now been placed in exactly
    # one disposition. A raise above skips this line and leaves the prefix
    # marked incomplete.
    result["walked"] = True

    if result["queued"] or result["omitted"]:
        logger.info(
            "Perimeter spawn complete",
            extra={
                "site": site,
                "job_id": str(job.id),
                "queued_count": len(result["queued"]),
                "omitted_count": len(result["omitted"]),
                "budget": budget,
                "budget_used": result["budget_used"],
            },
        )
    return result
