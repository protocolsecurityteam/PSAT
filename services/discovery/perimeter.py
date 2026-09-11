"""The analysis perimeter: which discovered contracts become analysis jobs.

One walker, two call sites, deliberately the SAME code path:

* the **resolution stage** spawns from the walk's first graph, and
* the **policy stage** spawns from the refreshed graph it rebuilds once
  ``permission_index`` exists — the refresh that projects
  ``role_principal`` nodes into the graph.

Until the second call site existed, every node FIRST discovered by the policy
refresh was permanently outside the perimeter even though it satisfied every
gate here. Measured on the PR-161 corpus: 32 addresses carry
``details->>'source' = 'semantic_capability:role_grant'`` with
``node_type='contract'``, of which **19 had no job** — all 19 had completed analysis,
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
from typing import TYPE_CHECKING, Any, Collection, Mapping, TypedDict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractDependency,
    ContractMembershipWitness,
    ContractProbeAttempt,
    Job,
    JobStage,
)
from db.queue import _mainnet_coalesced_chain, create_job, find_existing_job_for_address
from services.clients.rpc import chain_id_for_chain_name
from utils.chains import canonical_chain, chain_enabled
from utils.logging import record_degraded

if TYPE_CHECKING:
    from services.discovery.probes import ProbeResult

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

#: ``control_graph_nodes.details`` key recording what PRODUCED a node, persisted
#: by the FP materialization pass. Provenance on the stored row — read by
#: consumers of the graph plane, and NOT by the admission arm below.
#:
#: It cannot gate admission, and the earlier draft that used it was wrong to say
#: nothing else may write it. ``details`` is free-form JSONB copied verbatim from
#: upstream principal payloads by the walk (``recursive.py``: no key allowlist),
#: so any producer that can put a key in a principal's details can forge this
#: one — demonstrated: a hand-crafted walk node carrying the key passed the arm
#: and spawned a job. Admission is therefore decided by an explicit set the
#: CALLER passes (see ``fp_materialized_addresses``), which is a construction the
#: data plane cannot reach rather than a now-fact about writers.
CONTROL_GRAPH_BASIS_KEY = "control_graph_basis"

#: The value :data:`CONTROL_GRAPH_BASIS_KEY` carries on a minted node.
FP_MATERIALIZATION_BASIS = "fp_materialization"


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


def _structural_ownership(session: Session, job: Job) -> tuple[bool, dict[str, str], Contract | None]:
    """``(parent_is_member, {dep_address: relationship}, parent_contract)`` for
    structural same-protocol components of the parent — the W2 producer's edge
    walk (spec §3.2).

    ``cd.relationship_type`` alone isn't sufficient — it's the classifier's
    verdict on what kind of contract the dep IS, not the edge semantics. A
    member ether.fi contract calling Lido stETH has
    ``relationship_type='proxy'`` because stETH is a proxy — that doesn't make
    stETH ether.fi's structural proxy. We require the proxy/impl/beacon fields
    on the Contract row to actually link the two.

    ``library`` is intentionally excluded because the bucket is
    *heterogeneous*: the classifier's DELEGATECALL-only heuristic correctly
    identifies real libraries (verified — it does NOT mis-tag the primary
    proxy→impl edge), but the *targets* mix protocol-internal helpers with
    shared infrastructure. In a single sample dataset ``BucketLimiter``
    (etherfi-internal rate limiter) and ``SignatureChecker`` (Circle's USDC
    helper, shared across protocols) both land in the ``library`` bucket.
    Admitting either way would be wrong for the other. Until there's a
    downstream signal that splits "internal helper" from "shared lib,"
    structural admission skips this relationship type and those rows stay
    candidates. Same-name address pairs (e.g. two different contracts both
    called ``EtherFiOracle``) are common — never assume the
    ``dependency_name`` string equals the parent's identity without checking
    addresses.

    Best-effort: a failure falls back to "no propagation" (the safe default)
    rather than blocking discovery.
    """
    structural_rel_by_addr: dict[str, str] = {}
    try:
        parent_contract = session.execute(
            select(Contract).where(Contract.job_id == job.id).limit(1)
        ).scalar_one_or_none()
    except Exception as exc:
        logger.debug("Job %s: structural-propagation parent lookup failed: %s", job.id, exc)
        return False, {}, None
    if parent_contract is None:
        return False, {}, None

    # Membership, never a source tag: only a member parent's stored resolution
    # can admit (spec §3.2 W2; supersedes the HIGH-source shortcut).
    parent_is_member = getattr(parent_contract, "protocol_id", None) is not None
    parent_id = getattr(parent_contract, "id", None)
    parent_impl = (getattr(parent_contract, "implementation", None) or "").lower() or None
    parent_beacon = (getattr(parent_contract, "beacon", None) or "").lower() or None
    parent_addr_lower = (getattr(parent_contract, "address", None) or "").lower() or None
    parent_chain = _mainnet_coalesced_chain(canonical_chain(getattr(parent_contract, "chain", None)))
    if parent_id is None:
        return parent_is_member, {}, parent_contract

    try:
        dep_rows = list(
            session.execute(select(ContractDependency).where(ContractDependency.contract_id == parent_id)).scalars()
        )
    except Exception as exc:
        logger.debug("Job %s: structural-propagation dep-rows lookup failed: %s", job.id, exc)
        return parent_is_member, {}, parent_contract

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
    return parent_is_member, structural_rel_by_addr, parent_contract


def produce_structural_witness(
    session: Session,
    *,
    candidate: Contract,
    parent: Contract,
    protocol_id: int | None,
    relationship: str,
) -> str | None:
    """W2 producer (spec §3.2, invariant 6): write the witness only when the
    stored resolution on the rows themselves carries the edge — the parent's
    ``implementation``/``beacon`` pointer, or the candidate proxy's back-link
    — never a bare ``relationship_type`` or a request flag.

    Returns the verified edge kind, or None (no witness written). The witness
    protocol is the PARENT's membership; a parent that is not a member (or is
    a member of a different protocol than *protocol_id* claims) admits nothing.
    """
    from db.models import WITNESS_RULE_W2_STRUCTURAL
    from services.discovery import membership_gate as gate

    if parent.protocol_id is None:
        return None
    if protocol_id is not None and parent.protocol_id != protocol_id:
        return None
    # Chain-scoped: a CREATE2 twin on another chain satisfies the bare
    # address match, so the edge only holds within one chain.
    parent_chain = _mainnet_coalesced_chain(canonical_chain(parent.chain))
    candidate_chain = _mainnet_coalesced_chain(canonical_chain(candidate.chain))
    if parent_chain != candidate_chain:
        return None
    candidate_addr = (candidate.address or "").lower()
    parent_addr = (parent.address or "").lower()
    if not candidate_addr or not parent_addr:
        return None

    edge_kind: str | None = None
    resolved_pointer: str | None = None
    if relationship == "implementation" and (parent.implementation or "").lower() == candidate_addr:
        edge_kind, resolved_pointer = "implementation", candidate_addr
    elif relationship == "beacon" and (parent.beacon or "").lower() == candidate_addr:
        edge_kind, resolved_pointer = "beacon", candidate_addr
    elif relationship == "proxy" and (candidate.implementation or "").lower() == parent_addr:
        edge_kind, resolved_pointer = "proxy", parent_addr
    if edge_kind is None or resolved_pointer is None:
        return None

    gate.write_witness(
        session,
        contract_id=candidate.id,
        protocol_id=parent.protocol_id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind=edge_kind,
            member_contract_id=parent.id,
            member_address=parent_addr,
            resolved_pointer=resolved_pointer,
        ),
        via_address=parent_addr,
    )
    return edge_kind


def needs_probe(session: Session, contract: Contract) -> bool:
    """§3.4 event 1 trigger: no probe attempt persisted for the row's OWN
    chain, an attempt that never completed (``status != probed`` — an error or
    unroutable outcome is an attempt, never a verdict), or a pruned row seen
    again — re-nomination re-runs W1 (pruned is evidence-at-a-block, not
    terminal)."""
    from services.discovery.probes import STATUS_PROBED, UNRESOLVABLE_CHAIN_ID

    chain_id = chain_id_for_chain_name(contract.chain)
    key_chain = UNRESOLVABLE_CHAIN_ID if chain_id is None else chain_id
    attempt = session.get(ContractProbeAttempt, (contract.id, key_chain))
    if attempt is None:
        return True
    results = attempt.results if isinstance(attempt.results, dict) else {}
    if results.get("status") != STATUS_PROBED:
        return True
    address = (contract.address or "").lower()
    if chain_id is None or not address:
        return False
    witness = session.get(ContractCreationWitness, (chain_id, address))
    return witness is not None and witness.code_absent_at_probe is True


def probe_predates_revocation(session: Session, contract: Contract) -> bool:
    """A demoted member keeps its completed ``probed`` attempt, so
    ``needs_probe`` skips it. A witness revocation NEWER than that attempt
    makes the stored probe stale evidence for re-admission (invariant 8), so
    the probe pass re-targets the row through the normal event flow — the
    pickup path for demotions from request/queue contexts (e.g. the
    protocol-merge deployer cascade) where no inline probe may run."""
    from services.discovery.probes import UNRESOLVABLE_CHAIN_ID

    chain_id = chain_id_for_chain_name(contract.chain)
    key_chain = UNRESOLVABLE_CHAIN_ID if chain_id is None else chain_id
    attempt = session.get(ContractProbeAttempt, (contract.id, key_chain))
    if attempt is None or attempt.probed_at is None:
        return False
    newest = session.execute(
        select(func.max(ContractMembershipWitness.revoked_at)).where(
            ContractMembershipWitness.contract_id == contract.id,
            ContractMembershipWitness.revoked_at.is_not(None),
        )
    ).scalar_one()
    return newest is not None and attempt.probed_at < newest


def record_code_witness(session: Session, *, contract: Contract, protocol_id: int, probe_result: "ProbeResult") -> bool:
    """W1 from a fresh probe — only a code-present verdict block-stamped on the
    contract's OWN chain mints the witness (invariant 3)."""
    from db.models import WITNESS_RULE_W1_CODE
    from services.discovery import membership_gate as gate

    if probe_result.code_present is not True or probe_result.block_number is None or probe_result.chain_id is None:
        return False
    expected_chain = chain_id_for_chain_name(contract.chain)
    if expected_chain is None or probe_result.chain_id != expected_chain:
        return False
    gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=probe_result.chain_id, code_probe_block=probe_result.block_number),
    )
    return True


def _produce_structural_witnesses(
    session: Session,
    parent: Contract,
    rel_by_addr: Mapping[str, str],
) -> None:
    """W2 production for structurally-linked deps that already have Contract
    rows on the parent's chain; a dep with no row yet earns its witness at
    fetch time from the child request's edge hint (re-verified there).

    A witnessed candidate lacking a probe attempt gets the event-1 probe
    near-line, so a dep that never re-enters the fetch path (existing row +
    existing job) can still complete W2+W1 and promote."""
    from services.discovery import membership_gate as gate

    protocol_id = parent.protocol_id
    if protocol_id is None or not rel_by_addr:
        return
    parent_chain = _mainnet_coalesced_chain(canonical_chain(parent.chain))
    rows = list(
        session.execute(
            select(Contract).where(
                func.lower(Contract.address).in_(sorted(rel_by_addr)),
                func.lower(func.coalesce(Contract.chain, "ethereum")) == parent_chain,
            )
        ).scalars()
    )
    promoted: list[int] = []
    for row in rows:
        relationship = rel_by_addr.get((row.address or "").lower())
        if relationship is None:
            continue
        gate.nominate(session, contract=row, protocol_id=protocol_id, source_tag="structural_witness")
        if (
            produce_structural_witness(
                session, candidate=row, parent=parent, protocol_id=protocol_id, relationship=relationship
            )
            is None
        ):
            continue
        if row.protocol_id is None and needs_probe(session, row):
            probe_result = gate.probe(session, row)
            record_code_witness(session, contract=row, protocol_id=protocol_id, probe_result=probe_result)
        if row.protocol_id is None and gate.promote(session, contract=row, protocol_id=protocol_id):
            promoted.append(row.id)
    session.commit()
    if promoted:
        # A promotion is itself new evidence (spec §3.4 event 2d).
        gate.evaluate(session, gate.FactsDelta(new_member_contract_ids=tuple(promoted)))
        session.commit()


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


#: Ledger site of the FP→control-graph materialization pass.
FP_MATERIALIZATION_SITE = "fp_materialization"


class FpMaterializationResult(PerimeterSpawnResult):
    """The FP materialization pass's ledger. Same machinery, TWO planes.

    The inherited three dispositions keep their meaning verbatim — they
    partition every FP principal considered, on the one question the perimeter
    also asks: **will this address be offered to the walker as an analysis
    candidate?**

    * ``queued`` — offered. Minted, analyzable type, so ``node_type='contract'``.
    * ``omitted`` — could have been offered and was not: ``budget_exhausted``,
      ``chain_not_enabled``.
    * ``out_of_population`` — never offerable: ``not_analyzable_type`` (a safe /
      EOA: the node IS minted, the job never happens), ``existing_node``,
      ``zero_address``, ``invalid_address``, ``no_contract_anchor``,
      ``anchor_contract``, ``resolved_type_not_determined``,
      ``resolved_type_conflict``.

    ``minted`` is the ORTHOGONAL plane and is why it is a separate list rather
    than a fourth disposition: minting a node and offering a job are different
    acts, and the whole point of this pass is that a safe gets the first without
    the second. Folding them into one axis would force one of the two to lie.
    Its members are exactly ``queued`` ∪ the ``not_analyzable_type`` entries.

    ``budget_used`` counts MINTS, because the budget is spent at the COMMITTED
    INSERT and nowhere else — the same discipline ``queue_discovered_contracts``
    applies at ``create_job``, so no earlier gate's ordering can silently become
    load-bearing, and no entry here can name a row a rollback removed.

    ``budget_exhausted`` in ``omitted`` is a PERMANENT loss on this anchor, not a
    queue: the scope is rewritten before every mint, so the next pass re-mints
    the same sorted prefix and drops the same tail. See ``FP_MATERIALIZE_LIMIT``.
    """

    minted: list[dict[str, Any]]


def new_fp_materialization_result(*, budget: int | None) -> FpMaterializationResult:
    """An empty FP-materialization ledger, constructed by the CALLER for the
    same reason :func:`new_spawn_result` is: it has to survive a raise in the
    middle of the mint loop and still say which nodes were already committed."""
    return {
        "site": FP_MATERIALIZATION_SITE,
        "budget": budget,
        "budget_used": 0,
        "spawn_depth": 0,
        "queued": [],
        "omitted": [],
        "out_of_population": [],
        "walked": False,
        "minted": [],
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
    fp_materialized_addresses: Collection[str] | None = None,
) -> PerimeterSpawnResult:
    """Queue analysis jobs for contracts in *resolved_graph* that have none.

    ``budget=None`` (the resolution stage) means no cut: the walk's own
    ``max_depth`` already bounds it. An int (the policy stage) caps this
    stage's spawns and records every candidate it drops.

    Pass *result* (from :func:`new_spawn_result`) to keep the ledger reachable
    if this raises part-way through.

    *fp_materialized_addresses* — lowercase addresses this caller MINTED in this
    same job (``materialize_fp_principal_nodes``). Only these are exempt from the
    analysis-state gate. It is an explicit set, not a field on the node, because a
    field can be forged: ``details`` is free-form JSONB the walk copies verbatim
    from upstream principal payloads, so a provenance MARKER inside it is a
    now-fact about writers, whereas the caller's own set is a construction the
    graph data cannot reach.
    """
    spawn_depth = spawn_depth_of(job)
    if result is None:
        result = new_spawn_result(site=site, budget=budget, spawn_depth=spawn_depth)
    result["spawn_depth"] = spawn_depth
    fp_minted = {a.lower() for a in (fp_materialized_addresses or ()) if a}

    parent_company = _parent_company(session, job)
    parent_is_member, structural_rel_by_addr, parent_contract = _structural_ownership(session, job)
    if getattr(parent_contract, "protocol_id", None) is not None:
        assert parent_contract is not None
        # Witness production is evidence recording, not spawn control — a
        # failure degrades the gate's recall, never the walk.
        try:
            _produce_structural_witnesses(session, parent_contract, structural_rel_by_addr)
        except Exception as exc:
            session.rollback()
            logger.warning(
                "structural witness production failed",
                extra={"job_id": str(job.id), "exc_type": type(exc).__name__},
            )
            record_degraded(
                phase="structural_witness_production",
                exc=exc,
                context={"job_id": str(job.id), "site": site},
            )

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
        # Only queue contracts that were analyzed during the walk — with one
        # declared exception. ``analysis_state`` is the walk's own gate and it is
        # correct for walk-produced nodes: an unanalysed one was reached, and
        # not analysing it was a decision this stage already recorded.
        #
        # An FP-materialized node was never OFFERED to the walk. It exists
        # because a ``function_principals`` row proves the address is a resolved
        # principal of a gated function on this contract, while the walk's only
        # principal ingresses (``authority_roles[].principals`` and
        # ``controllers[].principals``) never saw it — 73 addresses / 411 of
        # 1,200 FP rows on the PR-161 corpus, 72 of them with no ``contracts``
        # row at all. Reading its missing analysis state as "this stage chose not to
        # analyse it" would restate the very defect: unanalysed is its
        # DEFINITION, not a verdict, and it is exactly the population that needs
        # analysis. Admitting it changes no other gate — ``node_type``,
        # ``existing_job``, ``chain_enabled``, depth and budget all still apply
        # below, which is what keeps safes and EOAs out (they mint
        # ``node_type='principal'``).
        #
        # Membership of the CALLER's minted set, never a field on the node: a
        # graph node's ``details`` is attacker-reachable through the walk's
        # verbatim copy of upstream principal payloads.
        if node.get("analysis_state") != "analyzed" and addr not in fp_minted:
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

        # ``label`` is deliberately NOT a fallback. It is display copy on the
        # graph plane ("role principal", "capability principal") and this value
        # becomes ``Job.name`` and ``request["name"]`` — an IDENTITY — for every
        # child, so the leg published a noun describing the EDGE as the name of
        # the CONTRACT. The address is a worse-looking but true fallback.
        contract_name = node.get("contract_name") or addr
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
            child_request["parent_is_member"] = parent_is_member

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
