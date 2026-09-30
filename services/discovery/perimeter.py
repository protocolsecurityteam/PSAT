"""The analysis perimeter: which discovered contracts become analysis jobs.

One walker for both the resolution stage (the first graph) and the policy stage (the refreshed graph with
``role_principal`` nodes); before the second call site, nodes first found by the refresh were never analysed.

Every non-job candidate lands in a disposition:

* ``queued``: a job was created;
* ``omitted``: could have been analysed but wasn't (budget, depth, chain, bad address), persisted with its reason;
* ``out_of_population``: never a candidate (the root, unanalysed walk nodes, non-contracts, existing jobs). Not
omissions.

They partition the node list only when ``walked`` is true. The caller builds the ledger and persists it from a
``finally``, so it can be written after a full walk, a partial walk, or none; ``walked`` is set only at loop exit, and
when false the lists are a prefix.

Budget is spent only at ``create_job``, so gate order never matters for it.
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

# Spawns per policy-stage refresh. The refresh recurses (new managers spawn their own), so without a cut it exhausts the
# graph. A chosen value, not calibrated from data; adjust in config.
PERIMETER_SPAWN_LIMIT = int(os.getenv("PSAT_PERIMETER_SPAWN_LIMIT", "8"))

# Spawn generations per root. Counts perimeter spawns only (carried in the request), never
# ``control_graph_nodes.depth``.
PERIMETER_SPAWN_DEPTH_CAP = int(os.getenv("PSAT_PERIMETER_SPAWN_DEPTH_CAP", "2"))

# Absent means generation 0.
PERIMETER_DEPTH_KEY = "perimeter_spawn_depth"

# ``details`` key recording what produced a node (the FP materialization pass). Provenance only, never admission:
# ``details`` is copied verbatim from upstream payloads (``recursive.py``), so it can be forged. Admission uses the
# caller's ``fp_materialized_addresses``.
CONTROL_GRAPH_BASIS_KEY = "control_graph_basis"

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
    # True only after the loop completes (see module docstring).
    walked: bool


def spawn_depth_of(job: Job) -> int:
    """The perimeter generation of *job*; malformed or absent is 0."""
    request = job.request if isinstance(job.request, dict) else {}
    raw = request.get(PERIMETER_DEPTH_KEY)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        return 0
    return raw


def _parent_company(session: Session, job: Job) -> str | None:
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
    """``(parent_is_member, {dep_address: relationship}, parent_contract)`` for structural same-protocol components
    of the parent (the W2 producer).

    ``relationship_type`` alone isn't enough: it's what the dep is, not the edge (a member calling Lido stETH sees
    ``proxy`` because stETH is a proxy). The Contract row's proxy/impl/beacon fields must link the two.

    ``library`` is excluded: it mixes internal helpers with shared infrastructure (e.g. etherfi's BucketLimiter vs
    Circle's SignatureChecker), and nothing yet distinguishes them. Never trust a dependency name to match the parent
    without comparing addresses.

    Best-effort: failure means no propagation.
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

    # Membership, never a source tag (W2).
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

    # Batch the back-link check for proxy edges.
    proxy_edge_addrs = [row.dependency_address.lower() for row in dep_rows if row.relationship_type == "proxy"]
    dep_impl_by_addr: dict[str, str | None] = {}
    # Chain-scoped (a CREATE2 twin elsewhere matches the bare address), mainnet-coalesced.
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
    """W2 producer: write the witness only when the rows' stored resolution carries the edge
    (the parent's ``implementation``/``beacon``, or the candidate proxy's back-link). The witness protocol is the
    parent's membership. Returns the edge kind, or None.
    """
    from db.models import WITNESS_RULE_W2_STRUCTURAL
    from services.discovery import membership_gate as gate

    if parent.protocol_id is None:
        return None
    if protocol_id is not None and parent.protocol_id != protocol_id:
        return None
    # Chain-scoped against CREATE2 twins.
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
    """Probe trigger: no probe for the row's own chain, an incomplete attempt (errors aren't verdicts), or a
    pruned row seen again (pruning is evidence at a block, not terminal).
    """
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
    """A demoted member keeps its old probe, so ``needs_probe`` skips it; a witness revocation newer than that probe
    makes it stale, so re-target it. The pickup path for demotions where no inline probe may run.
    """
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
    """W1 from a fresh probe: only code-present on the contract's own chain mints it."""
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
    """W2 for structurally linked deps that already have rows on the parent's chain; new deps earn it at fetch time.

    Witnessed candidates without a probe get one near-line so they can still promote.
    """
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
        # A promotion is new evidence.
        gate.evaluate(session, gate.FactsDelta(new_member_contract_ids=tuple(promoted)))
        session.commit()


def new_spawn_result(*, site: str, budget: int | None, spawn_depth: int = 0) -> PerimeterSpawnResult:
    """An empty ledger built by the caller so it survives a raise: if ``create_job`` fails partway, the caller's
    ``finally`` can still persist the committed children. ``walked`` starts ``False``.
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


FP_MATERIALIZATION_SITE = "fp_materialization"


class FpMaterializationResult(PerimeterSpawnResult):
    """The FP materialization pass's ledger, on two planes.

    The three dispositions answer "will this address be offered to the walker?": ``queued`` (minted analysable
    contract), ``omitted`` (``budget_exhausted``, ``chain_not_enabled``), ``out_of_population`` (``not_analyzable_type``
    for safes/EOAs, plus existing node, zero/invalid address, anchor problems, undetermined or conflicting type).

    ``minted`` is separate because minting a node and offering a job are different acts (a Safe gets the first only); it
    equals ``queued`` plus ``not_analyzable_type``.

    ``budget_used`` counts committed mints only. ``budget_exhausted`` is a permanent loss on this anchor: the next pass
    re-mints the same sorted prefix (see ``FP_MATERIALIZE_LIMIT``).
    """

    minted: list[dict[str, Any]]


def new_fp_materialization_result(*, budget: int | None) -> FpMaterializationResult:
    """An empty FP-materialization ledger built by the caller, like :func:`new_spawn_result`."""
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

    ``budget=None`` (resolution stage) means no cut beyond ``max_depth``; an int (policy stage) caps spawns and records
    every drop. Pass *result* (:func:`new_spawn_result`) so the ledger survives a raise.

    *fp_materialized_addresses* are the addresses this caller minted in this job (``materialize_fp_principal_nodes``),
    the only ones exempt from the ``analyzed`` gate. An explicit set because a field in ``details`` could be forged.
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
        # Witness production is recording; failures reduce recall but never stop the walk.
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
            # An unset pointer resolves to the zero address, whose job can only fail.
            _omit(addr, "zero_address")
            continue
        if addr == root_address:
            _out(addr, "root_node")
            continue
        # Only analysed walk nodes are queued, except FP-materialized ones: they were never offered to the walk (the FP
        # rows prove them principals the walk's ingresses missed), so ``analyzed=false`` is their definition, not a
        # decision. Other gates still apply, keeping safes and EOAs out. Checked against the caller's set, since node
        # ``details`` are attacker-reachable.
        if not node.get("analyzed") and addr not in fp_minted:
            _out(addr, "not_analyzed")
            continue
        if node.get("node_type") != "contract":
            _out(addr, "not_contract_node")
            continue
        # Case-insensitive and chain-scoped.
        if find_existing_job_for_address(session, addr, chain=chain_name) is not None:
            _out(addr, "existing_job")
            continue
        # Defence in depth: children share the parent's chain, but a disabled chain must never spawn.
        if not chain_enabled(chain_name):
            _omit(addr, "chain_not_enabled")
            continue
        if depth_cap is not None and spawn_depth >= depth_cap:
            _omit(addr, "depth_exhausted")
            continue
        if budget is not None and result["budget_used"] >= budget:
            _omit(addr, "budget_exhausted")
            continue

        # Not ``label``: that's edge display text ("role principal"), and this becomes the job's name. The address is a
        # true fallback.
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

        # Spent here only.
        result["budget_used"] += 1
        result["queued"].append({"address": addr, "name": contract_name, "job_id": str(child_job.id)})
        logger.info(
            "Job %s: queued discovered contract %s (%s) as job %s",
            job.id,
            contract_name,
            addr,
            child_job.id,
        )

    # Only at loop exit; a raise leaves the prefix marked incomplete.
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
