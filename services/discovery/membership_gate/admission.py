"""Nomination and the W5/W6 seeds, promotion/demotion primitives, and
stratum-(iii) admission derivation."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Mapping

from sqlalchemy import Text, cast, func, select
from sqlalchemy.dialects.postgresql import ARRAY

from db.models import (
    ADMITTING_WITNESS_RULES,
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W3_CONTROL,
    WITNESS_RULE_W4_DEPLOYER,
    WITNESS_RULE_W4_FACTORY,
    WITNESS_RULE_W5_HUMAN,
    WITNESS_RULE_W6_LLAMA_SEED,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    Protocol,
    UpgradeEvent,
)
from services.clients.rpc import chain_id_for_chain_name

from .deployers import _proof_registry_row
from .readers import (
    _chain_key,
    _d2_principal_facts,
    _member_factory_lineage,
    _member_rows_at,
    _probe_controller_values,
    _secondary_pointer_named,
    _w2_edge_holds,
    member_for_evidence,
)
from .rules import (
    _ADDRESS_RE,
    _TX_HASH_RE,
    DEFILLAMA_SOURCE_TAG,
    MEMBERSHIP_DIRTY_REASON,
    W2_SAME_CONTRACT_EDGE_KINDS,
    W3_CONTROLLER_PROVENANCE,
    W3_DIRECTION_D1,
    W3_DIRECTION_D2,
    _require_positive_int,
    active_witnesses,
    w1_evidence,
    w2_evidence,
    w3_evidence,
    w4_evidence,
    w4_factory_evidence,
    w5_evidence,
    w6_evidence,
    write_witness,
)
from .transitivity import _via_transitivity, _witness_fact_holds

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from services.discovery.probes import ProbeResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Nomination (spec §3.4 event 1) + W5 human assertion (spec §5.2, invariant 14)
# ---------------------------------------------------------------------------

#: ``jobs.request`` key carrying a serialized :class:`HumanAssertion` from the
#: admin submission edge to the discovery fetch path.
HUMAN_ASSERTION_REQUEST_KEY = "human_assertion"


@dataclass(frozen=True)
class HumanAssertion:
    """An admin's explicit membership assertion: actor + timestamp, never a
    source tag (invariant 14)."""

    actor: str
    asserted_at: datetime


def human_assertion_request_payload(assertion: HumanAssertion) -> dict[str, str]:
    """The JSON shape :data:`HUMAN_ASSERTION_REQUEST_KEY` carries on a job request."""
    if not isinstance(assertion.actor, str) or not assertion.actor.strip():
        raise ValueError("actor is required for a human assertion")
    return {"actor": assertion.actor.strip(), "asserted_at": assertion.asserted_at.isoformat()}


def human_assertion_from_request(request: Any) -> HumanAssertion | None:
    """Parse :data:`HUMAN_ASSERTION_REQUEST_KEY` off a job request dict.
    Returns ``None`` — never a defaulted actor/timestamp — when the payload is
    absent or malformed."""
    if not isinstance(request, Mapping):
        return None
    payload = request.get(HUMAN_ASSERTION_REQUEST_KEY)
    if not isinstance(payload, Mapping):
        return None
    actor = payload.get("actor")
    raw_ts = payload.get("asserted_at")
    if not isinstance(actor, str) or not actor.strip() or not isinstance(raw_ts, str):
        return None
    try:
        asserted_at = datetime.fromisoformat(raw_ts)
    except ValueError:
        return None
    return HumanAssertion(actor=actor.strip(), asserted_at=asserted_at)


def nominate(
    session: Session,
    *,
    contract: Contract,
    protocol_id: int,
    source_tag: str,
    human_assertion: HumanAssertion | None = None,
) -> None:
    """Record that a discovery source nominated *contract* for *protocol_id*.

    Sets ``nominated_protocol_id``, never ``protocol_id``. The first
    nomination wins; a differing later one is logged and kept as provenance in
    ``discovery_sources`` only. An existing MEMBER's empty nomination slot
    belongs to its own protocol (demotion provenance, invariant 4) — a foreign
    nomination may never claim it.

    ``human_assertion`` (spec §5.2 W5) writes the W5 witness for
    *protocol_id* and attempts promotion — which still requires W1
    (invariant 3): an assertion on an unprobed/unroutable chain yields a
    candidate-with-W5-witness, not a member.
    """
    _require_positive_int(protocol_id, "protocol_id")
    if contract.protocol_id is not None:
        if contract.nominated_protocol_id is None:
            contract.nominated_protocol_id = contract.protocol_id
        if protocol_id != contract.protocol_id:
            logger.info(
                "foreign nomination of an existing member recorded as provenance only",
                extra={
                    "contract_id": contract.id,
                    "member_of": contract.protocol_id,
                    "late_protocol_id": protocol_id,
                    "source_tag": source_tag,
                },
            )
    elif contract.nominated_protocol_id is None:
        contract.nominated_protocol_id = protocol_id
    elif contract.nominated_protocol_id != protocol_id:
        logger.info(
            "re-nomination kept first nominator",
            extra={
                "contract_id": contract.id,
                "nominated_protocol_id": contract.nominated_protocol_id,
                "late_protocol_id": protocol_id,
                "source_tag": source_tag,
            },
        )
    if source_tag:
        merged = list(contract.discovery_sources or [])
        if source_tag not in merged:
            merged.append(source_tag)
            contract.discovery_sources = merged
    if human_assertion is not None:
        # A member of ANOTHER protocol accepts no foreign W5 row — the
        # assertion is provenance in the log only (invariant 1 posture).
        if contract.protocol_id not in (None, protocol_id):
            logger.info(
                "human assertion for a foreign protocol not recorded on a member",
                extra={
                    "contract_id": contract.id,
                    "member_of": contract.protocol_id,
                    "asserted_protocol_id": protocol_id,
                    "actor": human_assertion.actor,
                },
            )
            return
        if contract.id is None:
            session.flush()
        write_witness(
            session,
            contract_id=contract.id,
            protocol_id=protocol_id,
            rule=WITNESS_RULE_W5_HUMAN,
            evidence=w5_evidence(actor=human_assertion.actor, asserted_at=human_assertion.asserted_at),
        )
        promote(session, contract=contract, protocol_id=protocol_id)


def seed_llama_witness(session: Session, *, contract: Contract) -> bool:
    """W6 seed for the contract's claimed protocol (spec §3.2): the
    ``defillama`` source tag plus a code-present probe on the row's own chain.
    The ONE producer of W6 rows — the live probe/intake paths and the re-earn
    migration both mint through here. A row already carrying a W6 row, active
    OR revoked, is left alone: re-observing the same listing is not new
    evidence, so a revoked seed (§3.2 revocation story) is never re-armed."""
    protocol_id = contract.protocol_id if contract.protocol_id is not None else contract.nominated_protocol_id
    if protocol_id is None or DEFILLAMA_SOURCE_TAG not in (contract.discovery_sources or []):
        return False
    chain_id = chain_id_for_chain_name(contract.chain)
    if chain_id is None or not contract.address:
        return False
    code_row = session.get(ContractCreationWitness, (chain_id, contract.address.lower()))
    if code_row is None or code_row.code_probe_block is None or code_row.code_absent_at_probe:
        return False
    if contract.id is None:
        session.flush()
    existing = session.execute(
        select(ContractMembershipWitness.id)
        .where(
            ContractMembershipWitness.contract_id == contract.id,
            ContractMembershipWitness.protocol_id == protocol_id,
            ContractMembershipWitness.rule == WITNESS_RULE_W6_LLAMA_SEED,
        )
        .limit(1)
    ).first()
    if existing is not None:
        return False
    protocol = session.get(Protocol, protocol_id)
    if protocol is None:
        return False
    # Adapter provenance: the DefiLlama family slug when resolved, else the
    # protocol name the adapter scan matched on.
    adapter_slug = protocol.canonical_slug or protocol.name
    write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W6_LLAMA_SEED,
        evidence=w6_evidence(
            adapter_slug=adapter_slug,
            chain_id=chain_id,
            code_probe_block=code_row.code_probe_block,
        ),
    )
    return True


# ---------------------------------------------------------------------------
# Promotion / demotion primitives
# ---------------------------------------------------------------------------


def _mark_membership_dirty(session: Session, protocol_id: int) -> None:
    from services.monitoring.enrollment import mark_enrollment_dirty
    from services.scoring.dirty import SCORE_DIRTY_MEMBERSHIP, mark_protocol_score_dirty

    mark_enrollment_dirty(session, protocol_id, MEMBERSHIP_DIRTY_REASON)
    mark_protocol_score_dirty(session, protocol_id, SCORE_DIRTY_MEMBERSHIP)


def promote(session: Session, *, contract: Contract, protocol_id: int) -> bool:
    """Promote to member iff W1 holds (invariant 3) AND ≥1 admitting witness
    is active AND its via-fact verifies against stored resolution — a witness
    row a caller wrote is a claim, not a license. Returns whether the contract
    is a member of *protocol_id* on exit; a refusal logs the named missing
    piece (invariant 5)."""
    _require_positive_int(protocol_id, "protocol_id")
    if contract.protocol_id == protocol_id:
        return True
    if contract.protocol_id is not None:
        logger.error(
            "promotion refused: contract already a member elsewhere",
            extra={"contract_id": contract.id, "member_of": contract.protocol_id, "requested": protocol_id},
        )
        return False
    rows = active_witnesses(session, contract_id=contract.id, protocol_id=protocol_id)
    rules = {row.rule for row in rows}
    # W1 must be a code proof on the CONTRACT'S OWN chain — a witness probed
    # elsewhere (or a row whose chain never resolves) satisfies nothing.
    expected_chain = chain_id_for_chain_name(contract.chain)
    # The LATEST persisted probe verdict outranks any stale active W1 row: a
    # later code-absent probe is proven-absent (§3.1), and proven-absent can
    # never promote.
    if expected_chain is not None and contract.address:
        code_row = session.get(ContractCreationWitness, (expected_chain, contract.address.lower()))
        if code_row is not None and code_row.code_absent_at_probe is True:
            logger.info(
                "promotion withheld",
                extra={
                    "contract_id": contract.id,
                    "protocol_id": protocol_id,
                    "missing": "code_present_at_latest_probe",
                    "contract_chain": contract.chain,
                    "active_rules": sorted(rules),
                },
            )
            return False
    has_w1 = expected_chain is not None and any(
        row.rule == WITNESS_RULE_W1_CODE
        and isinstance(row.evidence, dict)
        and row.evidence.get("chain_id") == expected_chain
        for row in rows
    )
    admitting = sorted(
        {
            row.rule
            for row in rows
            if row.rule in ADMITTING_WITNESS_RULES
            and _witness_fact_holds(
                session,
                contract=contract,
                protocol_id=protocol_id,
                rule=row.rule,
                evidence=row.evidence,
                via_address=row.via_address,
            )
        }
    )
    if not has_w1 or not admitting:
        logger.info(
            "promotion withheld",
            extra={
                "contract_id": contract.id,
                "protocol_id": protocol_id,
                "missing": "w1_code_for_contract_chain" if not has_w1 else "verified_admitting_witness",
                "contract_chain": contract.chain,
                "active_rules": sorted(rules),
            },
        )
        return False
    contract.protocol_id = protocol_id
    if contract.nominated_protocol_id != protocol_id:
        # Proof supersedes provenance: the earned membership realigns the
        # nomination slot so the demotion restore stays coherent. The first
        # nominator's identity survives in ``discovery_sources`` and here.
        if contract.nominated_protocol_id is not None:
            logger.info(
                "promotion supersedes foreign nomination slot",
                extra={
                    "contract_id": contract.id,
                    "protocol_id": protocol_id,
                    "prior_nominated_protocol_id": contract.nominated_protocol_id,
                },
            )
        contract.nominated_protocol_id = protocol_id
    _mark_membership_dirty(session, protocol_id)
    logger.info(
        "contract promoted to member",
        extra={"contract_id": contract.id, "protocol_id": protocol_id, "witness_rules": admitting},
    )
    return True


def demote_member(
    session: Session,
    *,
    contract: Contract,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Member → candidate: ``protocol_id`` cleared, nomination and witness
    history preserved (invariant 4). Witness revocation is the caller's step —
    this primitive only moves the stamp and marks the queues."""
    protocol_id = contract.protocol_id
    if protocol_id is None:
        return
    if contract.nominated_protocol_id is None:
        contract.nominated_protocol_id = protocol_id
    contract.protocol_id = None
    _mark_membership_dirty(session, protocol_id)
    logger.info(
        "member demoted to candidate",
        extra={
            "contract_id": contract.id,
            "protocol_id": protocol_id,
            "reason": reason,
            "evidence": evidence or {},
        },
    )


def _attempt_admission(
    session: Session, contract: Contract, protocol_id: int, *, heuristic_inheritance: bool = False
) -> str | None:
    """Stratum (iii) for one candidate: derive admitting witnesses from stored
    facts (each verified at derivation AND again in ``promote``), bind W1 from
    the persisted code probe, promote. Returns ``"promoted"``,
    ``"needs_probe"`` (verdict blocked on a probe fact — invariant 5's named
    missing piece), or ``None`` (no admissible evidence / proven-absent)."""
    addr = (contract.address or "").lower()
    if not addr:
        return None
    chain_id = chain_id_for_chain_name(contract.chain)
    code_row = session.get(ContractCreationWitness, (chain_id, addr)) if chain_id is not None else None
    code_absent = code_row.code_absent_at_probe if code_row is not None else None
    if code_absent is True:
        return None
    derived, w4_blocked_on_creation = _derive_admitting_facts(
        session, contract, protocol_id, heuristic_inheritance=heuristic_inheritance
    )
    has_admitting = bool(derived) or any(
        row.rule in ADMITTING_WITNESS_RULES
        for row in active_witnesses(session, contract_id=contract.id, protocol_id=protocol_id)
    )
    if not has_admitting:
        return "needs_probe" if w4_blocked_on_creation else None
    if chain_id is None:
        return None
    if code_absent is None:
        return "needs_probe"
    assert code_row is not None and code_row.code_probe_block is not None  # paired columns (schema CHECK)
    write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=w1_evidence(chain_id=chain_id, code_probe_block=code_row.code_probe_block),
    )
    for rule, evidence, via_address in derived:
        write_witness(
            session,
            contract_id=contract.id,
            protocol_id=protocol_id,
            rule=rule,
            evidence=evidence,
            via_address=via_address,
        )
    if promote(session, contract=contract, protocol_id=protocol_id):
        return "promoted"
    return "needs_probe" if w4_blocked_on_creation else None


def _derive_admitting_facts(
    session: Session, contract: Contract, protocol_id: int, *, heuristic_inheritance: bool = False
) -> tuple[list[tuple[str, dict[str, Any], str]], bool]:
    """W2/W3/W4 facts provable from stored resolution for one candidate,
    in deterministic order. Only control/lineage edges are consulted —
    control-graph presence and dependency rows never appear here
    (invariant 6). Returns ``(facts, w4_blocked_on_creation_witness)``.

    ``heuristic_inheritance=True`` additionally reads the §6 same-contract
    exception (DEPLOYER_HEURISTIC_SPEC.md): a HEURISTIC member proxy carries
    its implementation / secondary implementations, and the derived W2 records
    the heuristic via-fact. Off by default — the proof strata never see it."""
    addr = (contract.address or "").lower()
    chain_key = _chain_key(contract.chain)
    derived: list[tuple[str, dict[str, Any], str]] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, evidence: dict[str, Any], via: str) -> None:
        key = (rule, via)
        if key not in seen:
            seen.add(key)
            derived.append((rule, evidence, via))

    member_scope = (
        Contract.protocol_id == protocol_id,
        Contract.id != contract.id,
        func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key,
    )

    # W2 — members whose stored pointers resolve to the candidate.
    pointer_members = list(
        session.execute(
            select(Contract)
            .where(
                *member_scope,
                (func.lower(Contract.implementation) == addr)
                | (func.lower(Contract.beacon) == addr)
                | (func.lower(Contract.admin) == addr)
                | _secondary_pointer_named([addr]),
            )
            .order_by(Contract.id)
        ).scalars()
    )
    for member in pointer_members:
        proven_member = member_for_evidence(session, contract_id=member.id, protocol_id=protocol_id)
        for edge_kind in ("implementation", "beacon", "proxy_admin", "secondary_implementation"):
            if not proven_member and not (heuristic_inheritance and edge_kind in W2_SAME_CONTRACT_EDGE_KINDS):
                continue
            if _w2_edge_holds(session, contract=contract, member=member, edge_kind=edge_kind, evidence={}):
                add(
                    WITNESS_RULE_W2_STRUCTURAL,
                    w2_evidence(
                        edge_kind=edge_kind,
                        member_contract_id=member.id,
                        member_address=member.address,
                        resolved_pointer=addr,
                        heuristic_via=not proven_member,
                    ),
                    (member.address or "").lower(),
                )
                break

    # W2 — the candidate is a proxy whose resolved impl/beacon is a member.
    for pointer in ((contract.implementation or "").lower(), (contract.beacon or "").lower()):
        if not pointer or not _ADDRESS_RE.match(pointer):
            continue
        for member in _member_rows_at(session, protocol_id=protocol_id, address=pointer, chain_key=chain_key):
            if member.id == contract.id:
                continue
            add(
                WITNESS_RULE_W2_STRUCTURAL,
                w2_evidence(
                    edge_kind="proxy",
                    member_contract_id=member.id,
                    member_address=member.address,
                    resolved_pointer=(member.address or "").lower(),
                ),
                (member.address or "").lower(),
            )

    # W2 — historical impl of a member proxy, per stored UpgradeEvent rows.
    seen_event_members: set[int] = set()
    for event, member in session.execute(
        select(UpgradeEvent, Contract)
        .join(Contract, UpgradeEvent.contract_id == Contract.id)
        .where(*member_scope, func.lower(UpgradeEvent.new_impl) == addr)
        .order_by(Contract.id, UpgradeEvent.block_number.asc().nulls_last(), UpgradeEvent.id)
    ):
        if member.id in seen_event_members:
            continue
        seen_event_members.add(member.id)
        if not member_for_evidence(session, contract_id=member.id, protocol_id=protocol_id):
            continue
        tx = event.tx_hash if isinstance(event.tx_hash, str) and _TX_HASH_RE.match(event.tx_hash) else None
        add(
            WITNESS_RULE_W2_STRUCTURAL,
            w2_evidence(
                edge_kind="historical_implementation",
                member_contract_id=member.id,
                member_address=member.address,
                resolved_pointer=addr,
                upgrade_tx_hash=tx.lower() if tx else None,
            ),
            (member.address or "").lower(),
        )

    # W3 D2 — the candidate is a resolved controller of a member, read from a
    # governance derivation only (:data:`W3_D2_SOURCES`).
    for member in session.execute(
        select(Contract)
        .join(ContractProbeAttempt, ContractProbeAttempt.contract_id == Contract.id)
        .where(
            *member_scope,
            ContractProbeAttempt.results.op("->")("resolved_addresses").op("?|")(cast([addr], ARRAY(Text()))),
        )
        .distinct()
        .order_by(Contract.id)
    ).scalars():
        if not member_for_evidence(session, contract_id=member.id, protocol_id=protocol_id):
            continue
        if addr in _probe_controller_values(session, member):
            add(
                WITNESS_RULE_W3_CONTROL,
                w3_evidence(direction=W3_DIRECTION_D2, source="probe", via_address=member.address),
                (member.address or "").lower(),
            )

    # W3 D2 — the candidate is a resolved controller-typed principal of a
    # member's effective functions. The hosting member must anchor (F2): a
    # principal fact hosted only on D2-only entries admits nothing.
    for member, principal_fact in _d2_principal_facts(
        session, protocol_id=protocol_id, address=addr, chain_key=chain_key, exclude_contract_id=contract.id
    ):
        add(
            WITNESS_RULE_W3_CONTROL,
            w3_evidence(
                direction=W3_DIRECTION_D2,
                source="function_principal",
                via_address=member.address,
                principal_fact=principal_fact,
            ),
            (member.address or "").lower(),
        )

    # W3 D1 — the candidate's resolved controller is a TRANSITIVE perimeter
    # entity (the gate proves transitivity here; a caller cannot assert it).
    own_controllers: list[tuple[str, str]] = []
    for (value,) in session.execute(
        select(ControllerValue.value)
        .where(
            ControllerValue.contract_id == contract.id,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
        )
        .distinct()
    ):
        if value:
            own_controllers.append(("controller_values", value.lower()))
    admin_pointer = (contract.admin or "").lower()
    if admin_pointer:
        own_controllers.append(("proxy_admin_slot", admin_pointer))
    for value in sorted(_probe_controller_values(session, contract)):
        own_controllers.append(("probe", value))
    for source, via in sorted(own_controllers):
        if not _ADDRESS_RE.match(via) or via == addr or int(via, 16) == 0:
            continue
        if ("w3_control", via) in seen:
            continue
        proof = _via_transitivity(
            session, protocol_id=protocol_id, via_address=via, chain_key=chain_key, exclude_contract_id=contract.id
        )
        if proof is not None:
            add(
                WITNESS_RULE_W3_CONTROL,
                w3_evidence(
                    direction=W3_DIRECTION_D1,
                    source=source,
                    via_address=via,
                    via_transitive=True,
                    anchor_chain=proof.anchor_chain,
                    principal_fact=proof.principal_fact,
                ),
                via,
            )

    # W4 factory — the recorded creation attribution names an anchoring member
    # factory of this protocol (owner ruling). Its via-fact is that member, so
    # the factory's demotion revokes it.
    lineage = _member_factory_lineage(session, protocol_id=protocol_id, contract=contract)
    if lineage is not None:
        add(
            WITNESS_RULE_W4_FACTORY,
            w4_factory_evidence(
                factory_address=lineage.factory,
                factory_member_contract_id=lineage.member_contract_id,
                chain_id=lineage.chain_id,
                creation_tx_hash=lineage.creation_tx_hash,
            ),
            lineage.factory,
        )

    # W4 — deployer lineage through the registry.
    w4_blocked = False
    deployer = (contract.deployer or "").lower()
    if deployer and _ADDRESS_RE.match(deployer):
        # PROOF classes only: an H row licenses ``w4h_deployer_affinity`` in
        # the last stratum and never the proof rule (§1 precedence).
        registry = _proof_registry_row(session, protocol_id=protocol_id, address=deployer)
        if registry is not None:
            chain_id = chain_id_for_chain_name(contract.chain)
            creation = session.get(ContractCreationWitness, (chain_id, addr)) if chain_id is not None else None
            if creation is not None and creation.creation_tx_hash:
                add(
                    WITNESS_RULE_W4_DEPLOYER,
                    w4_evidence(
                        deployer_address=deployer,
                        deployer_registry_id=registry.id,
                        creation_tx_hash=creation.creation_tx_hash,
                        creation_block=creation.creation_block,
                    ),
                    deployer,
                )
            else:
                w4_blocked = True
    return derived, w4_blocked


# ---------------------------------------------------------------------------
# Probe delegation (spec §3.5)
# ---------------------------------------------------------------------------


def probe(session: Session, contract: Contract) -> "ProbeResult":
    """Run the §3.5 corroboration probe for *contract* and persist its results."""
    from services.discovery.probes import run_probe

    return run_probe(session, contract)
