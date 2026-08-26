"""Membership gate core primitives (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3, §5.1).

Covers: the four derived membership states, per-rule evidence constructors,
witness write/revoke idempotency, promotion/demotion, the deployer trust
ladder (incl. the Veda DB-local-exclusivity case), deployer revocation, and
targeted candidate lookup for ``evaluate``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from db.models import (
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W4_DEPLOYER,
    Contract,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    MonitoringEnrollmentQueue,
    Protocol,
    ProtocolDeployer,
    ProtocolScoreQueue,
)
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]


def _protocol(session, name: str | None = None) -> Protocol:
    row = Protocol(name=name or f"proto-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _contract(
    session,
    address: str,
    *,
    chain: str = "ethereum",
    protocol_id: int | None = None,
    nominated_protocol_id: int | None = None,
    deployer: str | None = None,
    implementation: str | None = None,
) -> Contract:
    row = Contract(
        address=address.lower(),
        chain=chain,
        protocol_id=protocol_id,
        nominated_protocol_id=nominated_protocol_id,
        deployer=deployer,
        implementation=implementation,
    )
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------------------
# membership_state (§3.1)
# ---------------------------------------------------------------------------


def test_membership_state_four_states():
    member = Contract(address=ADDR(1), protocol_id=7)
    candidate = Contract(address=ADDR(2), nominated_protocol_id=7)
    pruned = Contract(address=ADDR(3), nominated_protocol_id=7)
    unclaimed = Contract(address=ADDR(4))
    assert gate.membership_state(member) == "member"
    assert gate.membership_state(candidate) == "candidate"
    assert gate.membership_state(pruned, code_absent_at_probe=True) == "pruned"
    assert gate.membership_state(unclaimed) == "unclaimed"


def test_membership_state_unprobed_never_prunes():
    row = Contract(address=ADDR(5), nominated_protocol_id=7)
    # None = not probed; absence of a probe is not proof of absence.
    assert gate.membership_state(row, code_absent_at_probe=None) == "candidate"
    assert gate.membership_state(row, code_absent_at_probe=False) == "candidate"


def test_resolve_membership_state_reads_code_probe(db_session):
    from db.models import ContractCreationWitness

    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(10), nominated_protocol_id=protocol.id)
    assert gate.resolve_membership_state(db_session, row) == "candidate"
    db_session.add(
        ContractCreationWitness(chain_id=1, address=row.address, code_probe_block=100, code_absent_at_probe=True)
    )
    db_session.flush()
    assert gate.resolve_membership_state(db_session, row) == "pruned"


# ---------------------------------------------------------------------------
# Evidence constructors (invariant 2)
# ---------------------------------------------------------------------------


def test_w1_evidence_shape():
    ev = gate.w1_evidence(chain_id=1, code_probe_block=123)
    assert ev == {"chain_id": 1, "code_probe_block": 123, "code_present": True}
    with pytest.raises(ValueError):
        gate.w1_evidence(chain_id=0, code_probe_block=123)
    with pytest.raises(ValueError):
        gate.w1_evidence(chain_id=1, code_probe_block=-1)


def test_w2_evidence_requires_verified_edge_facts():
    ev = gate.w2_evidence(
        edge_kind="implementation",
        member_contract_id=4,
        member_address=ADDR(1),
        resolved_pointer=ADDR(2),
    )
    assert ev["edge_kind"] == "implementation"
    assert ev["resolved_pointer"] == ADDR(2)
    with pytest.raises(ValueError):
        gate.w2_evidence(edge_kind="library", member_contract_id=4, member_address=ADDR(1), resolved_pointer=ADDR(2))
    with pytest.raises(ValueError):
        gate.w2_evidence(
            edge_kind="proxy", member_contract_id=4, member_address="not-an-address", resolved_pointer=ADDR(2)
        )


def test_w3_evidence_d1_requires_transitive_proof():
    ev = gate.w3_evidence(direction="d1", source="controller_values", via_address=ADDR(3), via_transitive=True)
    assert ev["via_transitive"] is True
    with pytest.raises(ValueError):
        gate.w3_evidence(direction="d1", source="controller_values", via_address=ADDR(3))
    with pytest.raises(ValueError):
        gate.w3_evidence(direction="d1", source="controller_values", via_address=ADDR(3), via_transitive=False)


def test_w3_evidence_d2_entry_is_non_transitive_by_construction():
    ev = gate.w3_evidence(direction="d2", source="probe", via_address=ADDR(3))
    assert ev["perimeter_entry_transitive"] is False
    # The caller may not assert transitivity on a d2 edge.
    with pytest.raises(ValueError):
        gate.w3_evidence(direction="d2", source="probe", via_address=ADDR(3), via_transitive=True)
    with pytest.raises(ValueError):
        gate.w3_evidence(direction="d2", source="control_graph", via_address=ADDR(3))


def test_w4_w5_w6_evidence_shapes():
    tx = "0x" + "ab" * 32
    ev4 = gate.w4_evidence(deployer_address=ADDR(4), deployer_registry_id=9, creation_tx_hash=tx, creation_block=5)
    assert ev4["creation_tx_hash"] == tx
    with pytest.raises(ValueError):
        gate.w4_evidence(deployer_address=ADDR(4), deployer_registry_id=9, creation_tx_hash="0x123", creation_block=5)
    ev5 = gate.w5_evidence(actor="admin@psat", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc))
    assert ev5["actor"] == "admin@psat"
    with pytest.raises(ValueError):
        gate.w5_evidence(actor="  ", asserted_at=datetime.now(timezone.utc))
    ev6 = gate.w6_evidence(adapter_slug="ether.fi-stake", chain_id=1, code_probe_block=7)
    assert ev6["code_probe_block"] == 7
    # W6 requires W1: no constructible llama-seed evidence without a code probe.
    with pytest.raises(TypeError):
        kwargs: dict = {"adapter_slug": "ether.fi-stake", "chain_id": 1}
        gate.w6_evidence(**kwargs)
    with pytest.raises(ValueError):
        gate.w6_evidence(adapter_slug=" ", chain_id=1, code_probe_block=7)


# ---------------------------------------------------------------------------
# Nomination
# ---------------------------------------------------------------------------


def test_nominate_sets_nominated_never_protocol_id(db_session):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(20))
    gate.nominate(db_session, contract=row, protocol_id=protocol.id, source_tag="defillama")
    assert row.protocol_id is None
    assert row.nominated_protocol_id == protocol.id
    assert "defillama" in (row.discovery_sources or [])


def test_nominate_member_keeps_own_protocol_in_empty_slot(db_session):
    # A foreign nomination may never claim a member's NULL nominated slot —
    # that slot is the member's own demotion provenance (invariant 4).
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    row = _contract(db_session, ADDR(22), protocol_id=p1.id)
    gate.nominate(db_session, contract=row, protocol_id=p2.id, source_tag="defillama")
    assert row.protocol_id == p1.id
    assert row.nominated_protocol_id == p1.id
    assert "defillama" in (row.discovery_sources or [])


def test_nominate_first_nominator_wins(db_session):
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    row = _contract(db_session, ADDR(21))
    gate.nominate(db_session, contract=row, protocol_id=p1.id, source_tag="defillama")
    gate.nominate(db_session, contract=row, protocol_id=p2.id, source_tag="exa_deep_research")
    assert row.nominated_protocol_id == p1.id
    assert "exa_deep_research" in (row.discovery_sources or [])


# ---------------------------------------------------------------------------
# Witness primitives
# ---------------------------------------------------------------------------


def test_write_witness_idempotent(db_session):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(30), nominated_protocol_id=protocol.id)
    ev = gate.w1_evidence(chain_id=1, code_probe_block=10)
    w1 = gate.write_witness(
        db_session, contract_id=row.id, protocol_id=protocol.id, rule=WITNESS_RULE_W1_CODE, evidence=ev
    )
    w2 = gate.write_witness(
        db_session, contract_id=row.id, protocol_id=protocol.id, rule=WITNESS_RULE_W1_CODE, evidence=ev
    )
    assert w1.id == w2.id
    count = db_session.query(ContractMembershipWitness).filter(ContractMembershipWitness.contract_id == row.id).count()
    assert count == 1


def test_write_witness_rejects_unknown_rule_and_empty_evidence(db_session):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(31), nominated_protocol_id=protocol.id)
    with pytest.raises(ValueError):
        gate.write_witness(db_session, contract_id=row.id, protocol_id=protocol.id, rule="w9_vibes", evidence={"x": 1})
    with pytest.raises(ValueError):
        gate.write_witness(
            db_session, contract_id=row.id, protocol_id=protocol.id, rule=WITNESS_RULE_W1_CODE, evidence={}
        )


def test_write_witness_refuses_hand_rolled_evidence(db_session):
    # Invariant 2: only constructor-shaped evidence is admissible per rule.
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(34), nominated_protocol_id=protocol.id)
    good = gate.w1_evidence(chain_id=1, code_probe_block=5)
    for bad in (
        {"code_present": True},  # missing the block-stamp + chain
        {**good, "note": "extra"},  # extra field
        {**good, "code_present": False},  # non-canonical value
        gate.w2_evidence(
            edge_kind="implementation", member_contract_id=1, member_address=ADDR(1), resolved_pointer=ADDR(2)
        ),  # wrong rule's shape
    ):
        with pytest.raises(ValueError):
            gate.write_witness(
                db_session, contract_id=row.id, protocol_id=protocol.id, rule=WITNESS_RULE_W1_CODE, evidence=bad
            )
    assert db_session.query(ContractMembershipWitness).filter_by(contract_id=row.id).count() == 0


def test_revoke_preserves_row_and_reobservation_rearms(db_session):
    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(32), protocol_id=protocol.id)
    ev = gate.w2_evidence(
        edge_kind="implementation",
        member_contract_id=member.id,
        member_address=member.address,
        resolved_pointer=ADDR(33),
    )
    witness = gate.write_witness(
        db_session,
        contract_id=member.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=ev,
        via_address=ADDR(33),
    )
    assert gate.revoke_witness(db_session, witness, reason="edge_no_longer_holds") is True
    assert witness.revoked_at is not None
    assert gate.revoke_witness(db_session, witness, reason="again") is False
    # Re-observation of the same fact re-arms the SAME row.
    rearmed = gate.write_witness(
        db_session,
        contract_id=member.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=ev,
        via_address=ADDR(33),
    )
    assert rearmed.id == witness.id
    assert rearmed.revoked_at is None


# ---------------------------------------------------------------------------
# Promotion / demotion
# ---------------------------------------------------------------------------


def _dirty_protocols(db_session) -> tuple[set[int], set[int]]:
    enrollment = {r.protocol_id for r in db_session.query(MonitoringEnrollmentQueue).all()}
    scoring = {r.protocol_id for r in db_session.query(ProtocolScoreQueue).all()}
    return enrollment, scoring


def test_promote_requires_w1_precondition(db_session):
    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(40), protocol_id=protocol.id)
    row = _contract(db_session, ADDR(41), nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=member.id,
            member_address=member.address,
            resolved_pointer=row.address,
        ),
        via_address=member.address,
    )
    assert gate.promote(db_session, contract=row, protocol_id=protocol.id) is False
    assert row.protocol_id is None


def test_promote_requires_admitting_witness(db_session):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(42), nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=5),
    )
    # W1 alone admits nothing.
    assert gate.promote(db_session, contract=row, protocol_id=protocol.id) is False
    assert row.protocol_id is None


def test_promote_with_w1_and_admitting_marks_dirty(db_session):
    protocol = _protocol(db_session)
    # The member's STORED pointer must actually resolve to the candidate:
    # promote re-verifies the W2 edge, never trusting the witness row alone.
    member = _contract(db_session, ADDR(43), protocol_id=protocol.id, implementation=ADDR(44))
    row = _contract(db_session, ADDR(44), nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=5),
    )
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=member.id,
            member_address=member.address,
            resolved_pointer=row.address,
        ),
        via_address=member.address,
    )
    assert gate.promote(db_session, contract=row, protocol_id=protocol.id) is True
    assert row.protocol_id == protocol.id
    enrollment, scoring = _dirty_protocols(db_session)
    assert protocol.id in enrollment
    assert protocol.id in scoring


def test_promote_requires_w1_on_contracts_own_chain(db_session):
    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(47), protocol_id=protocol.id)

    def _admit(row: Contract) -> None:
        gate.write_witness(
            db_session,
            contract_id=row.id,
            protocol_id=protocol.id,
            rule=WITNESS_RULE_W2_STRUCTURAL,
            evidence=gate.w2_evidence(
                edge_kind="implementation",
                member_contract_id=member.id,
                member_address=member.address,
                resolved_pointer=row.address,
            ),
            via_address=member.address,
        )

    # W1 probed on a DIFFERENT chain than the contract's own row proves nothing.
    wrong_chain = _contract(db_session, ADDR(48), nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=wrong_chain.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=8453, code_probe_block=5),
    )
    _admit(wrong_chain)
    assert gate.promote(db_session, contract=wrong_chain, protocol_id=protocol.id) is False
    assert wrong_chain.protocol_id is None

    # A row whose chain never resolves can never satisfy W1.
    no_chain = _contract(db_session, ADDR(49), chain="unknown", nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=no_chain.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=5),
    )
    _admit(no_chain)
    assert gate.promote(db_session, contract=no_chain, protocol_id=protocol.id) is False


def test_promote_never_overwrites_other_membership(db_session):
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    row = _contract(db_session, ADDR(45), protocol_id=p1.id)
    assert gate.promote(db_session, contract=row, protocol_id=p2.id) is False
    assert row.protocol_id == p1.id


def test_demote_member_preserves_nomination_and_history(db_session):
    protocol = _protocol(db_session)
    # Legacy member shape: protocol_id set, nomination never recorded.
    row = _contract(db_session, ADDR(46), protocol_id=protocol.id)
    witness = gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=5),
    )
    gate.revoke_witness(db_session, witness, reason="reprobe_found_no_code")
    gate.demote_member(db_session, contract=row, reason="no_admitting_witness")
    assert row.protocol_id is None
    # Invariant 4: the nomination survives demotion, never destroyed.
    assert row.nominated_protocol_id == protocol.id
    survivors = db_session.query(ContractMembershipWitness).filter_by(contract_id=row.id).all()
    assert len(survivors) == 1 and survivors[0].revoked_at is not None
    enrollment, scoring = _dirty_protocols(db_session)
    assert protocol.id in enrollment
    assert protocol.id in scoring


# ---------------------------------------------------------------------------
# Deployer trust ladder (§3.3)
# ---------------------------------------------------------------------------


def _seed_w5_witness(db_session, member: Contract, protocol_id: int) -> None:
    # F2: only a member holding a non-D2 admitting witness anchors the ladder.
    gate.write_witness(
        db_session,
        contract_id=member.id,
        protocol_id=protocol_id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc)),
    )


def test_classify_deployer_class_a_perimeter_principal(db_session):
    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(50), protocol_id=protocol.id)
    _seed_w5_witness(db_session, member, protocol.id)
    eoa = ADDR(51)
    db_session.add(
        ControllerValue(contract_id=member.id, controller_id="owner", value=eoa, authority_provenance="caller_gate")
    )
    db_session.flush()
    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa)
    assert verdict.trust_class == "A"
    assert verdict.evidence["perimeter_fact"]["kind"] == "controller_value"


def test_classify_deployer_class_a_safe_signer(db_session):
    from db.models import EffectiveFunction, FunctionPrincipal

    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(52), protocol_id=protocol.id)
    _seed_w5_witness(db_session, member, protocol.id)
    eoa = ADDR(53)
    fn = EffectiveFunction(contract_id=member.id, function_name="upgradeTo")
    db_session.add(fn)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=fn.id,
            address=ADDR(54),
            resolved_type="safe",
            details={"owners": [eoa]},
        )
    )
    db_session.flush()
    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa)
    assert verdict.trust_class == "A"
    assert verdict.evidence["perimeter_fact"]["kind"] == "safe_owner"
    assert verdict.evidence["perimeter_fact"]["safe_address"] == ADDR(54)
    # A signer of a NON-member's Safe earns nothing.
    other = gate.classify_deployer(db_session, protocol_id=_protocol(db_session).id, address=eoa)
    assert other.trust_class is None


def _seed_class_b_members(db_session, protocol, eoa: str) -> list[Contract]:
    members = []
    for n in (60, 61):
        anchor = _contract(db_session, ADDR(n + 100), protocol_id=protocol.id)
        member = _contract(db_session, ADDR(n), protocol_id=protocol.id, deployer=eoa)
        gate.write_witness(
            db_session,
            contract_id=member.id,
            protocol_id=protocol.id,
            rule=WITNESS_RULE_W2_STRUCTURAL,
            evidence=gate.w2_evidence(
                edge_kind="implementation",
                member_contract_id=anchor.id,
                member_address=anchor.address,
                resolved_pointer=member.address,
            ),
            via_address=anchor.address,
        )
        members.append(member)
    return members


def test_classify_deployer_class_b_needs_positive_exclusivity(db_session):
    protocol = _protocol(db_session)
    eoa = ADDR(62)
    members = _seed_class_b_members(db_session, protocol, eoa)
    history = [m.address for m in members]
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=True
    )
    assert verdict.trust_class == "B"
    assert set(verdict.evidence["corroborating_member_ids"]) == {m.id for m in members}
    assert verdict.evidence["enumeration"]["complete"] is True


def test_classify_deployer_db_local_exclusivity_is_not_proof(db_session):
    # The Veda shape: every LOCAL row maps to this protocol, but no complete
    # enumeration exists — absence of counterevidence, not proof. Class C.
    protocol = _protocol(db_session)
    eoa = ADDR(63)
    _seed_class_b_members(db_session, protocol, eoa)
    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa)
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "no_complete_enumeration"
    # An enumeration that exceeded the cap is the same verdict.
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=[], history_complete=False
    )
    assert verdict.trust_class is None


def test_classify_deployer_foreign_creation_is_class_c(db_session):
    protocol = _protocol(db_session)
    eoa = ADDR(64)
    members = _seed_class_b_members(db_session, protocol, eoa)
    history = [m.address for m in members] + [ADDR(65)]  # one creation nobody maps
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=True
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "foreign_or_unknown_creations"
    assert ADDR(65) in verdict.evidence["unmapped_addresses"]


def _seed_code_and_creation(db_session, address: str, *, chain_id: int = 1) -> None:
    from db.models import ContractCreationWitness

    db_session.add(
        ContractCreationWitness(
            chain_id=chain_id,
            address=address.lower(),
            code_probe_block=100,
            code_absent_at_probe=False,
            creation_tx_hash="0x" + "77" * 32,
            creation_block=90,
        )
    )
    db_session.flush()


def _seed_w2_witness(db_session, contract: Contract, anchor: Contract, protocol_id: int) -> None:
    anchor.implementation = contract.address
    db_session.flush()
    gate.write_witness(
        db_session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=anchor.id,
            member_address=anchor.address,
            resolved_pointer=contract.address,
        ),
        via_address=anchor.address,
    )


def test_classify_deployer_nominated_creation_never_maps(db_session):
    """F1: a bare nomination is not membership evidence — a shared deployer's
    foreign creation that is merely nominated must NOT map into the Class-B
    exclusivity set, and the foreign creation must never ride in on W4."""
    protocol = _protocol(db_session)
    eoa = ADDR(0x510)
    members = _seed_class_b_members(db_session, protocol, eoa)
    foreign = _contract(db_session, ADDR(0x511), nominated_protocol_id=protocol.id, deployer=eoa)
    _seed_code_and_creation(db_session, foreign.address)
    history = [m.address for m in members] + [foreign.address]

    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=True
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "foreign_or_unknown_creations"
    assert foreign.address in verdict.evidence["unmapped_addresses"]

    gate.evaluate(
        db_session,
        gate.FactsDelta(recheck_contract_ids=(foreign.id,)),
        deployer_enumerator=lambda addr: (history, True),
    )
    # No proof-class row exists, so the row can hold no W4 witness. What it may
    # hold is the labeled heuristic one (DEPLOYER_HEURISTIC_SPEC.md §1) — the
    # distinction the rule string exists to keep.
    rules = {w.rule for w in gate.active_witnesses(db_session, contract_id=foreign.id, protocol_id=protocol.id)}
    assert WITNESS_RULE_W4_DEPLOYER not in rules
    assert rules <= {"w1_code", "w4h_deployer_affinity"}

    # The same creation holding a real W2 witness maps in — Class B allowed.
    anchor = _contract(db_session, ADDR(0x512), protocol_id=protocol.id)
    _seed_w2_witness(db_session, foreign, anchor, protocol.id)
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=True
    )
    assert verdict.trust_class == "B"


def test_classify_deployer_member_factory_child_maps(db_session):
    """Member-factory mapping rule (deliberate §3.3 deviation): a creation
    minted by this protocol's own anchoring MEMBER factory counts as mapped in
    the exclusivity test — mapping only, no admission and no witness."""
    protocol = _protocol(db_session)
    eoa = ADDR(0x550)
    members = _seed_class_b_members(db_session, protocol, eoa)
    factory = _contract(db_session, ADDR(0x551), protocol_id=protocol.id)
    anchor = _contract(db_session, ADDR(0x552), protocol_id=protocol.id)
    _seed_w2_witness(db_session, factory, anchor, protocol.id)
    child = ADDR(0x553)  # no contracts row at all
    history = [m.address for m in members] + [child]

    verdict = gate.classify_deployer(
        db_session,
        protocol_id=protocol.id,
        address=eoa,
        creation_history=history,
        history_complete=True,
        creation_factories={child: factory.address},
    )
    assert verdict.trust_class == "B"
    assert verdict.evidence["member_factory_mapped"] == {"count": 1, "factories": [factory.address]}


def test_classify_deployer_non_member_factory_child_does_not_map(db_session):
    protocol = _protocol(db_session)
    eoa = ADDR(0x558)
    members = _seed_class_b_members(db_session, protocol, eoa)
    child = ADDR(0x559)
    history = [m.address for m in members] + [child]

    # The factory has no contracts row at all — foreign machinery.
    verdict = gate.classify_deployer(
        db_session,
        protocol_id=protocol.id,
        address=eoa,
        creation_history=history,
        history_complete=True,
        creation_factories={child: ADDR(0x55A)},
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "foreign_or_unknown_creations"
    assert child in verdict.evidence["unmapped_addresses"]


def test_classify_deployer_foreign_protocol_member_factory_does_not_map(db_session):
    # A factory that is a MEMBER — of another protocol. Its children are that
    # protocol's family, never this one's.
    protocol = _protocol(db_session)
    other = _protocol(db_session)
    eoa = ADDR(0x560)
    members = _seed_class_b_members(db_session, protocol, eoa)
    factory = _contract(db_session, ADDR(0x561), protocol_id=other.id)
    factory_anchor = _contract(db_session, ADDR(0x562), protocol_id=other.id)
    _seed_w2_witness(db_session, factory, factory_anchor, other.id)
    child = ADDR(0x563)
    history = [m.address for m in members] + [child]

    verdict = gate.classify_deployer(
        db_session,
        protocol_id=protocol.id,
        address=eoa,
        creation_history=history,
        history_complete=True,
        creation_factories={child: factory.address},
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "foreign_or_unknown_creations"


def test_classify_deployer_d2_only_member_factory_does_not_map(db_session):
    # F2 carried into the factory rule: a D2-only member factory is
    # non-transitive and must not convert its children into mapped creations.
    protocol = _protocol(db_session)
    eoa = ADDR(0x568)
    members = _seed_class_b_members(db_session, protocol, eoa)
    factory = _contract(db_session, ADDR(0x569), protocol_id=protocol.id)
    _seed_d2_witness(db_session, factory, protocol.id, ADDR(0x56A))
    child = ADDR(0x56B)
    history = [m.address for m in members] + [child]

    verdict = gate.classify_deployer(
        db_session,
        protocol_id=protocol.id,
        address=eoa,
        creation_history=history,
        history_complete=True,
        creation_factories={child: factory.address},
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "foreign_or_unknown_creations"


def test_exclusivity_tolerates_member_factory_children(db_session):
    """Operator-exclusivity arm of the member-factory rule: a controlled row
    whose STORED creation attribution names this protocol's anchoring member
    factory is a protocol-family observation. NULL attribution stays a
    refusal — not-determined licenses nothing."""
    from db.models import ContractCreationWitness
    from services.discovery.membership_gate import _controller_is_exclusive

    protocol = _protocol(db_session)
    operator = ADDR(0x570)
    member = _contract(db_session, ADDR(0x571), protocol_id=protocol.id)
    member_anchor = _contract(db_session, ADDR(0x572), protocol_id=protocol.id)
    _seed_w2_witness(db_session, member, member_anchor, protocol.id)
    controlled = _contract(db_session, ADDR(0x573))
    for row in (member, controlled):
        db_session.add(
            ControllerValue(
                contract_id=row.id, controller_id="owner", value=operator, authority_provenance="caller_gate"
            )
        )
    db_session.flush()

    # No creation attribution recorded → the observation stays foreign.
    assert not _controller_is_exclusive(
        db_session, protocol_id=protocol.id, controller_address=operator, exclude_contract_ids=set()
    )

    factory = _contract(db_session, ADDR(0x574), protocol_id=protocol.id)
    factory_anchor = _contract(db_session, ADDR(0x575), protocol_id=protocol.id)
    _seed_w2_witness(db_session, factory, factory_anchor, protocol.id)
    db_session.add(
        ContractCreationWitness(
            chain_id=1,
            address=controlled.address,
            creation_tx_hash="0x" + "78" * 32,
            creation_block=90,
            creation_factory=factory.address,
        )
    )
    db_session.flush()
    assert _controller_is_exclusive(
        db_session, protocol_id=protocol.id, controller_address=operator, exclude_contract_ids=set()
    )


def test_nominate_enumerated_creations_writes_candidates_only(db_session):
    """2b producer: unknown creations become nominated candidates with the
    ``deployer_enumeration`` source tag — never members, never witnesses; an
    existing row at the same (address, chain) is left untouched."""
    from services.discovery.deployer_enumeration import DeployerCreation

    protocol = _protocol(db_session)
    eoa = ADDR(0x580)
    existing = _contract(db_session, ADDR(0x581), nominated_protocol_id=protocol.id, deployer=eoa)
    new_ids = gate.nominate_enumerated_creations(
        db_session,
        protocol_id=protocol.id,
        deployer=eoa,
        creations=[
            DeployerCreation(address=existing.address, chain_id=1),
            DeployerCreation(address=ADDR(0x582), chain_id=1, factory=ADDR(0x583)),
        ],
    )
    assert len(new_ids) == 1
    row = db_session.get(Contract, new_ids[0])
    assert row.address == ADDR(0x582)
    assert row.chain == "ethereum"
    assert row.deployer == eoa
    assert row.protocol_id is None
    assert row.nominated_protocol_id == protocol.id
    assert row.discovery_sources == ["deployer_enumeration"]
    assert gate.active_witnesses(db_session, contract_id=row.id, protocol_id=protocol.id) == []

    # The nominated-but-unevidenced row still refuses Class B (F1 pin).
    members = _seed_class_b_members(db_session, protocol, eoa)
    history = [m.address for m in members] + [row.address]
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=True
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "foreign_or_unknown_creations"


def test_exclusivity_tolerates_only_evidenced_candidates(db_session):
    """F1, operator-exclusivity path: a controlled row that is merely
    nominated refuses exclusivity; the same row with a non-lineage witness
    tolerates it."""
    from services.discovery.membership_gate import _controller_is_exclusive

    protocol = _protocol(db_session)
    operator = ADDR(0x520)
    member = _contract(db_session, ADDR(0x521), protocol_id=protocol.id)
    controlled = _contract(db_session, ADDR(0x522), nominated_protocol_id=protocol.id)
    for row in (member, controlled):
        db_session.add(
            ControllerValue(
                contract_id=row.id, controller_id="owner", value=operator, authority_provenance="caller_gate"
            )
        )
    db_session.flush()

    assert not _controller_is_exclusive(
        db_session, protocol_id=protocol.id, controller_address=operator, exclude_contract_ids=set()
    )

    anchor = _contract(db_session, ADDR(0x523), protocol_id=protocol.id)
    _seed_w2_witness(db_session, controlled, anchor, protocol.id)
    assert _controller_is_exclusive(
        db_session, protocol_id=protocol.id, controller_address=operator, exclude_contract_ids=set()
    )


def _seed_d2_witness(db_session, member: Contract, protocol_id: int, via: str) -> None:
    gate.write_witness(
        db_session,
        contract_id=member.id,
        protocol_id=protocol_id,
        rule="w3_control",
        evidence=gate.w3_evidence(direction="d2", source="probe", via_address=via),
        via_address=via,
    )


def test_classify_deployer_d2_only_member_never_anchors_class_a(db_session):
    """F2: D2 entries are non-transitive — a principal observed on a D2-only
    member (the EndpointV2 worst case) must not mint a Class-A anchor."""
    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(0x530), protocol_id=protocol.id)
    _seed_d2_witness(db_session, member, protocol.id, ADDR(0x531))
    eoa = ADDR(0x532)
    db_session.add(
        ControllerValue(contract_id=member.id, controller_id="owner", value=eoa, authority_provenance="caller_gate")
    )
    db_session.flush()

    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa)
    assert verdict.trust_class != "A"

    # With an independent non-D2 witness the same member anchors Class A.
    anchor = _contract(db_session, ADDR(0x533), protocol_id=protocol.id)
    _seed_w2_witness(db_session, member, anchor, protocol.id)
    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa)
    assert verdict.trust_class == "A"


def test_d2_only_member_does_not_corroborate_class_b(db_session):
    from services.discovery.membership_gate import _nonlineage_corroborating_member_ids

    protocol = _protocol(db_session)
    eoa = ADDR(0x540)
    m1 = _contract(db_session, ADDR(0x541), protocol_id=protocol.id, deployer=eoa)
    m2 = _contract(db_session, ADDR(0x542), protocol_id=protocol.id, deployer=eoa)
    for m in (m1, m2):
        _seed_d2_witness(db_session, m, protocol.id, ADDR(0x543))
    assert _nonlineage_corroborating_member_ids(db_session, protocol_id=protocol.id, address=eoa) == []

    anchor = _contract(db_session, ADDR(0x544), protocol_id=protocol.id)
    _seed_w2_witness(db_session, m1, anchor, protocol.id)
    assert _nonlineage_corroborating_member_ids(db_session, protocol_id=protocol.id, address=eoa) == [m1.id]


def test_classify_deployer_lineage_only_corroboration_is_class_c(db_session):
    protocol = _protocol(db_session)
    eoa = ADDR(66)
    registry = ProtocolDeployer(
        protocol_id=protocol.id, address=ADDR(67), trust_class="A", evidence={"perimeter_fact": {}}
    )
    db_session.add(registry)
    db_session.flush()
    members = []
    for n in (68, 69):
        member = _contract(db_session, ADDR(n), protocol_id=protocol.id, deployer=eoa)
        gate.write_witness(
            db_session,
            contract_id=member.id,
            protocol_id=protocol.id,
            rule=WITNESS_RULE_W4_DEPLOYER,
            evidence=gate.w4_evidence(
                deployer_address=ADDR(67),
                deployer_registry_id=registry.id,
                creation_tx_hash="0x" + "cd" * 32,
                creation_block=1,
            ),
            via_address=ADDR(67),
        )
        members.append(member)
    verdict = gate.classify_deployer(
        db_session,
        protocol_id=protocol.id,
        address=eoa,
        creation_history=[m.address for m in members],
        history_complete=True,
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "insufficient_nonlineage_corroboration"


def test_classify_deployer_cross_protocol_collision_is_class_c(db_session):
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    eoa = ADDR(70)
    db_session.add(ProtocolDeployer(protocol_id=p2.id, address=eoa, trust_class="A", evidence={"x": 1}))
    db_session.flush()
    verdict = gate.classify_deployer(db_session, protocol_id=p1.id, address=eoa)
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "cross_protocol_collision"
    # A foreign MEMBER deployed by the EOA is the same collision.
    _contract(db_session, ADDR(72), protocol_id=p2.id, deployer=ADDR(73))
    verdict3 = gate.classify_deployer(db_session, protocol_id=p1.id, address=ADDR(73))
    assert verdict3.trust_class is None
    assert verdict3.evidence["reason"] == "cross_protocol_collision"


def test_register_deployer_writes_row_and_rejects_class_c(db_session):
    protocol = _protocol(db_session)
    eoa = ADDR(74)
    classification = gate.DeployerClassification(trust_class="A", evidence={"perimeter_fact": {"kind": "x"}})
    row = gate.register_deployer(db_session, protocol_id=protocol.id, address=eoa, classification=classification)
    assert row.trust_class == "A" and row.revoked_at is None
    with pytest.raises(ValueError):
        gate.register_deployer(
            db_session,
            protocol_id=protocol.id,
            address=ADDR(75),
            classification=gate.DeployerClassification(trust_class=None, evidence={"reason": "x"}),
        )


def test_demote_deployer_single_level(db_session):
    protocol = _protocol(db_session)
    eoa = ADDR(80)
    registry = ProtocolDeployer(protocol_id=protocol.id, address=eoa, trust_class="B", evidence={"x": 1})
    db_session.add(registry)
    db_session.flush()
    # Stored pointer backs the survivor's W2 edge — the cascade's survival
    # check re-verifies the edge, not mere witness presence.
    anchor = _contract(db_session, ADDR(81), protocol_id=protocol.id, implementation=ADDR(83))

    def _w4(member: Contract) -> None:
        gate.write_witness(
            db_session,
            contract_id=member.id,
            protocol_id=protocol.id,
            rule=WITNESS_RULE_W4_DEPLOYER,
            evidence=gate.w4_evidence(
                deployer_address=eoa,
                deployer_registry_id=registry.id,
                creation_tx_hash="0x" + "ef" * 32,
                creation_block=2,
            ),
            via_address=eoa,
        )

    lineage_only = _contract(db_session, ADDR(82), protocol_id=protocol.id, deployer=eoa)
    _w4(lineage_only)
    independent = _contract(db_session, ADDR(83), protocol_id=protocol.id, deployer=eoa)
    _w4(independent)
    gate.write_witness(
        db_session,
        contract_id=independent.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=anchor.id,
            member_address=anchor.address,
            resolved_pointer=independent.address,
        ),
        via_address=anchor.address,
    )

    result = gate.demote(db_session, deployer_row=registry, reason="foreign_creation_observed")

    assert registry.revoked_at is not None
    assert registry.revocation_reason == "foreign_creation_observed"
    assert len(result.revoked_witness_ids) == 2
    # Only the member with no other admitting witness is demoted (invariant 8).
    assert result.demoted_contract_ids == (lineage_only.id,)
    assert result.reprobe_contract_ids == (lineage_only.id,)
    assert lineage_only.protocol_id is None
    assert lineage_only.nominated_protocol_id == protocol.id
    assert independent.protocol_id == protocol.id
    # Witness history preserved, revoked not deleted.
    rows = db_session.query(ContractMembershipWitness).filter_by(contract_id=lineage_only.id).all()
    assert len(rows) == 1 and rows[0].revoked_at is not None


# ---------------------------------------------------------------------------
# evaluate targeting (§3.4 event 2)
# ---------------------------------------------------------------------------


def test_evaluate_targets_only_reachable_candidates(db_session):
    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(90), protocol_id=protocol.id, implementation=ADDR(93))
    by_edge = _contract(db_session, ADDR(91), nominated_protocol_id=protocol.id)
    by_deployer = _contract(db_session, ADDR(92), nominated_protocol_id=protocol.id, deployer=ADDR(99))
    by_pointer = _contract(db_session, ADDR(93), nominated_protocol_id=protocol.id)
    by_probe = _contract(db_session, ADDR(94), nominated_protocol_id=protocol.id)
    db_session.add(
        ContractProbeAttempt(
            contract_id=by_probe.id,
            chain_id=1,
            block_number=100,
            results={"status": "probed", "resolved_addresses": [member.address]},
        )
    )
    unreachable = _contract(db_session, ADDR(95), nominated_protocol_id=protocol.id)
    unclaimed = _contract(db_session, ADDR(91), chain="base")  # candidate-shaped address, no nomination
    member_at_edge = _contract(db_session, ADDR(96), protocol_id=protocol.id)
    db_session.flush()

    delta = gate.FactsDelta(
        new_member_contract_ids=(member.id,),
        new_edge_addresses=(by_edge.address, member_at_edge.address),
        changed_deployer_addresses=(ADDR(99),),
    )
    result = gate.evaluate(db_session, delta)

    targeted = set(result.targeted_contract_ids)
    assert {by_edge.id, by_deployer.id, by_pointer.id, by_probe.id} <= targeted
    assert unreachable.id not in targeted
    assert unclaimed.id not in targeted
    assert member_at_edge.id not in targeted  # already a member; not a candidate
    # No candidate here carries a code probe, so nothing may promote
    # (invariant 3); the W2-reachable candidate parks on a NAMED missing
    # piece — its W1 probe (invariant 5).
    assert result.promoted_contract_ids == ()
    assert result.demoted_contract_ids == ()
    assert by_pointer.id in result.reprobe_contract_ids
