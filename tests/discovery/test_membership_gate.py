"""Membership gate core primitives.

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
# membership_state
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Evidence constructors
# ---------------------------------------------------------------------------


def test_w1_evidence_shape():
    ev = gate.w1_evidence(chain_id=1, code_probe_block=123)
    assert ev == {"chain_id": 1, "code_probe_block": 123, "code_present": True}
    with pytest.raises(ValueError):
        gate.w1_evidence(chain_id=0, code_probe_block=123)
    with pytest.raises(ValueError):
        gate.w1_evidence(chain_id=1, code_probe_block=-1)


def test_w3_evidence_d2_entry_is_non_transitive_by_construction():
    ev = gate.w3_evidence(direction="d2", source="probe", via_address=ADDR(3))
    assert ev["perimeter_entry_transitive"] is False
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
    with pytest.raises(TypeError):
        kwargs: dict = {"adapter_slug": "ether.fi-stake", "chain_id": 1}
        gate.w6_evidence(**kwargs)
    with pytest.raises(ValueError):
        gate.w6_evidence(adapter_slug=" ", chain_id=1, code_probe_block=7)


def test_write_witness_refuses_hand_rolled_evidence(db_session):
    # only constructor-shaped evidence is admissible per rule.
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


def _dirty_protocols(db_session) -> tuple[set[int], set[int]]:
    enrollment = {r.protocol_id for r in db_session.query(MonitoringEnrollmentQueue).all()}
    scoring = {r.protocol_id for r in db_session.query(ProtocolScoreQueue).all()}
    return enrollment, scoring


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
    assert gate.promote(db_session, contract=row, protocol_id=protocol.id) is False
    assert row.protocol_id is None


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
    # the nomination survives demotion, never destroyed.
    assert row.nominated_protocol_id == protocol.id
    survivors = db_session.query(ContractMembershipWitness).filter_by(contract_id=row.id).all()
    assert len(survivors) == 1 and survivors[0].revoked_at is not None
    enrollment, scoring = _dirty_protocols(db_session)
    assert protocol.id in enrollment
    assert protocol.id in scoring


# ---------------------------------------------------------------------------
# Deployer trust ladder
# ---------------------------------------------------------------------------


def _seed_w5_witness(db_session, member: Contract, protocol_id: int) -> None:
    # only a member holding a non-D2 admitting witness anchors the ladder.
    gate.write_witness(
        db_session,
        contract_id=member.id,
        protocol_id=protocol_id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc)),
    )


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
    other = gate.classify_deployer(db_session, protocol_id=_protocol(db_session).id, address=eoa)
    assert other.trust_class is None


def test_classify_deployer_principal_fact_requires_authority_derivation(db_session):
    from db.models import EffectiveFunction, FunctionPrincipal

    protocol = _protocol(db_session)
    member = _contract(db_session, ADDR(55), protocol_id=protocol.id)
    _seed_w5_witness(db_session, member, protocol.id)
    eoa = ADDR(56)
    fn = EffectiveFunction(contract_id=member.id, function_name="safeTransferFrom")
    db_session.add(fn)
    db_session.flush()
    principal = FunctionPrincipal(
        function_id=fn.id,
        address=eoa,
        resolved_type="eoa",
        details={"resolver_path": ["param_keyed_mapping_enumeration"]},
    )
    db_session.add(principal)
    db_session.flush()
    # Membership of an enumerated caller set is not control.
    assert gate._perimeter_fact(db_session, protocol_id=protocol.id, address=eoa) is None
    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa)
    assert verdict.trust_class is None

    principal.details = {"resolver_path": ["live_getter_resolution"]}
    db_session.flush()
    verdict = gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa)
    assert verdict.trust_class == "A"
    assert verdict.evidence["perimeter_fact"]["kind"] == "function_principal"


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


def test_exclusivity_tolerates_member_factory_children(db_session):
    """NULL attribution stays a refusal."""
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

    assert not _controller_is_exclusive(
        db_session,
        protocol_id=protocol.id,
        controller_address=operator,
        chain_key="ethereum",
        exclude_contract_ids=set(),
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
        db_session,
        protocol_id=protocol.id,
        controller_address=operator,
        chain_key="ethereum",
        exclude_contract_ids=set(),
    )


def test_enumeration_never_creates_contract_rows(db_session):
    """Pinned enumeration regression: a COMPLETE
    enumeration's unknown creations are counted, never materialized."""
    from sqlalchemy import func, select

    from services.discovery.deployer_enumeration import DeployerCreation

    protocol = _protocol(db_session)
    eoa = ADDR(0x580)
    members = _seed_class_b_members(db_session, protocol, eoa)
    candidate = _contract(db_session, ADDR(0x581), nominated_protocol_id=protocol.id, deployer=eoa)
    unknown = ADDR(0x582)
    history = sorted(m.address for m in members) + [candidate.address, unknown]

    class Enumerator:
        creations = {eoa: (DeployerCreation(address=unknown, chain_id=1, factory=ADDR(0x583)),)}

        def __call__(self, addr: str) -> tuple[list[str], bool]:
            return history, True

    rows_before = db_session.execute(select(func.count(Contract.id))).scalar_one()
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)), deployer_enumerator=Enumerator())
    assert db_session.execute(select(Contract).where(Contract.address == unknown)).first() is None
    assert db_session.execute(select(func.count(Contract.id))).scalar_one() == rows_before

    # The counted-but-unknown creation still refuses Class B.
    verdict = gate.classify_deployer(
        db_session, protocol_id=protocol.id, address=eoa, creation_history=history, history_complete=True
    )
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "foreign_or_unknown_creations"


def test_exclusivity_tolerates_only_evidenced_candidates(db_session):
    """Operator-exclusivity path: a controlled row that is merely
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
        db_session,
        protocol_id=protocol.id,
        controller_address=operator,
        chain_key="ethereum",
        exclude_contract_ids=set(),
    )

    anchor = _contract(db_session, ADDR(0x523), protocol_id=protocol.id)
    _seed_w2_witness(db_session, controlled, anchor, protocol.id)
    assert _controller_is_exclusive(
        db_session,
        protocol_id=protocol.id,
        controller_address=operator,
        chain_key="ethereum",
        exclude_contract_ids=set(),
    )


def test_classify_deployer_cross_protocol_collision_is_class_c(db_session):
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    eoa = ADDR(70)
    db_session.add(ProtocolDeployer(protocol_id=p2.id, address=eoa, trust_class="A", evidence={"x": 1}))
    db_session.flush()
    verdict = gate.classify_deployer(db_session, protocol_id=p1.id, address=eoa)
    assert verdict.trust_class is None
    assert verdict.evidence["reason"] == "cross_protocol_collision"
    _contract(db_session, ADDR(72), protocol_id=p2.id, deployer=ADDR(73))
    verdict3 = gate.classify_deployer(db_session, protocol_id=p1.id, address=ADDR(73))
    assert verdict3.trust_class is None
    assert verdict3.evidence["reason"] == "cross_protocol_collision"


def test_demote_deployer_single_level(db_session):
    protocol = _protocol(db_session)
    eoa = ADDR(80)
    registry = ProtocolDeployer(protocol_id=protocol.id, address=eoa, trust_class="B", evidence={"x": 1})
    db_session.add(registry)
    db_session.flush()
    # The cascade's survival check re-verifies the edge, not mere witness presence.
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
    # Only the member with no other admitting witness is demoted.
    assert result.demoted_contract_ids == (lineage_only.id,)
    assert result.reprobe_contract_ids == (lineage_only.id,)
    assert lineage_only.protocol_id is None
    assert lineage_only.nominated_protocol_id == protocol.id
    assert independent.protocol_id == protocol.id
    rows = db_session.query(ContractMembershipWitness).filter_by(contract_id=lineage_only.id).all()
    assert len(rows) == 1 and rows[0].revoked_at is not None


# ---------------------------------------------------------------------------
# evaluate targeting
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
    # No candidate here carries a code probe, so nothing may promote.
    # The W2-reachable candidate parks on a NAMED missing
    # piece — its W1 probe.
    assert result.promoted_contract_ids == ()
    assert result.demoted_contract_ids == ()
    assert by_pointer.id in result.reprobe_contract_ids
