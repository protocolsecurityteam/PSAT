"""Stratified fixpoint cascade + gate-side W2/W3 enforcement.

Multi-round promotion chains, revocation cascade to quiescence, confluence across arrival orders, termination on
cyclic pointers, the overreach regression fixtures (Lido/EigenLayer/USDC/WETH9 shapes + the shared-operator
two-hop kill), fact-delta targeting per hook, and the W5 human-assertion flow.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    Protocol,
    ProtocolDeployer,
)
from services.discovery import membership_gate as gate
from tests.conftest import requires_postgres
from tests.support.membership_builders import _contract

pytestmark = [requires_postgres]

_TX = "0x" + "ab" * 32


def _protocol(session, label: str) -> Protocol:
    row = Protocol(name=f"{label}-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _code_fact(session, address: str, *, chain_id: int = 1, tx: str | None = None, absent: bool = False) -> None:
    session.add(
        ContractCreationWitness(
            chain_id=chain_id,
            address=address.lower(),
            code_probe_block=50,
            code_absent_at_probe=absent,
            creation_tx_hash=tx,
            creation_block=10 if tx else None,
        )
    )
    session.flush()


def _member(session, protocol: Protocol, address: str, **fields) -> Contract:
    row = _contract(session, address, protocol_id=protocol.id, nominated_protocol_id=protocol.id, **fields)
    _code_fact(session, address)
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
    )
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc)),
    )
    return row


def _probe_read(session, subject: Contract, value: str) -> None:
    """The probe read of a governance getter — the derivation a W3-D2
    witness rests on (``W3_D2_SOURCES``); a bare caller gate is not one."""
    row = session.get(ContractProbeAttempt, (subject.id, 1))
    reads = dict(row.results.get("reads", {})) if row is not None and isinstance(row.results, dict) else {}
    slot = next(
        (
            name
            for name in ("owner", "authority", "admin")
            if name not in reads or reads[name]["value"] == value.lower()
        ),
        "owner",
    )
    reads[slot] = {"value": value.lower()}
    resolved = sorted({read["value"] for read in reads.values()})
    results = {"status": "probed", "code_present": True, "reads": reads, "resolved_addresses": resolved}
    if row is None:
        session.add(ContractProbeAttempt(contract_id=subject.id, chain_id=1, block_number=50, results=results))
    else:
        row.results = results
    session.flush()


def _owner_edge(session, subject: Contract, value: str) -> ControllerValue:
    row = ControllerValue(
        contract_id=subject.id, controller_id="owner", value=value.lower(), authority_provenance="caller_gate"
    )
    session.add(row)
    session.flush()
    _probe_read(session, subject, value)
    return row


def _active_rules(session, contract: Contract) -> set[str]:
    return {
        w.rule
        for w in session.query(ContractMembershipWitness).filter_by(contract_id=contract.id, revoked_at=None).all()
    }


def test_fixpoint_multi_round_chain_w2_then_class_b_then_w4(db_session):
    protocol = _protocol(db_session, "chain")
    deployer = _addr(0x1D0)
    member = _member(db_session, protocol, _addr(0x1A0), implementation=_addr(0x1A1), deployer=deployer)
    impl = _contract(db_session, _addr(0x1A1), nominated_protocol_id=protocol.id, deployer=deployer)
    sibling = _contract(db_session, _addr(0x1A2), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, impl.address, tx=_TX)
    _code_fact(db_session, sibling.address, tx=_TX)
    # a bare nomination never maps into the exclusivity set. The sibling
    # maps through an unrevoked W2 whose edge no longer holds (former anchor
    # rewritten) — W4 stays the witness that verifies and admits it.
    former_anchor = _member(db_session, protocol, _addr(0x1A3), implementation=sibling.address)
    gate.write_witness(
        db_session,
        contract_id=sibling.id,
        protocol_id=protocol.id,
        rule="w2_structural",
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=former_anchor.id,
            member_address=former_anchor.address,
            resolved_pointer=sibling.address,
        ),
        via_address=former_anchor.address,
    )
    former_anchor.implementation = None
    db_session.flush()

    enumerated = [member.address, impl.address, sibling.address]
    calls: list[str] = []

    def enumerator(address: str):
        calls.append(address)
        return enumerated, True

    result = gate.evaluate(
        db_session,
        gate.FactsDelta(new_member_contract_ids=(member.id,)),
        deployer_enumerator=enumerator,
    )
    db_session.commit()

    assert set(result.promoted_contract_ids) == {impl.id, sibling.id}
    assert result.demoted_contract_ids == ()
    assert impl.protocol_id == protocol.id
    assert sibling.protocol_id == protocol.id
    assert _active_rules(db_session, impl) == {"w1_code", "w2_structural"}
    assert _active_rules(db_session, sibling) == {"w1_code", "w2_structural", "w4_deployer"}
    registry = db_session.query(ProtocolDeployer).filter_by(protocol_id=protocol.id, address=deployer).one()
    assert registry.trust_class == "B" and registry.revoked_at is None
    assert calls == [deployer]


# ---------------------------------------------------------------------------
# Fixpoint: revocation cascade
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fixpoint: confluence + termination
# ---------------------------------------------------------------------------


def _settled_state(session, rows: dict[str, Contract], protocol: Protocol) -> dict[str, tuple]:
    out = {}
    for name, row in rows.items():
        witnesses = tuple(
            sorted(
                (
                    w.rule,
                    (w.via_address or "").lower() == "" or w.via_address == rows["m"].address,
                    w.revoked_at is None,
                )
                for w in session.query(ContractMembershipWitness).filter_by(contract_id=row.id).all()
            )
        )
        out[name] = (row.protocol_id == protocol.id, witnesses)
    return out


# ---------------------------------------------------------------------------
# Overreach regression fixtures
# ---------------------------------------------------------------------------


def test_demoting_the_via_revokes_dependent_d1(db_session):
    protocol = _protocol(db_session, "revoked1")
    safe = _contract(db_session, _addr(0x740), nominated_protocol_id=protocol.id)
    _code_fact(db_session, safe.address)
    member_x = _member(db_session, protocol, _addr(0x741))
    x_cv = _owner_edge(db_session, member_x, safe.address)
    y = _contract(db_session, _addr(0x742), nominated_protocol_id=protocol.id)
    _code_fact(db_session, y.address)
    _owner_edge(db_session, y, safe.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(safe.id, y.id)))
    db_session.commit()
    assert safe.protocol_id == protocol.id and y.protocol_id == protocol.id

    db_session.delete(x_cv)
    db_session.get(ContractProbeAttempt, (member_x.id, 1)).results = {"status": "probed", "reads": {}}
    db_session.flush()
    revoked, demoted = gate._revocation_quiescence(db_session, {member_x.address})
    db_session.commit()

    assert safe.protocol_id is None
    assert y.protocol_id is None
    assert set(demoted) == {safe.id, y.id}


def test_resolution_hook_promotes_controller_of_member(db_session):
    from workers.resolution_worker import _membership_gate_controller_hook

    protocol = _protocol(db_session, "reshook")
    member = _member(db_session, protocol, _addr(0x800))
    controller = _contract(db_session, _addr(0x801), nominated_protocol_id=protocol.id)
    _code_fact(db_session, controller.address)
    unrelated = _contract(db_session, _addr(0x802), nominated_protocol_id=protocol.id)
    _code_fact(db_session, unrelated.address)
    _owner_edge(db_session, member, controller.address)

    _membership_gate_controller_hook(
        db_session,
        member,
        {"owner": {"value": controller.address, "resolved_type": "safe"}},
    )

    assert controller.protocol_id == protocol.id
    assert _active_rules(db_session, controller) == {"w1_code", "w3_control"}
    assert unrelated.protocol_id is None
    assert _active_rules(db_session, unrelated) == set()


def test_resolution_hook_removed_controller_revokes_class_a_row(db_session):
    """F5: the removed address rides the hook's delta as a changed deployer."""
    from workers.resolution_worker import _membership_gate_controller_hook

    protocol = _protocol(db_session, "reshook-rm")
    member = _member(db_session, protocol, _addr(0x830))
    eoa = _addr(0x831)
    replacement = _addr(0x832)
    cv = ControllerValue(contract_id=member.id, controller_id="owner", value=eoa, authority_provenance="caller_gate")
    db_session.add(cv)
    db_session.flush()
    registry = gate.register_deployer(
        db_session,
        protocol_id=protocol.id,
        address=eoa,
        classification=gate.classify_deployer(db_session, protocol_id=protocol.id, address=eoa),
    )
    assert registry.trust_class == "A"
    db_session.commit()

    db_session.delete(cv)
    db_session.add(
        ControllerValue(
            contract_id=member.id, controller_id="owner", value=replacement, authority_provenance="caller_gate"
        )
    )
    db_session.flush()
    _membership_gate_controller_hook(
        db_session,
        member,
        {"owner": {"value": replacement, "resolved_type": "eoa"}},
        removed_values={eoa},
    )

    db_session.refresh(registry)
    assert registry.revoked_at is not None
    assert registry.revocation_reason == "perimeter_fact_lost"


# ---------------------------------------------------------------------------
# W5 flow
# ---------------------------------------------------------------------------


def test_human_assertion_request_round_trip():
    assertion = gate.HumanAssertion(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc))
    payload = gate.human_assertion_request_payload(assertion)
    parsed = gate.human_assertion_from_request({gate.HUMAN_ASSERTION_REQUEST_KEY: payload})
    assert parsed == assertion
    assert gate.human_assertion_from_request(None) is None
    assert gate.human_assertion_from_request({}) is None
    assert gate.human_assertion_from_request({gate.HUMAN_ASSERTION_REQUEST_KEY: {"actor": " "}}) is None
    assert (
        gate.human_assertion_from_request({gate.HUMAN_ASSERTION_REQUEST_KEY: {"actor": "a", "asserted_at": "nope"}})
        is None
    )


def test_fresh_foreign_enumeration_revokes_class_b_and_blocks_w4(db_session):
    """The later-foreign-observation rule revokes the Class B row in the same run."""
    protocol = _protocol(db_session, "b-foreign")
    deployer = _addr(0xC00)
    registry = ProtocolDeployer(protocol_id=protocol.id, address=deployer, trust_class="B", evidence={"x": 1})
    db_session.add(registry)
    db_session.flush()
    corr1 = _member(db_session, protocol, _addr(0xC01), deployer=deployer)
    corr2 = _member(db_session, protocol, _addr(0xC02), deployer=deployer)
    lineage_only = _contract(
        db_session, _addr(0xC03), protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer
    )
    _code_fact(db_session, lineage_only.address, tx=_TX)
    gate.write_witness(
        db_session,
        contract_id=lineage_only.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
    )
    gate.write_witness(
        db_session,
        contract_id=lineage_only.id,
        protocol_id=protocol.id,
        rule="w4_deployer",
        evidence=gate.w4_evidence(
            deployer_address=deployer, deployer_registry_id=registry.id, creation_tx_hash=_TX, creation_block=1
        ),
        via_address=deployer,
    )
    sibling = _contract(db_session, _addr(0xC04), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, sibling.address, tx=_TX)
    foreign_creation = _addr(0xC05)  # no row anywhere — an unknown creation

    def enumerator(address: str):
        return [corr1.address, corr2.address, lineage_only.address, sibling.address, foreign_creation], True

    result = gate.evaluate(
        db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)), deployer_enumerator=enumerator
    )
    db_session.commit()

    assert registry.revoked_at is not None
    assert registry.revocation_reason == "foreign_or_unknown_creations"
    assert lineage_only.protocol_id is None
    assert lineage_only.id in result.demoted_contract_ids
    assert sibling.protocol_id is None
    assert sibling.id not in result.promoted_contract_ids
    assert _active_rules(db_session, sibling) == set()
    # Independent-witness members are untouched.
    assert corr1.protocol_id == protocol.id and corr2.protocol_id == protocol.id


def test_collision_revokes_other_protocols_standing_row(db_session):
    """A collision verdict for (Q, EOA) is Class C for EVERY party
    P's standing row for the same EOA falls in the same
    reclassification pass, with its full demote cascade."""
    protocol_p = _protocol(db_session, "coll-p")
    protocol_q = _protocol(db_session, "coll-q")
    deployer = _addr(0xC10)
    registry_p = ProtocolDeployer(protocol_id=protocol_p.id, address=deployer, trust_class="B", evidence={"x": 1})
    db_session.add(registry_p)
    db_session.flush()
    lineage_p = _contract(
        db_session, _addr(0xC11), protocol_id=protocol_p.id, nominated_protocol_id=protocol_p.id, deployer=deployer
    )
    _code_fact(db_session, lineage_p.address, tx=_TX)
    gate.write_witness(
        db_session,
        contract_id=lineage_p.id,
        protocol_id=protocol_p.id,
        rule="w4_deployer",
        evidence=gate.w4_evidence(
            deployer_address=deployer, deployer_registry_id=registry_p.id, creation_tx_hash=_TX, creation_block=1
        ),
        via_address=deployer,
    )
    candidate_q = _contract(db_session, _addr(0xC12), nominated_protocol_id=protocol_q.id, deployer=deployer)
    _code_fact(db_session, candidate_q.address, tx=_TX)

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate_q.id,)))
    db_session.commit()

    assert registry_p.revoked_at is not None
    assert registry_p.revocation_reason == "cross_protocol_collision"
    assert lineage_p.protocol_id is None
    assert lineage_p.id in result.demoted_contract_ids
    assert candidate_q.protocol_id is None
    assert db_session.query(ProtocolDeployer).filter_by(protocol_id=protocol_q.id, address=deployer).count() == 0


def test_foreign_cv_write_revokes_dependent_d1(db_session):
    protocol = _protocol(db_session, "d1revoke")
    foreign_protocol = _protocol(db_session, "d1foreign")
    safe = _contract(db_session, _addr(0xC20), nominated_protocol_id=protocol.id)
    _code_fact(db_session, safe.address)
    member_x = _member(db_session, protocol, _addr(0xC21))
    _owner_edge(db_session, member_x, safe.address)
    y = _contract(db_session, _addr(0xC22), nominated_protocol_id=protocol.id)
    _code_fact(db_session, y.address)
    _owner_edge(db_session, y, safe.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(safe.id, y.id)))
    db_session.commit()
    assert safe.protocol_id == protocol.id and y.protocol_id == protocol.id

    foreign_w = _contract(db_session, _addr(0xC23), protocol_id=foreign_protocol.id)
    _owner_edge(db_session, foreign_w, safe.address)
    result = gate.evaluate(
        db_session,
        gate.FactsDelta(new_edge_addresses=(safe.address,), recheck_contract_ids=(foreign_w.id,)),
    )
    db_session.commit()

    assert y.protocol_id is None
    assert y.id in result.demoted_contract_ids
    assert _active_rules(db_session, y) == {"w1_code"}
    assert safe.protocol_id == protocol.id

    # Reconcile parity: zero drift on a re-run.
    again = gate.evaluate(
        db_session,
        gate.FactsDelta(new_edge_addresses=(safe.address,), recheck_contract_ids=(foreign_w.id,)),
    )
    assert again.promoted_contract_ids == () and again.demoted_contract_ids == ()


def test_stale_w1_cannot_promote_after_code_absent_probe(db_session):
    protocol = _protocol(db_session, "stalew1")
    row = _contract(db_session, _addr(0xC40), nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=5),
    )
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc)),
    )
    _code_fact(db_session, row.address, absent=True)

    assert gate.promote(db_session, contract=row, protocol_id=protocol.id) is False
    assert row.protocol_id is None


def test_secondary_impl_edge_matches_case_insensitively(db_session):
    protocol = _protocol(db_session, "casesec")
    checksummed = "0x" + "AB" * 20
    member = _member(db_session, protocol, _addr(0xC50), secondary_implementations=[checksummed])
    candidate = _contract(db_session, checksummed.lower(), nominated_protocol_id=protocol.id)
    _code_fact(db_session, candidate.address)

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
    db_session.commit()

    assert candidate.id in result.promoted_contract_ids
    w2 = (
        db_session.query(ContractMembershipWitness)
        .filter_by(contract_id=candidate.id, rule="w2_structural", revoked_at=None)
        .one()
    )
    assert w2.evidence["edge_kind"] == "secondary_implementation"
    assert w2.via_address == member.address


# ---------------------------------------------------------------------------
# Review round 2 (NEW-1): a demotion that voids a Class-A anchor revokes the
# standing registry row in the SAME evaluate run,
# without any candidate naming the EOA.
# ---------------------------------------------------------------------------


def test_demotion_voiding_class_a_anchor_revokes_registry_same_run(db_session):
    protocol = _protocol(db_session, "anchorloss")
    deployer = _addr(0xD10)
    seed = _member(db_session, protocol, _addr(0xD11), implementation=_addr(0xD12))
    anchor = _contract(db_session, _addr(0xD12), protocol_id=protocol.id, nominated_protocol_id=protocol.id)
    _code_fact(db_session, anchor.address)
    gate.write_witness(
        db_session,
        contract_id=anchor.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
    )
    gate.write_witness(
        db_session,
        contract_id=anchor.id,
        protocol_id=protocol.id,
        rule="w2_structural",
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=seed.id,
            member_address=seed.address,
            resolved_pointer=anchor.address,
        ),
        via_address=seed.address,
    )
    db_session.add(
        ControllerValue(
            contract_id=anchor.id, controller_id="owner", value=deployer, authority_provenance="caller_gate"
        )
    )
    registry = ProtocolDeployer(
        protocol_id=protocol.id,
        address=deployer,
        trust_class="A",
        evidence={"perimeter_fact": {"kind": "controller_value", "contract_id": None}, "checked_at": "2026-01-01"},
    )
    db_session.add(registry)
    w4_member = _contract(
        db_session, _addr(0xD13), protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer
    )
    _code_fact(db_session, w4_member.address, tx=_TX)
    gate.write_witness(
        db_session,
        contract_id=w4_member.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
    )
    db_session.flush()
    gate.write_witness(
        db_session,
        contract_id=w4_member.id,
        protocol_id=protocol.id,
        rule="w4_deployer",
        evidence=gate.w4_evidence(
            deployer_address=deployer,
            deployer_registry_id=registry.id,
            creation_tx_hash=_TX,
            creation_block=10,
        ),
        via_address=deployer,
    )
    for witness in gate.active_witnesses(db_session, contract_id=seed.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, witness, reason="test_seed_loss")
    gate.demote_member(db_session, contract=seed, reason="test_seed_loss")
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(seed.address,)))
    db_session.commit()

    assert anchor.protocol_id is None and w4_member.protocol_id is None
    assert {anchor.id, w4_member.id} <= set(result.demoted_contract_ids)
    db_session.refresh(registry)
    assert registry.revoked_at is not None and registry.revocation_reason == "perimeter_fact_lost"
    assert _active_rules(db_session, w4_member) <= {"w1_code"}


def test_w4h_auto_revoke_subtracts_the_same_runs_promotion(db_session):
    """It is published as a demotion, never a promotion, and stays queued for re-probe."""
    protocol = _protocol(db_session, "w4h-fold")
    other = _protocol(db_session, "w4h-foreign")
    deployer = _addr(0xD20)
    for n in range(2):
        _member(db_session, protocol, _addr(0x2600 + n), deployer=deployer)
    sibling = _contract(db_session, _addr(0x2610), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, sibling.address, tx=_TX)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()
    assert sibling.protocol_id == protocol.id
    assert "w4h_deployer_affinity" in _active_rules(db_session, sibling)

    # The standing w4h witness re-admits it in the next run.
    gate.demote_member(db_session, contract=sibling, reason="test_stamp_loss")
    for n in range(3):
        _member(db_session, other, _addr(0x2620 + n), deployer=deployer)
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(sibling.id,)))
    db_session.commit()

    assert sibling.protocol_id is None
    assert sibling.id in result.demoted_contract_ids
    assert sibling.id not in result.promoted_contract_ids
    assert sibling.id in result.reprobe_contract_ids


def test_policy_rerun_revokes_a_class_a_deployer_whose_principal_grant_turned_operational(db_session):
    """A Class-A row resting on a function principal falls, with its W4 children, when the policy stage rewrites that
    function's claims to an operational grant, even though the principal itself is still there."""
    from db.models import EffectiveFunction, FunctionPrincipal

    protocol = _protocol(db_session, "perimeter-grant")
    host = _member(db_session, protocol, _addr(0xE00))
    deployer = _addr(0xE01)
    fn = EffectiveFunction(
        contract_id=host.id,
        function_name="setOperator",
        claims=[{"claim_id": "roles.grant", "tier": "standard_exact", "witness": {}}],
    )
    db_session.add(fn)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=fn.id,
            address=deployer,
            resolved_type="eoa",
            details={"resolver_path": ["live_getter_resolution"]},
        )
    )
    db_session.flush()
    registry = gate.register_deployer(
        db_session,
        protocol_id=protocol.id,
        address=deployer,
        classification=gate.classify_deployer(db_session, protocol_id=protocol.id, address=deployer),
    )
    assert registry is not None and registry.trust_class == "A"
    child = _contract(db_session, _addr(0xE02), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, child.address, tx=_TX)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.commit()
    assert child.protocol_id == protocol.id
    assert "w4_deployer" in _active_rules(db_session, child)

    fn.claims = [
        {"claim_id": "value_router", "tier": "standard_exact", "witness": {}},
        {"claim_id": "flow.in", "tier": "idiom_structural", "witness": {}},
    ]
    db_session.commit()
    gate.evaluate_principal_change(db_session, contract_id=host.id, addresses={deployer}, context="test")

    db_session.refresh(registry)
    assert registry.revoked_at is not None and registry.revocation_reason == "perimeter_fact_lost"
    assert child.protocol_id is None
    assert _active_rules(db_session, child) <= {"w1_code"}


def test_policy_rerun_registers_a_principal_that_gains_a_control_grant(db_session):
    """The admission side of the same trigger: once the rewrite gives the principal a control grant, it is registered
    Class A and its nominated children are admitted on that policy run."""
    from db.models import EffectiveFunction, FunctionPrincipal

    protocol = _protocol(db_session, "perimeter-gain")
    host = _member(db_session, protocol, _addr(0xE10))
    deployer = _addr(0xE11)
    fn = EffectiveFunction(
        contract_id=host.id,
        function_name="bulkDeposit",
        claims=[{"claim_id": "value_router", "tier": "standard_exact", "witness": {}}],
    )
    db_session.add(fn)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=fn.id,
            address=deployer,
            resolved_type="eoa",
            details={"resolver_path": ["live_getter_resolution"]},
        )
    )
    child = _contract(db_session, _addr(0xE12), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, child.address, tx=_TX)
    gate.evaluate_principal_change(db_session, contract_id=host.id, addresses={deployer}, context="test")
    assert child.protocol_id is None

    fn.claims = [{"claim_id": "roles.grant", "tier": "standard_exact", "witness": {}}]
    db_session.commit()
    gate.evaluate_principal_change(db_session, contract_id=host.id, addresses={deployer}, context="test")

    registry = (
        db_session.query(ProtocolDeployer).filter_by(protocol_id=protocol.id, address=deployer, revoked_at=None).one()
    )
    assert registry.trust_class == "A"
    assert child.protocol_id == protocol.id
    assert "w4_deployer" in _active_rules(db_session, child)
