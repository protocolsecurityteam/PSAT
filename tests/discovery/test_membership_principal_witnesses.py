"""Principal-edge and member-factory admission (DISCOVERY_MEMBERSHIP_GATE_SPEC.md
§3.2/§3.3, salvage-wave owner rulings).

The recall gap these close is the dev DB's own shape: a protocol's governance
components are resolved as ``FunctionPrincipal`` rows on member functions, not
as ``ControllerValue`` rows on the component, so the old timelock and the
contracts its principals control held no admitting witness at all.

Both new arms rest on the F2 anchoring discipline: a principal fact hosted only
on a W3-D2 entry (the EndpointV2 shape) licenses nothing, because the D2 entry
itself is non-transitive.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from db.models import (
    WITNESS_RULE_W3_CONTROL,
    WITNESS_RULE_W4_FACTORY,
    Contract,
    ContractCreationWitness,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Protocol,
)
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]


@pytest.fixture()
def protocol(db_session):
    row = Protocol(name=f"principal-{uuid.uuid4().hex[:10]}")
    db_session.add(row)
    db_session.flush()
    return row


def _contract(db_session, address, *, protocol_id=None, nominated=None, chain="ethereum", code=True, factory=None):
    row = Contract(address=address.lower(), chain=chain, protocol_id=protocol_id, nominated_protocol_id=nominated)
    db_session.add(row)
    db_session.flush()
    if code:
        db_session.add(
            ContractCreationWitness(
                chain_id=1,
                address=row.address,
                code_probe_block=1000,
                code_absent_at_probe=False,
                creation_factory=factory.lower() if factory else None,
            )
        )
        db_session.flush()
    return row


def _anchored_member(db_session, protocol, address, *, factory=None):
    """A member whose admitting witness rests on no via-fact at all (W5) — the
    only kind that anchors outright."""
    row = _contract(db_session, address, protocol_id=protocol.id, nominated=protocol.id, factory=factory)
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin", asserted_at=datetime(2026, 8, 25, tzinfo=timezone.utc)),
    )
    gate.write_witness(
        db_session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=1000),
    )
    db_session.flush()
    return row


def _caller_gate(db_session, subject, value, controller_id="owner"):
    db_session.add(
        ControllerValue(
            contract_id=subject.id,
            controller_id=controller_id,
            value=value.lower(),
            authority_provenance="caller_gate",
        )
    )
    db_session.flush()


def _unclaimed_ward(db_session, controller):
    """A row the controller is observed to control that no protocol claims —
    every D2 fixture carries one so the pre-existing exclusivity arm cannot
    stand in for the rule under test, and a refusal is a real refusal."""
    row = Contract(address=ADDR(int(controller.address, 16) + 0x800000), chain="ethereum")
    db_session.add(row)
    db_session.flush()
    _caller_gate(db_session, row, controller.address)
    return row


def _d2_only_member(db_session, protocol, address, *, controls):
    """The EndpointV2 shape: a row that entered ONLY as a resolved controller
    of a member (W3-D2), so it anchors nothing."""
    row = _contract(db_session, address, nominated=protocol.id)
    _caller_gate(db_session, controls, row.address)
    _unclaimed_ward(db_session, row)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(row.id,)))
    db_session.flush()
    assert row.protocol_id == protocol.id, "fixture: the D2 controller must have entered as a member"
    assert {rule for rule, _ in _rules(db_session, row, protocol)} == {"w1_code", WITNESS_RULE_W3_CONTROL}
    assert _rules(db_session, row, protocol) >= {(WITNESS_RULE_W3_CONTROL, "d2")}
    return row


def _principal(db_session, host, address, *, resolved_type=None, details=None, name="admin"):
    fn = EffectiveFunction(contract_id=host.id, function_name=f"{name}-{uuid.uuid4().hex[:6]}")
    db_session.add(fn)
    db_session.flush()
    row = FunctionPrincipal(function_id=fn.id, address=address.lower(), resolved_type=resolved_type, details=details)
    db_session.add(row)
    db_session.flush()
    return row


def _rules(db_session, contract, protocol):
    return {
        (w.rule, (w.evidence or {}).get("direction"))
        for w in gate.active_witnesses(db_session, contract_id=contract.id, protocol_id=protocol.id)
    }


def _admitting_rules(db_session, contract, protocol):
    return {rule for rule, _ in _rules(db_session, contract, protocol) if rule != "w1_code"}


def _witness(db_session, contract, protocol, rule, direction=None):
    for w in gate.active_witnesses(db_session, contract_id=contract.id, protocol_id=protocol.id):
        if w.rule == rule and (direction is None or (w.evidence or {}).get("direction") == direction):
            return w
    raise AssertionError(f"contract {contract.id} holds no active {rule}/{direction} witness")


# ---------------------------------------------------------------------------
# Evidence shapes (invariant 2 — constructor-built, round-trip validated)
# ---------------------------------------------------------------------------


def _fact(**overrides):
    base = {
        "kind": "function_principal",
        "function_principal_id": 5,
        "function_id": 9,
        "member_contract_id": 11,
        "member_address": ADDR(0x11),
        "resolved_type": "timelock",
        "safe_address": None,
    }
    base.update(overrides)
    return base


def test_d2_principal_evidence_round_trips():
    evidence = gate.w3_evidence(
        direction="d2", source="function_principal", via_address=ADDR(0x11), principal_fact=_fact()
    )
    assert evidence["principal_fact"]["resolved_type"] == "timelock"
    assert gate._validate_evidence(WITNESS_RULE_W3_CONTROL, evidence) == evidence


def test_d2_principal_evidence_refuses_non_controller_type():
    with pytest.raises(ValueError, match="resolved_type"):
        gate.w3_evidence(
            direction="d2",
            source="function_principal",
            via_address=ADDR(0x11),
            principal_fact=_fact(resolved_type="eoa"),
        )


def test_function_principal_source_requires_its_fact_and_vice_versa():
    with pytest.raises(ValueError, match="principal_fact"):
        gate.w3_evidence(direction="d2", source="function_principal", via_address=ADDR(0x11))
    with pytest.raises(ValueError, match="principal_fact"):
        gate.w3_evidence(direction="d2", source="controller_values", via_address=ADDR(0x11), principal_fact=_fact())


def test_d1_principal_evidence_round_trips():
    fact = _fact(kind="safe_owner", resolved_type="safe", safe_address=ADDR(0x22))
    evidence = gate.w3_evidence(
        direction="d1",
        source="controller_values",
        via_address=ADDR(0x33),
        via_transitive=True,
        principal_fact=fact,
    )
    assert gate._validate_evidence(WITNESS_RULE_W3_CONTROL, evidence) == evidence


def test_the_two_d1_proofs_are_mutually_exclusive():
    chain = {
        "links": [{"from": ADDR(0x33), "address": ADDR(0x44), "kind": "probe_read", "detail": "probe"}],
        "anchor_address": ADDR(0x44),
        "anchor_kind": "member",
        "anchor_rule": "w5_human",
    }
    with pytest.raises(ValueError, match="alternative proofs"):
        gate.w3_evidence(
            direction="d1",
            source="probe",
            via_address=ADDR(0x33),
            via_transitive=True,
            anchor_chain=chain,
            principal_fact=_fact(),
        )


def test_w4_factory_evidence_round_trips():
    evidence = gate.w4_factory_evidence(
        factory_address=ADDR(0x55), factory_member_contract_id=3, chain_id=1, creation_tx_hash=None
    )
    assert gate._validate_evidence(WITNESS_RULE_W4_FACTORY, evidence) == evidence


# ---------------------------------------------------------------------------
# (a) D2-principal — the old-timelock shape
# ---------------------------------------------------------------------------


def test_resolved_principal_of_many_members_admits_the_controller(db_session, protocol):
    """The old EtherFiTimelock: a resolved ``timelock`` principal on many
    member functions and nothing else. Its only admitting evidence is the
    principal edge."""
    members = [_anchored_member(db_session, protocol, ADDR(0x1000 + i)) for i in range(3)]
    timelock = _contract(db_session, ADDR(0x1010), nominated=protocol.id)
    for member in members:
        _principal(db_session, member, timelock.address, resolved_type="timelock")

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(timelock.id,)))
    db_session.flush()

    assert timelock.protocol_id == protocol.id
    assert (WITNESS_RULE_W3_CONTROL, "d2") in _rules(db_session, timelock, protocol)
    witness = _witness(db_session, timelock, protocol, WITNESS_RULE_W3_CONTROL, "d2")
    assert witness.evidence["source"] == "function_principal"
    # One witness per hosting member, each naming the function it was read off.
    vias = {
        w.via_address
        for w in gate.active_witnesses(db_session, contract_id=timelock.id, protocol_id=protocol.id)
        if w.rule == WITNESS_RULE_W3_CONTROL
    }
    assert vias == {m.address for m in members}
    assert witness.evidence["principal_fact"]["member_address"] in vias


@pytest.mark.parametrize("resolved_type", ["safe", "contract"])
def test_safe_and_contract_principals_admit(db_session, protocol, resolved_type):
    member = _anchored_member(db_session, protocol, ADDR(0x1100))
    controller = _contract(db_session, ADDR(0x1101), nominated=protocol.id)
    _principal(db_session, member, controller.address, resolved_type=resolved_type)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id,)))
    db_session.flush()
    assert controller.protocol_id == protocol.id


@pytest.mark.parametrize("resolved_type", ["eoa", None, "unknown"])
def test_untyped_and_eoa_principals_never_admit(db_session, protocol, resolved_type):
    """An EOA is not deployed code, so a CONTRACT row carrying an eoa-typed
    principal is a resolution artifact; a NULL/unknown type is not_determined.
    Neither proves control of the member."""
    member = _anchored_member(db_session, protocol, ADDR(0x1200))
    candidate = _contract(db_session, ADDR(0x1201), nominated=protocol.id)
    _principal(db_session, member, candidate.address, resolved_type=resolved_type)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
    db_session.flush()
    assert candidate.protocol_id is None


def test_principal_on_a_foreign_chain_member_never_admits(db_session, protocol):
    """A principal fact is an observation on a deployment, and a deployment is
    (address, chain)."""
    member = _anchored_member(db_session, protocol, ADDR(0x1300))
    member.chain = "base"
    db_session.flush()
    candidate = _contract(db_session, ADDR(0x1301), nominated=protocol.id, chain="ethereum")
    _principal(db_session, member, candidate.address, resolved_type="timelock")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
    db_session.flush()
    assert candidate.protocol_id is None


# ---------------------------------------------------------------------------
# (b) D1-principal — the AtomicQueue shape, and its authority cascade
# ---------------------------------------------------------------------------


def test_owner_that_is_a_member_principal_admits_and_cascades(db_session, protocol):
    """AtomicQueue: its owner EOA is a resolved principal of an anchored
    member, so the queue admits on W3-D1 — and the row the queue in turn
    controls admits behind it."""
    member = _anchored_member(db_session, protocol, ADDR(0x2000))
    owner_eoa = ADDR(0x2001)
    _principal(db_session, member, owner_eoa, resolved_type="eoa")

    queue = _contract(db_session, ADDR(0x2002), nominated=protocol.id)
    _caller_gate(db_session, queue, owner_eoa)
    ward = _contract(db_session, ADDR(0x2003), nominated=protocol.id)
    _caller_gate(db_session, ward, queue.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(queue.id, ward.id)))
    db_session.flush()

    assert queue.protocol_id == protocol.id
    witness = _witness(db_session, queue, protocol, WITNESS_RULE_W3_CONTROL, "d1")
    assert witness.via_address == owner_eoa.lower()
    assert witness.evidence["principal_fact"]["member_contract_id"] == member.id
    assert witness.evidence["principal_fact"]["kind"] == "function_principal"
    # The cascade: the queue is now an anchored member, so its own ward admits.
    assert ward.protocol_id == protocol.id


def test_safe_signer_containment_does_not_prove_the_d1_via(db_session, protocol):
    """A signer set is affiliation, not control of the signer's own wards —
    the same line ``_perimeter_anchor`` draws when it refuses ``safe_owner``
    facts. The §3.3 ladder still reads them; D1 does not."""
    member = _anchored_member(db_session, protocol, ADDR(0x2100))
    signer = ADDR(0x2101)
    safe = ADDR(0x2102)
    _principal(db_session, member, safe, resolved_type="safe", details={"owners": [signer.upper()]})
    subject = _contract(db_session, ADDR(0x2103), nominated=protocol.id)
    _caller_gate(db_session, subject, signer)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(subject.id,)))
    db_session.flush()

    assert subject.protocol_id is None
    # The ladder's own reading is unchanged: the signer is still a §3.3
    # perimeter fact for deployer classification.
    assert gate._perimeter_fact(db_session, protocol_id=protocol.id, address=signer) is not None


@pytest.mark.parametrize("resolved_type", ["safe", "timelock", "contract"])
def test_only_an_eoa_principal_proves_d1_transitivity(db_session, protocol, resolved_type):
    """Monotonicity is the reason: a contract-typed via can itself become a
    member later, and §3.2 decides a member's transitivity from its OWN
    witnesses. Letting the principal arm also speak for it would let a
    promotion WITHDRAW transitivity and oscillate the fixpoint — and would
    license every ward a shared operator happens to control."""
    member = _anchored_member(db_session, protocol, ADDR(0x2400))
    operator = ADDR(0x2401)
    _principal(db_session, member, operator, resolved_type=resolved_type)
    ward = _contract(db_session, ADDR(0x2402), nominated=protocol.id)
    _caller_gate(db_session, ward, operator)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None
    assert (
        gate._via_transitivity(db_session, protocol_id=protocol.id, via_address=operator, chain_key="ethereum") is None
    )


def test_d2_only_member_recorded_as_a_principal_still_licenses_nothing(db_session, protocol):
    """D2 non-transitivity survives the new arm. A D2-only member controller is
    normally recorded as its member's principal too, so the principal arm must
    not be a second door into transitivity for it."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x2300))
    ops_safe = _d2_only_member(db_session, protocol, ADDR(0x2301), controls=anchor)
    _principal(db_session, anchor, ops_safe.address, resolved_type="safe", details={"owners": [ADDR(0x2302)]})
    ward = _contract(db_session, ADDR(0x2303), nominated=protocol.id)
    _caller_gate(db_session, ward, ops_safe.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(ward.id,)))
    db_session.flush()
    assert ward.protocol_id is None
    assert (
        gate._via_transitivity(db_session, protocol_id=protocol.id, via_address=ops_safe.address, chain_key="ethereum")
        is None
    )


def test_d1_via_controlling_a_foreign_row_is_refused(db_session, protocol):
    """§3.2's shared-operator warning as positive counterevidence: an operator
    observed controlling a row that provably belongs elsewhere licenses
    nothing here."""
    other = Protocol(name=f"other-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()
    member = _anchored_member(db_session, protocol, ADDR(0x2200))
    operator = ADDR(0x2201)
    _principal(db_session, member, operator, resolved_type="eoa")
    foreign = _contract(db_session, ADDR(0x2202), protocol_id=other.id, nominated=other.id)
    _caller_gate(db_session, foreign, operator)

    subject = _contract(db_session, ADDR(0x2203), nominated=protocol.id)
    _caller_gate(db_session, subject, operator)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(subject.id,)))
    db_session.flush()
    assert subject.protocol_id is None


# ---------------------------------------------------------------------------
# (c) F2 — a principal hosted only on a D2-only member admits NOTHING
# ---------------------------------------------------------------------------


def test_principal_hosted_only_on_a_d2_member_is_refused(db_session, protocol):
    """The EndpointV2 shape. Its principals (an EOA, a Safe) must license
    nothing: the D2 entry that made it a member is itself non-transitive, so
    the facts it hosts cannot license more than it does."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x3000))
    endpoint = _d2_only_member(db_session, protocol, ADDR(0x3001), controls=anchor)

    # D2 direction: a controller-typed principal of the D2-only member.
    controller = _contract(db_session, ADDR(0x3002), nominated=protocol.id)
    _principal(db_session, endpoint, controller.address, resolved_type="timelock")
    # D1 direction: a subject whose owner is an EOA principal of the same row.
    lone_eoa = ADDR(0x3003)
    _principal(db_session, endpoint, lone_eoa, resolved_type="eoa")
    subject = _contract(db_session, ADDR(0x3004), nominated=protocol.id)
    _caller_gate(db_session, subject, lone_eoa)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id, subject.id)))
    db_session.flush()

    assert controller.protocol_id is None, "a D2-only member's principal must not admit the controller"
    assert subject.protocol_id is None, "a D2-only member's principal must not license what it controls"


def test_the_same_principals_admit_once_an_anchoring_member_hosts_them(db_session, protocol):
    """Control for the refusal above: the fact, not the row, is what changes."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x3100))
    endpoint = _d2_only_member(db_session, protocol, ADDR(0x3101), controls=anchor)
    controller = _contract(db_session, ADDR(0x3102), nominated=protocol.id)
    _principal(db_session, endpoint, controller.address, resolved_type="timelock")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id,)))
    db_session.flush()
    assert controller.protocol_id is None

    _principal(db_session, anchor, controller.address, resolved_type="timelock")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(controller.id,)))
    db_session.flush()
    assert controller.protocol_id == protocol.id
    assert _witness(db_session, controller, protocol, WITNESS_RULE_W3_CONTROL, "d2").via_address == anchor.address


# ---------------------------------------------------------------------------
# (d) Revocation — the hosting member's demotion cascades (invariant 8)
# ---------------------------------------------------------------------------


def test_hosting_member_demotion_revokes_and_cascades(db_session, protocol):
    member = _anchored_member(db_session, protocol, ADDR(0x4000))
    timelock = _contract(db_session, ADDR(0x4001), nominated=protocol.id)
    _principal(db_session, member, timelock.address, resolved_type="timelock")
    owner_eoa = ADDR(0x4002)
    _principal(db_session, member, owner_eoa, resolved_type="eoa")
    subject = _contract(db_session, ADDR(0x4003), nominated=protocol.id)
    _caller_gate(db_session, subject, owner_eoa)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(timelock.id, subject.id)))
    db_session.flush()
    assert timelock.protocol_id == protocol.id and subject.protocol_id == protocol.id

    for row in gate.active_witnesses(db_session, contract_id=member.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, row, reason="test_demotion")
    gate.demote_member(db_session, contract=member, reason="test_demotion")
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(member.address,)))
    db_session.flush()

    assert timelock.protocol_id is None, "the D2-principal witness rests on the demoted host"
    assert subject.protocol_id is None, "the D1-principal proof rests on the same host"
    assert _admitting_rules(db_session, timelock, protocol) == set()
    assert _admitting_rules(db_session, subject, protocol) == set()


def test_dropping_the_principal_row_revokes_the_witness(db_session, protocol):
    """The FunctionPrincipal rewrite path: a re-analysis that no longer
    resolves the principal must not leave the witness standing."""
    member = _anchored_member(db_session, protocol, ADDR(0x4100))
    timelock = _contract(db_session, ADDR(0x4101), nominated=protocol.id)
    row = _principal(db_session, member, timelock.address, resolved_type="timelock")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(timelock.id,)))
    db_session.flush()
    assert timelock.protocol_id == protocol.id

    before = gate.principal_addresses(db_session, [member.id])
    db_session.delete(row)
    db_session.flush()
    gate.evaluate(
        db_session,
        gate.FactsDelta(new_edge_addresses=tuple(sorted(before | {member.address})), recheck_contract_ids=(member.id,)),
    )
    db_session.flush()
    assert timelock.protocol_id is None


# ---------------------------------------------------------------------------
# (e) §2 overreach family stays refused under both new arms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "external",
    ["weth9", "lido_steth", "eigenlayer_strategy", "usdc", "seaport", "deposit_contract"],
)
def test_integration_operands_never_admit_through_a_principal_edge(db_session, protocol, external):
    """The §2 overreach list. A member NAMES these as integration operands —
    ``call_target`` controller values and plain dependency rows — and never as
    a resolved principal. Neither arm may reach them."""
    member = _anchored_member(db_session, protocol, ADDR(0x5000))
    outsider = _contract(db_session, ADDR(0x5001 + hash(external) % 64), nominated=protocol.id)
    db_session.add(
        ControllerValue(
            contract_id=member.id,
            controller_id="nativeWrapper",
            value=outsider.address,
            authority_provenance="call_target",
        )
    )
    db_session.flush()
    # Its own owner is likewise nobody this protocol proved anything about.
    _caller_gate(db_session, outsider, ADDR(0x5F00))

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(outsider.id,)))
    db_session.flush()
    assert outsider.protocol_id is None, external


def test_call_target_operand_is_not_a_principal_fact(db_session, protocol):
    """A ``call_target`` row is an integration operand even when the same
    address is also read as a probe value elsewhere — the principal arms read
    ``FunctionPrincipal`` rows only."""
    member = _anchored_member(db_session, protocol, ADDR(0x5100))
    weth = _contract(db_session, ADDR(0x5101), nominated=protocol.id)
    db_session.add(
        ControllerValue(
            contract_id=member.id,
            controller_id="weth",
            value=weth.address,
            authority_provenance="call_target",
        )
    )
    db_session.flush()
    assert (
        gate._principal_perimeter_fact(db_session, protocol_id=protocol.id, address=weth.address, chain_key="ethereum")
        is None
    )
    assert (
        gate._d2_principal_facts(
            db_session, protocol_id=protocol.id, address=weth.address, chain_key="ethereum", exclude_contract_id=None
        )
        == []
    )


# ---------------------------------------------------------------------------
# (f) Member-factory admission (owner ruling)
# ---------------------------------------------------------------------------


def test_child_of_a_member_factory_admits(db_session, protocol):
    factory = _anchored_member(db_session, protocol, ADDR(0x6000))
    child = _contract(db_session, ADDR(0x6001), nominated=protocol.id, factory=factory.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.flush()
    assert child.protocol_id == protocol.id
    witness = _witness(db_session, child, protocol, WITNESS_RULE_W4_FACTORY)
    assert witness.via_address == factory.address
    assert witness.evidence["factory_member_contract_id"] == factory.id


def test_child_of_a_d2_only_factory_is_refused(db_session, protocol):
    anchor = _anchored_member(db_session, protocol, ADDR(0x6100))
    endpoint = _d2_only_member(db_session, protocol, ADDR(0x6101), controls=anchor)
    child = _contract(db_session, ADDR(0x6102), nominated=protocol.id, factory=endpoint.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.flush()
    assert child.protocol_id is None


def test_child_of_a_non_member_factory_is_refused(db_session, protocol):
    outsider = _contract(db_session, ADDR(0x6200), nominated=protocol.id)
    child = _contract(db_session, ADDR(0x6201), nominated=protocol.id, factory=outsider.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.flush()
    assert child.protocol_id is None


def test_null_factory_attribution_licenses_nothing(db_session, protocol):
    _anchored_member(db_session, protocol, ADDR(0x6300))
    child = _contract(db_session, ADDR(0x6301), nominated=protocol.id, factory=None)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.flush()
    assert child.protocol_id is None


def test_factory_demotion_cascades_to_its_children(db_session, protocol):
    factory = _anchored_member(db_session, protocol, ADDR(0x6400))
    child = _contract(db_session, ADDR(0x6401), nominated=protocol.id, factory=factory.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.flush()
    assert child.protocol_id == protocol.id

    for row in gate.active_witnesses(db_session, contract_id=factory.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, row, reason="test_demotion")
    gate.demote_member(db_session, contract=factory, reason="test_demotion")
    db_session.flush()
    gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(factory.address,)))
    db_session.flush()

    assert child.protocol_id is None
    assert _admitting_rules(db_session, child, protocol) == set()


def test_promoting_the_factory_targets_its_children(db_session, protocol):
    """The other arrival order: the child is recorded first and the factory
    becomes a member later. Only the promotion delta names it. The factory
    enters on W3-D1, the weakest entry that still anchors."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x6500))
    owner_eoa = ADDR(0x6503)
    factory = _contract(db_session, ADDR(0x6501), nominated=protocol.id)
    _caller_gate(db_session, factory, owner_eoa)
    child = _contract(db_session, ADDR(0x6502), nominated=protocol.id, factory=factory.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.flush()
    assert child.protocol_id is None

    _principal(db_session, anchor, owner_eoa, resolved_type="eoa")
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(factory.id,)))
    db_session.flush()
    assert factory.protocol_id == protocol.id
    assert child.protocol_id == protocol.id


# ---------------------------------------------------------------------------
# (g) Confluence — arrival order does not change the settled state
# ---------------------------------------------------------------------------


def _settled_state(db_session, proto, base):
    state = {}
    for row in db_session.query(Contract).filter(Contract.nominated_protocol_id == proto.id).all():
        state[int(row.address, 16) - base] = (
            row.protocol_id is not None,
            tuple(sorted(_rules(db_session, row, proto))),
        )
    return state


def test_principal_arms_settle_identically_across_arrival_orders(db_session):
    def build(base, principals_first):
        proto = Protocol(name=f"order-{uuid.uuid4().hex[:8]}")
        db_session.add(proto)
        db_session.flush()
        anchor = _anchored_member(db_session, proto, ADDR(base + 1))
        timelock = _contract(db_session, ADDR(base + 2), nominated=proto.id)
        owner_eoa = ADDR(base + 3)
        ward = _contract(db_session, ADDR(base + 4), nominated=proto.id)
        _caller_gate(db_session, ward, owner_eoa)
        # The spawn hangs off the ward, which enters on W3-D1 — a D2 entry
        # (the timelock) anchors nothing, factory lineage included.
        spawn = _contract(db_session, ADDR(base + 5), nominated=proto.id, factory=ward.address)

        def land_principals():
            _principal(db_session, anchor, timelock.address, resolved_type="timelock")
            _principal(db_session, anchor, owner_eoa, resolved_type="eoa")
            gate.evaluate(
                db_session,
                gate.FactsDelta(new_edge_addresses=(timelock.address, owner_eoa), recheck_contract_ids=(anchor.id,)),
            )

        def land_candidates():
            gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(timelock.id, ward.id, spawn.id)))

        if principals_first:
            land_principals()
            land_candidates()
        else:
            land_candidates()
            land_principals()
        db_session.flush()
        return _settled_state(db_session, proto, base)

    principals_first = build(0x7100, True)
    candidates_first = build(0x7200, False)
    assert principals_first == candidates_first
    assert all(is_member for is_member, _ in principals_first.values())
    assert (WITNESS_RULE_W4_FACTORY, None) in dict(principals_first)[5][1]


def test_closest_miss_names_a_non_anchoring_factory(db_session, protocol):
    """Invariant 5: a row parked behind the factory rule says so by name."""
    from scripts.membership_reporting import closest_miss

    outsider = _contract(db_session, ADDR(0x6600), nominated=protocol.id)
    child = _contract(db_session, ADDR(0x6601), nominated=protocol.id, factory=outsider.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(child.id,)))
    db_session.flush()
    assert child.protocol_id is None
    miss = closest_miss(db_session, contract=child, protocol_id=protocol.id)
    assert miss == {
        "nearest_rule": "w4_factory",
        "missing": "factory_not_anchoring_member",
        "factory": outsider.address,
    }


def test_settling_is_idempotent_under_the_principal_arms(db_session, protocol):
    """A second evaluation over unchanged evidence must promote and demote
    nothing. A non-monotone transitivity arm shows up here first: it makes a
    row oscillate between promoted and demoted instead of settling."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x7300))
    timelock = _contract(db_session, ADDR(0x7301), nominated=protocol.id)
    _principal(db_session, anchor, timelock.address, resolved_type="timelock")
    owner_eoa = ADDR(0x7302)
    _principal(db_session, anchor, owner_eoa, resolved_type="eoa")
    ward = _contract(db_session, ADDR(0x7303), nominated=protocol.id)
    _caller_gate(db_session, ward, owner_eoa)
    spawn = _contract(db_session, ADDR(0x7304), nominated=protocol.id, factory=ward.address)

    ids = (timelock.id, ward.id, spawn.id)
    first = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=ids))
    db_session.flush()
    assert set(first.promoted_contract_ids) == set(ids)

    second = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=ids))
    db_session.flush()
    assert second.promoted_contract_ids == ()
    assert second.demoted_contract_ids == ()
    assert all(session_row.protocol_id == protocol.id for session_row in (timelock, ward, spawn))


def test_losing_the_anchoring_witness_without_demotion_still_cascades(db_session, protocol):
    """The drift shape reconcile caught on the dev-DB re-earn: a member keeps
    membership on a W3-D2 witness while the W3-D1 witness that made it ANCHOR
    is revoked. Everything resting on its anchoring — factory lineage,
    principal-keyed W3 — must fall with it (invariant 8)."""
    anchor = _anchored_member(db_session, protocol, ADDR(0x8000))
    owner_eoa = ADDR(0x8001)
    _principal(db_session, anchor, owner_eoa, resolved_type="eoa")

    # The factory enters on BOTH a D1 (anchoring) and a D2 (non-anchoring)
    # witness, so losing the D1 leaves it a member that no longer anchors.
    factory = _contract(db_session, ADDR(0x8002), nominated=protocol.id)
    _caller_gate(db_session, factory, owner_eoa)
    _caller_gate(db_session, anchor, factory.address)
    _unclaimed_ward(db_session, factory)
    child = _contract(db_session, ADDR(0x8003), nominated=protocol.id, factory=factory.address)
    grandchild = _contract(db_session, ADDR(0x8004), nominated=protocol.id, factory=child.address)

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(factory.id, child.id, grandchild.id)))
    db_session.flush()
    assert factory.protocol_id == protocol.id
    assert _rules(db_session, factory, protocol) >= {
        (WITNESS_RULE_W3_CONTROL, "d1"),
        (WITNESS_RULE_W3_CONTROL, "d2"),
    }
    assert child.protocol_id == protocol.id and grandchild.protocol_id == protocol.id

    # Drop the principal that proved the D1 via; the D2 witness is untouched.
    db_session.query(FunctionPrincipal).filter(FunctionPrincipal.address == owner_eoa.lower()).delete(
        synchronize_session=False
    )
    db_session.flush()
    gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(anchor.address, owner_eoa)))
    db_session.flush()

    assert factory.protocol_id == protocol.id, "the D2 witness still holds — the factory stays a member"
    assert (WITNESS_RULE_W3_CONTROL, "d1") not in _rules(db_session, factory, protocol)
    assert child.protocol_id is None, "a D2-only member anchors no factory lineage"
    assert grandchild.protocol_id is None, "and the cascade follows"
