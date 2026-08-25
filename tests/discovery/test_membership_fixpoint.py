"""Stratified fixpoint cascade + gate-side W2/W3 enforcement
(DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3.4 event 3, invariants 6/8/9).

Covers: multi-round promotion chains (W2 → deployer Class B → W4 sibling),
revocation cascade to quiescence, confluence across arrival orders,
termination on cyclic pointers, the §7 overreach regression fixtures
(Lido/EigenLayer/USDC/WETH9 shapes + the shared-operator two-hop kill),
event-2 delta targeting per hook, and the W5 human-assertion flow.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractDependency,
    ContractMembershipWitness,
    ControllerValue,
    Protocol,
    ProtocolDeployer,
)
from services.discovery import membership_gate as gate
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

_TX = "0x" + "ab" * 32


def _protocol(session, label: str) -> Protocol:
    row = Protocol(name=f"{label}-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _contract(session, address: str, **fields) -> Contract:
    row = Contract(address=address.lower(), chain=fields.pop("chain", "ethereum"), **fields)
    session.add(row)
    session.flush()
    return row


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
    """A proven member: stamp + W1 + W5 witness rows (the anchor shape)."""
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


def _active_rules(session, contract: Contract) -> set[str]:
    return {
        w.rule
        for w in session.query(ContractMembershipWitness).filter_by(contract_id=contract.id, revoked_at=None).all()
    }


# ---------------------------------------------------------------------------
# Fixpoint: multi-round promotion chain
# ---------------------------------------------------------------------------


def test_fixpoint_multi_round_chain_w2_then_class_b_then_w4(db_session):
    """One evaluate call settles a three-hop chain: the member's impl admits
    via W2; the shared deployer then earns Class B (corroborated by the fresh
    member, enumeration complete); the sibling admits via W4."""
    protocol = _protocol(db_session, "chain")
    deployer = _addr(0x1D0)
    member = _member(db_session, protocol, _addr(0x1A0), implementation=_addr(0x1A1), deployer=deployer)
    impl = _contract(db_session, _addr(0x1A1), nominated_protocol_id=protocol.id, deployer=deployer)
    sibling = _contract(db_session, _addr(0x1A2), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, impl.address, tx=_TX)
    _code_fact(db_session, sibling.address, tx=_TX)

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
    assert _active_rules(db_session, sibling) == {"w1_code", "w4_deployer"}
    registry = db_session.query(ProtocolDeployer).filter_by(protocol_id=protocol.id, address=deployer).one()
    assert registry.trust_class == "B" and registry.revoked_at is None
    # The enumeration is fetched once, then cached across rounds.
    assert calls == [deployer]


def test_fixpoint_without_enumerator_never_mints_class_b(db_session):
    """No positive exclusivity evidence at hand → no Class B row and no W4
    admission; the sibling parks (invariant 5 posture, Class C by absence)."""
    protocol = _protocol(db_session, "noenum")
    deployer = _addr(0x2D0)
    member = _member(db_session, protocol, _addr(0x2A0), implementation=_addr(0x2A1), deployer=deployer)
    impl = _contract(db_session, _addr(0x2A1), nominated_protocol_id=protocol.id, deployer=deployer)
    sibling = _contract(db_session, _addr(0x2A2), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, impl.address, tx=_TX)
    _code_fact(db_session, sibling.address, tx=_TX)

    result = gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(member.id,)))
    db_session.commit()

    assert set(result.promoted_contract_ids) == {impl.id}
    assert sibling.protocol_id is None
    assert db_session.query(ProtocolDeployer).filter_by(address=deployer).count() == 0


# ---------------------------------------------------------------------------
# Fixpoint: revocation cascade (invariant 8)
# ---------------------------------------------------------------------------


def test_revocation_cascade_demotes_exactly_the_witnessless(db_session):
    """Deployer revocation cascades through via-facts to quiescence: the
    lineage-only member falls, the member resting on IT falls next, and the
    member with an independent witness is untouched."""
    protocol = _protocol(db_session, "cascade")
    deployer = _addr(0x3D0)
    registry = ProtocolDeployer(protocol_id=protocol.id, address=deployer, trust_class="B", evidence={"x": 1})
    db_session.add(registry)
    db_session.flush()

    # A: member via W4 only; its stored impl pointer backs B's W2.
    a = _contract(
        db_session,
        _addr(0x3A0),
        protocol_id=protocol.id,
        nominated_protocol_id=protocol.id,
        deployer=deployer,
        implementation=_addr(0x3A1),
        secondary_implementations=[_addr(0x3A2)],
    )
    _code_fact(db_session, a.address, tx=_TX)
    gate.write_witness(
        db_session,
        contract_id=a.id,
        protocol_id=protocol.id,
        rule="w4_deployer",
        evidence=gate.w4_evidence(
            deployer_address=deployer, deployer_registry_id=registry.id, creation_tx_hash=_TX, creation_block=1
        ),
        via_address=deployer,
    )
    # B: member via W2 resting on A only.
    b = _contract(db_session, _addr(0x3A1), protocol_id=protocol.id, nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=b.id,
        protocol_id=protocol.id,
        rule="w2_structural",
        evidence=gate.w2_evidence(
            edge_kind="implementation", member_contract_id=a.id, member_address=a.address, resolved_pointer=b.address
        ),
        via_address=a.address,
    )
    # C: member via W2 on A AND an independent W5.
    c = _contract(db_session, _addr(0x3A2), protocol_id=protocol.id, nominated_protocol_id=protocol.id)
    gate.write_witness(
        db_session,
        contract_id=c.id,
        protocol_id=protocol.id,
        rule="w2_structural",
        evidence=gate.w2_evidence(
            edge_kind="secondary_implementation",
            member_contract_id=a.id,
            member_address=a.address,
            resolved_pointer=c.address,
        ),
        via_address=a.address,
    )
    gate.write_witness(
        db_session,
        contract_id=c.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc)),
    )

    result = gate.demote(db_session, deployer_row=registry, reason="foreign_creation_observed")
    db_session.commit()

    assert set(result.demoted_contract_ids) == {a.id, b.id}
    assert set(result.reprobe_contract_ids) == {a.id, b.id}
    assert a.protocol_id is None and b.protocol_id is None
    assert c.protocol_id == protocol.id
    # Invariant 4: history preserved — revoked, never deleted.
    assert db_session.query(ContractMembershipWitness).filter_by(contract_id=b.id).count() == 1
    assert _active_rules(db_session, b) == set()
    assert _active_rules(db_session, c) == {"w5_human"}


# ---------------------------------------------------------------------------
# Fixpoint: confluence + termination (invariant 9)
# ---------------------------------------------------------------------------


def _confluence_universe(db_session, base: int) -> tuple[Protocol, dict[str, Contract]]:
    """Member M points at impl X; X points at impl Y (chain of W2 edges)."""
    protocol = _protocol(db_session, "confl")
    m = _member(db_session, protocol, _addr(base), implementation=_addr(base + 1))
    x = _contract(
        db_session,
        _addr(base + 1),
        nominated_protocol_id=protocol.id,
        implementation=_addr(base + 2),
    )
    y = _contract(db_session, _addr(base + 2), nominated_protocol_id=protocol.id)
    _code_fact(db_session, x.address)
    _code_fact(db_session, y.address)
    return protocol, {"m": m, "x": x, "y": y}


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


def test_fixpoint_confluent_across_arrival_orders(db_session):
    """Same stored evidence, two event orders → the same settled membership
    and witness sets (invariant 9)."""
    p1, u1 = _confluence_universe(db_session, 0x400)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(u1["y"].id,)))
    gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(u1["m"].id,)))
    db_session.commit()

    p2, u2 = _confluence_universe(db_session, 0x500)
    gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(u2["m"].id,)))
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(u2["y"].id,)))
    db_session.commit()

    state1 = _settled_state(db_session, u1, p1)
    state2 = _settled_state(db_session, u2, p2)
    assert state1 == state2
    assert u1["x"].protocol_id == p1.id and u1["y"].protocol_id == p1.id
    assert u2["x"].protocol_id == p2.id and u2["y"].protocol_id == p2.id


def test_fixpoint_terminates_on_cyclic_pointers(db_session):
    """Mutually pointing proxies (P1.impl = C2, C2.impl = P1) settle in
    finitely many rounds — each admission consumes a strictly new witness."""
    protocol = _protocol(db_session, "cycle")
    _member(db_session, protocol, _addr(0x600), implementation=_addr(0x601))
    p1 = _contract(db_session, _addr(0x601), nominated_protocol_id=protocol.id, implementation=_addr(0x602))
    c2 = _contract(db_session, _addr(0x602), nominated_protocol_id=protocol.id, implementation=_addr(0x601))
    _code_fact(db_session, p1.address)
    _code_fact(db_session, c2.address)

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(p1.id, c2.id)))
    db_session.commit()

    assert set(result.promoted_contract_ids) == {p1.id, c2.id}
    # A second pass over the settled state changes nothing.
    again = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(p1.id, c2.id)))
    assert again.promoted_contract_ids == () and again.demoted_contract_ids == ()


# ---------------------------------------------------------------------------
# Overreach regression fixtures (§7 / invariant 6)
# ---------------------------------------------------------------------------


def test_externals_in_member_graph_are_never_admitted(db_session):
    """Lido/EigenLayer-core/USDC/WETH9 shape: externals present as a member's
    dependencies (``regular`` / ``library`` / typed-``proxy``) — even when a
    source nominated them — never admit. Presence in a graph is not a
    control/lineage edge."""
    protocol = _protocol(db_session, "overreach")
    member = _member(db_session, protocol, _addr(0x700))
    externals = {
        "lido_steth": (_addr(0x701), "proxy"),
        "eigen_core": (_addr(0x702), "regular"),
        "usdc": (_addr(0x703), "proxy"),
        "weth9": (_addr(0x704), "regular"),
        "shared_lib": (_addr(0x705), "library"),
    }
    rows: dict[str, Contract] = {}
    for name, (address, rel) in externals.items():
        row = _contract(db_session, address, nominated_protocol_id=protocol.id)
        _code_fact(db_session, address)  # real deployed code — W1 alone admits nothing
        db_session.add(
            ContractDependency(
                contract_id=member.id,
                dependency_address=address,
                relationship_type=rel,
                source=["static"],
            )
        )
        rows[name] = row
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=tuple(r.id for r in rows.values())))
    db_session.commit()

    assert result.promoted_contract_ids == ()
    for name, row in rows.items():
        assert row.protocol_id is None, f"{name} was admitted from mere graph/dependency presence"
        assert _active_rules(db_session, row) == set(), f"{name} gained a witness without a control/lineage edge"


def test_dependency_typed_proxy_is_not_a_structural_edge(db_session):
    """The stETH trap: ``relationship_type='proxy'`` says the dependency IS a
    proxy, not that it is the member's proxy. Only the member's own stored
    pointer admits."""
    protocol = _protocol(db_session, "steth")
    member = _member(db_session, protocol, _addr(0x710), implementation=_addr(0x712))
    steth = _contract(db_session, _addr(0x711), nominated_protocol_id=protocol.id)
    real_impl = _contract(db_session, _addr(0x712), nominated_protocol_id=protocol.id)
    _code_fact(db_session, steth.address)
    _code_fact(db_session, real_impl.address)
    db_session.add(
        ContractDependency(
            contract_id=member.id, dependency_address=steth.address, relationship_type="proxy", source=["dynamic"]
        )
    )
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(steth.id, real_impl.id)))
    db_session.commit()

    assert set(result.promoted_contract_ids) == {real_impl.id}
    assert steth.protocol_id is None
    assert real_impl.protocol_id == protocol.id


def test_shared_operator_two_hop_kill(db_session):
    """Third-party ops Safe S controls member X of P and also foreign W.
    S itself admits (D2) — but S is NON-TRANSITIVE (foreign observation
    breaks exclusivity), so candidate Y whose owner is S must not admit."""
    protocol = _protocol(db_session, "twohop")
    foreign_protocol = _protocol(db_session, "foreignq")
    safe = _contract(db_session, _addr(0x720), nominated_protocol_id=protocol.id)
    _code_fact(db_session, safe.address)
    member_x = _member(db_session, protocol, _addr(0x721))
    db_session.add(ControllerValue(contract_id=member_x.id, controller_id="owner", value=safe.address))
    # Foreign vault the SAME operator controls — the two-hop shape's tell.
    foreign_w = _contract(db_session, _addr(0x722), protocol_id=foreign_protocol.id)
    db_session.add(ControllerValue(contract_id=foreign_w.id, controller_id="owner", value=safe.address))
    # Candidate Y of P whose resolved owner is the shared operator.
    y = _contract(db_session, _addr(0x723), nominated_protocol_id=protocol.id)
    _code_fact(db_session, y.address)
    db_session.add(ControllerValue(contract_id=y.id, controller_id="owner", value=safe.address))
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(safe.id, y.id)))
    db_session.commit()

    # S admits as a D2 controller of member X…
    assert safe.protocol_id == protocol.id
    assert _active_rules(db_session, safe) == {"w1_code", "w3_control"}
    # …but licenses nothing: Y stays a candidate.
    assert y.protocol_id is None
    assert y.id not in result.promoted_contract_ids
    assert _active_rules(db_session, y) == set()


def test_exclusive_d2_controller_is_transitive(db_session):
    """Positive control for the kill: with no foreign observation, the D2
    controller is proven exclusive and the second vault admits via D1."""
    protocol = _protocol(db_session, "exclusive")
    safe = _contract(db_session, _addr(0x730), nominated_protocol_id=protocol.id)
    _code_fact(db_session, safe.address)
    member_x = _member(db_session, protocol, _addr(0x731))
    db_session.add(ControllerValue(contract_id=member_x.id, controller_id="owner", value=safe.address))
    y = _contract(db_session, _addr(0x732), nominated_protocol_id=protocol.id)
    _code_fact(db_session, y.address)
    db_session.add(ControllerValue(contract_id=y.id, controller_id="owner", value=safe.address))
    db_session.flush()

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(safe.id, y.id)))
    db_session.commit()

    assert safe.protocol_id == protocol.id
    assert y.protocol_id == protocol.id
    y_w3 = (
        db_session.query(ContractMembershipWitness)
        .filter_by(contract_id=y.id, rule="w3_control", revoked_at=None)
        .one()
    )
    assert y_w3.evidence["direction"] == "d1"
    assert y_w3.evidence["via_transitive"] is True


def test_demoting_the_via_revokes_dependent_d1(db_session):
    """Revocability of the transitive license: when the operator's member
    status falls, the D1 members resting on it are re-checked and demoted."""
    protocol = _protocol(db_session, "revoked1")
    safe = _contract(db_session, _addr(0x740), nominated_protocol_id=protocol.id)
    _code_fact(db_session, safe.address)
    member_x = _member(db_session, protocol, _addr(0x741))
    x_cv = ControllerValue(contract_id=member_x.id, controller_id="owner", value=safe.address)
    db_session.add(x_cv)
    y = _contract(db_session, _addr(0x742), nominated_protocol_id=protocol.id)
    _code_fact(db_session, y.address)
    db_session.add(ControllerValue(contract_id=y.id, controller_id="owner", value=safe.address))
    db_session.flush()
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(safe.id, y.id)))
    db_session.commit()
    assert safe.protocol_id == protocol.id and y.protocol_id == protocol.id

    # The control edge that admitted S disappears (owner rotated away).
    db_session.delete(x_cv)
    db_session.flush()
    revoked, demoted = gate._revocation_quiescence(db_session, {member_x.address})
    db_session.commit()

    assert safe.protocol_id is None
    assert y.protocol_id is None
    assert set(demoted) == {safe.id, y.id}


# ---------------------------------------------------------------------------
# Event-2 delta targeting per hook (transport stubbed / none needed)
# ---------------------------------------------------------------------------


def test_resolution_hook_promotes_controller_of_member(db_session):
    from workers.resolution_worker import _membership_gate_controller_hook

    protocol = _protocol(db_session, "reshook")
    member = _member(db_session, protocol, _addr(0x800))
    controller = _contract(db_session, _addr(0x801), nominated_protocol_id=protocol.id)
    _code_fact(db_session, controller.address)
    unrelated = _contract(db_session, _addr(0x802), nominated_protocol_id=protocol.id)
    _code_fact(db_session, unrelated.address)
    # The stage's commit wrote this CV row; the hook receives the snapshot.
    db_session.add(ControllerValue(contract_id=member.id, controller_id="owner", value=controller.address))
    db_session.flush()

    _membership_gate_controller_hook(
        db_session,
        member,
        {"owner": {"value": controller.address, "resolved_type": "safe"}},
    )

    assert controller.protocol_id == protocol.id
    assert _active_rules(db_session, controller) == {"w1_code", "w3_control"}
    # Delta targeting: the unrelated candidate is untouched.
    assert unrelated.protocol_id is None
    assert _active_rules(db_session, unrelated) == set()


def test_static_hook_edge_addresses_admit_member_proxys_impl(db_session):
    """The proxy-classification delta carries the freshly stored pointer
    addresses; a nominated candidate AT a member proxy's impl address admits."""
    protocol = _protocol(db_session, "statichook")
    proxy = _member(db_session, protocol, _addr(0x810), implementation=_addr(0x811))
    impl = _contract(db_session, _addr(0x811), nominated_protocol_id=protocol.id)
    _code_fact(db_session, impl.address)

    result = gate.evaluate_committed(
        db_session,
        gate.FactsDelta(new_edge_addresses=(impl.address,), recheck_contract_ids=(proxy.id,)),
        context="test_static_hook",
    )

    assert result is not None
    assert set(result.promoted_contract_ids) == {impl.id}
    assert impl.protocol_id == protocol.id


def test_evaluate_committed_swallows_failures(db_session, monkeypatch):
    """A gate failure inside a hook rolls back and returns None — the
    pipeline stage never fails on the gate."""
    monkeypatch.setattr(gate, "_target_candidates", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    result = gate.evaluate_committed(db_session, gate.FactsDelta(), context="test_failure")
    assert result is None


# ---------------------------------------------------------------------------
# W5 flow (spec §5.2, invariants 3 + 14)
# ---------------------------------------------------------------------------


def test_w5_assertion_candidate_until_w1_then_member(db_session):
    protocol = _protocol(db_session, "w5flow")
    row = _contract(db_session, _addr(0x900))
    assertion = gate.HumanAssertion(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc))

    gate.nominate(db_session, contract=row, protocol_id=protocol.id, source_tag="", human_assertion=assertion)
    db_session.flush()

    # Assertion recorded, promotion withheld: W1 is still a precondition.
    assert row.nominated_protocol_id == protocol.id
    assert row.protocol_id is None
    assert _active_rules(db_session, row) == {"w5_human"}

    # The probe fact lands; the next targeted evaluation binds W1 + promotes.
    _code_fact(db_session, row.address)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(row.id,)))
    db_session.commit()

    assert row.protocol_id == protocol.id
    assert _active_rules(db_session, row) == {"w1_code", "w5_human"}
    w5 = db_session.query(ContractMembershipWitness).filter_by(contract_id=row.id, rule="w5_human").one()
    assert w5.evidence["actor"] == "admin_api_key"


def test_w5_assertion_on_unroutable_chain_stays_candidate(db_session):
    """Invariant 3 binds W5: an assertion on a chain that never resolves can
    never satisfy W1, so the row stays a candidate-with-W5-witness."""
    protocol = _protocol(db_session, "w5park")
    row = _contract(db_session, _addr(0x901), chain="unknown")
    assertion = gate.HumanAssertion(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc))

    gate.nominate(db_session, contract=row, protocol_id=protocol.id, source_tag="", human_assertion=assertion)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(row.id,)))
    db_session.commit()

    assert row.protocol_id is None
    assert _active_rules(db_session, row) == {"w5_human"}


def test_human_assertion_request_round_trip():
    assertion = gate.HumanAssertion(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc))
    payload = gate.human_assertion_request_payload(assertion)
    parsed = gate.human_assertion_from_request({gate.HUMAN_ASSERTION_REQUEST_KEY: payload})
    assert parsed == assertion
    # Malformed payloads parse to None — never a defaulted actor/timestamp.
    assert gate.human_assertion_from_request(None) is None
    assert gate.human_assertion_from_request({}) is None
    assert gate.human_assertion_from_request({gate.HUMAN_ASSERTION_REQUEST_KEY: {"actor": " "}}) is None
    assert (
        gate.human_assertion_from_request({gate.HUMAN_ASSERTION_REQUEST_KEY: {"actor": "a", "asserted_at": "nope"}})
        is None
    )


# ---------------------------------------------------------------------------
# Pruned rows never admit
# ---------------------------------------------------------------------------


def test_proven_code_absent_candidate_never_promotes(db_session):
    protocol = _protocol(db_session, "pruned")
    member = _member(db_session, protocol, _addr(0xA00), implementation=_addr(0xA01))
    phantom = _contract(db_session, _addr(0xA01), nominated_protocol_id=protocol.id)
    _code_fact(db_session, phantom.address, absent=True)

    result = gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(member.id,)))
    db_session.commit()

    assert result.promoted_contract_ids == ()
    assert phantom.protocol_id is None
    assert gate.resolve_membership_state(db_session, phantom) == "pruned"


# ---------------------------------------------------------------------------
# Review round 1: promotion-expansion targeting (finding 1)
# ---------------------------------------------------------------------------


def _proxy_chain_universe(db_session, base: int) -> tuple[Protocol, dict[str, Contract]]:
    """Member M0 points at impl X; candidate proxy PR points at X — PR is
    reachable only through its OWN stored pointer once X promotes."""
    protocol = _protocol(db_session, "proxchain")
    m0 = _member(db_session, protocol, _addr(base), implementation=_addr(base + 1))
    x = _contract(db_session, _addr(base + 1), nominated_protocol_id=protocol.id)
    pr = _contract(db_session, _addr(base + 2), nominated_protocol_id=protocol.id, implementation=_addr(base + 1))
    _code_fact(db_session, x.address)
    _code_fact(db_session, pr.address)
    return protocol, {"m0": m0, "x": x, "pr": pr}


def _role_state(session, protocol: Protocol, rows: dict[str, Contract]) -> dict[str, tuple]:
    out = {}
    for name, row in rows.items():
        rules = tuple(
            sorted(
                (w.rule, w.revoked_at is None)
                for w in session.query(ContractMembershipWitness).filter_by(contract_id=row.id).all()
            )
        )
        out[name] = (row.protocol_id == protocol.id, rules)
    return out


def test_promotion_expands_to_candidate_proxy_pointing_at_new_member(db_session):
    """A member promoting INSIDE the fixpoint reaches the candidate proxy
    whose own pointer names it — same settled state as a recheck-after."""
    p1, u1 = _proxy_chain_universe(db_session, 0xB00)
    single = gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(u1["m0"].id,)))
    db_session.commit()
    assert set(single.promoted_contract_ids) == {u1["x"].id, u1["pr"].id}
    assert u1["pr"].protocol_id == p1.id

    p2, u2 = _proxy_chain_universe(db_session, 0xB10)
    gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(u2["m0"].id,)))
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(u2["pr"].id,)))
    db_session.commit()

    assert _role_state(db_session, p1, u1) == _role_state(db_session, p2, u2)


def _d1_chain_universe(db_session, base: int) -> tuple[Protocol, dict[str, Contract]]:
    """Member M0; candidate S is M0's resolved controller (D2 fuel); candidate
    Y's own stored ControllerValue names S (D1 fuel once S promotes)."""
    protocol = _protocol(db_session, "d1chain")
    m0 = _member(db_session, protocol, _addr(base))
    s = _contract(db_session, _addr(base + 1), nominated_protocol_id=protocol.id)
    y = _contract(db_session, _addr(base + 2), nominated_protocol_id=protocol.id)
    _code_fact(db_session, s.address)
    _code_fact(db_session, y.address)
    db_session.add(ControllerValue(contract_id=m0.id, controller_id="owner", value=s.address))
    db_session.add(ControllerValue(contract_id=y.id, controller_id="owner", value=s.address))
    db_session.flush()
    return protocol, {"m0": m0, "s": s, "y": y}


def test_promotion_expands_to_stored_cv_naming_new_member(db_session):
    """S promoting inside the fixpoint reaches Y via Y's own STORED
    ControllerValue row — no probe needed; both orders settle identically."""
    p1, u1 = _d1_chain_universe(db_session, 0xB20)
    single = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(u1["s"].id,)))
    db_session.commit()
    assert set(single.promoted_contract_ids) == {u1["s"].id, u1["y"].id}
    assert u1["y"].protocol_id == p1.id

    p2, u2 = _d1_chain_universe(db_session, 0xB30)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(u2["y"].id,)))
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(u2["s"].id,)))
    db_session.commit()

    assert _role_state(db_session, p1, u1) == _role_state(db_session, p2, u2)


# ---------------------------------------------------------------------------
# Review round 1: Class B revocation on fresh counterevidence (finding 2)
# ---------------------------------------------------------------------------


def test_fresh_foreign_enumeration_revokes_class_b_and_blocks_w4(db_session):
    """A fresh enumeration naming a foreign creation revokes the standing
    Class B row (later-foreign-observation rule), demotes the lineage-only
    member, and the same run mints no new W4 for the sibling."""
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
    # The disqualifying verdict blocks any W4 admission in the same run.
    assert sibling.protocol_id is None
    assert sibling.id not in result.promoted_contract_ids
    assert _active_rules(db_session, sibling) == set()
    # Independent-witness members are untouched (invariant 8).
    assert corr1.protocol_id == protocol.id and corr2.protocol_id == protocol.id


def test_collision_revokes_other_protocols_standing_row(db_session):
    """A collision verdict for (Q, EOA) is Class C for EVERY party
    (invariant 7): P's standing row for the same EOA falls in the same
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
    # Q registers nothing and admits nothing off the collided EOA.
    assert candidate_q.protocol_id is None
    assert db_session.query(ProtocolDeployer).filter_by(protocol_id=protocol_q.id, address=deployer).count() == 0


# ---------------------------------------------------------------------------
# Review round 1: D1 revocability on fresh foreign observations (finding 3)
# ---------------------------------------------------------------------------


def test_foreign_cv_write_revokes_dependent_d1(db_session):
    """A foreign protocol's resolution writes a controller value naming the
    exclusive operator S: the edge delta seeds S into the revocation stratum,
    exclusivity re-checks, and the D1 member resting on S is demoted."""
    protocol = _protocol(db_session, "d1revoke")
    foreign_protocol = _protocol(db_session, "d1foreign")
    safe = _contract(db_session, _addr(0xC20), nominated_protocol_id=protocol.id)
    _code_fact(db_session, safe.address)
    member_x = _member(db_session, protocol, _addr(0xC21))
    db_session.add(ControllerValue(contract_id=member_x.id, controller_id="owner", value=safe.address))
    y = _contract(db_session, _addr(0xC22), nominated_protocol_id=protocol.id)
    _code_fact(db_session, y.address)
    db_session.add(ControllerValue(contract_id=y.id, controller_id="owner", value=safe.address))
    db_session.flush()
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(safe.id, y.id)))
    db_session.commit()
    assert safe.protocol_id == protocol.id and y.protocol_id == protocol.id

    # The foreign observation arrives exactly as a hook would deliver it: a
    # fresh CV row on another protocol's member naming S as its controller.
    foreign_w = _contract(db_session, _addr(0xC23), protocol_id=foreign_protocol.id)
    db_session.add(ControllerValue(contract_id=foreign_w.id, controller_id="owner", value=safe.address))
    db_session.flush()
    result = gate.evaluate(
        db_session,
        gate.FactsDelta(new_edge_addresses=(safe.address,), recheck_contract_ids=(foreign_w.id,)),
    )
    db_session.commit()

    assert y.protocol_id is None
    assert y.id in result.demoted_contract_ids
    # The admitting D1 is revoked; the W1 probe fact stays (it still holds).
    assert _active_rules(db_session, y) == {"w1_code"}
    # S itself still holds its D2 edge to member X — untouched.
    assert safe.protocol_id == protocol.id

    # Reconcile parity: re-running the same delta over the settled state
    # finds zero drift.
    again = gate.evaluate(
        db_session,
        gate.FactsDelta(new_edge_addresses=(safe.address,), recheck_contract_ids=(foreign_w.id,)),
    )
    assert again.promoted_contract_ids == () and again.demoted_contract_ids == ()


# ---------------------------------------------------------------------------
# Review round 1: W5 write gating + stale-W1 guard (findings 4 + 5)
# ---------------------------------------------------------------------------


def test_foreign_assertion_never_writes_w5_on_member(db_session):
    p1 = _protocol(db_session, "w5own")
    p2 = _protocol(db_session, "w5other")
    row = _contract(db_session, _addr(0xC30), protocol_id=p1.id, nominated_protocol_id=p1.id)
    assertion = gate.HumanAssertion(actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc))

    gate.nominate(db_session, contract=row, protocol_id=p2.id, source_tag="", human_assertion=assertion)
    db_session.flush()

    assert row.protocol_id == p1.id
    assert db_session.query(ContractMembershipWitness).filter_by(contract_id=row.id, protocol_id=p2.id).count() == 0

    # The member's OWN protocol still accepts the assertion.
    gate.nominate(db_session, contract=row, protocol_id=p1.id, source_tag="", human_assertion=assertion)
    db_session.flush()
    w5 = db_session.query(ContractMembershipWitness).filter_by(contract_id=row.id, protocol_id=p1.id).one()
    assert w5.rule == "w5_human" and w5.revoked_at is None


def test_stale_w1_cannot_promote_after_code_absent_probe(db_session):
    """A later code-absent probe is proven-absent; an older active W1 witness
    row cannot outrank it at promotion time."""
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
    # The LATEST probe proves the address empty at its block.
    _code_fact(db_session, row.address, absent=True)

    assert gate.promote(db_session, contract=row, protocol_id=protocol.id) is False
    assert row.protocol_id is None


# ---------------------------------------------------------------------------
# Review round 1: case-folded secondary-impl match (finding 8)
# ---------------------------------------------------------------------------


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
# standing registry row in the SAME evaluate run (invariant 8's trigger),
# without any candidate naming the EOA.
# ---------------------------------------------------------------------------


def test_demotion_voiding_class_a_anchor_revokes_registry_same_run(db_session):
    protocol = _protocol(db_session, "anchorloss")
    deployer = _addr(0xD10)
    seed = _member(db_session, protocol, _addr(0xD11), implementation=_addr(0xD12))
    # Anchor member: sole support is the W2 edge from the seed; it carries the
    # Class A perimeter fact (a resolved controller value naming the EOA).
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
    db_session.add(ControllerValue(contract_id=anchor.id, controller_id="owner", value=deployer))
    registry = ProtocolDeployer(
        protocol_id=protocol.id,
        address=deployer,
        trust_class="A",
        evidence={"perimeter_fact": {"kind": "controller_value", "contract_id": None}, "checked_at": "2026-01-01"},
    )
    db_session.add(registry)
    # W4 member resting only on the registry row's lineage.
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
    # The seed loses its status out-of-band (honestly: witnesses revoked too).
    for witness in gate.active_witnesses(db_session, contract_id=seed.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, witness, reason="test_seed_loss")
    gate.demote_member(db_session, contract=seed, reason="test_seed_loss")
    db_session.flush()

    result = gate.evaluate(db_session, gate.FactsDelta(new_edge_addresses=(seed.address,)))
    db_session.commit()

    # Stratum (i) demotes the anchor (via-fact gone); the SAME run's stratum
    # (ii) loss check then revokes the Class-A row and demotes the W4 member.
    assert anchor.protocol_id is None and w4_member.protocol_id is None
    assert {anchor.id, w4_member.id} <= set(result.demoted_contract_ids)
    db_session.refresh(registry)
    assert registry.revoked_at is not None and registry.revocation_reason == "perimeter_fact_lost"
    assert _active_rules(db_session, w4_member) <= {"w1_code"}
