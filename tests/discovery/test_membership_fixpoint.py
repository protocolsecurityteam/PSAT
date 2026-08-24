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
