"""Cross-protocol admission (candidacy for A must not block membership in B).

The nomination slot is first-wins recall provenance; admission is
evidence-keyed: the fixpoint may evaluate a candidate for protocol P whenever
P's own stored facts (P's member edge, P's registry row, P's witness rows)
admit it — regardless of which protocol claimed the slot first. Promotion to P
aligns ``nominated_protocol_id`` to P (proof supersedes provenance); the
first-nominator's tag stays in ``discovery_sources``. Determinism rule: the
nominated slot's protocol is attempted first, then every other
evidence-bearing protocol in ascending protocol id; the first valid admission
wins and a contract holds ONE ``protocol_id``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import Contract, ContractCreationWitness, ContractMembershipWitness, Protocol
from services.discovery import membership_gate as gate
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

_TX = "0x" + "cd" * 32


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


def _code_fact(session, address: str, *, tx: str | None = None) -> None:
    session.add(
        ContractCreationWitness(
            chain_id=1,
            address=address.lower(),
            code_probe_block=50,
            code_absent_at_probe=False,
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


def _active_witness_protocols(session, contract: Contract) -> set[int]:
    return {
        w.protocol_id
        for w in session.query(ContractMembershipWitness).filter_by(contract_id=contract.id, revoked_at=None).all()
    }


# ---------------------------------------------------------------------------
# The fixed shape: A-nominated candidate + B's genuine W2 edge → B member
# ---------------------------------------------------------------------------


def test_a_nominated_candidate_admits_to_b_on_b_w2_edge(db_session):
    """A candidate slot-claimed by protocol A earns B-membership when B's
    member's stored impl pointer names it (genuine W2 for B). The slot aligns
    to B on promotion; A's nomination stays visible as provenance."""
    protocol_a = _protocol(db_session, "slot-a")
    protocol_b = _protocol(db_session, "evidence-b")
    candidate = _contract(db_session, _addr(0xC1))
    gate.nominate(db_session, contract=candidate, protocol_id=protocol_a.id, source_tag="inventory")
    assert candidate.nominated_protocol_id == protocol_a.id
    _code_fact(db_session, candidate.address)
    b_member = _member(db_session, protocol_b, _addr(0xC2), implementation=candidate.address)
    db_session.commit()

    result = gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(b_member.id,)))
    db_session.commit()
    db_session.refresh(candidate)

    assert candidate.id in result.promoted_contract_ids
    assert candidate.protocol_id == protocol_b.id
    assert candidate.nominated_protocol_id == protocol_b.id  # proof supersedes provenance
    assert "inventory" in (candidate.discovery_sources or [])  # A's provenance survives
    assert protocol_b.id in _active_witness_protocols(db_session, candidate)


def test_slot_squatting_by_deployer_keyed_nomination_cannot_block(db_session):
    """A deployer-keyed nomination slot-claims the row for A first; B's
    evidence still admits to B."""
    protocol_a = _protocol(db_session, "squatter-a")
    protocol_b = _protocol(db_session, "victim-b")
    candidate = _contract(db_session, _addr(0xC5), deployer=_addr(0xD5))
    gate.nominate(db_session, contract=candidate, protocol_id=protocol_a.id, source_tag="registry_probe")
    _code_fact(db_session, candidate.address, tx=_TX)
    b_member = _member(db_session, protocol_b, _addr(0xC6), beacon=candidate.address)
    db_session.commit()

    result = gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(b_member.id,)))
    db_session.commit()
    db_session.refresh(candidate)

    assert candidate.id in result.promoted_contract_ids
    assert candidate.protocol_id == protocol_b.id
    assert candidate.nominated_protocol_id == protocol_b.id
    assert "registry_probe" in (candidate.discovery_sources or [])


# ---------------------------------------------------------------------------
# No new overreach
# ---------------------------------------------------------------------------


def test_b_evidence_never_admits_to_a(db_session):
    """Wrong-protocol derivation is impossible: B's member edge admits the
    candidate to B only — never to the slot-claiming A."""
    protocol_a = _protocol(db_session, "no-overreach-a")
    protocol_b = _protocol(db_session, "no-overreach-b")
    candidate = _contract(db_session, _addr(0xC8))
    gate.nominate(db_session, contract=candidate, protocol_id=protocol_a.id, source_tag="inventory")
    _code_fact(db_session, candidate.address)
    b_member = _member(db_session, protocol_b, _addr(0xC9), implementation=candidate.address)
    db_session.commit()

    gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(b_member.id,)))
    db_session.commit()
    db_session.refresh(candidate)

    assert candidate.protocol_id == protocol_b.id
    # No A-witness was minted from B's facts.
    a_rows = (
        db_session.query(ContractMembershipWitness).filter_by(contract_id=candidate.id, protocol_id=protocol_a.id).all()
    )
    assert a_rows == []


def test_candidate_own_pointer_to_foreign_member_does_not_cross(db_session):
    """Deliberate narrowing: a candidate proxy whose OWN impl pointer resolves
    to B's member (the shared-singleton shape) is NOT vacuumed into B — the
    W2 proxy / W3-D1 shapes admit only for the nominated protocol."""
    protocol_a = _protocol(db_session, "own-ptr-a")
    protocol_b = _protocol(db_session, "own-ptr-b")
    b_impl = _member(db_session, protocol_b, _addr(0xF1))
    candidate = _contract(db_session, _addr(0xF2), implementation=b_impl.address)
    gate.nominate(db_session, contract=candidate, protocol_id=protocol_a.id, source_tag="inventory")
    _code_fact(db_session, candidate.address)
    db_session.commit()

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
    db_session.commit()
    db_session.refresh(candidate)

    assert candidate.protocol_id is None
    assert candidate.nominated_protocol_id == protocol_a.id


def test_dual_evidence_resolves_deterministically_nominated_slot_first(db_session):
    """Evidence for BOTH A and B: the nominated slot's protocol is attempted
    first and wins; the loser's evidence mints no membership (one protocol_id
    per contract) and the settled state is independent of fact arrival order."""
    for arrival in ("a_first", "b_first"):
        protocol_a = _protocol(db_session, f"dual-a-{arrival}")
        protocol_b = _protocol(db_session, f"dual-b-{arrival}")
        candidate = _contract(db_session, _addr(0xD0 if arrival == "a_first" else 0xD3))
        gate.nominate(db_session, contract=candidate, protocol_id=protocol_a.id, source_tag="inventory")
        _code_fact(db_session, candidate.address)
        member_addr_a = _addr(0xD1 if arrival == "a_first" else 0xD4)
        member_addr_b = _addr(0xD2 if arrival == "a_first" else 0xD5)
        if arrival == "a_first":
            a_member = _member(db_session, protocol_a, member_addr_a, implementation=candidate.address)
            b_member = _member(db_session, protocol_b, member_addr_b, implementation=candidate.address)
        else:
            b_member = _member(db_session, protocol_b, member_addr_b, implementation=candidate.address)
            a_member = _member(db_session, protocol_a, member_addr_a, implementation=candidate.address)
        db_session.commit()

        gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(a_member.id, b_member.id)))
        db_session.commit()
        db_session.refresh(candidate)

        # Nominated-slot-first: A wins in BOTH arrival orders.
        assert candidate.protocol_id == protocol_a.id, arrival
        assert candidate.nominated_protocol_id == protocol_a.id, arrival


def test_existing_member_never_flipped_by_foreign_evidence(db_session):
    """promote()'s existing-membership guard: a proven A-member named by B's
    member edge stays an A-member."""
    protocol_a = _protocol(db_session, "keep-a")
    protocol_b = _protocol(db_session, "flip-b")
    a_member = _member(db_session, protocol_a, _addr(0xE0))
    b_member = _member(db_session, protocol_b, _addr(0xE1), implementation=a_member.address)
    db_session.commit()

    result = gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(b_member.id,)))
    db_session.commit()
    db_session.refresh(a_member)

    assert a_member.protocol_id == protocol_a.id
    assert a_member.id not in result.promoted_contract_ids


def test_demotion_restore_coherent_after_cross_protocol_promotion(db_session):
    """After an A-slotted candidate promotes to B, a demotion restores the
    ALIGNED slot (B), never the stale foreign one."""
    protocol_a = _protocol(db_session, "demote-a")
    protocol_b = _protocol(db_session, "demote-b")
    candidate = _contract(db_session, _addr(0xE4))
    gate.nominate(db_session, contract=candidate, protocol_id=protocol_a.id, source_tag="inventory")
    _code_fact(db_session, candidate.address)
    b_member = _member(db_session, protocol_b, _addr(0xE5), implementation=candidate.address)
    db_session.commit()

    gate.evaluate(db_session, gate.FactsDelta(new_member_contract_ids=(b_member.id,)))
    db_session.commit()
    db_session.refresh(candidate)
    assert candidate.protocol_id == protocol_b.id

    gate.demote_member(db_session, contract=candidate, reason="test_demotion")
    db_session.commit()
    db_session.refresh(candidate)
    assert candidate.protocol_id is None
    assert candidate.nominated_protocol_id == protocol_b.id


def test_w5_assertion_for_b_on_a_slotted_candidate_admits_via_fixpoint(db_session):
    """The W5 admin path on an A-slotted candidate: nominate() records the
    W5-for-B witness (slot stays A, first-wins) and the fixpoint's
    evidence-keyed admission binds W1 from the persisted code probe and
    promotes to B."""
    protocol_a = _protocol(db_session, "w5-a")
    protocol_b = _protocol(db_session, "w5-b")
    candidate = _contract(db_session, _addr(0xE8))
    gate.nominate(db_session, contract=candidate, protocol_id=protocol_a.id, source_tag="inventory")
    _code_fact(db_session, candidate.address)
    gate.nominate(
        db_session,
        contract=candidate,
        protocol_id=protocol_b.id,
        source_tag="admin_submission",
        human_assertion=gate.HumanAssertion(
            actor="admin_api_key", asserted_at=datetime(2026, 8, 24, tzinfo=timezone.utc)
        ),
    )
    db_session.commit()
    db_session.refresh(candidate)
    assert candidate.nominated_protocol_id == protocol_a.id  # slot stays first-wins

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(candidate.id,)))
    db_session.commit()
    db_session.refresh(candidate)

    assert candidate.protocol_id == protocol_b.id
    assert candidate.nominated_protocol_id == protocol_b.id
