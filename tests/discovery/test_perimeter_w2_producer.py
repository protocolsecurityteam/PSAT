"""Perimeter W2 producer (spec §3.2/§5.2): ``_structural_ownership``'s verified
edges become witness rows + gate promotion — never a stamped ``protocol_id``.
"""

from __future__ import annotations

import uuid

from db.models import (
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W2_STRUCTURAL,
    Contract,
    ContractMembershipWitness,
    Protocol,
)
from services.discovery import membership_gate as gate
from services.discovery.perimeter import _produce_structural_witnesses, produce_structural_witness
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]


def _protocol(session) -> Protocol:
    row = Protocol(name=f"proto-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _contract(session, address: str, **kwargs) -> Contract:
    row = Contract(address=address.lower(), chain=kwargs.pop("chain", "ethereum"), **kwargs)
    session.add(row)
    session.flush()
    return row


def _witnesses(session, contract_id: int) -> list[ContractMembershipWitness]:
    return (
        session.query(ContractMembershipWitness)
        .filter_by(contract_id=contract_id, rule=WITNESS_RULE_W2_STRUCTURAL)
        .all()
    )


def test_w2_written_only_from_member_parents_stored_pointer(db_session):
    protocol = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x400))

    non_member = _contract(db_session, ADDR(0x401), implementation=candidate.address)
    assert (
        produce_structural_witness(
            db_session, candidate=candidate, parent=non_member, protocol_id=None, relationship="implementation"
        )
        is None
    )

    member_wrong_pointer = _contract(db_session, ADDR(0x402), protocol_id=protocol.id, implementation=ADDR(0x999))
    assert (
        produce_structural_witness(
            db_session,
            candidate=candidate,
            parent=member_wrong_pointer,
            protocol_id=protocol.id,
            relationship="implementation",
        )
        is None
    )
    assert _witnesses(db_session, candidate.id) == []

    member = _contract(db_session, ADDR(0x403), protocol_id=protocol.id, implementation=candidate.address)
    assert (
        produce_structural_witness(
            db_session, candidate=candidate, parent=member, protocol_id=protocol.id, relationship="implementation"
        )
        == "implementation"
    )
    rows = _witnesses(db_session, candidate.id)
    assert len(rows) == 1
    assert rows[0].via_address == member.address
    assert rows[0].evidence["resolved_pointer"] == candidate.address


def test_w2_protocol_mismatch_and_chain_mismatch_admit_nothing(db_session):
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    candidate = _contract(db_session, ADDR(0x410))
    member_other_protocol = _contract(db_session, ADDR(0x411), protocol_id=p2.id, implementation=candidate.address)
    assert (
        produce_structural_witness(
            db_session,
            candidate=candidate,
            parent=member_other_protocol,
            protocol_id=p1.id,
            relationship="implementation",
        )
        is None
    )
    # A CREATE2 twin's pointer on another chain is not evidence on this one.
    member_other_chain = _contract(
        db_session, ADDR(0x412), chain="base", protocol_id=p1.id, implementation=candidate.address
    )
    assert (
        produce_structural_witness(
            db_session,
            candidate=candidate,
            parent=member_other_chain,
            protocol_id=p1.id,
            relationship="implementation",
        )
        is None
    )
    assert _witnesses(db_session, candidate.id) == []


def test_w2_proxy_direction_requires_candidate_back_link(db_session):
    protocol = _protocol(db_session)
    member_impl = _contract(db_session, ADDR(0x420), protocol_id=protocol.id)
    proxy = _contract(db_session, ADDR(0x421), is_proxy=True, implementation=member_impl.address)
    assert (
        produce_structural_witness(
            db_session, candidate=proxy, parent=member_impl, protocol_id=protocol.id, relationship="proxy"
        )
        == "proxy"
    )
    rows = _witnesses(db_session, proxy.id)
    assert len(rows) == 1 and rows[0].evidence["edge_kind"] == "proxy"

    stray = _contract(db_session, ADDR(0x422), is_proxy=True, implementation=ADDR(0x999))
    assert (
        produce_structural_witness(
            db_session, candidate=stray, parent=member_impl, protocol_id=protocol.id, relationship="proxy"
        )
        is None
    )


def test_witness_pass_nominates_and_promotes_w1_holders_only(db_session):
    protocol = _protocol(db_session)
    parent = _contract(db_session, ADDR(0x430), protocol_id=protocol.id, implementation=ADDR(0x431))

    with_w1 = _contract(db_session, ADDR(0x431))
    gate.write_witness(
        db_session,
        contract_id=with_w1.id,
        protocol_id=protocol.id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=44),
    )
    without_w1 = _contract(db_session, ADDR(0x432), is_proxy=True, implementation=parent.address)
    db_session.flush()

    _produce_structural_witnesses(
        db_session,
        parent,
        {with_w1.address: "implementation", without_w1.address: "proxy"},
    )

    # Both nominated + witnessed; only the W1 holder promotes (invariant 3).
    assert with_w1.nominated_protocol_id == protocol.id
    assert with_w1.protocol_id == protocol.id
    assert without_w1.nominated_protocol_id == protocol.id
    assert without_w1.protocol_id is None
    assert len(_witnesses(db_session, with_w1.id)) == 1
    assert len(_witnesses(db_session, without_w1.id)) == 1
