"""Gate-aware protocol-dedup merge (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.2).

Invariant 1 through ``_merge_protocol_into``: contract membership, witness
rows, and deployer-registry rows all move to the destination protocol in one
transaction. The (protocol_id, …) unique keys on
``contract_membership_witnesses`` / ``protocol_deployers`` mean a src+dst
pair can hold the same key — the destination row survives, preferring the
active observation over a revoked one.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from db.models import (
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W5_HUMAN,
    Contract,
    ContractMembershipWitness,
    MonitoringEnrollmentQueue,
    Protocol,
    ProtocolDeployer,
    ProtocolScoreQueue,
)
from db.queue.discovery import _merge_protocol_into
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]


@pytest.fixture()
def two_protocols(db_session):
    src = Protocol(name=f"merge-src-{uuid.uuid4().hex[:12]}")
    dst = Protocol(name=f"merge-dst-{uuid.uuid4().hex[:12]}")
    db_session.add_all([src, dst])
    db_session.flush()
    return src, dst


def _contract(session, addr: str, **kw) -> Contract:
    row = Contract(address=addr.lower(), chain="ethereum", **kw)
    session.add(row)
    session.flush()
    return row


def _w2(
    session,
    *,
    contract: Contract,
    protocol_id: int,
    member: Contract,
    via: str,
    edge_kind: str = "implementation",
) -> ContractMembershipWitness:
    return gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        via_address=via,
        evidence=gate.w2_evidence(
            edge_kind=edge_kind,
            member_contract_id=member.id,
            member_address=member.address,
            resolved_pointer=contract.address,
        ),
    )


def _w5(session, *, contract: Contract, protocol_id: int, actor: str) -> ContractMembershipWitness:
    return gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W5_HUMAN,
        evidence=gate.w5_evidence(actor=actor, asserted_at=datetime(2026, 8, 1, tzinfo=timezone.utc)),
    )


def _deployer(session, *, protocol_id: int, address: str) -> ProtocolDeployer:
    row = ProtocolDeployer(
        protocol_id=protocol_id,
        address=address.lower(),
        trust_class="A",
        evidence={"perimeter_fact": {"kind": "controller_value"}, "checked_at": "2026-08-01T00:00:00+00:00"},
    )
    session.add(row)
    session.flush()
    return row


def test_merge_moves_membership_and_nominations(db_session, two_protocols):
    src, dst = two_protocols
    member = _contract(db_session, ADDR(0x3A01), protocol_id=src.id, nominated_protocol_id=src.id)
    candidate = _contract(db_session, ADDR(0x3A02), nominated_protocol_id=src.id)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    assert db_session.get(Protocol, src.id) is None
    assert db_session.get(Contract, member.id).protocol_id == dst.id
    # nominated_protocol_id is rewritten, never SET-NULLed by the src delete.
    assert db_session.get(Contract, member.id).nominated_protocol_id == dst.id
    assert db_session.get(Contract, candidate.id).nominated_protocol_id == dst.id


def test_merge_rewrites_noncolliding_witnesses(db_session, two_protocols):
    src, dst = two_protocols
    member = _contract(db_session, ADDR(0x3B01), protocol_id=src.id)
    subject = _contract(db_session, ADDR(0x3B02), nominated_protocol_id=src.id)
    row = _w2(db_session, contract=subject, protocol_id=src.id, member=member, via=member.address)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    moved = db_session.get(ContractMembershipWitness, row.id)
    assert moved is not None
    assert moved.protocol_id == dst.id
    assert moved.revoked_at is None


def test_merge_witness_collision_both_active_keeps_dst(db_session, two_protocols):
    src, dst = two_protocols
    member = _contract(db_session, ADDR(0x3C01), protocol_id=dst.id)
    subject = _contract(db_session, ADDR(0x3C02), nominated_protocol_id=src.id)
    src_row = _w2(db_session, contract=subject, protocol_id=src.id, member=member, via=member.address)
    dst_row = _w2(db_session, contract=subject, protocol_id=dst.id, member=member, via=member.address)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    survivors = (
        db_session.query(ContractMembershipWitness)
        .filter(
            ContractMembershipWitness.contract_id == subject.id,
            ContractMembershipWitness.rule == WITNESS_RULE_W2_STRUCTURAL,
        )
        .all()
    )
    assert [w.id for w in survivors] == [dst_row.id]
    assert survivors[0].protocol_id == dst.id
    assert survivors[0].revoked_at is None
    assert db_session.get(ContractMembershipWitness, src_row.id) is None


def test_merge_witness_collision_active_src_rearms_revoked_dst(db_session, two_protocols):
    src, dst = two_protocols
    member = _contract(db_session, ADDR(0x3D01), protocol_id=dst.id)
    subject = _contract(db_session, ADDR(0x3D02), nominated_protocol_id=src.id)
    src_row = _w2(db_session, contract=subject, protocol_id=src.id, member=member, via=member.address)
    # Same key, distinguishable evidence — proves the surviving row carries
    # the active observation's evidence, not its own stale copy.
    dst_row = _w2(
        db_session, contract=subject, protocol_id=dst.id, member=member, via=member.address, edge_kind="beacon"
    )
    assert gate.revoke_witness(db_session, dst_row, reason="test_setup")
    db_session.flush()
    src_evidence = dict(src_row.evidence)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    survivor = db_session.get(ContractMembershipWitness, dst_row.id)
    assert survivor is not None
    # The active observation wins: the surviving dst row is re-armed with the
    # src row's evidence rather than staying revoked.
    assert survivor.revoked_at is None
    assert survivor.evidence == src_evidence
    assert db_session.get(ContractMembershipWitness, src_row.id) is None


def test_merge_witness_collision_revoked_src_keeps_active_dst_untouched(db_session, two_protocols):
    src, dst = two_protocols
    member = _contract(db_session, ADDR(0x3E01), protocol_id=dst.id)
    subject = _contract(db_session, ADDR(0x3E02), nominated_protocol_id=src.id)
    src_row = _w2(db_session, contract=subject, protocol_id=src.id, member=member, via=member.address)
    assert gate.revoke_witness(db_session, src_row, reason="test_setup")
    dst_row = _w2(db_session, contract=subject, protocol_id=dst.id, member=member, via=member.address)
    db_session.flush()
    dst_evidence = dict(dst_row.evidence)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    survivor = db_session.get(ContractMembershipWitness, dst_row.id)
    assert survivor is not None
    assert survivor.revoked_at is None
    assert survivor.evidence == dst_evidence
    assert db_session.get(ContractMembershipWitness, src_row.id) is None


def test_merge_witness_collision_on_via_less_rule(db_session, two_protocols):
    # The no-via partial unique key ((contract, protocol, rule) where
    # via IS NULL) collides exactly like the with-via key.
    src, dst = two_protocols
    subject = _contract(db_session, ADDR(0x3F01), nominated_protocol_id=src.id)
    src_row = _w5(db_session, contract=subject, protocol_id=src.id, actor="admin-src")
    dst_row = _w5(db_session, contract=subject, protocol_id=dst.id, actor="admin-dst")

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    survivors = (
        db_session.query(ContractMembershipWitness)
        .filter(
            ContractMembershipWitness.contract_id == subject.id,
            ContractMembershipWitness.rule == WITNESS_RULE_W5_HUMAN,
        )
        .all()
    )
    assert [w.id for w in survivors] == [dst_row.id]
    assert db_session.get(ContractMembershipWitness, src_row.id) is None


def test_merge_deployer_collision_keeps_dst_row(db_session, two_protocols):
    src, dst = two_protocols
    shared = ADDR(0x4A01)
    src_only = ADDR(0x4A02)
    src_shared = _deployer(db_session, protocol_id=src.id, address=shared)
    dst_shared = _deployer(db_session, protocol_id=dst.id, address=shared)
    src_solo = _deployer(db_session, protocol_id=src.id, address=src_only)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    rows = db_session.query(ProtocolDeployer).filter(ProtocolDeployer.protocol_id == dst.id).all()
    by_address = {r.address: r for r in rows}
    # Post-merge src and dst are the same protocol, so the invariant-7
    # collision resolves to ONE surviving row per address.
    assert by_address[shared].id == dst_shared.id
    assert by_address[src_only].id == src_solo.id
    assert db_session.get(ProtocolDeployer, src_shared.id) is None


def test_merge_marks_dst_dirty_when_members_move(db_session, two_protocols):
    src, dst = two_protocols
    _contract(db_session, ADDR(0x4B01), protocol_id=src.id)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    assert db_session.get(MonitoringEnrollmentQueue, dst.id) is not None
    assert db_session.get(ProtocolScoreQueue, dst.id) is not None


def test_merge_without_members_marks_nothing(db_session, two_protocols):
    src, dst = two_protocols
    _contract(db_session, ADDR(0x4C01), nominated_protocol_id=src.id)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    assert db_session.get(MonitoringEnrollmentQueue, dst.id) is None
    assert db_session.get(ProtocolScoreQueue, dst.id) is None
