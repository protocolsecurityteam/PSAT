"""Gate-aware protocol-dedup merge.

Through ``_merge_protocol_into``: contract membership, witness
rows, and deployer-registry rows all move to the destination protocol in one
transaction. The (protocol_id, …) unique keys on
``contract_membership_witnesses`` / ``protocol_deployers`` mean a src+dst
pair can hold the same key — the destination row survives. A revoked witness
row is re-armed only by an observation postdating the revocation; a revoked
deployer row wins conservatively and its demotion cascade runs.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from db.models import (
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W4_DEPLOYER,
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


def _deployer(
    session,
    *,
    protocol_id: int,
    address: str,
    evidence: dict | None = None,
    revoked_at: datetime | None = None,
    revocation_reason: str | None = None,
) -> ProtocolDeployer:
    row = ProtocolDeployer(
        protocol_id=protocol_id,
        address=address.lower(),
        trust_class="A",
        evidence=evidence
        or {"perimeter_fact": {"kind": "controller_value"}, "checked_at": "2026-08-01T00:00:00+00:00"},
        revoked_at=revoked_at,
        revocation_reason=revocation_reason,
    )
    session.add(row)
    session.flush()
    return row


def _w4(session, *, contract: Contract, protocol_id: int, deployer_row: ProtocolDeployer) -> ContractMembershipWitness:
    return gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W4_DEPLOYER,
        via_address=deployer_row.address,
        evidence=gate.w4_evidence(
            deployer_address=deployer_row.address,
            deployer_registry_id=deployer_row.id,
            creation_tx_hash="0x" + "ab" * 32,
            creation_block=123,
        ),
    )


def test_merge_witness_collision_active_src_rearms_revoked_dst(db_session, two_protocols):
    src, dst = two_protocols
    member = _contract(db_session, ADDR(0x3D01), protocol_id=dst.id)
    subject = _contract(db_session, ADDR(0x3D02), nominated_protocol_id=src.id)
    src_row = _w2(db_session, contract=subject, protocol_id=src.id, member=member, via=member.address)
    # Distinguishable evidence proves which observation the survivor carries.
    dst_row = _w2(
        db_session, contract=subject, protocol_id=dst.id, member=member, via=member.address, edge_kind="beacon"
    )
    assert gate.revoke_witness(db_session, dst_row, reason="test_setup")
    revoked_at = dst_row.revoked_at
    assert revoked_at is not None
    src_row.observed_at = revoked_at + timedelta(minutes=5)
    db_session.flush()
    src_evidence = dict(src_row.evidence)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    survivor = db_session.get(ContractMembershipWitness, dst_row.id)
    assert survivor is not None
    assert survivor.revoked_at is None
    assert survivor.evidence == src_evidence
    assert db_session.get(ContractMembershipWitness, src_row.id) is None


def test_merge_witness_collision_revoked_src_keeps_active_dst_untouched(db_session, two_protocols):
    src, dst = two_protocols
    member = _contract(db_session, ADDR(0x3E01), protocol_id=dst.id)
    subject = _contract(db_session, ADDR(0x3E02), nominated_protocol_id=src.id)
    src_row = _w2(
        db_session, contract=subject, protocol_id=src.id, member=member, via=member.address, edge_kind="beacon"
    )
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


def test_merge_deployer_revoked_dst_stays_revoked_and_cascades(db_session, two_protocols):
    # Shape (a): dst's registry row is revoked, src's is active. Revoked wins
    # conservatively; the moved W4 witness is revoked and the member resting
    # only on it is demoted.
    src, dst = two_protocols
    shared = ADDR(0x4D01)
    revoked_at = datetime(2026, 8, 10, tzinfo=timezone.utc)
    dst_dep = _deployer(
        db_session,
        protocol_id=dst.id,
        address=shared,
        revoked_at=revoked_at,
        revocation_reason="dst_reason",
    )
    src_dep = _deployer(db_session, protocol_id=src.id, address=shared)
    member = _contract(
        db_session, ADDR(0x4D02), protocol_id=src.id, nominated_protocol_id=src.id, deployer=shared.lower()
    )
    w4 = _w4(db_session, contract=member, protocol_id=src.id, deployer_row=src_dep)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    survivor = db_session.get(ProtocolDeployer, dst_dep.id)
    assert survivor is not None
    assert survivor.revoked_at is not None
    assert survivor.revocation_reason == "dst_reason"
    assert db_session.get(ProtocolDeployer, src_dep.id) is None
    moved_w4 = db_session.get(ContractMembershipWitness, w4.id)
    assert moved_w4 is not None
    assert moved_w4.protocol_id == dst.id
    assert moved_w4.revoked_at is not None
    demoted = db_session.get(Contract, member.id)
    assert demoted.protocol_id is None
    assert demoted.nominated_protocol_id == dst.id


def test_merge_deployer_revoked_src_revokes_dst_and_cascades(db_session, two_protocols):
    # Shape (b): src's registry row is revoked, dst's is active. Negative
    # evidence survives the merge — the surviving dst row adopts src's
    # revocation and dst's dependent members are demoted.
    src, dst = two_protocols
    shared = ADDR(0x4E01)
    src_evidence = {"reason": "foreign_creation_observed", "checked_at": "2026-08-10T00:00:00+00:00"}
    src_dep = _deployer(
        db_session,
        protocol_id=src.id,
        address=shared,
        evidence=src_evidence,
        revoked_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
        revocation_reason="src_reason",
    )
    dst_dep = _deployer(db_session, protocol_id=dst.id, address=shared)
    member = _contract(
        db_session, ADDR(0x4E02), protocol_id=dst.id, nominated_protocol_id=dst.id, deployer=shared.lower()
    )
    w4 = _w4(db_session, contract=member, protocol_id=dst.id, deployer_row=dst_dep)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    db_session.expire_all()
    survivor = db_session.get(ProtocolDeployer, dst_dep.id)
    assert survivor is not None
    assert survivor.revoked_at is not None
    assert survivor.revocation_reason == "src_reason"
    assert survivor.evidence == src_evidence
    assert db_session.get(ProtocolDeployer, src_dep.id) is None
    revoked_w4 = db_session.get(ContractMembershipWitness, w4.id)
    assert revoked_w4 is not None
    assert revoked_w4.revoked_at is not None
    demoted = db_session.get(Contract, member.id)
    assert demoted.protocol_id is None
    assert demoted.nominated_protocol_id == dst.id


def test_merge_marks_dst_dirty_when_members_move(db_session, two_protocols):
    src, dst = two_protocols
    _contract(db_session, ADDR(0x4B01), protocol_id=src.id)

    _merge_protocol_into(db_session, src=src, dst=dst)
    db_session.commit()

    assert db_session.get(MonitoringEnrollmentQueue, dst.id) is not None
    assert db_session.get(ProtocolScoreQueue, dst.id) is not None
