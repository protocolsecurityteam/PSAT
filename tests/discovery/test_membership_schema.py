"""Membership-gate schema assertions (migration b7d3e9a02c51, spec §4)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from db.models import Contract, ContractMembershipWitness, OpsKv, Protocol, ProtocolDeployer
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]


def _protocol(session) -> Protocol:
    row = Protocol(name=f"proto-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def test_contracts_nominated_protocol_id_column(db_session):
    inspector = inspect(db_session.get_bind())
    columns = {c["name"]: c for c in inspector.get_columns("contracts")}
    assert "nominated_protocol_id" in columns
    assert columns["nominated_protocol_id"]["nullable"] is True
    fks = inspector.get_foreign_keys("contracts")
    nominated_fk = [fk for fk in fks if fk["constrained_columns"] == ["nominated_protocol_id"]]
    assert nominated_fk and nominated_fk[0]["referred_table"] == "protocols"
    assert nominated_fk[0]["options"].get("ondelete") == "SET NULL"
    index_names = {ix["name"] for ix in inspector.get_indexes("contracts")}
    assert "ix_contracts_nominated_protocol_id" in index_names


def test_witness_table_shape(db_session):
    inspector = inspect(db_session.get_bind())
    columns = {c["name"] for c in inspector.get_columns("contract_membership_witnesses")}
    assert columns >= {
        "id",
        "contract_id",
        "protocol_id",
        "rule",
        "via_address",
        "evidence",
        "observed_at",
        "revoked_at",
    }
    checks = {c["name"] for c in inspector.get_check_constraints("contract_membership_witnesses")}
    assert "ck_contract_membership_witnesses_rule" in checks
    indexes = {ix["name"]: ix for ix in inspector.get_indexes("contract_membership_witnesses")}
    assert indexes["uq_membership_witness_with_via"]["unique"] is True
    assert indexes["uq_membership_witness_no_via"]["unique"] is True


def test_witness_unique_covers_null_via(db_session):
    # Postgres NULL != NULL would admit duplicate via-less rows under a plain
    # composite unique; the partial-index pair must reject them.
    protocol = _protocol(db_session)
    row = Contract(address=ADDR(0x300), chain="ethereum", nominated_protocol_id=protocol.id)
    db_session.add(row)
    db_session.flush()
    db_session.add(
        ContractMembershipWitness(
            contract_id=row.id, protocol_id=protocol.id, rule="w1_code", evidence={"code_present": True}
        )
    )
    db_session.flush()
    db_session.add(
        ContractMembershipWitness(
            contract_id=row.id, protocol_id=protocol.id, rule="w1_code", evidence={"code_present": True}
        )
    )
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_witness_rule_vocabulary_enforced(db_session):
    protocol = _protocol(db_session)
    row = Contract(address=ADDR(0x301), chain="ethereum", nominated_protocol_id=protocol.id)
    db_session.add(row)
    db_session.flush()
    db_session.add(
        ContractMembershipWitness(contract_id=row.id, protocol_id=protocol.id, rule="w9_vibes", evidence={"x": 1})
    )
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_protocol_deployers_shape(db_session):
    inspector = inspect(db_session.get_bind())
    columns = {c["name"] for c in inspector.get_columns("protocol_deployers")}
    assert columns >= {
        "id",
        "protocol_id",
        "address",
        "trust_class",
        "evidence",
        "observed_at",
        "revoked_at",
        "revocation_reason",
    }
    uniques = {u["name"] for u in inspector.get_unique_constraints("protocol_deployers")}
    assert "uq_protocol_deployers_protocol_address" in uniques
    checks = {c["name"] for c in inspector.get_check_constraints("protocol_deployers")}
    assert "ck_protocol_deployers_trust_class" in checks


def test_protocol_deployers_rejects_class_c_rows(db_session):
    # Class C is the ABSENCE of a row (invariant 7) — the CHECK refuses a third value.
    protocol = _protocol(db_session)
    db_session.add(ProtocolDeployer(protocol_id=protocol.id, address=ADDR(0x302), trust_class="C", evidence={"x": 1}))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_probe_attempts_and_ops_kv_exist(db_session):
    inspector = inspect(db_session.get_bind())
    probe_columns = {c["name"] for c in inspector.get_columns("contract_probe_attempts")}
    assert probe_columns >= {"contract_id", "chain_id", "block_number", "results", "probed_at"}
    kv_columns = {c["name"] for c in inspector.get_columns("ops_kv")}
    assert kv_columns >= {"key", "value", "updated_at"}


def test_ops_kv_roundtrip(db_session):
    key = f"test_marker_{uuid.uuid4().hex[:8]}"
    db_session.add(OpsKv(key=key, value={"enabled_chains_seen": [1, 8453]}))
    db_session.flush()
    row = db_session.get(OpsKv, key)
    assert row is not None
    assert row.value == {"enabled_chains_seen": [1, 8453]}
    db_session.delete(row)
    db_session.flush()
