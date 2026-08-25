"""Reconcile CLI (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.4, invariant 13):
verdicts recomputed from stored witnesses with EDGE VALIDITY re-verified —
zero drift on a freshly gated DB; seeded drift detected in report and fixed by
apply; the report is read-only.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, text

from db.models import (
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ControllerValue,
    Protocol,
    ProtocolDeployer,
)
from scripts.reconcile_membership import (
    DRIFT_CANDIDATE_WITH_EVIDENCE,
    DRIFT_MEMBER_NO_EVIDENCE,
    apply_fixes,
    audit,
)
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]

_TX = "0x" + "ab" * 32


def _protocol(session) -> Protocol:
    row = Protocol(name=f"proto-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _contract(session, address: str, **fields) -> Contract:
    row = Contract(address=address.lower(), chain=fields.pop("chain", "ethereum"), **fields)
    session.add(row)
    session.flush()
    return row


def _code_fact(session, address: str, *, absent: bool = False, tx: str | None = None) -> None:
    session.add(
        ContractCreationWitness(
            chain_id=1,
            address=address.lower(),
            code_probe_block=50,
            code_absent_at_probe=absent,
            creation_tx_hash=tx,
            creation_block=10 if tx else None,
        )
    )
    session.flush()


def _gate_member(session, protocol: Protocol, address: str, **fields) -> Contract:
    """A member earned through the gate itself: W5 nomination + fixpoint."""
    row = _contract(session, address, nominated_protocol_id=protocol.id, **fields)
    _code_fact(session, row.address)
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="test", asserted_at=datetime.now()),
    )
    result = gate.evaluate(session, gate.FactsDelta(recheck_contract_ids=(row.id,)))
    assert row.id in result.promoted_contract_ids
    return row


def _freshly_gated(session):
    """Members + a parked candidate, all through gate paths."""
    protocol = _protocol(session)
    anchor = _gate_member(session, protocol, ADDR(1))
    proxy = _contract(session, ADDR(2), nominated_protocol_id=protocol.id, implementation=anchor.address)
    _code_fact(session, proxy.address)
    result = gate.evaluate(session, gate.FactsDelta(recheck_contract_ids=(proxy.id,)))
    assert proxy.id in result.promoted_contract_ids
    parked = _contract(session, ADDR(3), nominated_protocol_id=protocol.id)
    _code_fact(session, parked.address)
    return protocol, anchor, proxy, parked


def test_zero_drift_on_freshly_gated_db(db_session):
    _freshly_gated(db_session)
    assert audit(db_session) == []


def test_full_ladder_gated_db_reconciles_zero_drift(db_session):
    """Invariant-13 handshake: a DB whose every membership fact was earned
    through the gate's own primitives — W5 anchor, W2 impl, a Class-A registry
    row earned by the ladder plus its W4 member, a revoked-and-demoted row,
    and a parked candidate — reconciles with zero drift."""
    protocol = _protocol(db_session)
    deployer = ADDR(0xE5)

    anchor = _contract(db_session, ADDR(20), nominated_protocol_id=protocol.id, implementation=ADDR(21))
    _code_fact(db_session, anchor.address)
    db_session.add(
        ControllerValue(
            contract_id=anchor.id, controller_id="owner", value=deployer, authority_provenance="caller_gate"
        )
    )
    gate.write_witness(
        db_session,
        contract_id=anchor.id,
        protocol_id=protocol.id,
        rule="w5_human",
        evidence=gate.w5_evidence(actor="test", asserted_at=datetime.now()),
    )
    impl = _contract(db_session, ADDR(21), nominated_protocol_id=protocol.id)
    _code_fact(db_session, impl.address)
    result = gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(anchor.id, impl.id)))
    assert {anchor.id, impl.id} <= set(result.promoted_contract_ids)

    # The ladder itself earns the Class-A row (perimeter fact = the anchor's
    # controller value), then W4 admits the deployer's creation.
    w4_member = _contract(db_session, ADDR(22), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, w4_member.address, tx=_TX)
    result = gate.evaluate(
        db_session,
        gate.FactsDelta(recheck_contract_ids=(w4_member.id,), changed_deployer_addresses=(deployer,)),
    )
    assert w4_member.id in result.promoted_contract_ids
    registry = db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == deployer)).scalar_one()
    assert registry.trust_class == "A" and registry.revoked_at is None

    demoted = _gate_member(db_session, protocol, ADDR(23))
    for witness in gate.active_witnesses(db_session, contract_id=demoted.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, witness, reason="test_revocation")
    gate.demote_member(db_session, contract=demoted, reason="test_demotion")

    parked = _contract(db_session, ADDR(24), nominated_protocol_id=protocol.id)
    _code_fact(db_session, parked.address)

    assert anchor.protocol_id == protocol.id and impl.protocol_id == protocol.id
    assert w4_member.protocol_id == protocol.id
    assert demoted.protocol_id is None and parked.protocol_id is None
    assert audit(db_session) == []


def test_audit_is_read_only(db_session):
    protocol, anchor, proxy, parked = _freshly_gated(db_session)
    # Seed drift so the savepoint verdict paths actually run.
    anchor.protocol_id = None
    db_session.flush()
    db_session.commit()
    before = db_session.execute(text("SELECT * FROM contracts")).all()
    witnesses_before = db_session.execute(text("SELECT * FROM contract_membership_witnesses")).all()

    drifts = audit(db_session)
    assert drifts  # non-trivial audit

    assert db_session.execute(text("SELECT * FROM contracts")).all() == before
    assert db_session.execute(text("SELECT * FROM contract_membership_witnesses")).all() == witnesses_before


def test_manually_flipped_stamp_detected_and_fixed(db_session):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(4), nominated_protocol_id=protocol.id)
    _code_fact(db_session, row.address)
    # Out-of-band stamp with no witness rows — the exact drift shape
    # invariant 1 forbids.
    row.protocol_id = protocol.id
    db_session.flush()

    drifts = audit(db_session)
    assert [(d.kind, d.contract_id) for d in drifts] == [(DRIFT_MEMBER_NO_EVIDENCE, row.id)]

    apply_fixes(db_session, drifts)
    assert row.protocol_id is None and row.nominated_protocol_id == protocol.id
    assert audit(db_session) == []


def test_witness_with_demoted_via_member_counts_as_invalid(db_session):
    # Edge validity (invariant 13): the dependent's W2 row is still ACTIVE,
    # but its via-member was demoted — presence is not validity.
    protocol, anchor, proxy, _parked = _freshly_gated(db_session)
    for witness in gate.active_witnesses(db_session, contract_id=anchor.id, protocol_id=protocol.id):
        gate.revoke_witness(db_session, witness, reason="test_revocation")
    gate.demote_member(db_session, contract=anchor, reason="test_demotion")
    db_session.flush()

    drifts = audit(db_session)
    assert [(d.kind, d.contract_id) for d in drifts] == [(DRIFT_MEMBER_NO_EVIDENCE, proxy.id)]
    assert drifts[0].detail["missing"] == "via_fact_not_held"
    assert drifts[0].detail["via"] == anchor.address

    apply_fixes(db_session, drifts)
    assert proxy.protocol_id is None and proxy.nominated_protocol_id == protocol.id
    w2 = [
        w
        for w in db_session.execute(
            select(ContractMembershipWitness).where(ContractMembershipWitness.contract_id == proxy.id)
        ).scalars()
        if w.rule == "w2_structural"
    ]
    assert w2 and all(w.revoked_at is not None for w in w2)
    assert audit(db_session) == []


def test_cleared_stamp_with_valid_witnesses_repromoted(db_session):
    protocol, anchor, _proxy, _parked = _freshly_gated(db_session)
    # Out-of-band clear: witnesses stay valid, stamp vanished.
    anchor.protocol_id = None
    db_session.flush()

    drifts = audit(db_session)
    kinds = {(d.kind, d.contract_id) for d in drifts}
    assert (DRIFT_CANDIDATE_WITH_EVIDENCE, anchor.id) in kinds
    anchor_drift = next(d for d in drifts if d.contract_id == anchor.id)
    assert "w5_human" in anchor_drift.detail["rules"]

    apply_fixes(db_session, drifts)
    assert anchor.protocol_id == protocol.id
    # The proxy's transient member_without_evidence drift resolved when the
    # anchor re-promoted within the same pass — it must not be demoted.
    assert _proxy.protocol_id == protocol.id
    assert audit(db_session) == []


def test_parked_candidate_is_not_drift(db_session):
    protocol = _protocol(db_session)
    parked = _contract(db_session, ADDR(9), nominated_protocol_id=protocol.id)
    _code_fact(db_session, parked.address)
    pruned = _contract(db_session, ADDR(10), nominated_protocol_id=protocol.id)
    _code_fact(db_session, pruned.address, absent=True)
    assert audit(db_session) == []


# ---------------------------------------------------------------------------
# CLI exit codes (report drift = 1; apply residual = 1; clean = 0)
# ---------------------------------------------------------------------------


def _bind_cli_session(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    import scripts.reconcile_membership as reconcile_module
    from tests.conftest import DATABASE_URL

    engine = create_engine(DATABASE_URL)
    monkeypatch.setattr(reconcile_module, "SessionLocal", lambda: Session(engine))
    return reconcile_module


def test_cli_exit_codes_report_and_apply(db_session, monkeypatch):
    reconcile_module = _bind_cli_session(monkeypatch)
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(11), nominated_protocol_id=protocol.id)
    _code_fact(db_session, row.address)
    row.protocol_id = protocol.id  # out-of-band stamp, no witnesses
    db_session.commit()

    assert reconcile_module.main([]) == 1  # report mode: drift is nonzero exit
    assert reconcile_module.main(["--apply"]) == 0  # fixed and logged
    assert reconcile_module.main([]) == 0  # clean after the fix
    db_session.expire_all()
    fixed = db_session.get(Contract, row.id)
    assert fixed is not None and fixed.protocol_id is None and fixed.nominated_protocol_id == protocol.id


def test_cli_exit_1_when_drift_remains_after_apply_passes(db_session, monkeypatch):
    reconcile_module = _bind_cli_session(monkeypatch)
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(12), nominated_protocol_id=protocol.id)
    _code_fact(db_session, row.address)
    row.protocol_id = protocol.id
    db_session.commit()

    # A fix pass that fixes nothing leaves residual drift — the loop must
    # surface it as a failure, never a green exit.
    monkeypatch.setattr(reconcile_module, "apply_fixes", lambda session, drifts: 0)
    assert reconcile_module.main(["--apply"]) == 1
