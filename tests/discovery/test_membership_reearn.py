"""Re-earn migration end-to-end on fixture rows (DISCOVERY_MEMBERSHIP_GATE_SPEC.md
§5.3.3, §7 migration dry-run gate, invariant 12).

Covers: provenance-gated inventory→W5 conversion, W6 seeding gated on W1,
grounded re-earning (members without seed-grounded evidence demote — mutual
support is not an anchor), closest-miss evidence on every demotion, the
FULL-TABLE diff (cross-protocol cascade demotions appear in a scoped run's
report), two-pass registry-loss handling, enumeration-budget honesty,
report-mode writing nothing, apply-mode idempotence incl. registry rows,
pruned handling, and unclaimed rows staying untouched.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select, text

from db.models import (
    WITNESS_RULE_W4_DEPLOYER,
    WITNESS_RULE_W5_HUMAN,
    WITNESS_RULE_W6_LLAMA_SEED,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ControllerValue,
    Job,
    MonitoringEnrollmentQueue,
    Protocol,
    ProtocolDeployer,
    ProtocolScoreQueue,
)
from scripts.membership_reporting import closest_miss
from scripts.reconcile_membership import audit as reconcile_audit
from scripts.reearn_membership import CONVERSION_ACTOR, BudgetedEnumerator, run_reearn
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]

_TX = "0x" + "ab" * 32

_SNAPSHOT_TABLES = (
    "contracts",
    "contract_membership_witnesses",
    "protocol_deployers",
    "contract_creation_witnesses",
    "contract_probe_attempts",
    "monitoring_enrollment_queue",
    "protocol_score_queue",
)


def _snapshot(session) -> dict[str, list[tuple]]:
    out: dict[str, list[tuple]] = {}
    for table in _SNAPSHOT_TABLES:
        rows = session.execute(text(f"SELECT * FROM {table}")).all()
        out[table] = sorted((tuple(str(v) for v in row) for row in rows), key=str)
    return out


def _protocol(session, *, slug: str | None = None) -> Protocol:
    row = Protocol(name=f"proto-{uuid.uuid4().hex[:12]}", canonical_slug=slug)
    session.add(row)
    session.flush()
    return row


def _contract(session, address: str, **fields) -> Contract:
    row = Contract(address=address.lower(), chain=fields.pop("chain", "ethereum"), **fields)
    session.add(row)
    session.flush()
    return row


def _code_fact(session, address: str, *, chain_id: int = 1, absent: bool = False, tx: str | None = None) -> None:
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


def _admin_job(session, address: str, protocol_id: int) -> Job:
    """The legacy admin-submission provenance shape: router-stamped
    ``discovery_sources=["inventory"]`` + protocol linkage on the request."""
    job = Job(
        address=address.lower(),
        protocol_id=protocol_id,
        request={"address": address.lower(), "protocol_id": protocol_id, "discovery_sources": ["inventory"]},
    )
    session.add(job)
    session.flush()
    return job


def _inventory_contract(session, protocol: Protocol, address: str, **fields) -> Contract:
    """An admin-submitted legacy row: inventory tag + job provenance."""
    _admin_job(session, address, protocol.id)
    return _contract(session, address, discovery_sources=["inventory"], **fields)


def _registry_row(session, protocol: Protocol, address: str, *, trust_class: str = "A") -> ProtocolDeployer:
    row = ProtocolDeployer(
        protocol_id=protocol.id,
        address=address.lower(),
        trust_class=trust_class,
        evidence={"perimeter_fact": {"kind": "test_fixture"}, "checked_at": "2026-01-01T00:00:00+00:00"},
    )
    session.add(row)
    session.flush()
    return row


def _witness_rows(session, contract_id: int) -> list[ContractMembershipWitness]:
    return list(
        session.execute(
            select(ContractMembershipWitness).where(ContractMembershipWitness.contract_id == contract_id)
        ).scalars()
    )


# ---------------------------------------------------------------------------
# Conversions (§5.3.3 a/b)
# ---------------------------------------------------------------------------


def test_inventory_with_provenance_converts_to_w5_and_reearns(db_session):
    protocol = _protocol(db_session)
    row = _inventory_contract(db_session, protocol, ADDR(1), protocol_id=protocol.id, nominated_protocol_id=protocol.id)
    _code_fact(db_session, row.address)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert report.converted_w5 == [row.id]
    assert report.w5_provenance_missing == []
    assert row.protocol_id == protocol.id
    rules = {(w.rule, w.revoked_at is None) for w in _witness_rows(db_session, row.id)}
    assert (WITNESS_RULE_W5_HUMAN, True) in rules and ("w1_code", True) in rules
    w5 = next(w for w in _witness_rows(db_session, row.id) if w.rule == WITNESS_RULE_W5_HUMAN)
    assert w5.evidence["actor"] == CONVERSION_ACTOR
    assert report.counts["demote"] == 0


def test_inventory_tag_without_provenance_is_reported_not_converted(db_session):
    protocol = _protocol(db_session)
    # Tag only — the inventory SEARCH pipeline writes the same tag and
    # asserts nothing; no admin job exists for this address.
    row = _contract(
        db_session, ADDR(2), protocol_id=protocol.id, nominated_protocol_id=protocol.id, discovery_sources=["inventory"]
    )
    _code_fact(db_session, row.address)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert report.converted_w5 == []
    assert report.w5_provenance_missing == [row.id]
    assert report.counts["w5_skipped_no_provenance"] == 1
    skip_lines = [c for c in report.changes if c.kind == "w5skip"]
    assert [c.contract_id for c in skip_lines] == [row.id]
    assert skip_lines[0].detail == {"missing": "admin_provenance", "tag": "inventory"}
    assert not any(w.rule == WITNESS_RULE_W5_HUMAN for w in _witness_rows(db_session, row.id))
    # Without the assertion the row cannot re-earn.
    assert row.protocol_id is None and row.nominated_protocol_id == protocol.id


def test_w6_seeded_only_when_w1_passes(db_session):
    protocol = _protocol(db_session, slug="ether.fi")
    with_code = _contract(db_session, ADDR(3), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    _code_fact(db_session, with_code.address)
    no_code = _contract(db_session, ADDR(4), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    _code_fact(db_session, no_code.address, absent=True)
    unprobed = _contract(db_session, ADDR(5), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert report.seeded_w6 == [with_code.id]
    assert with_code.protocol_id == protocol.id
    w6 = next(w for w in _witness_rows(db_session, with_code.id) if w.rule == WITNESS_RULE_W6_LLAMA_SEED)
    assert w6.evidence["adapter_slug"] == "ether.fi"
    # Proven-absent stays pruned; not-probed stays candidate (invariant 3).
    assert no_code.protocol_id is None and unprobed.protocol_id is None
    assert not _witness_rows(db_session, no_code.id)
    assert report.counts["unchanged_pruned"] == 1 and report.counts["unchanged_candidate"] == 1


# ---------------------------------------------------------------------------
# Grounded re-earning + demotion (§5.3.3 c/d, invariant 12)
# ---------------------------------------------------------------------------


def test_member_without_evidence_demoted_with_closest_miss(db_session):
    protocol = _protocol(db_session)
    row = _contract(db_session, ADDR(6), protocol_id=protocol.id)
    _code_fact(db_session, row.address)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert row.protocol_id is None
    assert row.nominated_protocol_id == protocol.id  # never deleted, provenance kept
    changes = [c for c in report.changes if c.kind == "demote"]
    assert [c.contract_id for c in changes] == [row.id]
    assert changes[0].detail["missing"] == "deployer_not_determined"
    # Demotion marks enrollment + scoring dirty for the protocol.
    assert (
        db_session.execute(
            select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == protocol.id)
        ).first()
        is not None
    )
    assert (
        db_session.execute(select(ProtocolScoreQueue).where(ProtocolScoreQueue.protocol_id == protocol.id)).first()
        is not None
    )


def test_mutual_support_without_seed_is_not_grounded(db_session):
    # Two members whose only edges point at each other re-earn nothing: the
    # re-earn is grounded in seeds, never in a row's prior stamp.
    protocol = _protocol(db_session)
    proxy = _contract(db_session, ADDR(7), protocol_id=protocol.id, implementation=ADDR(8))
    impl = _contract(db_session, ADDR(8), protocol_id=protocol.id)
    _code_fact(db_session, proxy.address)
    _code_fact(db_session, impl.address)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert proxy.protocol_id is None and impl.protocol_id is None
    assert report.counts["demote"] == 2


def test_seeded_member_grounds_w2_expansion(db_session):
    # inventory member (W5 seed) whose stored implementation pointer names a
    # candidate: both settle as members through the gate's own fixpoint.
    protocol = _protocol(db_session)
    proxy = _inventory_contract(db_session, protocol, ADDR(9), protocol_id=protocol.id, implementation=ADDR(10))
    impl = _contract(db_session, ADDR(10), nominated_protocol_id=protocol.id)
    _code_fact(db_session, proxy.address)
    _code_fact(db_session, impl.address)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert proxy.protocol_id == protocol.id and impl.protocol_id == protocol.id
    promoted = [c for c in report.changes if c.kind == "promote"]
    assert [c.contract_id for c in promoted] == [impl.id]
    assert "w2_structural" in promoted[0].detail["rules"]
    assert report.counts["unchanged_member"] == 1


def test_member_with_code_absent_probe_prunes(db_session):
    protocol = _protocol(db_session)
    row = _inventory_contract(db_session, protocol, ADDR(11), protocol_id=protocol.id)
    _code_fact(db_session, row.address, absent=True)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert row.protocol_id is None and row.nominated_protocol_id == protocol.id
    prunes = [c for c in report.changes if c.kind == "prune"]
    assert [c.contract_id for c in prunes] == [row.id]
    assert prunes[0].detail["missing"] == "code_present_at_latest_probe"


def test_unclaimed_rows_untouched(db_session):
    protocol = _protocol(db_session)
    stray = _contract(db_session, ADDR(12))
    _contract(db_session, ADDR(13), nominated_protocol_id=protocol.id)

    report = run_reearn(db_session)

    assert stray.protocol_id is None and stray.nominated_protocol_id is None
    assert not _witness_rows(db_session, stray.id)
    assert report.counts["unclaimed_untouched"] == 1


# ---------------------------------------------------------------------------
# Full-table diff: cross-protocol cascade in a scoped run (review item 1)
# ---------------------------------------------------------------------------


def test_scoped_run_reports_cross_protocol_cascade_demotion(db_session):
    p1 = _protocol(db_session)
    p2 = _protocol(db_session)
    deployer = ADDR(0xE0)
    _registry_row(db_session, p2, deployer, trust_class="A")
    m2 = _contract(db_session, ADDR(14), protocol_id=p2.id, nominated_protocol_id=p2.id, deployer=deployer)
    _code_fact(db_session, m2.address, tx=_TX)
    gate.write_witness(
        db_session,
        contract_id=m2.id,
        protocol_id=p2.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
    )
    gate.write_witness(
        db_session,
        contract_id=m2.id,
        protocol_id=p2.id,
        rule=WITNESS_RULE_W4_DEPLOYER,
        evidence=gate.w4_evidence(
            deployer_address=deployer,
            deployer_registry_id=1,
            creation_tx_hash=_TX,
            creation_block=10,
        ),
        via_address=deployer,
    )
    # P1 candidate naming the same deployer: the scoped run's ladder check
    # discovers the cross-protocol collision.
    c1 = _contract(db_session, ADDR(15), nominated_protocol_id=p1.id, deployer=deployer)
    _code_fact(db_session, c1.address, tx=_TX)

    report = run_reearn(db_session, protocol_ids=[p1.id])

    # The collision revoked P2's registry row and demoted its member — and the
    # scoped report shows it (full-table diff).
    assert m2.protocol_id is None and m2.nominated_protocol_id == p2.id
    demotes = [c for c in report.changes if c.kind == "demote"]
    assert (m2.id, p2.id) in [(c.contract_id, c.protocol_id) for c in demotes]
    assert report.counts["demote"] >= 1
    registry = db_session.execute(select(ProtocolDeployer).where(ProtocolDeployer.address == deployer)).scalar_one()
    assert registry.revoked_at is not None and registry.revocation_reason == "cross_protocol_collision"


# ---------------------------------------------------------------------------
# Two-pass registry-loss handling (review item 2)
# ---------------------------------------------------------------------------


def _w4_member_fixture(db_session, protocol, deployer, address):
    """A member whose only support is W4 lineage through a standing registry row."""
    registry = _registry_row(db_session, protocol, deployer, trust_class="A")
    member = _contract(
        db_session, address, protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer
    )
    _code_fact(db_session, member.address, tx=_TX)
    return registry, member


def _registry_state(session, registry_id: int) -> tuple:
    row = session.get(ProtocolDeployer, registry_id)
    assert row is not None
    return (row.trust_class, str(row.evidence), row.observed_at, row.revoked_at, row.revocation_reason)


def test_rerun_without_enumerator_keeps_w4_members_and_registry(db_session):
    # Reviewer repro: the cleared-stamp world must not mint loss verdicts —
    # a re-run with no enumerator demotes nothing and touches no registry row.
    protocol = _protocol(db_session)
    deployer = ADDR(0xE1)
    registry, member = _w4_member_fixture(db_session, protocol, deployer, ADDR(16))
    before = _registry_state(db_session, registry.id)

    report = run_reearn(db_session, protocol_ids=[protocol.id], enumerator=None)

    assert member.protocol_id == protocol.id
    assert report.counts["demote"] == 0
    assert _registry_state(db_session, registry.id) == before
    w4 = [w for w in _witness_rows(db_session, member.id) if w.rule == WITNESS_RULE_W4_DEPLOYER]
    assert w4 and all(w.revoked_at is None for w in w4)


def test_genuine_registry_loss_revokes_in_pass_two(db_session):
    # A candidate naming the deployer forces the settled-world ladder check in
    # pass 2; the Class A row's perimeter fact is genuinely absent → revoked,
    # and the member resting only on its lineage demotes for real.
    protocol = _protocol(db_session)
    deployer = ADDR(0xE2)
    registry, member = _w4_member_fixture(db_session, protocol, deployer, ADDR(17))
    parked = _contract(db_session, ADDR(18), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, parked.address)  # no creation witness: W4-blocked, stays candidate

    report = run_reearn(db_session, protocol_ids=[protocol.id], enumerator=None)

    registry_row = db_session.get(ProtocolDeployer, registry.id)
    assert registry_row is not None and registry_row.revoked_at is not None
    assert registry_row.revocation_reason == "perimeter_fact_lost"
    assert member.protocol_id is None
    demotes = [c for c in report.changes if c.kind == "demote"]
    assert member.id in [c.contract_id for c in demotes]


def test_apply_idempotent_with_registry_fixture(db_session):
    # Supportable registry (Class A perimeter fact = controller value on a
    # member) + W4 member + parked candidate naming the deployer: the second
    # apply produces zero membership diffs AND zero registry churn.
    protocol = _protocol(db_session)
    deployer = ADDR(0xE3)
    anchor = _inventory_contract(db_session, protocol, ADDR(19), protocol_id=protocol.id)
    _code_fact(db_session, anchor.address)
    db_session.add(ControllerValue(contract_id=anchor.id, controller_id="owner", value=deployer))
    registry = _registry_row(db_session, protocol, deployer, trust_class="A")
    w4_member = _contract(
        db_session, ADDR(20), protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer
    )
    _code_fact(db_session, w4_member.address, tx=_TX)
    parked = _contract(db_session, ADDR(21), nominated_protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, parked.address)
    db_session.commit()

    first = run_reearn(db_session, protocol_ids=[protocol.id])
    db_session.commit()
    assert first.counts["demote"] == 0
    assert anchor.protocol_id == protocol.id and w4_member.protocol_id == protocol.id
    registry_after_first = _registry_state(db_session, registry.id)
    membership = {
        c.id: (c.protocol_id, c.nominated_protocol_id) for c in db_session.execute(select(Contract)).scalars()
    }

    second = run_reearn(db_session, protocol_ids=[protocol.id])
    db_session.commit()
    assert second.counts["promote"] == 0 and second.counts["demote"] == 0 and second.counts["prune"] == 0
    assert membership == {
        c.id: (c.protocol_id, c.nominated_protocol_id) for c in db_session.execute(select(Contract)).scalars()
    }
    assert _registry_state(db_session, registry.id) == registry_after_first


# ---------------------------------------------------------------------------
# Enumeration budget honesty (review item 3)
# ---------------------------------------------------------------------------


def test_budget_exhaustion_recorded_and_named_in_closest_miss(db_session):
    protocol = _protocol(db_session)
    deployer = ADDR(0xE4)
    for n in (22, 23):  # two W5-corroborated members deployed by the EOA
        row = _inventory_contract(
            db_session, protocol, ADDR(n), protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer
        )
        _code_fact(db_session, row.address)
    doomed = _contract(db_session, ADDR(24), protocol_id=protocol.id, deployer=deployer)
    _code_fact(db_session, doomed.address, tx=_TX)

    enumerator = BudgetedEnumerator(db_session, 0)
    report = run_reearn(db_session, protocol_ids=[protocol.id], enumerator=enumerator)

    assert enumerator.exhausted == {deployer}
    assert report.counts["enumeration_budget_exhausted_eoas"] == 1
    demotes = [c for c in report.changes if c.kind == "demote" and c.contract_id == doomed.id]
    assert demotes and demotes[0].detail["missing"] == "enumeration_budget_exhausted"
    # The shared closest-miss helper names the budget too.
    miss = closest_miss(db_session, doomed, protocol.id, budget_exhausted_deployers=enumerator.exhausted)
    assert miss["missing"] == "enumeration_budget_exhausted"


# ---------------------------------------------------------------------------
# Report-mode purity + apply-mode idempotence (invariant 12)
# ---------------------------------------------------------------------------


def _mixed_fixture(session):
    protocol = _protocol(session, slug="mix")
    member = _inventory_contract(session, protocol, ADDR(30), protocol_id=protocol.id, implementation=ADDR(31))
    impl_candidate = _contract(session, ADDR(31), nominated_protocol_id=protocol.id)
    doomed = _contract(session, ADDR(32), protocol_id=protocol.id)
    for row in (member, impl_candidate, doomed):
        _code_fact(session, row.address)
    return protocol


def test_report_mode_mutates_nothing(db_session):
    _mixed_fixture(db_session)
    db_session.commit()
    before = _snapshot(db_session)

    report = run_reearn(db_session)
    assert report.counts["promote"] == 1 and report.counts["demote"] == 1
    db_session.rollback()  # exactly what --report does

    assert _snapshot(db_session) == before


def test_apply_idempotent_second_run_zero_changes(db_session):
    protocol = _mixed_fixture(db_session)
    db_session.commit()

    first = run_reearn(db_session, protocol_ids=[protocol.id])
    db_session.commit()
    assert first.counts["promote"] == 1 and first.counts["demote"] == 1

    membership = {
        c.id: (c.protocol_id, c.nominated_protocol_id) for c in db_session.execute(select(Contract)).scalars()
    }
    active = {
        (w.contract_id, w.rule, w.via_address)
        for w in db_session.execute(select(ContractMembershipWitness)).scalars()
        if w.revoked_at is None
    }

    second = run_reearn(db_session, protocol_ids=[protocol.id])
    db_session.commit()
    assert second.counts["promote"] == 0 and second.counts["demote"] == 0 and second.counts["prune"] == 0
    assert second.converted_w5 == [] and second.seeded_w6 == []
    assert membership == {
        c.id: (c.protocol_id, c.nominated_protocol_id) for c in db_session.execute(select(Contract)).scalars()
    }
    assert active == {
        (w.contract_id, w.rule, w.via_address)
        for w in db_session.execute(select(ContractMembershipWitness)).scalars()
        if w.revoked_at is None
    }


# ---------------------------------------------------------------------------
# Invariant-13 handshake: a re-earned DB reconciles with zero drift
# ---------------------------------------------------------------------------


def test_reearn_apply_then_reconcile_zero_drift(db_session):
    protocol = _protocol(db_session)
    deployer = ADDR(0xE5)
    anchor = _inventory_contract(db_session, protocol, ADDR(33), protocol_id=protocol.id, implementation=ADDR(34))
    _code_fact(db_session, anchor.address)
    db_session.add(ControllerValue(contract_id=anchor.id, controller_id="owner", value=deployer))
    impl = _contract(db_session, ADDR(34), nominated_protocol_id=protocol.id)
    _code_fact(db_session, impl.address)
    _registry_row(db_session, protocol, deployer, trust_class="A")
    w4_member = _contract(
        db_session, ADDR(35), protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer
    )
    _code_fact(db_session, w4_member.address, tx=_TX)
    doomed = _contract(db_session, ADDR(36), protocol_id=protocol.id)
    _code_fact(db_session, doomed.address)
    parked = _contract(db_session, ADDR(37), nominated_protocol_id=protocol.id)
    _code_fact(db_session, parked.address)
    db_session.commit()

    run_reearn(db_session, protocol_ids=[protocol.id])
    db_session.commit()

    assert anchor.protocol_id == protocol.id and impl.protocol_id == protocol.id
    assert w4_member.protocol_id == protocol.id and doomed.protocol_id is None
    assert reconcile_audit(db_session) == []
