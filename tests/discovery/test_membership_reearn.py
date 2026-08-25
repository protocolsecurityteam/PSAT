"""Re-earn migration end-to-end on fixture rows (DISCOVERY_MEMBERSHIP_GATE_SPEC.md
§5.3.3, §7 migration dry-run gate, invariant 12).

Covers: inventory→W5 conversion, W6 seeding gated on W1, grounded re-earning
(members without seed-grounded evidence demote — mutual support is not an
anchor), closest-miss evidence on every demotion, report-mode writing nothing,
apply-mode idempotence, pruned handling, and unclaimed rows staying untouched.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select, text

from db.models import (
    WITNESS_RULE_W5_HUMAN,
    WITNESS_RULE_W6_LLAMA_SEED,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    MonitoringEnrollmentQueue,
    Protocol,
    ProtocolScoreQueue,
)
from scripts.reearn_membership import CONVERSION_ACTOR, run_reearn
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]

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


def _code_fact(session, address: str, *, chain_id: int = 1, absent: bool = False) -> None:
    session.add(
        ContractCreationWitness(
            chain_id=chain_id, address=address.lower(), code_probe_block=50, code_absent_at_probe=absent
        )
    )
    session.flush()


def _witness_rows(session, contract_id: int) -> list[ContractMembershipWitness]:
    return list(
        session.execute(
            select(ContractMembershipWitness).where(ContractMembershipWitness.contract_id == contract_id)
        ).scalars()
    )


# ---------------------------------------------------------------------------
# Conversions (§5.3.3 a/b)
# ---------------------------------------------------------------------------


def test_inventory_converts_to_w5_and_reearns(db_session):
    protocol = _protocol(db_session)
    row = _contract(
        db_session,
        ADDR(1),
        protocol_id=protocol.id,
        nominated_protocol_id=protocol.id,
        discovery_sources=["inventory"],
    )
    _code_fact(db_session, row.address)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert report.converted_w5 == [row.id]
    assert row.protocol_id == protocol.id
    rules = {(w.rule, w.revoked_at is None) for w in _witness_rows(db_session, row.id)}
    assert (WITNESS_RULE_W5_HUMAN, True) in rules and ("w1_code", True) in rules
    w5 = next(w for w in _witness_rows(db_session, row.id) if w.rule == WITNESS_RULE_W5_HUMAN)
    assert w5.evidence["actor"] == CONVERSION_ACTOR
    assert report.counts["demote"] == 0


def test_w6_seeded_only_when_w1_passes(db_session):
    protocol = _protocol(db_session, slug="ether.fi")
    with_code = _contract(db_session, ADDR(2), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    _code_fact(db_session, with_code.address)
    no_code = _contract(db_session, ADDR(3), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])
    _code_fact(db_session, no_code.address, absent=True)
    unprobed = _contract(db_session, ADDR(4), nominated_protocol_id=protocol.id, discovery_sources=["defillama"])

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
    row = _contract(db_session, ADDR(5), protocol_id=protocol.id)
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
    proxy = _contract(db_session, ADDR(6), protocol_id=protocol.id, implementation=ADDR(7))
    impl = _contract(db_session, ADDR(7), protocol_id=protocol.id)
    _code_fact(db_session, proxy.address)
    _code_fact(db_session, impl.address)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert proxy.protocol_id is None and impl.protocol_id is None
    assert report.counts["demote"] == 2


def test_seeded_member_grounds_w2_expansion(db_session):
    # inventory member (W5 seed) whose stored implementation pointer names a
    # candidate: both settle as members through the gate's own fixpoint.
    protocol = _protocol(db_session)
    proxy = _contract(
        db_session,
        ADDR(8),
        protocol_id=protocol.id,
        discovery_sources=["inventory"],
        implementation=ADDR(9),
    )
    impl = _contract(db_session, ADDR(9), nominated_protocol_id=protocol.id)
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
    row = _contract(db_session, ADDR(10), protocol_id=protocol.id, discovery_sources=["inventory"])
    _code_fact(db_session, row.address, absent=True)

    report = run_reearn(db_session, protocol_ids=[protocol.id])

    assert row.protocol_id is None and row.nominated_protocol_id == protocol.id
    prunes = [c for c in report.changes if c.kind == "prune"]
    assert [c.contract_id for c in prunes] == [row.id]
    assert prunes[0].detail["missing"] == "code_present_at_latest_probe"


def test_unclaimed_rows_untouched(db_session):
    protocol = _protocol(db_session)
    stray = _contract(db_session, ADDR(11))
    _contract(db_session, ADDR(12), nominated_protocol_id=protocol.id)

    report = run_reearn(db_session)

    assert stray.protocol_id is None and stray.nominated_protocol_id is None
    assert not _witness_rows(db_session, stray.id)
    assert report.counts["unclaimed_untouched"] == 1


# ---------------------------------------------------------------------------
# Report-mode purity + apply-mode idempotence (invariant 12)
# ---------------------------------------------------------------------------


def _mixed_fixture(session):
    protocol = _protocol(session, slug="mix")
    member = _contract(
        session,
        ADDR(20),
        protocol_id=protocol.id,
        discovery_sources=["inventory"],
        implementation=ADDR(21),
    )
    impl_candidate = _contract(session, ADDR(21), nominated_protocol_id=protocol.id)
    doomed = _contract(session, ADDR(22), protocol_id=protocol.id)
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
