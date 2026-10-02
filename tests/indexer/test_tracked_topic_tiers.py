"""Tracked-topic enrolment indexes only specs a reader consumes: ``activity`` and ``hint`` tiers are skipped before
the per-pass budget, their addresses still get a floor witness, and other sources enrol the same keys as before.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update

from db.floor_witnesses import read_floor_witness
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStage,
    JobStatus,
    MonitoredContract,
    Protocol,
)
from db.queue import store_artifact
from services.monitoring.restaking_enrollment import PUBKEY_LINKED_TOPIC0, node_addresses_from_fold
from services.resolution.creation_block_floor import clear_scan_floor_cache, resolve_scan_floor_with_basis
from tests.conftest import requires_postgres
from tests.support.witness_wire import stub_seed_witness
from workers.event_log_indexer import (
    EnrollmentCaches,
    enroll_from_completed_jobs,
    enroll_from_tracked_topics,
    tracked_spec_enrols,
)

pytestmark = requires_postgres

_ADDR = "0x00000000000000000000000000000000000c0a01"
_CREATION = 17_000_001
_SEED = _CREATION - 1
_ACTIVITY = "0x" + "a0" * 32
_HINT = "0x" + "b0" * 32
_SELF = "0x" + "c0" * 32


def _spec(topic0: str, tier: str | None) -> dict[str, Any]:
    spec: dict[str, Any] = {"topic0": topic0, "signature": "X(address)"}
    if tier is not None:
        spec["witness_tier"] = tier
    return spec


def _monitored(
    session, specs: list[dict[str, Any]], *, address: str = _ADDR, row_id: uuid.UUID | None = None
) -> MonitoredContract:
    protocol = Protocol(name=f"tiers-{address[-6:]}")
    session.add(protocol)
    session.flush()
    row = MonitoredContract(
        id=row_id or uuid.uuid4(),
        address=address,
        chain="ethereum",
        protocol_id=protocol.id,
        is_active=True,
        monitoring_config={"tracked_topics": specs},
    )
    session.add(row)
    session.commit()
    return row


def _cursors(session, address: str = _ADDR) -> dict[str, str | None]:
    session.expire_all()
    return {
        c.topic0: c.enrollment_basis
        for c in session.execute(
            select(IndexedEventCursor).where(IndexedEventCursor.event_address == address)
        ).scalars()
    }


def test_tier_predicate():
    assert not tracked_spec_enrols({"witness_tier": "activity"})
    assert not tracked_spec_enrols({"witness_tier": "hint"})
    assert tracked_spec_enrols({"witness_tier": "self_describing"})
    # An unstamped or unknown tier keeps its cursor: skipping is reserved for a tier proven to feed no reader.
    assert tracked_spec_enrols({})
    assert tracked_spec_enrols({"witness_tier": "something_new"})


def test_activity_and_hint_specs_are_skipped_and_a_self_describing_sibling_enrols(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    _monitored(db_session, [_spec(_ACTIVITY, "activity"), _spec(_HINT, "hint"), _spec(_SELF, "self_describing")])
    assert enroll_from_tracked_topics(db_session) == 1
    assert _cursors(db_session) == {_SELF: ENROLLMENT_BASIS_TRACKED_TOPICS}


def test_skipped_topic_never_shadows_a_self_describing_spec_for_the_same_topic(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    _monitored(db_session, [_spec(_SELF, "activity"), _spec(_SELF, "self_describing")])
    assert enroll_from_tracked_topics(db_session) == 1
    assert _cursors(db_session) == {_SELF: ENROLLMENT_BASIS_TRACKED_TOPICS}


def test_a_retiered_spec_enrols_on_the_next_pass(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    row = _monitored(db_session, [_spec(_ACTIVITY, "activity")])
    assert enroll_from_tracked_topics(db_session) == 0
    assert _cursors(db_session) == {}
    db_session.execute(
        update(MonitoredContract)
        .where(MonitoredContract.id == row.id)
        .values(monitoring_config={"tracked_topics": [_spec(_ACTIVITY, "self_describing")]})
    )
    db_session.commit()
    assert enroll_from_tracked_topics(db_session) == 1
    assert _cursors(db_session) == {_ACTIVITY: ENROLLMENT_BASIS_TRACKED_TOPICS}


def test_a_predicate_hint_on_a_skipped_key_still_enrols(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    _monitored(db_session, [_spec(_HINT, "hint")])
    assert enroll_from_tracked_topics(db_session) == 0
    job = Job(
        address=_ADDR,
        chain_id=1,
        request={"address": _ADDR},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.flush()
    store_artifact(
        db_session,
        job.id,
        "predicate_trees",
        data={"trees": {"f()": {"op": "LEAF", "leaf": {"set_descriptor": {"enumeration_hint": [{"topic0": _HINT}]}}}}},
    )
    db_session.commit()
    assert enroll_from_completed_jobs(db_session) == 1
    assert _cursors(db_session) == {_HINT: ENROLLMENT_BASIS_PREDICATE_HINT}


def test_skipped_addresses_spend_no_budget_and_repeat_no_witness_reads(db_session, monkeypatch):
    wire = stub_seed_witness(monkeypatch, creation_block=_CREATION)
    skipped = [f"0x{0xC0B00 + i:040x}" for i in range(5)]
    for rank, address in enumerate(skipped):
        _monitored(
            db_session,
            [_spec(_ACTIVITY, "activity"), _spec(_HINT, "hint")],
            address=address,
            row_id=uuid.UUID(int=rank),
        )
    last = f"0x{0xC0BFF:040x}"
    _monitored(db_session, [_spec(_SELF, "self_describing")], address=last, row_id=uuid.UUID(int=2**127))

    # Rows are scanned in id order, so every skipped address comes first; they spend none of the budget of one, and
    # the self-describing spec behind them enrols on the first pass.
    assert enroll_from_tracked_topics(db_session, limit=1) == 1
    assert _cursors(db_session, last) == {_SELF: ENROLLMENT_BASIS_TRACKED_TOPICS}
    for _ in range(3):
        assert enroll_from_tracked_topics(db_session, limit=1) == 0
    assert all(_cursors(db_session, a) == {} for a in skipped)
    # Each address is witnessed exactly once (three reads), however many passes run.
    assert len(wire.calls) == 3 * (len(skipped) + 1)
    assert all(read_floor_witness(db_session, chain_id=1, address=a) is not None for a in skipped)


def test_a_skipped_address_keeps_a_witnessed_floor_without_any_cursor(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    clear_scan_floor_cache()
    _monitored(db_session, [_spec(_ACTIVITY, "activity")])
    enroll_from_tracked_topics(db_session)
    db_session.commit()
    assert db_session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one() == 0
    assert read_floor_witness(db_session, chain_id=1, address=_ADDR) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    assert resolve_scan_floor_with_basis(_ADDR, 1, session=db_session) == (_SEED, "cursor_first_indexed")
    clear_scan_floor_cache()


def test_an_unresolvable_creation_block_records_a_failed_witness_for_the_retry_step(db_session, monkeypatch):
    from db.models import AddressFloorWitness

    stub_seed_witness(monkeypatch, creation_block=None)
    _monitored(db_session, [_spec(_ACTIVITY, "activity")])
    pending: set[tuple[int, str]] = set()
    enroll_from_tracked_topics(db_session, pending=pending, caches=EnrollmentCaches())
    assert pending == set()
    row = db_session.execute(select(AddressFloorWitness).where(AddressFloorWitness.address == _ADDR)).scalar_one()
    assert (row.outcome, row.seed_block, row.attempts, row.next_attempt_at is not None) == ("failed", None, 1, True)
    # The row now exists, so later passes leave the address to the retry step's backoff.
    enroll_from_tracked_topics(db_session, caches=EnrollmentCaches())
    db_session.expire_all()
    assert (
        db_session.execute(select(AddressFloorWitness).where(AddressFloorWitness.address == _ADDR))
        .scalar_one()
        .attempts
        == 1
    )


def test_restaking_pubkey_linked_still_enrols_and_feeds_the_fold(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    _monitored(db_session, [_spec(PUBKEY_LINKED_TOPIC0, "self_describing"), _spec(_ACTIVITY, "activity")])
    assert enroll_from_tracked_topics(db_session) == 1
    assert _cursors(db_session) == {PUBKEY_LINKED_TOPIC0: ENROLLMENT_BASIS_TRACKED_TOPICS}
    node = "0x" + "4e" * 20
    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=_ADDR,
            topic0=PUBKEY_LINKED_TOPIC0,
            block_number=_CREATION + 5,
            block_hash=b"\x01" * 32,
            tx_hash=b"\x02" * 32,
            log_index=0,
            transaction_index=0,
            topics=[PUBKEY_LINKED_TOPIC0, "0x" + "00" * 32, "0x" + "00" * 12 + node[2:]],
            data_words=[],
        )
    )
    db_session.commit()
    assert node_addresses_from_fold(db_session, chain_id=1) == [node]
