"""Floor-witness self-heal: undecided witnesses are retried with backoff, decided ones never are, and a newly proven
floor reaches only the cursors enrolled at exactly that seed.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import delete, func, select, text, update

from db.floor_witnesses import WITNESS_FAILED, WITNESS_PRIOR_INCARNATION, WITNESS_PROVEN, record_floor_witness
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    FIRST_INDEXED_BASIS_CREATION,
    AddressFloorWitness,
    IndexedEventCursor,
    IndexerWork,
    Job,
    JobStage,
    JobStatus,
    cursor_permits_exactness,
)
from db.queue import store_artifact
from services.resolution import indexer_scheduler
from services.resolution.creation_block_floor import clear_scan_floor_cache, resolve_scan_floor_with_basis
from services.resolution.indexer_work import mark_dirty
from tests.conftest import requires_postgres
from workers.event_log_indexer import (
    EnrollmentCaches,
    _enroll_witnessed,
    enroll_event_cursor,
    floor_witness_summary,
    rewitness_due_floors,
)

pytestmark = requires_postgres

_A = "0x00000000000000000000000000000000000c4a01"
_B = "0x00000000000000000000000000000000000c4a02"
_C = "0x00000000000000000000000000000000000c4a03"
_SEED = 18_000_000
_T1 = "0x" + "a1" * 32
_T2 = "0x" + "a2" * 32
_T3 = "0x" + "a3" * 32


class _Wire:
    """The witness's wire: Etherscan's creation block and the three pinned RPC reads."""

    def __init__(self) -> None:
        self.fail = False
        self.prior_logs: list[Any] = []
        self.seeds: dict[str, int] = {}
        self.rpc: list[tuple[str, str]] = []
        self.etherscan: list[str] = []

    def rpc_request(self, url, method, params, chain_id=None):
        address = params[0]["address"] if method == "eth_getLogs" else params[0]
        self.rpc.append((method, address))
        if self.fail:
            raise RuntimeError("stubbed upstream timeout")
        if method == "eth_getCode":
            return "0x" if int(params[1], 16) <= self.seed(address) else "0x6080"
        if method == "eth_getLogs":
            return self.prior_logs
        raise AssertionError(method)

    def seed(self, address: str) -> int:
        return self.seeds.get(address, _SEED)

    def creation_block(self, address, *, chain_id):
        self.etherscan.append(address)
        return self.seed(address) + 1

    def calls(self) -> int:
        return len(self.rpc) + len(self.etherscan)


@pytest.fixture()
def wire(monkeypatch, db_session):
    import workers.event_log_indexer as eli

    stub = _Wire()
    monkeypatch.setattr(eli, "rpc_request", stub.rpc_request)
    monkeypatch.setattr(eli, "require_rpc_url", lambda **_kw: "http://stub")
    monkeypatch.setattr(eli, "get_contract_creation_block", stub.creation_block)
    # Budget and call-count assertions need a slate without other files' leftover cursors.
    for model in (IndexerWork, IndexedEventCursor, AddressFloorWitness):
        db_session.execute(delete(model))
    db_session.commit()
    clear_scan_floor_cache()
    yield stub
    clear_scan_floor_cache()
    db_session.execute(delete(IndexerWork))
    db_session.commit()


def _enrol(session, address: str, topic0: str) -> None:
    caches = EnrollmentCaches()
    assert _enroll_witnessed(
        session,
        chain_id=1,
        address=address,
        topic0=topic0,
        seed_cache=caches.seeds,
        witness_cache=caches.witnesses,
        enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
    )
    session.commit()


def _maybe_row(session, address: str) -> AddressFloorWitness | None:
    session.expire_all()
    return session.execute(
        select(AddressFloorWitness).where(AddressFloorWitness.chain_id == 1, AddressFloorWitness.address == address)
    ).scalar_one_or_none()


def _row(session, address: str) -> AddressFloorWitness:
    row = _maybe_row(session, address)
    assert row is not None
    return row


def _cursor(session, address: str, topic0: str) -> IndexedEventCursor:
    session.expire_all()
    return session.execute(
        select(IndexedEventCursor).where(
            IndexedEventCursor.event_address == address, IndexedEventCursor.topic0 == topic0
        )
    ).scalar_one()


def _make_due(session, address: str) -> None:
    session.execute(
        update(AddressFloorWitness)
        .where(AddressFloorWitness.address == address)
        .values(next_attempt_at=text("now() - interval '1 second'"))
    )
    session.commit()


def _reconcile_revision(session) -> int | None:
    session.expire_all()
    row = session.get(IndexerWork, ("reconcile", "1"))
    return None if row is None else row.revision


def test_transient_failure_is_retried_after_backoff_and_heals_floor_and_cursor(db_session, wire):
    wire.fail = True
    _enrol(db_session, _A, _T1)
    assert (_row(db_session, _A).outcome, _row(db_session, _A).attempts) == ("failed", 1)
    assert resolve_scan_floor_with_basis(_A, 1, session=db_session) == (None, None)
    cursor = _cursor(db_session, _A, _T1)
    assert not cursor_permits_exactness(cursor.enrollment_basis, cursor.first_indexed_block_basis)

    wire.fail = False
    calls = wire.calls()
    assert rewitness_due_floors(db_session) == 0
    assert wire.calls() == calls, "a failure is not retried before its backoff elapses"

    _make_due(db_session, _A)
    before = _reconcile_revision(db_session)
    assert rewitness_due_floors(db_session) == 1
    row = _row(db_session, _A)
    assert (row.outcome, row.first_indexed_block, row.attempts, row.next_attempt_at) == ("proven", _SEED, 0, None)
    cursor = _cursor(db_session, _A, _T1)
    assert (cursor.first_indexed_block, cursor.first_indexed_block_basis) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    assert cursor_permits_exactness(cursor.enrollment_basis, cursor.first_indexed_block_basis)
    assert _reconcile_revision(db_session) != before
    assert db_session.get(IndexerWork, ("reconcile", "1")).dirty
    assert resolve_scan_floor_with_basis(_A, 1, session=db_session) == (_SEED, "cursor_first_indexed")


def test_a_proven_retry_at_an_address_with_no_cursor_marks_reconciliation(db_session, wire):
    record_floor_witness(db_session, chain_id=1, address=_A, outcome=WITNESS_FAILED)
    db_session.commit()
    _make_due(db_session, _A)
    db_session.execute(delete(IndexerWork))
    db_session.commit()

    wire.fail = True
    assert rewitness_due_floors(db_session) == 1
    assert _row(db_session, _A).outcome == "failed"
    assert _reconcile_revision(db_session) is None

    wire.fail = False
    _make_due(db_session, _A)
    assert rewitness_due_floors(db_session) == 1
    assert _row(db_session, _A).outcome == "proven"
    assert db_session.scalar(select(func.count()).select_from(IndexedEventCursor)) == 0
    assert db_session.get(IndexerWork, ("reconcile", "1")).dirty


def test_repeated_failure_backs_off_and_never_touches_a_proven_row(db_session, wire):
    wire.fail = True
    _enrol(db_session, _A, _T1)
    enroll_event_cursor(db_session, chain_id=1, event_address=_B, topic0=_T1, start_block=_SEED)
    record_floor_witness(db_session, chain_id=1, address=_B, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    db_session.commit()
    proven_before = _row(db_session, _B).witnessed_at
    delays = []
    for attempt in range(2, 6):
        _make_due(db_session, _A)
        assert rewitness_due_floors(db_session) == 1
        row = _row(db_session, _A)
        assert (row.outcome, row.attempts) == ("failed", attempt)
        delays.append(
            db_session.execute(
                text(
                    "SELECT extract(epoch FROM next_attempt_at - now()) FROM address_floor_witnesses WHERE address=:a"
                ),
                {"a": _A},
            ).scalar_one()
        )
    assert delays == pytest.approx([1200, 2400, 4800, 9600], abs=5)
    assert all(address == _A for _method, address in wire.rpc)
    assert _row(db_session, _B).witnessed_at == proven_before
    assert _row(db_session, _B).outcome == "proven"


def test_prior_incarnation_is_never_retried(db_session, wire):
    enroll_event_cursor(db_session, chain_id=1, event_address=_A, topic0=_T1, start_block=_SEED)
    record_floor_witness(db_session, chain_id=1, address=_A, outcome=WITNESS_PRIOR_INCARNATION, seed_block=_SEED)
    db_session.commit()
    before = _row(db_session, _A).witnessed_at
    assert rewitness_due_floors(db_session) == 0
    assert wire.calls() == 0
    row = _row(db_session, _A)
    assert (row.outcome, row.witnessed_at, row.next_attempt_at) == ("prior_incarnation", before, None)
    assert _cursor(db_session, _A, _T1).first_indexed_block_basis == "not_determined"


def test_unwitnessed_cursored_addresses_are_witnessed_within_the_budget(db_session, wire):
    for address in (_A, _B, _C):
        enroll_event_cursor(db_session, chain_id=1, event_address=address, topic0=_T1, start_block=_SEED)
    db_session.commit()
    assert floor_witness_summary(db_session)["due"] == 3

    assert rewitness_due_floors(db_session, budget=2) == 2
    assert len(wire.etherscan) == 2 and len(wire.rpc) == 6
    assert [_row(db_session, a).outcome for a in (_A, _B)] == ["proven", "proven"]
    assert _maybe_row(db_session, _C) is None

    assert rewitness_due_floors(db_session, budget=2) == 1
    assert _row(db_session, _C).outcome == "proven"
    assert len(wire.etherscan) == 3 and len(wire.rpc) == 9
    summary = floor_witness_summary(db_session)
    assert summary == {"due": 0, "by_outcome": {"proven": 3}}


def test_proven_retry_upgrades_only_cursors_enrolled_at_the_proven_seed(db_session, wire):
    enroll_event_cursor(db_session, chain_id=1, event_address=_A, topic0=_T1, start_block=_SEED)
    enroll_event_cursor(db_session, chain_id=1, event_address=_A, topic0=_T2, start_block=_SEED + 5)
    enroll_event_cursor(db_session, chain_id=1, event_address=_A, topic0=_T3, start_block=_SEED)
    for topic0 in (_T1, _T2, _T3):
        db_session.execute(
            update(IndexedEventCursor)
            .where(IndexedEventCursor.topic0 == topic0)
            .values(enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT, last_indexed_block=_SEED + 1_000)
        )
    # Enrolled before seeds were recorded: its start can't be shown.
    db_session.execute(
        update(IndexedEventCursor).where(IndexedEventCursor.topic0 == _T3).values(enrolled_seed_block=None)
    )
    db_session.commit()

    assert rewitness_due_floors(db_session) == 1
    matched, moved, legacy = (_cursor(db_session, _A, t) for t in (_T1, _T2, _T3))
    assert (matched.first_indexed_block, matched.first_indexed_block_basis) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    assert cursor_permits_exactness(matched.enrollment_basis, matched.first_indexed_block_basis)
    for cursor in (moved, legacy):
        assert (cursor.first_indexed_block, cursor.first_indexed_block_basis) == (None, "not_determined")
        assert not cursor_permits_exactness(cursor.enrollment_basis, cursor.first_indexed_block_basis)
    assert matched.last_indexed_block == _SEED + 1_000


def test_migrated_cursor_conflict_rows_are_retried(db_session, wire):
    enroll_event_cursor(db_session, chain_id=1, event_address=_A, topic0=_T1, start_block=_SEED)
    db_session.execute(
        text(
            "INSERT INTO address_floor_witnesses (chain_id, address, basis, outcome, next_attempt_at) "
            "VALUES (1, :a, 'not_determined', 'cursor_conflict', now())"
        ),
        {"a": _A},
    )
    db_session.commit()
    assert floor_witness_summary(db_session) == {"due": 1, "by_outcome": {"cursor_conflict": 1}}
    assert rewitness_due_floors(db_session) == 1
    assert _row(db_session, _A).outcome == "proven"
    assert _cursor(db_session, _A, _T1).first_indexed_block_basis == FIRST_INDEXED_BASIS_CREATION


def test_seed_lookup_failure_backs_off_instead_of_retrying_every_pass(db_session, wire, monkeypatch):
    import workers.event_log_indexer as eli

    enroll_event_cursor(db_session, chain_id=1, event_address=_A, topic0=_T1, start_block=_SEED)
    db_session.commit()
    monkeypatch.setattr(eli, "get_contract_creation_block", lambda *_a, **_k: None)
    assert rewitness_due_floors(db_session) == 1
    row = _row(db_session, _A)
    assert (row.outcome, row.seed_block, row.attempts) == ("failed", None, 1)
    assert wire.rpc == []
    assert rewitness_due_floors(db_session) == 0


def test_steady_state_makes_no_wire_calls(db_session, wire):
    for address in (_A, _B):
        _enrol(db_session, address, _T1)
    enroll_event_cursor(db_session, chain_id=1, event_address=_C, topic0=_T1, start_block=_SEED)
    record_floor_witness(db_session, chain_id=1, address=_C, outcome=WITNESS_PRIOR_INCARNATION, seed_block=_SEED)
    db_session.commit()
    calls = wire.calls()
    for _ in range(3):
        assert rewitness_due_floors(db_session) == 0
        indexer_scheduler.drain_enrollment(db_session)
    assert wire.calls() == calls
    assert floor_witness_summary(db_session)["due"] == 0


def test_enrolment_drain_runs_the_retry_step_and_reports_it(db_session, wire):
    enroll_event_cursor(db_session, chain_id=1, event_address=_A, topic0=_T1, start_block=_SEED)
    db_session.commit()
    reported: list[int] = []
    indexer_scheduler.drain_enrollment(db_session, on_rewitness=reported.append)
    assert reported == [1]
    assert _row(db_session, _A).outcome == "proven"


def test_a_retry_step_that_fails_partway_reports_the_retries_it_completed(db_session, wire, monkeypatch):
    import workers.event_log_indexer as eli

    for address in (_A, _B, _C):
        enroll_event_cursor(db_session, chain_id=1, event_address=address, topic0=_T1, start_block=_SEED)
    db_session.commit()
    real_witness = eli._witness_seed_block
    witnessed: list[str] = []

    def fail_third(address, *args, **kwargs):
        witnessed.append(address)
        if len(witnessed) == 3:
            raise RuntimeError("database went away mid-step")
        return real_witness(address, *args, **kwargs)

    monkeypatch.setattr(eli, "_witness_seed_block", fail_third)
    reported: list[int] = []

    indexer_scheduler.drain_enrollment(db_session, on_rewitness=reported.append)

    assert reported == [2]
    assert [_row(db_session, a).outcome for a in (_A, _B)] == ["proven", "proven"]
    assert _maybe_row(db_session, _C) is None


def _hinting_job(session, address: str, topic0: str) -> Job:
    job = Job(
        address=address, chain_id=1, request={"address": address}, status=JobStatus.completed, stage=JobStage.done
    )
    session.add(job)
    session.flush()
    leaf = {"op": "LEAF", "leaf": {"set_descriptor": {"enumeration_hint": [{"topic0": topic0}]}}}
    store_artifact(session, job.id, "predicate_trees", data={"trees": {"f()": leaf}})
    return job


def test_a_rolled_back_source_leaves_no_witness_verdict_for_the_next_one(db_session, wire, monkeypatch):
    import workers.event_log_indexer as eli

    jobs = [_hinting_job(db_session, _A, topic0) for topic0 in (_T1, _T2)]
    db_session.execute(delete(IndexerWork))
    for job in jobs:
        mark_dirty(db_session, "job", str(job.id))
    db_session.commit()
    real_enroll = eli.enroll_event_cursor
    inserts: list[str] = []

    def fail_first_insert(session, **kwargs):
        inserts.append(kwargs["topic0"])
        if len(inserts) == 1:
            raise RuntimeError("connection lost after the witness was graded")
        return real_enroll(session, **kwargs)

    monkeypatch.setattr(eli, "enroll_event_cursor", fail_first_insert)

    indexer_scheduler.drain_enrollment(db_session, tracked_limit=0, witness_budget=0)

    (cursor,) = db_session.execute(select(IndexedEventCursor)).scalars().all()
    assert cursor.topic0 == inserts[1]
    assert (cursor.first_indexed_block, cursor.first_indexed_block_basis) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    row = _row(db_session, _A)
    assert (row.outcome, row.first_indexed_block) == ("proven", _SEED)
    assert [method for method, _address in wire.rpc].count("eth_getLogs") == 2
