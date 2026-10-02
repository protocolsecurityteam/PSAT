"""Enrolment never waits on a cursor row while holding the chain's reconciliation row.

An indexer page write locks its group's cursors, then its log insert's trigger takes ``indexer_work('reconcile',
chain)``. Enrolment takes the same two locks when it upgrades a cursor (the basis upgrade's trigger, or the explicit
mark after a floor-witness upgrade). These tests run both sides on real sessions, with the indexer holding the cursor
the enrolment needs, and require that neither side is aborted as a deadlock.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import create_engine, delete, func, select, text
from sqlalchemy.orm import Session

from db.floor_witnesses import WITNESS_PROVEN, record_floor_witness
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    AddressFloorWitness,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStage,
    JobStatus,
)
from db.queue import store_artifact
from services.resolution import indexer_scheduler
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import DATABASE_URL, requires_postgres
from tests.support.one_page_fetch import OnePagePerFetch
from tests.support.witness_wire import stub_seed_witness
from workers import event_log_indexer as eli

pytestmark = requires_postgres

_X = "0x00000000000000000000000000000000000d1a01"  # the group the indexer is writing
_Y = "0x00000000000000000000000000000000000d1a02"  # upgraded first, so enrolment holds the reconciliation row
_TOPIC = "0x" + "d5" * 32
_CREATION = 19_500_001
_SEED = _CREATION - 1
_TARGET = _SEED + 100


class _OnePage(OnePagePerFetch):
    def fetch_logs(self, *, event_address, topics, from_block, to_block, window_stats=None):
        block = _SEED + 50
        return [
            FetchedEventLog(
                tx_hash=bytes([7]) * 32,
                log_index=0,
                block_number=block,
                block_hash=bytes([block % 251]) * 32,
                transaction_index=0,
                topics=[_TOPIC],
                data_words=[],
            )
        ]


class _Hashes:
    def block_hash(self, block_number: int) -> bytes:
        return bytes([block_number % 251]) * 32


def _cursor(session, address: str, *, basis: str, witnessed: bool) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0=_TOPIC,
            last_indexed_block=_SEED,
            enrolled_seed_block=_SEED,
            first_indexed_block=_SEED if witnessed else None,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION if witnessed else "not_determined",
            enrollment_basis=basis,
        )
    )


def _hint_job(session) -> uuid.UUID:
    job = Job(
        address=_Y,
        request={"address": _Y},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    hints = [{"topic0": _TOPIC, "event_address": address} for address in (_Y, _X)]
    store_artifact(
        session,
        job.id,
        "predicate_trees",
        data={"trees": {"f()": {"op": "LEAF", "leaf": {"set_descriptor": {"enumeration_hint": hints}}}}},
    )
    return job.id


def _waiting_backends(probe: Session) -> int:
    return probe.execute(
        text(
            "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
            "WHERE NOT l.granted AND a.datname = current_database()"
        )
    ).scalar_one()


def _race(monkeypatch, enrol) -> dict[str, Any]:
    """Hold the indexer between locking X's cursors and inserting its logs until ``enrol`` is waiting on a lock."""
    engine = create_engine(DATABASE_URL)
    outcome: dict[str, Any] = {"indexer": None, "enrolment": None, "enrolment_waited": False}
    locked = threading.Event()
    real_insert = eli._bulk_insert_logs

    def held_insert(*args, **kwargs):
        if not locked.is_set():
            locked.set()
            with Session(engine) as probe:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if _waiting_backends(probe):
                        outcome["enrolment_waited"] = True
                        break
                    probe.rollback()
                    time.sleep(0.05)
        return real_insert(*args, **kwargs)

    monkeypatch.setattr(eli, "_bulk_insert_logs", held_insert)

    def indexer() -> None:
        with Session(engine, expire_on_commit=False) as session:
            try:
                for _ in eli.index_event_group_steps(
                    session,
                    chain_id=1,
                    event_address=_X,
                    fetcher=_OnePage(),
                    target=_TARGET,
                    block_hash_fetcher=_Hashes(),
                ):
                    session.commit()
            except Exception as exc:
                session.rollback()
                outcome["indexer"] = exc

    def enrolment() -> None:
        locked.wait(10)
        with Session(engine, expire_on_commit=False) as session:
            session.execute(text("SET lock_timeout = '20s'"))
            try:
                enrol(session)
                session.commit()
            except Exception as exc:
                session.rollback()
                outcome["enrolment"] = exc

    threads = [threading.Thread(target=indexer), threading.Thread(target=enrolment)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    engine.dispose()
    return outcome


def _assert_no_deadlock(outcome: dict[str, Any]) -> None:
    assert outcome["enrolment_waited"], "the interleaving was not reproduced: enrolment never waited on X's cursor"
    assert outcome["indexer"] is None, f"indexer page write aborted: {outcome['indexer']!r}"
    assert outcome["enrolment"] is None, f"enrolment aborted: {outcome['enrolment']!r}"


def _state(session, address: str) -> tuple[str | None, str | None, int]:
    session.expire_all()
    cursor = session.execute(select(IndexedEventCursor).where(IndexedEventCursor.event_address == address)).scalar_one()
    return cursor.enrollment_basis, cursor.first_indexed_block_basis, int(cursor.last_indexed_block)


def test_basis_upgrades_never_deadlock_with_a_page_write(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    for address in (_Y, _X):
        _cursor(db_session, address, basis=ENROLLMENT_BASIS_TRACKED_TOPICS, witnessed=True)
    job_id = _hint_job(db_session)
    db_session.commit()

    outcome = _race(
        monkeypatch,
        lambda session: eli.enroll_from_completed_jobs(session, job_id=job_id, progress=session.commit, commit=False),
    )

    _assert_no_deadlock(outcome)
    assert _state(db_session, _Y)[0] == _state(db_session, _X)[0] == ENROLLMENT_BASIS_PREDICATE_HINT
    assert _state(db_session, _X)[2] == _TARGET
    assert db_session.execute(select(func.count()).select_from(IndexedEventLog)).scalar_one() == 1


def test_enrolment_drain_with_a_witness_upgrade_never_deadlocks_with_a_page_write(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    _cursor(db_session, _Y, basis=ENROLLMENT_BASIS_TRACKED_TOPICS, witnessed=True)
    # X's enrolment witness failed; its retry is due and proves the seed the cursor was enrolled at.
    _cursor(db_session, _X, basis=ENROLLMENT_BASIS_PREDICATE_HINT, witnessed=False)
    db_session.flush()
    db_session.execute(
        text(
            "INSERT INTO address_floor_witnesses (chain_id, address, basis, outcome, seed_block, attempts, "
            "next_attempt_at) VALUES (1, :a, 'not_determined', 'failed', :s, 1, now() - interval '1 second')"
        ),
        {"a": _X, "s": _SEED},
    )
    record_floor_witness(db_session, chain_id=1, address=_Y, outcome=WITNESS_PROVEN, first_indexed_block=_SEED)
    job_id = _hint_job(db_session)
    db_session.execute(text("SELECT indexer_mark_dirty('job', :k)"), {"k": str(job_id)})
    db_session.commit()

    outcome = _race(monkeypatch, lambda session: indexer_scheduler.drain_enrollment(session, tracked_limit=0))

    _assert_no_deadlock(outcome)
    assert _state(db_session, _Y)[0] == ENROLLMENT_BASIS_PREDICATE_HINT
    assert _state(db_session, _X) == (ENROLLMENT_BASIS_PREDICATE_HINT, FIRST_INDEXED_BASIS_CREATION, _TARGET)
    witness = db_session.execute(select(AddressFloorWitness).where(AddressFloorWitness.address == _X)).scalar_one()
    assert witness.outcome == "proven"


@pytest.fixture(autouse=True)
def _clean_slate(db_session):
    """The retry step's budget must reach X, so no other file's leftover cursors may queue ahead of it."""
    for model in (IndexedEventLog, IndexedEventCursor, AddressFloorWitness):
        db_session.execute(delete(model))
    db_session.commit()
