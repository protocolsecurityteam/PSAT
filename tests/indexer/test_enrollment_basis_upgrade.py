"""A predicate-hint enrolment upgrades an existing witnessed cursor to ``predicate_tree_hint``, so the order in which
sources enrol a (chain, address, topic0) never decides whether it can license exactness.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import delete, func, select, update

from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexerWork,
)
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres
from tests.support.witness_wire import stub_seed_witness
from workers.event_log_indexer import EnrollmentCaches, _enroll_witnessed

pytestmark = requires_postgres

_ADDR = "0x00000000000000000000000000000000000ba5e1"
_TOPIC = "0x" + "c4" * 32
_CREATION = 19_000_000

_STATE_COLUMNS = (
    "chain_id",
    "event_address",
    "topic0",
    "last_indexed_block",
    "last_indexed_block_hash",
    "backfill_complete",
    "first_indexed_block",
    "first_indexed_block_basis",
    "enrollment_basis",
    "max_window_log_count",
    "window_stats_cap",
    "window_stats_basis",
)


def _enroll(session, basis: str) -> bool:
    caches = EnrollmentCaches()
    return _enroll_witnessed(
        session,
        chain_id=1,
        address=_ADDR,
        topic0=_TOPIC,
        seed_cache=caches.seeds,
        witness_cache=caches.witnesses,
        enrollment_basis=basis,
    )


def _state(session) -> dict[str, Any]:
    cursor = session.execute(select(IndexedEventCursor).where(IndexedEventCursor.event_address == _ADDR)).scalar_one()
    session.refresh(cursor)
    return {column: getattr(cursor, column) for column in _STATE_COLUMNS}


def _eligible(session) -> bool:
    session.execute(
        update(IndexedEventCursor)
        .where(IndexedEventCursor.event_address == _ADDR)
        .values(backfill_complete=True, last_indexed_block=_CREATION + 10)
    )
    _block, complete = PostgresEventLogRepo(session).cursor_state(1, _ADDR, _TOPIC)
    return complete


def _reset(session) -> None:
    session.execute(delete(IndexedEventCursor).where(IndexedEventCursor.event_address == _ADDR))
    session.commit()


@pytest.mark.parametrize("witness_fails", [False, True], ids=["witnessed", "witness_failed"])
def test_tracked_then_hint_and_hint_then_tracked_end_in_the_same_eligibility(db_session, monkeypatch, witness_fails):
    stub_seed_witness(monkeypatch, creation_block=_CREATION, fail=witness_fails)

    assert _enroll(db_session, ENROLLMENT_BASIS_TRACKED_TOPICS)
    assert not _enroll(db_session, ENROLLMENT_BASIS_PREDICATE_HINT)
    db_session.commit()
    tracked_first = _state(db_session)
    tracked_first_eligible = _eligible(db_session)
    _reset(db_session)

    assert _enroll(db_session, ENROLLMENT_BASIS_PREDICATE_HINT)
    assert not _enroll(db_session, ENROLLMENT_BASIS_TRACKED_TOPICS)
    db_session.commit()
    hint_first = _state(db_session)
    hint_first_eligible = _eligible(db_session)

    assert tracked_first_eligible is hint_first_eligible is (not witness_fails)
    if witness_fails:
        # A witness-failed cursor is never upgraded, and neither order can license exactness.
        assert tracked_first["enrollment_basis"] == ENROLLMENT_BASIS_TRACKED_TOPICS
        assert tracked_first["first_indexed_block_basis"] == hint_first["first_indexed_block_basis"] == "not_determined"
    else:
        assert tracked_first == hint_first
        assert hint_first["enrollment_basis"] == ENROLLMENT_BASIS_PREDICATE_HINT
        assert hint_first["first_indexed_block_basis"] == FIRST_INDEXED_BASIS_CREATION


def test_upgrade_changes_only_the_enrollment_basis(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    assert _enroll(db_session, ENROLLMENT_BASIS_TRACKED_TOPICS)
    db_session.execute(update(IndexedEventCursor).values(last_indexed_block=_CREATION + 500, backfill_complete=True))
    db_session.commit()
    before = _state(db_session)

    _enroll(db_session, ENROLLMENT_BASIS_PREDICATE_HINT)
    db_session.commit()
    after = _state(db_session)

    assert {k for k in _STATE_COLUMNS if before[k] != after[k]} == {"enrollment_basis"}


@pytest.mark.parametrize("first_basis", [None, "explicit_seed", "not_determined"])
def test_unwitnessed_lower_bounds_are_not_upgraded(db_session, monkeypatch, first_basis):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    assert _enroll(db_session, ENROLLMENT_BASIS_TRACKED_TOPICS)
    db_session.execute(update(IndexedEventCursor).values(first_indexed_block_basis=first_basis))
    _enroll(db_session, ENROLLMENT_BASIS_PREDICATE_HINT)
    db_session.commit()
    assert _state(db_session)["enrollment_basis"] == ENROLLMENT_BASIS_TRACKED_TOPICS
    assert not _eligible(db_session)


def test_upgrade_marks_reconcile(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    assert _enroll(db_session, ENROLLMENT_BASIS_TRACKED_TOPICS)
    db_session.commit()
    db_session.execute(update(IndexerWork).values(dirty=False, completed_at=func.now()))
    db_session.commit()
    before = db_session.get(IndexerWork, ("reconcile", "1"))
    assert before is not None
    revision = before.revision

    _enroll(db_session, ENROLLMENT_BASIS_PREDICATE_HINT)
    db_session.commit()
    db_session.expire_all()
    after = db_session.get(IndexerWork, ("reconcile", "1"))
    assert after is not None
    assert (after.dirty, after.revision) == (True, revision + 1)


def test_hint_reenrolment_of_an_eligible_cursor_writes_nothing(db_session, monkeypatch):
    stub_seed_witness(monkeypatch, creation_block=_CREATION)
    assert _enroll(db_session, ENROLLMENT_BASIS_PREDICATE_HINT)
    db_session.commit()
    db_session.execute(update(IndexerWork).values(dirty=False, completed_at=func.now()))
    db_session.commit()
    revision = db_session.get(IndexerWork, ("reconcile", "1")).revision

    _enroll(db_session, ENROLLMENT_BASIS_PREDICATE_HINT)
    db_session.commit()
    db_session.expire_all()
    assert db_session.get(IndexerWork, ("reconcile", "1")).revision == revision
