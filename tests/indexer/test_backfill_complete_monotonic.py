"""``backfill_complete`` is monotonic: once a cursor reaches the confirmed head it stays complete while a sibling topic
backfills at the same address, and only an explicit reorg rewind resets it.
"""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import select

from db.models import ENROLLMENT_BASIS_PREDICATE_HINT, FIRST_INDEXED_BASIS_CREATION, IndexedEventCursor
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import requires_postgres
from tests.support.one_page_fetch import OnePagePerFetch
from workers.event_log_indexer import PageLimits, index_event_group_steps

pytestmark = requires_postgres

_ADDR = "0x00000000000000000000000000000000000a11e5"
_WARM = "0x" + "d1" * 32
_COLD = "0x" + "d2" * 32
_WARM_AT = 1_000
_TARGET = 5_000


class _EmptyFetcher(OnePagePerFetch):
    def fetch_logs(
        self, *, event_address: str | Sequence[str], topics, from_block: int, to_block: int, window_stats=None
    ) -> list[FetchedEventLog]:
        return []


class _Hashes:
    def __init__(self, reorged: set[int] | None = None) -> None:
        self.reorged = reorged or set()

    def block_hash(self, block_number: int) -> bytes:
        return (b"\xff" if block_number in self.reorged else b"\x00") + block_number.to_bytes(31, "big")


def _cursor(topic0: str, last: int, *, complete: bool) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=_ADDR,
        topic0=topic0,
        last_indexed_block=last,
        last_indexed_block_hash=_Hashes().block_hash(last) if complete else None,
        backfill_complete=complete,
        first_indexed_block=99,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
        enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
    )


def _step(session, hashes: _Hashes) -> None:
    for _prefix in index_event_group_steps(
        session,
        chain_id=1,
        event_address=_ADDR,
        fetcher=_EmptyFetcher(),
        target=_TARGET,
        block_hash_fetcher=hashes,
        limits=PageLimits(max_block_span=500, max_pages=1),
    ):
        session.commit()


def _get(session, topic0: str) -> IndexedEventCursor:
    cursor = session.execute(select(IndexedEventCursor).where(IndexedEventCursor.topic0 == topic0)).scalar_one()
    session.refresh(cursor)
    return cursor


def _writes(session, block: int):
    return PostgresEventLogRepo(session).fold_event_writes(
        chain_id=1,
        event_address=_ADDR,
        topic0=_WARM,
        topics_to_keys={1: 0},
        data_to_keys={},
        key_sources=[{"source": "msg_sender"}],
        direction="add",
        block=block,
    )


def test_sibling_backfill_leaves_the_warm_cursor_complete_and_exact(db_session):
    db_session.add_all([_cursor(_WARM, _WARM_AT, complete=True), _cursor(_COLD, 100, complete=False)])
    db_session.commit()

    _step(db_session, _Hashes())

    warm, cold = _get(db_session, _WARM), _get(db_session, _COLD)
    # The shared window [101, 600] stays below the warm cursor, which neither moves nor loses completeness.
    assert (cold.last_indexed_block, cold.backfill_complete) == (600, False)
    assert (warm.last_indexed_block, warm.backfill_complete) == (_WARM_AT, True)
    covered = _writes(db_session, block=_WARM_AT - 10)
    assert (covered.confidence, covered.partial_reason) == ("enumerable", None)
    # Staleness is judged by coverage of the evaluated block, not by the flag.
    assert _writes(db_session, block=_WARM_AT + 10).partial_reason == "cursor_behind_block"


def test_reorg_rewind_still_resets_the_flag(db_session):
    db_session.add(_cursor(_WARM, _WARM_AT, complete=True))
    db_session.commit()

    _step(db_session, _Hashes(reorged={_WARM_AT}))

    warm = _get(db_session, _WARM)
    assert warm.backfill_complete is False
    assert warm.last_indexed_block < _TARGET


def test_reaching_the_target_marks_complete(db_session):
    db_session.add(_cursor(_COLD, _TARGET - 300, complete=False))
    db_session.commit()

    _step(db_session, _Hashes())

    cold = _get(db_session, _COLD)
    assert (cold.last_indexed_block, cold.backfill_complete) == (_TARGET, True)
    assert cold.last_indexed_block_hash == _Hashes().block_hash(_TARGET)
