"""The durable event-log queries must be index-sargable.

``PostgresEventLogRepo`` filters ``indexed_event_logs`` / ``indexed_event_cursors``
by ``(chain_id, event_address, topic0)``. Those columns are stored lowercase and
``ix_indexed_event_logs_lookup`` covers the raw columns, so the queries compare the
raw columns directly (the literals are lowercased by the caller). Wrapping a column
in ``lower(...)`` would make the predicate non-sargable and force a sequential scan,
so these tests assert (a) the compiled SQL never wraps an indexed column in
``lower()`` and (b) on real seeded data the planner picks the lookup index.

These drive the production repo + a real Postgres session; only the rows are
seeded.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.dialects import postgresql

from db.models import IndexedEventCursor, IndexedEventLog  # noqa: E402
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

pytestmark = requires_postgres

# A selective (address, topic0) the planner should serve from the lookup index,
# plus a high-cardinality decoy address that fills the table so a sequential scan
# is the expensive alternative.
TARGET_ADDR = "0xaba6ba1e95e0926a6a6b917fe4e2f19ceae4ff2e"
TARGET_TOPIC0 = "0xa52ea92e6e955aa8ac66420b86350f7139959adfcc7e6a14eee1bd116d09860e"
DECOY_ADDR = "0x1a44076050125825900e736c501f859c50fe728c"
DECOY_TOPIC0 = "0x3d52ff888d033fd3dd1d8057da59e850c91d91a72c41dfa445b247dfedeb6dc1"


def _log(addr: str, topic0: str, *, block: int, log_index: int) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=addr,
        topic0=topic0,
        tx_hash=(block * 1000 + log_index).to_bytes(8, "big").rjust(32, b"\x00"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(8, "big").rjust(32, b"\x11"),
        transaction_index=0,
        topics=[topic0],
        data_words=[],
    )


def _compiled(query) -> str:
    return str(query.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})).lower()


def test_fold_queries_do_not_wrap_indexed_columns_in_lower():
    # The exact predicates the repo emits for the three lookups, compiled to SQL.
    # None may wrap an indexed column in lower(): that would defeat the raw-column
    # lookup index. The literals are already lowercase (asserted by the caller).
    single = (
        select(IndexedEventLog)
        .where(IndexedEventLog.chain_id == 1)
        .where(IndexedEventLog.event_address == TARGET_ADDR)
        .where(IndexedEventLog.topic0 == TARGET_TOPIC0)
    )
    multi = (
        select(IndexedEventLog)
        .where(IndexedEventLog.chain_id == 1)
        .where(IndexedEventLog.event_address == TARGET_ADDR)
        .where(IndexedEventLog.topic0.in_([TARGET_TOPIC0]))
    )
    cursor = (
        select(IndexedEventCursor.last_indexed_block, IndexedEventCursor.backfill_complete)
        .where(IndexedEventCursor.chain_id == 1)
        .where(IndexedEventCursor.event_address == TARGET_ADDR)
        .where(IndexedEventCursor.topic0 == TARGET_TOPIC0)
    )
    for query in (single, multi, cursor):
        sql = _compiled(query)
        assert "lower(" not in sql, sql


def _seed_index_demo(session) -> None:
    rows = [_log(TARGET_ADDR, TARGET_TOPIC0, block=100 + i, log_index=i) for i in range(40)]
    # ~4k decoy rows under a different address so the target predicate is highly
    # selective and an index scan strictly beats a sequential scan.
    rows += [_log(DECOY_ADDR, DECOY_TOPIC0, block=1000 + i, log_index=i) for i in range(4000)]
    for row in rows:
        session.add(row)
    session.flush()
    # Refresh planner stats for this session's view of the freshly seeded table.
    session.execute(text("ANALYZE indexed_event_logs"))


def _explain(session, query) -> str:
    sql = _compiled(query)
    plan_rows = session.execute(text("EXPLAIN " + sql)).fetchall()
    return "\n".join(r[0] for r in plan_rows)


def test_selective_fold_query_uses_lookup_index(db_session):
    _seed_index_demo(db_session)
    query = (
        select(IndexedEventLog)
        .where(IndexedEventLog.chain_id == 1)
        .where(IndexedEventLog.event_address == TARGET_ADDR)
        .where(IndexedEventLog.topic0.in_([TARGET_TOPIC0]))
        .order_by(
            IndexedEventLog.block_number.asc(),
            IndexedEventLog.transaction_index.asc(),
            IndexedEventLog.log_index.asc(),
        )
    )
    plan = _explain(db_session, query)
    assert "ix_indexed_event_logs_lookup" in plan, plan
    assert "Seq Scan" not in plan, plan


def test_lower_wrapped_query_would_seq_scan(db_session):
    # Control: the pre-fix shape (lower()-wrapped columns) on the same data CANNOT
    # use the raw-column index and falls back to a sequential scan. Demonstrates
    # the sargability the raw-column query restores.
    _seed_index_demo(db_session)
    plan = "\n".join(
        r[0]
        for r in db_session.execute(
            text(
                "EXPLAIN SELECT * FROM indexed_event_logs "
                "WHERE chain_id = 1 "
                "AND lower(event_address) = :addr AND lower(topic0) = :topic"
            ),
            {"addr": TARGET_ADDR, "topic": TARGET_TOPIC0},
        ).fetchall()
    )
    assert "ix_indexed_event_logs_lookup" not in plan, plan
    assert "Seq Scan" in plan, plan


def test_repo_returns_rows_with_raw_column_comparison(db_session):
    # End-to-end: the repo's raw-column query still returns the right rows, and a
    # mixed-case literal handed in by a caller is lowercased before the comparison
    # (the stored data is lowercase, so the match holds).
    _seed_index_demo(db_session)
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=TARGET_ADDR,
            topic0=TARGET_TOPIC0,
            last_indexed_block=10_000,
            backfill_complete=True,
        )
    )
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)

    lowered = repo.iter_event_rows(chain_id=1, event_address=TARGET_ADDR, topic0s=[TARGET_TOPIC0])
    assert len(lowered) == 40
    # A caller passing a checksum/upper variant resolves to the same 40 rows: the
    # repo lowercases the literal, matching the lowercase-stored column.
    mixed = repo.iter_event_rows(chain_id=1, event_address=TARGET_ADDR.upper(), topic0s=[TARGET_TOPIC0.upper()])
    assert len(mixed) == 40
    block, complete = repo._cursor_state(1, TARGET_ADDR.upper(), TARGET_TOPIC0.upper())
    assert (block, complete) == (10_000, True)


@pytest.mark.parametrize("table", ["indexed_event_logs", "indexed_event_cursors"])
def test_no_mixed_case_rows_invariant_documented(db_session, table):
    # The raw-column lookup relies on every stored event_address/topic0 being
    # lowercase. Assert the invariant holds for any rows this suite seeds (the
    # production indexer writes lowercase); a regression that stored mixed case
    # would silently miss the raw-column predicate.
    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=TARGET_ADDR,
            topic0=TARGET_TOPIC0,
            tx_hash=b"\x00" * 32,
            log_index=0,
            block_number=1,
            block_hash=b"\x11" * 32,
            transaction_index=0,
            topics=[TARGET_TOPIC0],
            data_words=[],
        )
    )
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=TARGET_ADDR,
            topic0=TARGET_TOPIC0,
            last_indexed_block=1,
            backfill_complete=True,
        )
    )
    db_session.flush()
    mixed = db_session.execute(
        text(f"SELECT count(*) FROM {table} WHERE event_address <> lower(event_address) OR topic0 <> lower(topic0)")
    ).scalar()
    assert mixed == 0
