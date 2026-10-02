"""Columns are stored lowercase, so wrapping one in ``lower()`` would force a sequential scan."""

from __future__ import annotations

from sqlalchemy import text

from db.models import IndexedEventCursor, IndexedEventLog
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres

pytestmark = requires_postgres

# The decoy fills the table so a sequential scan is the expensive alternative.
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


def _seed_index_demo(session) -> None:
    rows = [_log(TARGET_ADDR, TARGET_TOPIC0, block=100 + i, log_index=i) for i in range(40)]
    rows += [_log(DECOY_ADDR, DECOY_TOPIC0, block=1000 + i, log_index=i) for i in range(4000)]
    for row in rows:
        session.add(row)
    session.flush()
    session.execute(text("ANALYZE indexed_event_logs"))


def test_repo_returns_rows_with_raw_column_comparison(db_session):
    _seed_index_demo(db_session)
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=TARGET_ADDR,
            topic0=TARGET_TOPIC0,
            last_indexed_block=10_000,
            backfill_complete=True,
            first_indexed_block=0,
            first_indexed_block_basis="creation_block_minus_one",
        )
    )
    db_session.flush()
    repo = PostgresEventLogRepo(db_session)

    lowered = repo.iter_event_rows(chain_id=1, event_address=TARGET_ADDR, topic0s=[TARGET_TOPIC0])
    assert len(lowered) == 40
    mixed = repo.iter_event_rows(chain_id=1, event_address=TARGET_ADDR.upper(), topic0s=[TARGET_TOPIC0.upper()])
    assert len(mixed) == 40
    block, complete = repo._cursor_state(1, TARGET_ADDR.upper(), TARGET_TOPIC0.upper())
    assert (block, complete) == (10_000, True)
