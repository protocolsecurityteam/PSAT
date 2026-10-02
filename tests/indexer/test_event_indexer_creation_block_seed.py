"""Cursors are seeded from the address's creation block, not 0, which used to rescan ~20M empty pre-deployment
blocks.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from tests.support.indexer_stubs import _DeterministicBlockHash
from workers.event_log_indexer import (
    enroll_event_cursor,
    scan_enrolled_events,
)


@pytest.fixture(autouse=True)
def _no_creation_witness(monkeypatch):
    """This module asserts the seed, not the grade."""
    import workers.event_log_indexer as eli

    def _no_wire(*_a, **_kw):
        raise RuntimeError("no rpc")

    monkeypatch.setattr(eli, "rpc_request", _no_wire)


_DEPLOY = 19_000_000
_HEAD = 19_300_000
_CONFIRMATIONS = 12
_TARGET = _HEAD - _CONFIRMATIONS
_MAX_SPAN = 100_000
_AUTHORITY = "0x" + "5c" * 20
_TOPIC = "0x" + "ab" * 32


class _RecordingFetcher:
    def __init__(self) -> None:
        self.from_blocks: list[int] = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block) -> list[FetchedEventLog]:
        self.from_blocks.append(from_block)
        return []


class _FixedHead:
    def head_block(self) -> int:
        return _HEAD


@pytest.fixture()
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, IndexedEventCursor, IndexedEventLog, Job, Protocol

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        for model in (IndexedEventLog, IndexedEventCursor, Contract):
            s.query(model).delete()
        s.query(Job).delete()
        s.query(Protocol).delete()
        s.commit()
        s.close()
        engine.dispose()


def _maps(fetcher):
    return ({1: fetcher}, {1: _FixedHead()}, {1: _DeterministicBlockHash()})


def _cursor_state(session, address: str):
    from db.models import IndexedEventCursor

    row = session.execute(
        select(IndexedEventCursor.last_indexed_block, IndexedEventCursor.backfill_complete).where(
            func.lower(IndexedEventCursor.event_address) == address.lower()
        )
    ).first()
    return (row[0], row[1]) if row else (None, None)


def _etherscan_down(*_a, **_k):
    raise RuntimeError("etherscan down")


_CREATOR = "0x" + "ab" * 20


@pytest.mark.parametrize(
    ("address", "es_get", "kwargs", "expected"),
    [
        pytest.param(
            _CREATOR,
            lambda module, action, **params: {
                "status": "1",
                "result": [
                    {"contractAddress": _CREATOR, "contractCreator": "0x" + "cd" * 20, "blockNumber": "18500000"}
                ],
            },
            {},
            18_500_000,
            id="prefers_blocknumber",
        ),
        pytest.param(
            _CREATOR,
            lambda module, action, **params: {"status": "1", "result": [{"txHash": "0x" + "11" * 32}]},
            {"rpc_url": "http://stub"},
            18_500_000,
            id="falls_back_to_txhash",
        ),
        pytest.param(_CREATOR, _etherscan_down, {}, None, id="none_on_failure"),
        pytest.param(
            _CREATOR,
            lambda module, action, **params: {"status": "1", "result": [{"blockNumber": 18_500_000}]},
            {},
            18_500_000,
            id="accepts_int_blocknumber",
        ),
        pytest.param("not-an-address", _etherscan_down, {}, None, id="rejects_non_address"),
        pytest.param(
            _CREATOR,
            lambda module, action, **params: {"status": "1", "result": [{"contractCreator": "0x" + "cd" * 20}]},
            {},
            None,
            id="none_when_no_block_and_no_txhash",
        ),
    ],
)
def test_get_contract_creation_block(monkeypatch, address, es_get, kwargs, expected):
    import services.clients.etherscan as es
    import services.clients.rpc as rpc

    monkeypatch.setattr(es, "get", es_get)
    monkeypatch.setattr(rpc, "rpc_request", lambda url, method, params, chain_id=None: {"blockNumber": hex(18_500_000)})
    assert es.get_contract_creation_block(address, chain_id=1, **kwargs) == expected


@requires_postgres
def test_index_step_marks_backfill_complete_when_already_at_head(session):
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC, start_block=_HEAD)
    session.commit()

    fetcher = _RecordingFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_MAX_SPAN,
        max_windows_per_cursor=5,
    )
    assert fetcher.from_blocks == []  # already at head → no scan window
    _, complete = _cursor_state(session, _AUTHORITY)
    assert complete is True


@requires_postgres
def test_pg_repo_not_backfill_complete_is_not_trusted(session):
    # A partial history must not fold as exact.
    from db.models import IndexedEventCursor, IndexedEventLog
    from services.resolution.repos.event_logs_pg import PostgresEventLogRepo

    addr = "0x" + "7e" * 20
    topic = "0x" + "cd" * 32
    member = "0x" + "77" * 20
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=addr,
            topic0=topic,
            last_indexed_block=19_000_000,
            backfill_complete=False,
            first_indexed_block=0,
            first_indexed_block_basis="creation_block_minus_one",
        )
    )
    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=addr,
            topic0=topic,
            tx_hash=b"\x01" * 32,
            log_index=0,
            block_number=18_500_000,
            block_hash=b"\x02" * 32,
            transaction_index=0,
            topics=[topic, "0x" + "00" * 12 + member[2:]],
            data_words=[],
        )
    )
    session.commit()

    repo = PostgresEventLogRepo(session)
    assert repo.min_indexed_block(chain_id=1, event_address=addr, topic0s=[topic]) is None
    hist = repo.fold_event_history(
        chain_id=1,
        event_address=addr,
        event_hints=[{"topic0": topic, "direction": "add", "topics_to_keys": {1: 0}, "data_to_keys": {}}],
        key_sources=[{"source": "msg_sender"}],
    )
    assert hist.partial_reason == "no_index_cursor"
    writes = repo.fold_event_writes(
        chain_id=1,
        event_address=addr,
        topic0=topic,
        topics_to_keys={1: 0},
        data_to_keys={},
        key_sources=[{"source": "msg_sender"}],
        direction="add",
    )
    assert writes.partial_reason == "no_index_cursor"

    cursor = session.execute(select(IndexedEventCursor)).scalar_one()
    cursor.backfill_complete = True
    session.commit()
    assert repo.min_indexed_block(chain_id=1, event_address=addr, topic0s=[topic]) == 19_000_000
    # Evaluate at a covered height (#119); block=None would demote.
    hist2 = repo.fold_event_history(
        chain_id=1,
        event_address=addr,
        event_hints=[{"topic0": topic, "direction": "add", "topics_to_keys": {1: 0}, "data_to_keys": {}}],
        key_sources=[{"source": "msg_sender"}],
        block=19_000_000,
    )
    assert hist2.confidence == "enumerable"
    assert hist2.members == [member]
