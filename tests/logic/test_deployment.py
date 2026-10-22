"""The logic engine's production edges: event history from ``indexed_event_logs``, and the resolution switch."""

from __future__ import annotations

import pytest
from sqlalchemy import delete

from tests.conftest import requires_postgres

EMITTER = "0x" + "ab" * 20
TOPIC = "0x" + "11" * 32
OTHER_TOPIC = "0x" + "22" * 32


def _seed(db_session, count: int, topic0: str = TOPIC, indexed_to: int | None = 1_000_000) -> None:
    from db.models import IndexedEventCursor, IndexedEventLog

    if indexed_to is not None:
        db_session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=EMITTER,
                topic0=topic0,
                last_indexed_block=indexed_to,
                backfill_complete=True,
            )
        )

    for i in range(count):
        db_session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=EMITTER,
                topic0=topic0,
                tx_hash=bytes([i % 256, i // 256, *topic0.encode()[:30]]),
                log_index=i,
                block_number=100 + i,
                block_hash=b"\xbb" * 32,
                transaction_index=0,
                topics=[topic0, "0x" + format(i, "064x")],
                data_words=["0x" + format(1000 + i, "064x")],
            )
        )
    db_session.commit()


@pytest.fixture()
def logs(db_session):
    from db.models import IndexedEventCursor, IndexedEventLog

    yield db_session
    db_session.execute(delete(IndexedEventLog).where(IndexedEventLog.event_address == EMITTER))
    db_session.execute(delete(IndexedEventCursor).where(IndexedEventCursor.event_address == EMITTER))
    db_session.commit()


def _chain(session, block: int, rpc=lambda method, params: None):
    from services.logic.deployment import IndexedChain

    return IndexedChain(session, 1, rpc, block)


@requires_postgres
def test_logs_come_in_chain_order_up_to_the_pinned_block(logs):
    _seed(logs, 5)
    _seed(logs, 2, OTHER_TOPIC)
    chain = _chain(logs, 102)
    got = chain.logs(int(EMITTER, 16), frozenset({TOPIC}))
    assert [topics[1] for topics, _ in got] == [0, 1, 2]
    assert [data[0] for _, data in got] == [1000, 1001, 1002]
    assert int(EMITTER, 16) not in chain.truncated


@requires_postgres
def test_a_history_too_long_to_read_keeps_both_ends_and_is_marked_partial(logs, monkeypatch):
    import services.logic.deployment as deployment

    monkeypatch.setattr(deployment, "LOG_ROWS", 4)
    _seed(logs, 9)
    chain = _chain(logs, 10_000)
    got = chain.logs(int(EMITTER, 16), frozenset({TOPIC}))
    assert [topics[1] for topics, _ in got] == [0, 1, 7, 8]
    assert int(EMITTER, 16) in chain.truncated


@requires_postgres
def test_a_history_the_indexer_has_not_finished_is_used_but_marked_partial(logs):
    _seed(logs, 3, indexed_to=None)  # logs without a finished backfill
    chain = _chain(logs, 102)
    assert [topics[1] for topics, _ in chain.logs(int(EMITTER, 16), frozenset({TOPIC}))] == [0, 1, 2]
    assert int(EMITTER, 16) in chain.truncated


@requires_postgres
def test_a_history_never_indexed_is_read_from_the_chain(logs):
    def rpc(method, params):
        assert method == "eth_getLogs"
        return [{"topics": [TOPIC, "0x" + format(7, "064x")], "data": "0x"}]

    chain = _chain(logs, 102, rpc)
    assert [topics[1] for topics, _ in chain.logs(int(EMITTER, 16), frozenset({TOPIC}))] == [7]
    assert int(EMITTER, 16) not in chain.truncated


@requires_postgres
def test_an_index_that_lags_the_block_is_partial(logs):
    _seed(logs, 3, indexed_to=50)
    chain = _chain(logs, 10_000)
    chain.logs(int(EMITTER, 16), frozenset({TOPIC}))
    assert int(EMITTER, 16) in chain.truncated


@requires_postgres
def test_every_word_an_address_emitted_is_a_candidate_source(logs):
    _seed(logs, 3)
    words = _chain(logs, 10_000).all_log_words(int(EMITTER, 16))
    assert {0, 1, 2, 1000, 1001, 1002} <= words


def test_the_logic_engine_is_off_unless_switched_on(monkeypatch):
    from workers.resolution_worker import logic_engine_enabled

    monkeypatch.delenv("PSAT_LOGIC_ENGINE", raising=False)
    assert not logic_engine_enabled()
    monkeypatch.setenv("PSAT_LOGIC_ENGINE", "1")
    assert logic_engine_enabled()
