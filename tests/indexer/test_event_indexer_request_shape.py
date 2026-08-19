"""The indexer's request shape against request-metered upstreams.

The getLogs fast lane (Envio HyperRPC behind eRPC) meters a flat 1000 credits
per REQUEST — 60/min — regardless of block range (measured 2026-06-11: a
1M-block ``eth_getLogs`` costs exactly what a 10k one costs). The old shape
spent ~7 requests per 50k window (10k client-side pages + per-window head/hash
lookups), times the number of topic0 cursors on the same address — exhausting
the lane and spilling every call onto the slow fallback. These tests pin the
cheap shape:

* one (chain, address) group = ONE ``eth_getLogs`` per window with every
  topic0 OR'd, demuxed back to per-topic cursors advancing in lockstep;
* one request per window in ``RpcEventLogFetcher`` (no client-side paging),
  bisecting only when the upstream rejects the range — upstreams fail loudly
  ("Limit exceeded: More than 50000 logs returned" / "Query timed out"),
  never truncate;
* block-hash stamps only at the confirmed fringe (finalized mid-backfill
  blocks can't reorg) with a per-pass memo, and one head fetch per pass.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select, update

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from services.resolution.repos.event_logs_rpc import FetchedEventLog, RpcEventLogFetcher
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from utils.rpc import RpcClientTimeout
from workers.event_log_indexer import enroll_event_cursor, scan_enrolled_events

_CONFIRMATIONS = 12
_ADDRESS = "0x" + "4d" * 20
_TOPIC_A = "0x" + "aa" * 32
_TOPIC_B = "0x" + "bb" * 32


class _RecordingMultiTopicFetcher:
    """Emits one log per requested topic every ``density`` blocks and records
    each call's (topics, from, to)."""

    def __init__(self, density: int = 100) -> None:
        self.density = density
        self.calls: list[tuple[tuple[str, ...], int, int]] = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block) -> list[FetchedEventLog]:
        self.calls.append((tuple(sorted(topics)), from_block, to_block))
        out: list[FetchedEventLog] = []
        first = ((from_block + self.density - 1) // self.density) * self.density
        for blk in range(first, to_block + 1, self.density):
            for topic0 in topics:
                out.append(
                    FetchedEventLog(
                        tx_hash=blk.to_bytes(31, "big") + bytes([int(topic0[3], 16)]),
                        log_index=0,
                        block_number=blk,
                        block_hash=blk.to_bytes(32, "big"),
                        transaction_index=0,
                        topics=[topic0, "0x" + "00" * 31 + "01"],
                        data_words=["0x" + "00" * 31 + "01"],
                    )
                )
        return out


class _EmptyFetcher:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block) -> list[FetchedEventLog]:
        self.calls.append((from_block, to_block))
        return []


class _CountingHead:
    def __init__(self, head: int) -> None:
        self.head = head
        self.calls = 0

    def head_block(self) -> int:
        self.calls += 1
        return self.head


class _CountingBlockHash:
    def __init__(self) -> None:
        self.calls: list[int] = []

    def block_hash(self, block_number: int) -> bytes:
        self.calls.append(block_number)
        return block_number.to_bytes(32, "big")


@pytest.fixture()
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import IndexedEventCursor, IndexedEventLog

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        for model in (IndexedEventLog, IndexedEventCursor):
            s.query(model).delete()
        s.commit()
        s.close()
        engine.dispose()


def _set_cursor(session, topic0: str, *, last: int, block_hash: bytes | None = None) -> None:
    from db.models import IndexedEventCursor

    session.execute(
        update(IndexedEventCursor)
        .where(func.lower(IndexedEventCursor.event_address) == _ADDRESS)
        .where(func.lower(IndexedEventCursor.topic0) == topic0)
        .values(last_indexed_block=last, last_indexed_block_hash=block_hash)
    )


def _cursor(session, topic0: str):
    from db.models import IndexedEventCursor

    return session.execute(
        select(
            IndexedEventCursor.last_indexed_block,
            IndexedEventCursor.backfill_complete,
            IndexedEventCursor.last_indexed_block_hash,
        )
        .where(func.lower(IndexedEventCursor.event_address) == _ADDRESS)
        .where(func.lower(IndexedEventCursor.topic0) == topic0)
    ).one()


def _topic_blocks(session, topic0: str) -> list[int]:
    from db.models import IndexedEventLog

    return [
        row[0]
        for row in session.execute(
            select(IndexedEventLog.block_number)
            .where(func.lower(IndexedEventLog.event_address) == _ADDRESS)
            .where(func.lower(IndexedEventLog.topic0) == topic0)
            .order_by(IndexedEventLog.block_number)
        )
    ]


@requires_postgres
def test_multi_topic_address_scans_once_per_window_and_demuxes(session):
    """Two topic0 cursors on one address must cost ONE getLogs per window (the
    topics OR'd into a single request), with results demuxed per topic and a
    drifted-ahead cursor only ever receiving logs above its own position."""
    head = 10_000 + _CONFIRMATIONS
    target = 10_000
    span = 2_500
    density = 100
    drift = 5_000  # topic B already indexed through here

    enroll_event_cursor(session, chain_id=1, event_address=_ADDRESS, topic0=_TOPIC_A)
    enroll_event_cursor(session, chain_id=1, event_address=_ADDRESS, topic0=_TOPIC_B)
    _set_cursor(session, _TOPIC_B, last=drift)
    session.commit()

    fetcher = _RecordingMultiTopicFetcher(density=density)
    summary = scan_enrolled_events(
        session,
        fetchers={1: fetcher},
        head_fetchers={1: _CountingHead(head)},
        block_hash_fetchers={1: _CountingBlockHash()},
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=span,
        max_windows_per_cursor=100,
        max_windows_per_pass=100,
    )

    # The economy claim: 4 windows of 2_500 cover the 10_000-block gap in 4
    # requests TOTAL — not 4 per topic — and every request carried both topics.
    assert len(fetcher.calls) == target // span
    assert all(topics == (_TOPIC_A, _TOPIC_B) for topics, _f, _t in fetcher.calls)
    assert summary.windows_scanned == target // span

    # Demux: each topic's rows land under its own topic0; the drifted cursor
    # got nothing at or below its position despite the shared scan windows.
    assert _topic_blocks(session, _TOPIC_A) == list(range(density, target + 1, density))
    assert _topic_blocks(session, _TOPIC_B) == list(range(drift + density, target + 1, density))

    # Lockstep: both cursors finish at the confirmed head, complete.
    for topic0 in (_TOPIC_A, _TOPIC_B):
        last, complete, _hash = _cursor(session, topic0)
        assert (last, complete) == (target, True)


@requires_postgres
def test_block_hash_and_head_traffic_stays_out_of_the_hot_loop(session):
    """Finalized mid-backfill windows must not generate eth_getBlockByNumber
    traffic: one head fetch per pass, and the only hash lookup is the fringe
    stamp when a cursor reaches the confirmed target. The warm incremental pass
    pays one pre-check + one re-stamp, memoized."""
    span = 1_000
    head1 = 4_000 + _CONFIRMATIONS  # target 4_000 → 4 windows from genesis

    enroll_event_cursor(session, chain_id=1, event_address=_ADDRESS, topic0=_TOPIC_A)
    session.commit()

    fetcher = _EmptyFetcher()
    hashes = _CountingBlockHash()
    head = _CountingHead(head1)

    def run_pass():
        return scan_enrolled_events(
            session,
            fetchers={1: fetcher},
            head_fetchers={1: head},
            block_hash_fetchers={1: hashes},
            confirmation_depth=_CONFIRMATIONS,
            max_block_span=span,
            max_windows_per_cursor=100,
            max_windows_per_pass=100,
        )

    # Cold drain: 4 fetches, 1 head call, and exactly ONE hash call — the
    # fringe stamp at the target. The old shape did 2 hash + 1 head per window.
    run_pass()
    assert len(fetcher.calls) == 4
    assert head.calls == 1
    assert hashes.calls == [4_000]
    last, complete, stamped = _cursor(session, _TOPIC_A)
    assert (last, complete) == (4_000, True)
    assert stamped == (4_000).to_bytes(32, "big")

    # Warm no-op pass: head is re-read (it's the pass's one per-chain fact),
    # nothing is fetched, no hash traffic.
    run_pass()
    assert len(fetcher.calls) == 4
    assert head.calls == 2
    assert hashes.calls == [4_000]

    # Head advances less than a window: one pre-check of the stored fringe
    # stamp (reorg guard), one fetch, one re-stamp at the new target.
    head.head = 4_500 + _CONFIRMATIONS
    run_pass()
    assert len(fetcher.calls) == 5
    assert fetcher.calls[-1] == (4_001, 4_500)
    assert hashes.calls == [4_000, 4_000, 4_500]


@requires_postgres
def test_mid_backfill_advance_clears_position_bound_stamp(session):
    """A legacy per-window stamp (pre-refactor rows carry one) is checked once,
    then cleared on advance: the stamp is position-bound, and carrying it past
    its block would make the next pre-check compare one block's hash against
    another's position and spuriously rewind."""
    span = 1_000
    head = 4_000 + _CONFIRMATIONS
    legacy_last = 2_000

    enroll_event_cursor(session, chain_id=1, event_address=_ADDRESS, topic0=_TOPIC_A)
    _set_cursor(session, _TOPIC_A, last=legacy_last, block_hash=legacy_last.to_bytes(32, "big"))
    session.commit()

    fetcher = _EmptyFetcher()
    hashes = _CountingBlockHash()
    scan_enrolled_events(
        session,
        fetchers={1: fetcher},
        head_fetchers={1: _CountingHead(head)},
        block_hash_fetchers={1: hashes},
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=span,
        max_windows_per_cursor=1,
        max_windows_per_pass=1,
    )

    # Pre-check ran once (hash matched → no rewind), the single window advanced
    # the cursor, and the stale stamp is gone rather than re-pointed.
    assert hashes.calls == [legacy_last]
    assert fetcher.calls == [(legacy_last + 1, legacy_last + span)]
    last, complete, stamped = _cursor(session, _TOPIC_A)
    assert (last, complete, stamped) == (legacy_last + span, False, None)


@requires_postgres
def test_reorged_fringe_stamp_rewinds_the_whole_group(session):
    """A reorg detected on one member rewinds every sibling above the rewind
    point: the delete is address-wide (all topics), so leaving a sibling's
    cursor ahead would silently empty its already-indexed range."""
    from db.models import IndexedEventLog

    span = 500
    head = 4_000 + _CONFIRMATIONS
    stamp_pos = 2_000
    rewind_to = stamp_pos - _CONFIRMATIONS

    enroll_event_cursor(session, chain_id=1, event_address=_ADDRESS, topic0=_TOPIC_A)
    enroll_event_cursor(session, chain_id=1, event_address=_ADDRESS, topic0=_TOPIC_B)
    # A's fringe stamp no longer matches the canonical hash (the deterministic
    # fetcher returns block-number bytes) — a reorg happened under it.
    _set_cursor(session, _TOPIC_A, last=stamp_pos, block_hash=b"\xff" * 32)
    _set_cursor(session, _TOPIC_B, last=3_000)
    for block in (1_000, 2_900):  # B's indexed rows below and above the rewind point
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=_ADDRESS,
                topic0=_TOPIC_B,
                tx_hash=block.to_bytes(32, "big"),
                log_index=0,
                block_number=block,
                block_hash=block.to_bytes(32, "big"),
                transaction_index=0,
                topics=[_TOPIC_B],
                data_words=[],
            )
        )
    session.commit()

    scan_enrolled_events(
        session,
        fetchers={1: _EmptyFetcher()},
        head_fetchers={1: _CountingHead(head)},
        block_hash_fetchers={1: _CountingBlockHash()},
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=span,
        max_windows_per_cursor=1,
        max_windows_per_pass=1,
    )

    # B's row above the rewind point went with the address-wide delete; the row
    # below survived. Both cursors resumed in lockstep from the rewind point.
    assert _topic_blocks(session, _TOPIC_B) == [1_000]
    last_a, complete_a, _ = _cursor(session, _TOPIC_A)
    last_b, complete_b, _ = _cursor(session, _TOPIC_B)
    assert last_a == last_b == rewind_to + span
    assert complete_a is False and complete_b is False


def _raw_log(topic0: str, block: int) -> dict:
    return {
        "transactionHash": "0x" + f"{block:064x}",
        "blockHash": "0x" + f"{block:064x}",
        "logIndex": "0x0",
        "blockNumber": hex(block),
        "transactionIndex": "0x0",
        "topics": [topic0],
        "data": "0x",
    }


def test_rpc_fetcher_sends_one_request_per_window(monkeypatch):
    """A window up to MAX_BLOCK_RANGE is ONE eth_getLogs with the topics OR'd —
    no client-side paging. The request, not the range, is what the upstream
    budget meters."""
    calls: list[tuple[str, list]] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        calls.append((method, params))
        return [_raw_log(_TOPIC_A, 42)]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test")
    logs = fetcher.fetch_logs(
        event_address=_ADDRESS, topics=[_TOPIC_A, _TOPIC_B], from_block=100, to_block=100 + 499_999
    )

    assert len(calls) == 1
    method, params = calls[0]
    assert method == "eth_getLogs"
    assert params[0]["address"] == _ADDRESS
    assert params[0]["topics"] == [[_TOPIC_A, _TOPIC_B]]
    assert params[0]["fromBlock"] == hex(100)
    assert params[0]["toBlock"] == hex(100 + 499_999)
    assert [log.block_number for log in logs] == [42]


def test_rpc_fetcher_bisects_on_loud_range_errors(monkeypatch):
    """Upstream range/result caps fail loudly, never truncate (HyperRPC: -32005
    "Limit exceeded" / -32603 "Query timed out") — so the fetcher halves the
    range on error and merges the sub-results in block order."""
    calls: list[tuple[int, int]] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        from_block = int(params[0]["fromBlock"], 16)
        to_block = int(params[0]["toBlock"], 16)
        calls.append((from_block, to_block))
        if to_block - from_block + 1 > 100_000:
            raise RuntimeError("{'code': -32005, 'message': 'Limit exceeded: More than 50000 logs returned'}")
        return [_raw_log(_TOPIC_A, from_block)]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    logs = fetcher.fetch_logs(event_address=_ADDRESS, topics=[_TOPIC_A], from_block=0, to_block=399_999)

    # 400k fails → 2×200k fail → 4×100k succeed: 7 requests, results in order.
    assert len(calls) == 7
    assert [log.block_number for log in logs] == [0, 100_000, 200_000, 300_000]


def test_rpc_fetcher_bisect_floor_propagates_the_error(monkeypatch):
    """At/below the bisect floor the error is real (not a sizing problem) and
    must propagate instead of recursing forever."""
    calls: list[int] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        span = int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1
        calls.append(span)
        raise RuntimeError("{'code': -32603, 'message': 'Internal error: Query timed out'}")

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    with pytest.raises(RuntimeError, match="Query timed out"):
        fetcher.fetch_logs(event_address=_ADDRESS, topics=[_TOPIC_A], from_block=0, to_block=19_999)

    # 20k failed → two 10k halves; the first floor-sized failure propagates.
    assert calls == [20_000, 10_000]


def test_client_timeout_retries_the_same_window_before_bisecting(monkeypatch):
    """A client timeout is this process's wait ending, not the upstream refusing
    the window — so it earns ONE retry of the identical window. Bisecting a
    window that was merely slow hands each half the same stall and fans one
    request out into hundreds (measured: 756 getLogs for ~12 windows' work)."""
    calls: list[tuple[int, int]] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        from_block = int(params[0]["fromBlock"], 16)
        to_block = int(params[0]["toBlock"], 16)
        calls.append((from_block, to_block))
        # The retry succeeds: the window was slow, not unservable.
        if calls.count((from_block, to_block)) == 1:
            raise RpcClientTimeout("RPC request failed for <redacted>: read timed out")
        return [_raw_log(_TOPIC_A, from_block)]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    monkeypatch.setattr(event_logs_rpc.time, "sleep", lambda _s: None)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    logs = fetcher.fetch_logs(event_address=_ADDRESS, topics=[_TOPIC_A], from_block=0, to_block=399_999)

    # Two requests for one window, never a narrower one: no bisect happened.
    assert calls == [(0, 399_999), (0, 399_999)]
    assert [log.block_number for log in logs] == [0]


def test_second_client_timeout_falls_through_to_the_bisect(monkeypatch):
    """The retry is one extra attempt, not a loop: a window that times out twice
    is treated exactly as today's reject and bisects."""
    calls: list[tuple[int, int]] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        from_block = int(params[0]["fromBlock"], 16)
        to_block = int(params[0]["toBlock"], 16)
        calls.append((from_block, to_block))
        if to_block - from_block + 1 > 100_000:
            raise RpcClientTimeout("RPC request failed for <redacted>: read timed out")
        return [_raw_log(_TOPIC_A, from_block)]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    monkeypatch.setattr(event_logs_rpc.time, "sleep", lambda _s: None)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    logs = fetcher.fetch_logs(event_address=_ADDRESS, topics=[_TOPIC_A], from_block=0, to_block=399_999)

    # Each timing-out window is tried twice, then split — the same halves the
    # error path has always produced.
    assert calls[:2] == [(0, 399_999), (0, 399_999)]
    assert calls[2:4] == [(0, 199_999), (0, 199_999)]
    assert [log.block_number for log in logs] == [0, 100_000, 200_000, 300_000]


def test_upstream_reject_bisects_immediately_without_a_retry(monkeypatch):
    """Every other RpcEventLogFetcher user (asset sweep, indexer, watcher) must
    see exactly one behaviour change: the extra attempt on a CLIENT timeout. An
    upstream reject is a verdict on the query and still bisects on first sight —
    retrying it would only spend budget to be refused again."""
    calls: list[tuple[int, int]] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        from_block = int(params[0]["fromBlock"], 16)
        to_block = int(params[0]["toBlock"], 16)
        calls.append((from_block, to_block))
        if to_block - from_block + 1 > 100_000:
            raise RuntimeError("{'code': -32005, 'message': 'Limit exceeded: More than 50000 logs returned'}")
        return [_raw_log(_TOPIC_A, from_block)]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    logs = fetcher.fetch_logs(event_address=_ADDRESS, topics=[_TOPIC_A], from_block=0, to_block=399_999)

    # The pre-existing 7-request shape, byte for byte: no window is repeated.
    assert calls == [
        (0, 399_999),
        (0, 199_999),
        (0, 99_999),
        (100_000, 199_999),
        (200_000, 399_999),
        (200_000, 299_999),
        (300_000, 399_999),
    ]
    assert [log.block_number for log in logs] == [0, 100_000, 200_000, 300_000]
