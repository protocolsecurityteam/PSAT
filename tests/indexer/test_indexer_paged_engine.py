"""The paged engine against a simulated upstream: transactions around RPC, rewind order, page sizing and the ceiling.

Only ``rpc_request`` is stubbed (``tests/support/sim_chain.py``); fetchers, scan loop, triggers and Postgres are real.
"""

from __future__ import annotations

import dataclasses
import gc
import logging
import math
import weakref
from threading import Event
from typing import cast

import pytest
from sqlalchemy import delete, event, func, select, text, update

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
    IndexerWork,
)
from services.resolution.repos.event_logs_rpc import FetchedEventLog, FetchWindowStat, LogPage, RpcEventLogFetcher
from tests.conftest import requires_postgres
from tests.support.sim_chain import SimChain, SimLog, address, topic, word
from utils.chains import chain_by_id
from workers.event_log_indexer import (
    PageLimits,
    _build_indexer_fetchers,
    enroll_event_cursor,
    scan_enrolled_events,
)

pytestmark = requires_postgres

_HEAD = 2_000_012
_TARGET = 2_000_000
_SEED = 1_000_000
_ADDR = address(0xA1)
_T1 = topic(0x11)
_T2 = topic(0x22)


@pytest.fixture()
def sim(monkeypatch):
    chain = SimChain(heads={1: _HEAD, 8453: 30_000_075})
    monkeypatch.setattr(event_logs_rpc, "rpc_request", chain.rpc_request)
    monkeypatch.setattr(event_logs_rpc.time, "sleep", lambda _s: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    return chain


def _fetchers(engine: str = "paged"):
    base = dataclasses.replace(chain_by_id(8453), hypersync_url="https://base.hypersync.xyz")
    return _build_indexer_fetchers(chains=(chain_by_id(1), base), engine=engine)


def _enroll(session, addr: str = _ADDR, topics=(_T1,), *, seed: int = _SEED, chain_id: int = 1) -> None:
    for t in topics:
        enroll_event_cursor(
            session,
            chain_id=chain_id,
            event_address=addr,
            topic0=t,
            start_block=seed,
            first_indexed_block=seed,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
            enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
        )
    session.commit()


def _uniform(addr: str, t: str, *, lo: int, hi: int, every: int, tx_base: int = 0) -> list[SimLog]:
    return [
        SimLog(address=addr, topics=(t, "0x" + word(b)), data="0x" + word(b), block=b, tx_index=tx_base, log_index=0)
        for b in range(lo, hi + 1, every)
    ]


def _scan(session, *, limits: PageLimits | None = None, engine: str = "paged", **kwargs):
    fetchers, heads, hashes = _fetchers(engine)
    return scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        engine=engine,
        page_limits=limits,
        **kwargs,
    )


def _drain(session, **kwargs) -> None:
    for _ in range(200):
        _scan(session, max_windows_per_cursor=1_000, max_windows_per_pass=1_000, **kwargs)
        behind = session.scalar(
            select(func.count())
            .select_from(IndexedEventCursor)
            .where((IndexedEventCursor.last_indexed_block < _TARGET) | ~IndexedEventCursor.backfill_complete)
        )
        if not behind:
            return
    raise AssertionError("backfill never completed")


def _rows(session):
    return session.execute(
        select(
            IndexedEventLog.event_address,
            IndexedEventLog.topic0,
            IndexedEventLog.block_number,
            IndexedEventLog.tx_hash,
            IndexedEventLog.log_index,
            IndexedEventLog.block_hash,
            IndexedEventLog.data_words,
        ).order_by(IndexedEventLog.event_address, IndexedEventLog.block_number, IndexedEventLog.log_index)
    ).all()


def _cursor(session, t: str = _T1, addr: str = _ADDR) -> IndexedEventCursor:
    session.expire_all()
    return session.execute(
        select(IndexedEventCursor).where(IndexedEventCursor.event_address == addr, IndexedEventCursor.topic0 == t)
    ).scalar_one()


# Transactions around RPC, rewind order, target hash timing, shutdown, topic narrowing


@pytest.mark.parametrize("engine", ["paged", "legacy"])
def test_no_transaction_is_open_during_any_rpc(db_session, sim, engine):
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_TARGET, every=500))
    _enroll(db_session, topics=(_T1, _T2))
    seen: list[tuple[str, bool]] = []
    sim.before_request = lambda method, _params: seen.append((method, db_session.in_transaction()))

    _drain(db_session, engine=engine, limits=PageLimits(max_block_span=100_000))
    # A reorg under the stamped fringe: the check, the rewind hash and the refetch all go over the wire.
    db_session.execute(update(IndexedEventCursor).values(last_indexed_block_hash=b"\x01" * 32))
    db_session.commit()
    _scan(db_session, engine=engine)

    methods = {method for method, _open in seen}
    assert {"eth_getLogs", "eth_getBlockByNumber", "eth_blockNumber"} <= methods
    open_during = [method for method, in_transaction in seen if in_transaction]
    if engine == "paged":
        assert open_during == []
    else:
        # Control: the legacy engine holds its FOR UPDATE across the fetch, which is what the probe must catch.
        assert "eth_getLogs" in open_during


def test_rewind_flushes_the_cursor_decrease_before_the_delete_in_the_first_write(db_session, sim):
    _enroll(db_session)
    db_session.execute(
        update(IndexedEventCursor).values(
            last_indexed_block=_TARGET - 100, last_indexed_block_hash=b"\x02" * 32, backfill_complete=True
        )
    )
    db_session.commit()
    db_session.query(IndexerWork).delete()
    db_session.commit()
    trace: list[str] = []
    bind = db_session.get_bind()

    def statements(conn, cursor, statement, parameters, context, executemany):
        head = statement.lstrip().split("\n", 1)[0][:60]
        if head.startswith(("UPDATE indexed_event_cursors", "DELETE FROM indexed_event_logs", "INSERT INTO indexed")):
            trace.append(head.split(" SET ")[0].split(" WHERE ")[0].strip())

    event.listen(bind, "after_cursor_execute", statements)
    event.listen(db_session, "after_commit", lambda _s: trace.append("COMMIT"))
    try:
        _scan(db_session)
    finally:
        event.remove(bind, "after_cursor_execute", statements)

    first_commit = trace.index("COMMIT", trace.index("DELETE FROM indexed_event_logs"))
    window = trace[:first_commit]
    assert window.index("UPDATE indexed_event_cursors") < window.index("DELETE FROM indexed_event_logs")
    # The rewind and the first advance land in one transaction.
    assert window.count("UPDATE indexed_event_cursors") >= 2
    work = db_session.get(IndexerWork, ("reorg", f"1:{_ADDR}"))
    assert work is not None and work.dirty
    cursor = _cursor(db_session)
    assert cursor.last_indexed_block == _TARGET and cursor.backfill_complete


def test_target_hash_is_read_before_the_logs_that_reach_it(db_session, sim):
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_TARGET - 500, hi=_TARGET, every=10))
    _enroll(db_session, seed=_TARGET - 1_000)

    _scan(db_session)

    hash_reads = [
        i for i, (m, _c, p) in enumerate(sim.calls) if m == "eth_getBlockByNumber" and int(p[0], 16) == _TARGET
    ]
    final_fetch = [
        i for i, (m, _c, p) in enumerate(sim.calls) if m == "eth_getLogs" and int(p[0]["toBlock"], 16) == _TARGET
    ]
    assert hash_reads and final_fetch
    assert hash_reads[0] < final_fetch[0]
    assert _cursor(db_session).last_indexed_block_hash == bytes.fromhex(sim.block_hash(1, _TARGET)[2:])


def test_shutdown_between_pages_keeps_committed_pages_and_resumes_identically(db_session, sim):
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_TARGET, every=400))
    _enroll(db_session)
    limits = PageLimits(max_block_span=100_000, initial_span=100_000)
    stop = Event()

    fetches = 0

    def stop_on_third(method, params):
        nonlocal fetches
        if method == "eth_getLogs":
            fetches += 1
            if fetches == 3:
                stop.set()

    sim.before_request = stop_on_third
    _scan(db_session, limits=limits, stop_event=stop, max_windows_per_cursor=1_000)
    # The in-flight third page completed and committed; nothing past it was requested.
    assert sim.getlogs_count() == 3
    assert _cursor(db_session).last_indexed_block == _SEED + 300_000
    sim.before_request = None
    _drain(db_session, limits=limits)
    interrupted = _rows(db_session)

    db_session.execute(delete(IndexedEventLog))
    db_session.execute(delete(IndexedEventCursor))
    db_session.commit()
    _enroll(db_session)
    _drain(db_session, limits=limits)
    assert interrupted == _rows(db_session)
    assert len(interrupted) == len(range(_SEED + 1, _TARGET + 1, 400))


def test_sibling_topic_narrowing_skips_at_target_siblings(db_session, sim):
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_TARGET, every=500))
    sim.add_many(1, _uniform(_ADDR, _T2, lo=_SEED + 3, hi=_TARGET, every=1_000, tx_base=1))
    _enroll(db_session, topics=(_T1,))
    _drain(db_session)
    _enroll(db_session, topics=(_T2,))
    before = sim.getlogs_count()

    _drain(db_session)

    requests = sim.getlogs[before:]
    assert requests and all(r["topics"] == {_T2} for r in requests)
    t2 = _cursor(db_session, _T2)
    assert t2.last_indexed_block == _TARGET and t2.backfill_complete
    assert db_session.scalar(
        select(func.count()).select_from(IndexedEventLog).where(IndexedEventLog.topic0 == _T2)
    ) == len(range(_SEED + 3, _TARGET + 1, 1_000))


# Page sizing, the memory ceiling, the timeout


def _mark_advanced(session, t: str = _T1, addr: str = _ADDR) -> None:
    """A cursor that has advanced before but whose page density is unknown (e.g. written by the legacy engine)."""
    session.execute(
        update(IndexedEventCursor)
        .where(IndexedEventCursor.event_address == addr, IndexedEventCursor.topic0 == t)
        .values(last_advanced_at=func.now(), recent_logs_per_block=None)
    )
    session.commit()


def test_span_doubles_while_pages_come_back_sparse(db_session, sim):
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_SEED + 200_000, every=1_000))
    _enroll(db_session, seed=_SEED)
    _mark_advanced(db_session)
    limits = PageLimits(max_block_span=100_000, initial_span=10_000, target_page_logs=2_000, max_page_logs=50_000)

    _scan(db_session, limits=limits, max_windows_per_cursor=6)

    assert [r["to"] - r["from"] + 1 for r in sim.getlogs] == [10_000, 20_000, 40_000, 80_000, 100_000, 100_000]


def test_a_never_advanced_sparse_group_needs_one_page_per_widest_span(db_session, sim):
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_TARGET, every=10_000))
    _enroll(db_session, seed=_SEED)
    limits = PageLimits(max_block_span=100_000, initial_span=10_000, target_page_logs=2_000, max_page_logs=50_000)

    _drain(db_session, limits=limits)

    spans = [r["to"] - r["from"] + 1 for r in sim.getlogs]
    assert spans == [100_000] * math.ceil((_TARGET - _SEED) / 100_000)
    assert db_session.scalar(select(func.count()).select_from(IndexedEventLog)) == 100


def test_span_converges_to_the_target_page(db_session, sim):
    sim.add_many(
        1,
        [
            SimLog(address=_ADDR, topics=(_T1,), data="0x", block=b, tx_index=i, log_index=i)
            for b in range(_SEED + 1, _SEED + 5_001)
            for i in range(2)
        ],
    )
    _enroll(db_session)
    _mark_advanced(db_session)
    limits = PageLimits(max_block_span=500_000, initial_span=2_000, target_page_logs=2_000, max_page_logs=50_000)

    _scan(db_session, limits=limits, max_windows_per_cursor=4)

    counts = [len(sim.lanes[(1, _ADDR)].between(r["from"], r["to"])) for r in sim.getlogs]
    assert counts[0] == 4_000  # unknown density: the initial span overshoots once
    assert counts[1:] == [2_000] * (len(counts) - 1)
    cursor = _cursor(db_session)
    assert cursor.recent_logs_per_block == 2.0
    assert cursor.max_window_log_count == 4_000


def test_dense_request_count_is_bounded_by_logs_over_target_plus_ramp(db_session, sim):
    dense = [
        SimLog(address=_ADDR, topics=(_T1,), data="0x", block=b, tx_index=0, log_index=0)
        for b in range(_SEED + 1, _SEED + 10_001)
    ]
    sim.add_many(1, dense)
    _enroll(db_session, seed=_SEED)
    target_logs, initial = 2_000, 250
    limits = PageLimits(
        max_block_span=500_000, initial_span=initial, target_page_logs=target_logs, max_page_logs=50_000
    )

    _drain(db_session, limits=limits)

    ramp = math.ceil(math.log2(target_logs / initial)) + 2
    dense_requests = [r for r in sim.getlogs if r["from"] <= _SEED + 10_000]
    assert len(dense_requests) <= math.ceil(len(dense) / target_logs) + ramp
    assert db_session.scalar(select(func.count()).select_from(IndexedEventLog)) == len(dense)


_QUERY_TIMED_OUT = "{'code': -32603, 'message': 'Internal error: Query timed out'}"


def test_a_query_timeout_caps_the_next_visit_below_the_refused_span(db_session, sim):
    refuse_over = 150_000
    sim.refuse = lambda _chain, lo, hi: _QUERY_TIMED_OUT if hi - lo + 1 > refuse_over else None
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_TARGET, every=50_000))
    _enroll(db_session, seed=_SEED)
    limits = PageLimits(max_block_span=500_000, initial_span=50_000, target_page_logs=2_000, max_page_logs=50_000)

    _scan(db_session, limits=limits, max_windows_per_cursor=2)
    first_visit = len(sim.getlogs)
    assert [r["to"] - r["from"] + 1 for r in sim.getlogs] == [500_000, 250_000, 125_000, 125_000]
    assert _cursor(db_session).request_span_limit == 125_000

    _drain(db_session, limits=limits)
    later = sim.getlogs[first_visit:]
    assert later[0]["to"] - later[0]["from"] + 1 <= refuse_over
    assert all(r["to"] - r["from"] + 1 <= 125_000 for r in later)
    # Two refusals in all, then one request per capped span.
    assert len(sim.getlogs) == 2 + math.ceil((_TARGET - _SEED) / 125_000)
    assert db_session.scalar(select(func.count()).select_from(IndexedEventLog)) == 20
    # The limit served this backlog; a later one starts from density again.
    assert _cursor(db_session).request_span_limit is None


@pytest.mark.parametrize(
    "error",
    [
        "{'code': -32000, 'message': 'upstream unavailable'}",
        "{'code': -32005, 'message': 'rate limit exceeded'}",
        "{'code': -32000, 'message': 'requested block range is not synced yet'}",
    ],
    ids=["outage", "rate_limit", "not_synced"],
)
def test_a_transient_upstream_error_bisects_but_sets_no_span_limit(db_session, sim, error):
    failed: list[int] = []

    def flaky(_chain, lo, hi):
        if not failed:
            failed.append(hi - lo + 1)
            return error
        return None

    sim.refuse = flaky
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_TARGET, every=50_000))
    _enroll(db_session, seed=_SEED)
    limits = PageLimits(max_block_span=500_000, initial_span=50_000, target_page_logs=2_000, max_page_logs=50_000)

    _scan(db_session, limits=limits, max_windows_per_cursor=1)

    assert failed == [500_000]
    assert _cursor(db_session).request_span_limit is None


def test_a_persisted_span_limit_never_falls_below_the_bisect_floor(db_session, sim):
    sim.refuse = lambda _chain, lo, hi: _QUERY_TIMED_OUT if hi - lo + 1 > 3_000 else None
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_TARGET, every=50_000))
    _enroll(db_session, seed=_SEED)
    limits = PageLimits(max_block_span=20_000, initial_span=20_000, target_page_logs=2_000, max_page_logs=50_000)
    fetchers, heads, hashes = _fetchers()
    cast(RpcEventLogFetcher, fetchers[1]).min_bisect_span = 1_000

    scan_enrolled_events(
        db_session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        page_limits=limits,
        max_windows_per_cursor=12,
    )

    # Bisection reached pages under 3,000 blocks, but neither the rest of the visit nor the next one shrinks below the
    # floor: each later chunk is requested at 10,000 blocks.
    spans = [r["to"] - r["from"] + 1 for r in sim.getlogs]
    assert min(spans) <= 3_000
    first_accepted = next(i for i, r in enumerate(sim.getlogs) if r["served"] is not None)
    assert 10_000 in spans[first_accepted + 1 :]
    assert _cursor(db_session).request_span_limit == 10_000


def test_the_page_names_only_the_narrowest_span_the_upstream_refused(sim):
    sim.refuse = lambda _chain, lo, hi: _QUERY_TIMED_OUT if hi - lo + 1 > 40_000 else None
    sim.add(1, SimLog(address=_ADDR, topics=(_T1,), data="0x", block=_SEED + 5, tx_index=0, log_index=0))
    fetcher = RpcEventLogFetcher("https://erpc.example/main/evm/1", chain_id=1, min_bisect_span=1_000)
    pages = list(fetcher.iter_pages(event_address=_ADDR, topics=[_T1], from_block=_SEED + 1, to_block=_SEED + 100_000))
    assert [(p.to_block - p.from_block + 1, p.rejected, p.rejected_span) for p in pages] == [
        (25_000, 2, 50_000),
        (25_000, 0, None),
        (25_000, 1, 50_000),
        (25_000, 0, None),
    ]


def test_a_local_ceiling_discard_is_not_an_upstream_refusal(sim):
    sim.add_many(
        1,
        [
            SimLog(address=_ADDR, topics=(_T1,), data="0x", block=_SEED + 1 + i, tx_index=0, log_index=0)
            for i in range(8)
        ],
    )
    fetcher = RpcEventLogFetcher("https://erpc.example/main/evm/1", chain_id=1)
    pages = list(
        fetcher.iter_pages(event_address=_ADDR, topics=[_T1], from_block=_SEED + 1, to_block=_SEED + 8, max_page_logs=4)
    )
    assert pages[0].rejected == 1 and pages[0].rejected_span is None


def _merged_wide_range_sim(
    sim, *, lo: int, hi: int, logs: int, refuse_over: int, error: str = "Limit exceeded: More than {n} logs returned"
) -> None:
    """The upstream serves exactly ``[lo, hi]`` whole (an aggregator merging its split sub-requests) but refuses any
    other request holding more than ``refuse_over`` logs."""
    every = (hi - lo + 1) // logs
    sim.add_many(1, _uniform(_ADDR, _T1, lo=lo, hi=lo + every * (logs - 1), every=every))
    lane = sim.lanes[(1, _ADDR)]

    def refuse(_chain, a, b):
        if (a, b) == (lo, hi) or len(lane.between(a, b)) <= refuse_over:
            return None
        return "{'code': -32005, 'message': '" + error.format(n=refuse_over) + "'}"

    sim.refuse = refuse


def test_a_refusal_below_the_floor_after_a_ceiling_split_keeps_bisecting(sim):
    lo, hi = _SEED + 1, _SEED + 20_000
    _merged_wide_range_sim(sim, lo=lo, hi=hi, logs=3_000, refuse_over=600)
    fetcher = RpcEventLogFetcher("https://erpc.example/main/evm/1", chain_id=1, min_bisect_span=10_000)

    pages = list(fetcher.iter_pages(event_address=_ADDR, topics=[_T1], from_block=lo, to_block=hi, max_page_logs=1_000))

    # The whole range came back over the ceiling, its 10,000-block halves were refused at the floor, and the
    # bisection went on below it rather than failing the group on every pass.
    assert pages[0].from_block == lo and pages[-1].to_block == hi
    assert all(a.to_block + 1 == b.from_block for a, b in zip(pages, pages[1:]))
    assert sum(len(p.logs) for p in pages) == 3_000
    assert max(p.to_block - p.from_block + 1 for p in pages) < 10_000


def test_a_non_size_error_below_the_floor_raises_even_after_a_ceiling_split(sim):
    lo, hi = _SEED + 1, _SEED + 20_000
    _merged_wide_range_sim(sim, lo=lo, hi=hi, logs=3_000, refuse_over=600, error="upstream unavailable")
    fetcher = RpcEventLogFetcher("https://erpc.example/main/evm/1", chain_id=1, min_bisect_span=10_000)
    with pytest.raises(RuntimeError, match="upstream unavailable"):
        list(fetcher.iter_pages(event_address=_ADDR, topics=[_T1], from_block=lo, to_block=hi, max_page_logs=1_000))
    # Only the wide request and one ceiling-split half: an outage isn't chased down to single blocks.
    assert [r["to"] - r["from"] + 1 for r in sim.getlogs] == [20_000, 10_000]


def test_a_refusal_at_the_floor_without_a_ceiling_split_still_raises(sim):
    lo, hi = _SEED + 1, _SEED + 10_000
    _merged_wide_range_sim(sim, lo=lo, hi=hi + 10_000, logs=3_000, refuse_over=600)
    fetcher = RpcEventLogFetcher("https://erpc.example/main/evm/1", chain_id=1, min_bisect_span=10_000)
    with pytest.raises(RuntimeError, match="Limit exceeded"):
        list(fetcher.iter_pages(event_address=_ADDR, topics=[_T1], from_block=lo, to_block=hi, max_page_logs=1_000))


def test_the_engine_completes_a_group_whose_upstream_refuses_split_halves(db_session, sim):
    lo, hi = _SEED + 1, _SEED + 20_000
    _merged_wide_range_sim(sim, lo=lo, hi=hi, logs=3_000, refuse_over=600)
    _enroll(db_session, seed=_SEED)
    db_session.execute(update(IndexedEventCursor).values(request_span_limit=20_000))
    db_session.commit()
    limits = PageLimits(max_block_span=500_000, initial_span=50_000, target_page_logs=2_000, max_page_logs=1_000)

    _drain(db_session, limits=limits)

    assert db_session.scalar(select(func.count()).select_from(IndexedEventLog)) == 3_000
    assert _cursor(db_session).last_indexed_block == _TARGET


def test_over_ceiling_page_is_discarded_and_bisected_with_no_writes(db_session, sim):
    burst = [
        SimLog(address=_ADDR, topics=(_T1,), data="0x", block=_SEED + 10 + i // 10, tx_index=i % 10, log_index=i % 10)
        for i in range(1_500)
    ]
    sim.add_many(1, burst)
    _enroll(db_session, seed=_SEED)
    trace: list[str] = []
    sim.before_request = lambda method, params: trace.append(
        f"rpc {int(params[0]['fromBlock'], 16)}-{int(params[0]['toBlock'], 16)}" if method == "eth_getLogs" else method
    )
    bind = db_session.get_bind()

    def inserts(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO indexed_event_logs"):
            trace.append("insert")

    event.listen(bind, "after_cursor_execute", inserts)
    try:
        _scan(db_session, limits=PageLimits(max_block_span=1_000, initial_span=1_000, max_page_logs=1_000))
    finally:
        event.remove(bind, "after_cursor_execute", inserts)

    fetches = [t for t in trace if t.startswith("rpc") or t == "insert"]
    assert fetches[0] == f"rpc {_SEED + 1}-{_SEED + 1_000}"
    assert fetches[1].startswith("rpc ")  # the over-ceiling page wrote nothing before its halves were requested
    assert db_session.scalar(select(func.count()).select_from(IndexedEventLog)) == 1_500
    cursor = _cursor(db_session)
    assert cursor.max_window_log_count is not None and cursor.max_window_log_count <= 1_000


def test_single_block_over_the_ceiling_is_committed_alone(db_session, sim, caplog):
    block = _SEED + 77
    sim.add_many(
        1,
        [SimLog(address=_ADDR, topics=(_T1,), data="0x", block=block, tx_index=i, log_index=i) for i in range(1_200)]
        + _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_SEED + 2_000, every=100, tx_base=2_000),
    )
    _enroll(db_session)

    with caplog.at_level(logging.WARNING, logger="services.resolution.repos.event_logs_rpc"):
        _scan(db_session, limits=PageLimits(max_block_span=2_000, initial_span=2_000, max_page_logs=1_000))

    assert any(r["from"] == r["to"] == block for r in sim.getlogs)
    (warning,) = [
        r for r in caplog.records if r.getMessage() == "single block exceeds the page ceiling; accepted whole"
    ]
    assert warning.__dict__["returned_log_count"] == 1_200
    commits = db_session.execute(
        text("SELECT min(block_number), max(block_number), count(*) FROM indexed_event_logs GROUP BY xmin::text")
    ).all()
    assert (block, block, 1_200) in [tuple(row) for row in commits]
    assert (
        db_session.scalar(
            select(func.count()).select_from(IndexedEventLog).where(IndexedEventLog.block_number == block)
        )
        == 1_200
    )
    assert _cursor(db_session).max_window_log_count == 1_200


def test_getlogs_timeout_is_set_only_on_the_paged_indexer_fetcher(sim):
    paged, _, _ = _fetchers("paged")
    legacy, _, _ = _fetchers("legacy")
    assert isinstance(paged[1], RpcEventLogFetcher) and paged[1].timeout == 35
    assert isinstance(legacy[1], RpcEventLogFetcher) and legacy[1].timeout is None
    # The live watcher's construction keeps rpc_request's default.
    assert RpcEventLogFetcher("http://stub", max_block_range=10_000, min_bisect_span=1_000, chain_id=1).timeout is None


def test_unknown_engine_is_refused(db_session, sim):
    with pytest.raises(ValueError, match="unknown event indexer engine"):
        _scan(db_session, engine="turbo")


def test_each_page_folds_its_count_only_into_the_cursors_it_advanced(db_session, sim):
    # T1's dense stretch lies wholly below T2's position: T2 never crosses that page, so its count isn't T2's.
    sim.add_many(
        1,
        [
            SimLog(address=_ADDR, topics=(_T1,), data="0x", block=b, tx_index=i, log_index=i)
            for b in range(_SEED + 1, _SEED + 5_001)
            for i in range(2)
        ],
    )
    sim.add_many(1, _uniform(_ADDR, _T2, lo=_SEED + 5_001, hi=_SEED + 60_000, every=1_000, tx_base=9))
    _enroll(db_session, topics=(_T1, _T2))
    db_session.execute(
        update(IndexedEventCursor)
        .where(IndexedEventCursor.topic0 == _T2)
        .values(last_indexed_block=_SEED + 5_000, last_advanced_at=func.now())
    )
    db_session.commit()
    limits = PageLimits(max_block_span=500_000, initial_span=5_000, target_page_logs=50_000, max_page_logs=50_000)

    _scan(db_session, limits=limits, max_windows_per_cursor=2)

    assert [r["topics"] for r in sim.getlogs] == [{_T1}, {_T1, _T2}]
    assert _cursor(db_session, _T1).max_window_log_count == 10_000
    t2 = _cursor(db_session, _T2)
    assert t2.last_indexed_block > _SEED + 5_000
    assert t2.max_window_log_count == sim.getlogs[1]["served"] < 10_000


class _GappyFetcher:
    """Streams pages that skip a range, or none at all, as a broken upstream adapter might."""

    def __init__(self, mode: str) -> None:
        self.mode = mode

    def fetch_logs(self, *, event_address, topics, from_block, to_block):
        raise AssertionError("the paged engine streams pages")

    def iter_pages(self, *, event_address, topics, from_block, to_block, max_page_logs=None):
        if self.mode == "empty":
            return
        if self.mode == "overrun":
            stat = FetchWindowStat(from_block=from_block, to_block=to_block + 50, returned_log_count=0, cap=None)
            yield LogPage(from_block=from_block, to_block=to_block + 50, logs=[], stats=(stat,))
            return
        stat = FetchWindowStat(from_block=from_block, to_block=from_block + 9, returned_log_count=0, cap=None)
        yield LogPage(from_block=from_block, to_block=from_block + 9, logs=[], stats=(stat,))
        later = from_block + 20
        stat = FetchWindowStat(from_block=later, to_block=to_block, returned_log_count=0, cap=None)
        yield LogPage(from_block=later, to_block=to_block, logs=[], stats=(stat,))


@pytest.mark.parametrize("mode", ["gap", "empty", "overrun"])
def test_pages_must_cover_the_range_without_gaps(db_session, sim, mode):
    _enroll(db_session)
    fetchers = _fetchers()

    summary = scan_enrolled_events(
        db_session,
        fetchers={1: _GappyFetcher(mode)},
        head_fetchers=fetchers[1],
        block_hash_fetchers=fetchers[2],
        engine="paged",
    )

    assert summary.failed_groups == 1
    assert _cursor(db_session).last_indexed_block <= _SEED + 10


def test_a_cursor_moved_under_a_warm_batch_only_delays_that_group(db_session, sim, monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from tests.conftest import DATABASE_URL

    addrs = [address(0xE00 + i) for i in range(4)]
    for i, addr in enumerate(addrs):
        sim.add_many(
            1,
            [
                SimLog(address=addr, topics=(_T1,), data="0x", block=b, tx_index=i, log_index=i)
                for b in range(_TARGET - 300, _TARGET + 1, 11)
            ],
        )
        _enroll(db_session, addr=addr, seed=_TARGET - 400)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()
    engine = create_engine(DATABASE_URL)
    moved = {"done": False}

    def enrol_sibling_mid_fetch(method, params):
        if method == "eth_getLogs" and not moved["done"] and len(params[0].get("address") or []) == 4:
            moved["done"] = True
            with Session(engine) as other:
                _enroll(other, addr=addrs[0], topics=(_T2,), seed=_TARGET - 400)

    sim.before_request = enrol_sibling_mid_fetch
    try:
        summary = _scan(db_session, scan_mode="warm")
    finally:
        engine.dispose()

    assert moved["done"] and summary.failed_groups == 0
    behind = [addr for addr in addrs[1:] if _cursor(db_session, _T1, addr).last_indexed_block < _TARGET]
    assert behind == []


def test_a_sibling_enrolled_far_back_mid_sweep_leaves_the_batch(db_session, sim):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from tests.conftest import DATABASE_URL

    lagging = address(0xF00)
    batched = [address(0xF01 + i) for i in range(3)]
    _enroll(db_session, addr=lagging, seed=_TARGET - 5_000)
    for addr in batched:
        _enroll(db_session, addr=addr, seed=_TARGET - 300)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()
    engine = create_engine(DATABASE_URL)
    done = {"enrolled": False}

    def enrol_while_singles_run(method, params):
        if method == "eth_getLogs" and params[0].get("address") == lagging and not done["enrolled"]:
            done["enrolled"] = True
            with Session(engine) as other:
                _enroll(other, addr=batched[0], topics=(_T2,), seed=_TARGET - 300_000)

    sim.before_request = enrol_while_singles_run
    try:
        _scan(db_session, scan_mode="warm")
    finally:
        engine.dispose()

    assert done["enrolled"]
    multi = [r for r in sim.getlogs if len(r["addresses"]) > 1]
    assert multi and all(r["to"] - r["from"] < 1_000 for r in multi)
    assert batched[0] not in {a for r in multi for a in r["addresses"]}


# Memory: at most one page of logs is resident


class _TrackedPages:
    """Streams small pages and records, at each request, how many logs from earlier pages are still reachable."""

    def __init__(self, span: int, every: int) -> None:
        self.span = span
        self.every = every
        self.refs: list[weakref.ref] = []
        self.alive_at_request: list[int] = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block):
        raise AssertionError("the paged engine streams pages")

    def iter_pages(self, *, event_address, topics, from_block, to_block, max_page_logs=None):
        lo = from_block
        while lo <= to_block:
            gc.collect()
            self.alive_at_request.append(sum(ref() is not None for ref in self.refs))
            hi = min(to_block, lo + self.span - 1)
            logs = [
                FetchedEventLog(
                    tx_hash=b.to_bytes(32, "big"),
                    log_index=0,
                    block_number=b,
                    block_hash=b.to_bytes(32, "big"),
                    transaction_index=0,
                    topics=[topics[0]],
                    data_words=[],
                )
                for b in range(lo + (-lo % self.every), hi + 1, self.every)
            ]
            self.refs.extend(weakref.ref(log) for log in logs)
            stat = FetchWindowStat(from_block=lo, to_block=hi, returned_log_count=len(logs), cap=None)
            yield LogPage(from_block=lo, to_block=hi, logs=logs, stats=(stat,))
            logs = []
            lo = hi + 1


def test_the_engine_releases_each_page_before_requesting_the_next(db_session, sim):
    _enroll(db_session, seed=_TARGET - 2_000)
    pages = _TrackedPages(span=100, every=10)
    fetchers = _fetchers()

    scan_enrolled_events(
        db_session,
        fetchers={1: pages},
        head_fetchers=fetchers[1],
        block_hash_fetchers=fetchers[2],
        engine="paged",
        page_limits=PageLimits(max_block_span=500_000, initial_span=500_000),
    )

    assert len(pages.alive_at_request) == 20
    assert pages.alive_at_request == [0] * 20
    assert db_session.scalar(select(func.count()).select_from(IndexedEventLog)) == 200


def test_iter_pages_keeps_no_reference_to_a_yielded_page(sim):
    sim.add_many(1, _uniform(_ADDR, _T1, lo=_SEED + 1, hi=_SEED + 5_000, every=5))
    refs: list[weakref.ref] = []
    alive: list[int] = []

    def count_reachable(method, _params):
        if method == "eth_getLogs":
            gc.collect()
            alive.append(sum(ref() is not None for ref in refs))

    sim.before_request = count_reachable
    fetcher = RpcEventLogFetcher("http://unit.test", chain_id=1, max_block_range=1_000, keep_raw=False, strict=True)
    for page in fetcher.iter_pages(event_address=_ADDR, topics=[_T1], from_block=_SEED + 1, to_block=_SEED + 5_000):
        refs.extend(weakref.ref(log) for log in page.logs)
        del page

    assert len(refs) == 1_000
    assert alive == [0] * 5
