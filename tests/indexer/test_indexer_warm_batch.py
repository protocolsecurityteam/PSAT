"""The batched warm sweep: one eth_getLogs per up to 50 warm groups, with the same rows, cursors and reconciliation
marks as per-address sweeps, under a moving head, a fringe reorg, a failing group and cross-talk between addresses."""

from __future__ import annotations

import dataclasses
import math
import threading
from typing import Literal

from sqlalchemy import create_engine, event, select, update
from sqlalchemy.orm import Session

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
    IndexerWork,
)
from services.resolution import indexer_settings
from tests.conftest import DATABASE_URL, requires_postgres
from tests.support.sim_chain import SimChain, SimLog, address, topic, word
from utils.chains import chain_by_id
from workers.event_log_indexer import _build_indexer_fetchers, enroll_event_cursor, scan_enrolled_events

pytestmark = requires_postgres

MAINNET, BASE = 1, 8453
START = {MAINNET: 2_000_012, BASE: 30_000_075}
STEP = {MAINNET: 400, BASE: 600}
GROUPS = {
    MAINNET: {
        address(0x61): [topic(1)],
        address(0x62): [topic(2), topic(3)],
        address(0x63): [topic(4)],
        address(0x64): [topic(5)],
        address(0x65): [topic(6)],
        address(0x66): [topic(7)],
    },
    BASE: {address(0x71): [topic(8)], address(0x72): [topic(9)]},
}
FLAKY = address(0x66)
CROSS_TALKER = address(0x63)


def _depth(chain: int) -> int:
    return chain_by_id(chain).confirmation_depth


def _build() -> SimChain:
    sim = SimChain(heads=dict(START))
    for chain, groups in GROUPS.items():
        lo, hi = START[chain] - 2_000, START[chain] + 10 * STEP[chain]
        for slot, (addr, topics) in enumerate(sorted(groups.items())):
            for i, t in enumerate(topics):
                sim.add_many(
                    chain,
                    [
                        SimLog(addr, (t, "0x" + word(b)), "0x" + word(b), b, slot, slot * 10 + i)
                        for b in range(lo + slot + i, hi, 7 + slot)
                    ],
                )
    # An address emitting a topic only another address is enrolled for.
    sim.add_many(
        MAINNET,
        [
            SimLog(CROSS_TALKER, (topic(1),), "0x", b, 9, 99)
            for b in range(START[MAINNET] - 1_000, START[MAINNET] + 4_000, 5)
        ],
    )
    return sim


def _enroll(session) -> None:
    for chain, groups in GROUPS.items():
        seed = START[chain] - _depth(chain) - 300
        for addr, topics in groups.items():
            for t in topics:
                enroll_event_cursor(
                    session,
                    chain_id=chain,
                    event_address=addr,
                    topic0=t,
                    start_block=seed,
                    first_indexed_block=seed,
                    first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
                    enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
                )
    session.commit()


def _fetchers():
    base = dataclasses.replace(chain_by_id(BASE), hypersync_url="https://base.hypersync.xyz")
    return _build_indexer_fetchers(chains=(chain_by_id(MAINNET), base))


def _scan(session, fetchers, mode: Literal["all", "warm", "cold"]):
    return scan_enrolled_events(
        session,
        fetchers=fetchers[0],
        head_fetchers=fetchers[1],
        block_hash_fetchers=fetchers[2],
        scan_mode=mode,
    )


def _snapshot(session):
    session.expire_all()
    rows = session.execute(
        select(*[c for c in IndexedEventLog.__table__.columns if c.name != "detected_at"]).order_by(
            IndexedEventLog.chain_id,
            IndexedEventLog.event_address,
            IndexedEventLog.topic0,
            IndexedEventLog.block_number,
        )
    ).all()
    skip = {"last_run_at", "last_advanced_at", "recent_logs_per_block", "max_window_log_count"}
    cursors = session.execute(
        select(*[c for c in IndexedEventCursor.__table__.columns if c.name not in skip]).order_by(
            IndexedEventCursor.chain_id, IndexedEventCursor.event_address, IndexedEventCursor.topic0
        )
    ).all()
    work = set(session.execute(select(IndexerWork.kind, IndexerWork.key).where(IndexerWork.dirty)).all())
    return rows, cursors, work


def _run(session, monkeypatch, mode: str):
    for model in (IndexedEventLog, IndexedEventCursor, IndexerWork):
        session.query(model).delete()
    session.commit()
    sim = _build()
    monkeypatch.setattr(event_logs_rpc, "rpc_request", sim.rpc_request)
    monkeypatch.setattr(indexer_settings, "WARM_BATCH_ADDRESSES", 1 if mode == "single" else 50)
    fetchers = _fetchers()
    _enroll(session)
    _scan(session, fetchers, "all")
    failing = {"on": False}

    def flaky(method, params):
        if failing["on"] and method == "eth_getLogs" and FLAKY in str(params[0].get("address")):
            raise RuntimeError("{'code': -32603, 'message': 'Internal error'}")

    sim.before_request = flaky
    sweeps: list[list[dict]] = []
    for step in range(1, 9):
        for chain in START:
            sim.heads[chain] += STEP[chain]
        failing["on"] = step in (1, 2, 3)  # the flaky group lags past the batch limit, then recovers singly
        if step == 5:
            target = sim.heads[MAINNET] - STEP[MAINNET] - _depth(MAINNET)
            sim.reorg(MAINNET, target - 5)
            sim.remove(MAINNET, lambda log: log.address == address(0x61) and target - 5 <= log.block <= target)
            sim.add(MAINNET, SimLog(address(0x61), (topic(1),), "0x", target - 2, 0, 77, tag=1))
        before = len(sim.getlogs)
        _scan(session, fetchers, "warm")
        sweeps.append(sim.getlogs[before:])
    _scan(session, fetchers, "all")
    return _snapshot(session), sim, sweeps


def _expected_rows(sim: SimChain) -> set[tuple[int, str, str, int, int]]:
    return {
        (chain, addr, t, log.block, log.log_index)
        for chain, groups in GROUPS.items()
        for addr, topics in groups.items()
        for t in topics
        for log in sim.lanes[(chain, addr)].between(
            START[chain] - _depth(chain) - 299, sim.heads[chain] - _depth(chain)
        )
        if log.topics[0] == t
    }


def test_batched_warm_sweep_matches_per_address_sweeps(db_session, monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.delenv("PSAT_GETLOGS_RESULT_CAP", raising=False)
    batched, sim, sweeps = _run(db_session, monkeypatch, "batched")
    single, _, _ = _run(db_session, monkeypatch, "single")

    stored = {(r.chain_id, r.event_address, r.topic0, r.block_number, r.log_index) for r in batched[0]}
    assert stored == _expected_rows(sim)
    assert len(batched[0]) == len(stored)
    assert batched[0] == single[0]
    assert batched[1] == single[1]
    assert batched[2] == single[2]
    assert ("reorg", f"{MAINNET}:{address(0x61)}") in batched[2]
    # Batches really carried several addresses; the flaky group and the reorged fringe went single.
    assert any(len(r["addresses"]) > 1 for sweep in sweeps for r in sweep)
    assert any(r["addresses"] == [FLAKY] for r in sweeps[3])
    # Cross-talk: nothing is stored for an (address, topic) pair that has no cursor.
    assert not [r for r in batched[0] if r.event_address == CROSS_TALKER and r.topic0 == topic(1)]


def test_warm_sweep_requests_at_most_one_getlogs_per_fifty_groups_per_chain(db_session, monkeypatch):
    """With a moving head, each sweep is ceil(groups / 50) requests per chain."""
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    counts = {MAINNET: 120, BASE: 60}
    sim = SimChain(heads=dict(START))
    monkeypatch.setattr(event_logs_rpc, "rpc_request", sim.rpc_request)
    for chain, n in counts.items():
        seed = START[chain] - _depth(chain)
        for i in range(n):
            addr = address(0x1000 * chain + i)
            sim.add_many(chain, [SimLog(addr, (topic(1),), "0x", b, 0, i) for b in range(seed, seed + 5_000, 97)])
            enroll_event_cursor(db_session, chain_id=chain, event_address=addr, topic0=topic(1), start_block=seed)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()
    fetchers = _fetchers()

    for _sweep in range(5):
        for chain in START:
            sim.heads[chain] += STEP[chain]
        before = len(sim.getlogs)
        summary = _scan(db_session, fetchers, "warm")
        requests = sim.getlogs[before:]
        for chain, n in counts.items():
            assert len([r for r in requests if r["chain_id"] == chain]) <= math.ceil(n / 50)
        assert summary.warm_max_lag_blocks == {MAINNET: 0, BASE: 0}


def test_an_address_array_rejection_splits_the_batch(db_session, monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    sim = SimChain(heads=dict(START), max_addresses=3)
    monkeypatch.setattr(event_logs_rpc, "rpc_request", sim.rpc_request)
    seed = START[MAINNET] - _depth(MAINNET) - 200
    addrs = [address(0x900 + i) for i in range(8)]
    for i, addr in enumerate(addrs):
        sim.add_many(MAINNET, [SimLog(addr, (topic(2),), "0x", b, 0, i) for b in range(seed + 1, seed + 200, 3)])
        enroll_event_cursor(db_session, chain_id=MAINNET, event_address=addr, topic0=topic(2), start_block=seed)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()

    summary = _scan(db_session, _fetchers(), "warm")

    assert summary.failed_groups == 0
    served = [r for r in sim.getlogs if r["served"] is not None]
    assert served and all(len(r["addresses"]) <= 3 for r in served)
    assert any(r["served"] is None and len(r["addresses"]) == 8 for r in sim.getlogs)
    stored = db_session.execute(select(IndexedEventLog.event_address)).scalars().all()
    assert sorted(set(stored)) == sorted(addrs)
    assert len(stored) == 8 * len(range(seed + 1, seed + 200, 3))


def test_concurrent_sweeps_lock_in_canonical_order_without_deadlock(db_session, monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    sim = SimChain(heads=dict(START))
    monkeypatch.setattr(event_logs_rpc, "rpc_request", sim.rpc_request)
    seed = START[MAINNET] - _depth(MAINNET) - 100
    addrs = [address(0x500 + i) for i in range(6)]
    for i, addr in enumerate(addrs):
        sim.add_many(MAINNET, [SimLog(addr, (topic(3),), "0x", b, 0, i) for b in range(seed + 1, seed + 100, 2)])
        for t in (topic(3), topic(4)):
            enroll_event_cursor(db_session, chain_id=MAINNET, event_address=addr, topic0=t, start_block=seed)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()
    gate = threading.Barrier(2, timeout=10)
    entered = {"n": 0}
    lock = threading.Lock()

    def together(method, params):
        if method == "eth_getLogs":
            with lock:
                entered["n"] += 1
                first_two = entered["n"] <= 2
            if first_two:
                gate.wait()

    sim.before_request = together
    engine = create_engine(DATABASE_URL)
    locks: list[str] = []
    event.listen(
        engine,
        "before_cursor_execute",
        lambda _c, _cur, statement, *_a: locks.append(statement) if "FOR UPDATE" in statement else None,
    )
    results: list = []
    fetchers = _fetchers()

    def sweep() -> None:
        with Session(engine, expire_on_commit=False) as session:
            results.append(_scan(session, fetchers, "warm"))

    # Two sweeps over the same groups, fetching together, then locking overlapping batches.
    monkeypatch.setattr(indexer_settings, "WARM_BATCH_ADDRESSES", 4)
    threads = [threading.Thread(target=sweep) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    engine.dispose()

    assert len(results) == 2 and all(not t.is_alive() for t in threads)
    # Every row lock is taken in one global order: address, then topic0.
    assert locks and all(
        "ORDER BY lower(indexed_event_cursors.event_address), indexed_event_cursors.topic0" in sql for sql in locks
    )
    assert sum(r.failed_groups for r in results) == 0  # no deadlock victim
    stored = db_session.execute(select(IndexedEventLog.event_address, IndexedEventLog.block_number)).all()
    assert len(stored) == len(set(stored)) == 6 * len(range(seed + 1, seed + 100, 2))
    cursors = db_session.execute(select(IndexedEventCursor.last_indexed_block)).scalars().all()
    assert set(cursors) == {START[MAINNET] - _depth(MAINNET)}


def test_a_group_lagging_past_the_batch_limit_is_swept_alone(db_session, monkeypatch):
    lag = indexer_settings.WARM_BATCH_MAX_LAG + 1
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    sim = SimChain(heads=dict(START))
    monkeypatch.setattr(event_logs_rpc, "rpc_request", sim.rpc_request)
    target = START[MAINNET] - _depth(MAINNET)
    near, far = address(0x701), address(0x702)
    enroll_event_cursor(db_session, chain_id=MAINNET, event_address=near, topic0=topic(5), start_block=target - 10)
    enroll_event_cursor(
        db_session, chain_id=MAINNET, event_address=address(0x703), topic0=topic(5), start_block=target - 10
    )
    enroll_event_cursor(db_session, chain_id=MAINNET, event_address=far, topic0=topic(5), start_block=target - lag)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()

    _scan(db_session, _fetchers(), "warm")

    assert sorted(len(r["addresses"]) for r in sim.getlogs) == [1, 2]
    assert [r["addresses"] for r in sim.getlogs if len(r["addresses"]) == 1] == [[far]]
