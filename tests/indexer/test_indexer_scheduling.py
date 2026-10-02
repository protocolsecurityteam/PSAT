"""Scheduling under the paged engine: cold rotation, the warm thread's cadence, the claim set, and shutdown."""

from __future__ import annotations

import dataclasses
import threading
import time
from contextlib import nullcontext
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

import services.resolution.repos.event_logs_rpc as event_logs_rpc
import workers.event_log_indexer as indexer
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
)
from services.resolution import indexer_scheduler
from tests.conftest import DATABASE_URL, requires_postgres
from tests.support.sim_chain import SimChain, SimLog, address, topic, word
from utils.chains import chain_by_id
from workers.event_log_indexer import GroupClaims, ScanSummary, enroll_event_cursor, scan_enrolled_events

_TOPIC = topic(0x51)
_HEADS = {1: 2_000_012, 8453: 30_000_075}


@pytest.fixture()
def sim(monkeypatch):
    chain = SimChain(heads=dict(_HEADS))
    monkeypatch.setattr(event_logs_rpc, "rpc_request", chain.rpc_request)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    return chain


def _fetchers():
    base = dataclasses.replace(chain_by_id(8453), hypersync_url="https://base.hypersync.xyz")
    return indexer._build_indexer_fetchers(chains=(chain_by_id(1), base))


def _enroll(session, addr: str, *, seed: int, basis: str = ENROLLMENT_BASIS_PREDICATE_HINT, chain_id: int = 1):
    enroll_event_cursor(
        session,
        chain_id=chain_id,
        event_address=addr,
        topic0=_TOPIC,
        start_block=seed,
        first_indexed_block=seed,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
        enrollment_basis=basis,
    )


def _logs(addr: str, lo: int, hi: int, every: int) -> list[SimLog]:
    return [
        # Positions unique per block across addresses, as on chain, so batched pages pass strict decoding.
        SimLog(
            address=addr, topics=(_TOPIC,), data="0x" + word(b), block=b, tx_index=0, log_index=int(addr, 16) % 1_000
        )
        for b in range(lo, hi + 1, every)
    ]


def _scan(session, fetchers, **kwargs) -> ScanSummary:
    return scan_enrolled_events(
        session,
        fetchers=fetchers[0],
        head_fetchers=fetchers[1],
        block_hash_fetchers=fetchers[2],
        **kwargs,
    )


# Rotation


@requires_postgres
def test_new_hint_group_is_visited_before_an_older_cold_dense_group(db_session, sim):
    dense, fresh = address(0xD1), address(0xF1)
    sim.add_many(1, _logs(dense, 1_000_001, 1_900_000, 3))
    _enroll(db_session, dense, seed=1_000_000)
    _enroll(db_session, fresh, seed=1_500_000)
    db_session.execute(
        update(IndexedEventCursor)
        .where(IndexedEventCursor.event_address == dense)
        .values(
            last_indexed_block=1_200_000,
            last_advanced_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            last_run_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
    )
    db_session.commit()

    _scan(db_session, _fetchers(), scan_mode="cold", max_windows_per_pass=1)

    assert [r["addresses"] for r in sim.getlogs] == [[fresh]]


@requires_postgres
def test_rotation_prefers_hint_bases_among_never_advanced_groups(db_session, sim):
    tracked, hint = address(0xE1), address(0xE2)
    _enroll(db_session, tracked, seed=1_500_000, basis=ENROLLMENT_BASIS_TRACKED_TOPICS)
    _enroll(db_session, hint, seed=1_500_000)
    db_session.execute(
        update(IndexedEventCursor)
        .where(IndexedEventCursor.event_address == tracked)
        .values(last_run_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    )
    db_session.commit()

    _scan(db_session, _fetchers(), scan_mode="cold", max_windows_per_pass=1)

    assert [r["addresses"] for r in sim.getlogs] == [[hint]]


@requires_postgres
def test_a_page_commit_stamps_last_advanced_at(db_session, sim):
    addr = address(0xE3)
    _enroll(db_session, addr, seed=1_999_000)
    db_session.commit()

    _scan(db_session, _fetchers(), scan_mode="cold")

    db_session.expire_all()
    cursor = db_session.execute(select(IndexedEventCursor).where(IndexedEventCursor.event_address == addr)).scalar_one()
    assert cursor.last_advanced_at is not None and cursor.last_indexed_block == 2_000_000


# Claim set and concurrency


def _two_threads(make_session, fetchers, claims_for) -> None:
    errors: list[BaseException] = []

    def run(index: int) -> None:
        try:
            with make_session() as session:
                _scan(session, fetchers, scan_mode="cold", claims=claims_for(index))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors


@requires_postgres
@pytest.mark.parametrize("shared_claims", [True, False], ids=["claims", "no-claims"])
def test_two_scan_threads_on_one_group_never_double_write(db_session, sim, shared_claims):
    addr = address(0xC1)
    sim.add_many(1, _logs(addr, 1_990_001, 2_000_000, 7))
    _enroll(db_session, addr, seed=1_990_000)
    db_session.commit()
    # Without claims, both threads fetch the one page together; with claims, the first holds the group while the
    # second arrives.
    gate = threading.Barrier(2, timeout=10)

    def slow(method, params):
        if method != "eth_getLogs":
            return
        if shared_claims:
            time.sleep(0.3)
        else:
            gate.wait()

    sim.before_request = slow
    engine = create_engine(DATABASE_URL)
    claims = GroupClaims()
    try:
        _two_threads(
            lambda: Session(engine, expire_on_commit=False),
            _fetchers(),
            lambda _i: claims if shared_claims else None,
        )
    finally:
        engine.dispose()

    ranges = [(r["from"], r["to"]) for r in sim.getlogs]
    if shared_claims:
        # The second thread skipped the claimed group: every range was fetched once.
        assert len(ranges) == len(set(ranges))
    else:
        # Both fetched; the position check discarded the loser's page, so nothing doubled.
        assert len(ranges) > len(set(ranges))
    rows = db_session.execute(select(IndexedEventLog.block_number).order_by(IndexedEventLog.block_number)).scalars()
    assert list(rows) == list(range(1_990_001, 2_000_001, 7))


@requires_postgres
def test_a_claimed_group_is_skipped(db_session, sim):
    addr = address(0xC2)
    _enroll(db_session, addr, seed=1_999_000)
    db_session.commit()
    claims = GroupClaims()
    assert claims.claim([(1, addr)])

    summary = _scan(db_session, _fetchers(), scan_mode="cold", claims=claims)

    assert sim.getlogs == []
    assert summary.budget_exhausted  # the skipped group comes back on the short cadence


# The run loop


def test_shutdown_joins_both_scan_threads_before_returning(monkeypatch):
    stop = threading.Event()
    finished: dict[str, float] = {}
    started = {"warm": threading.Event(), "cold": threading.Event()}

    def fake_scan(_session, *, scan_mode, stop_event, **_kwargs):
        started[scan_mode].set()
        stop_event.wait(5)
        # A scan still finishing its last commit after the stop request.
        time.sleep(0.2)
        finished[scan_mode] = time.monotonic()
        return ScanSummary()

    monkeypatch.setattr(indexer, "SessionLocal", lambda: nullcontext(MagicMock()))
    monkeypatch.setattr(indexer_scheduler, "drain_enrollment", lambda _s, **_k: 0)
    monkeypatch.setattr(indexer_scheduler, "drain_reconciliation", lambda _s, **_k: (0, 0))
    monkeypatch.setattr(indexer, "scan_enrolled_events", fake_scan)
    monkeypatch.setattr(indexer, "_cursor_progress", lambda _s: (0, 0))
    monkeypatch.setattr(indexer, "record_heartbeat", lambda *_a, **_k: None)

    def request_stop():
        assert started["warm"].wait(5) and started["cold"].wait(5)
        stop.set()

    threading.Thread(target=request_stop, daemon=True).start()
    indexer.run_event_log_indexer_loop(
        fetchers={}, head_fetchers={}, block_hash_fetchers={}, interval=0.05, stop_event=stop
    )
    returned = time.monotonic()

    assert set(finished) == {"warm", "cold"}
    assert all(at <= returned for at in finished.values())
    assert not [t for t in threading.enumerate() if t.name in ("event-indexer-warm", "event-indexer-backfill")]


@requires_postgres
def test_warm_cursors_keep_up_with_a_moving_head_while_a_cold_fetch_blocks(db_session, sim, monkeypatch):
    """Time-scaled: a 0.3 s interval stands for 60 s, and the cold fetch blocks for 10 intervals."""
    interval = 0.3
    rates = {1: 40.0, 8453: 120.0}  # blocks per second
    t0 = time.monotonic()
    sim.head_fn = lambda chain: _HEADS[chain] + int((time.monotonic() - t0) * rates[chain])
    warm = {1: [address(0xA1), address(0xA2)], 8453: [address(0xB1)]}
    cold = address(0xCC)
    depth = {chain: chain_by_id(chain).confirmation_depth for chain in rates}
    for chain, addrs in warm.items():
        for addr in addrs:
            sim.add_many(chain, _logs(addr, _HEADS[chain] - 500, _HEADS[chain] + 2_000, 3))
            _enroll(db_session, addr, seed=_HEADS[chain] - depth[chain], chain_id=chain)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    _enroll(db_session, cold, seed=1_000_000)
    db_session.commit()
    release = threading.Event()
    blocked: list[tuple[float, float]] = []

    def block_cold(method, params):
        if method == "eth_getLogs" and cold in str(params[0].get("address")):
            began = time.monotonic()
            release.wait(10 * interval)
            blocked.append((began, time.monotonic()))

    sim.before_request = block_cold
    engine = create_engine(DATABASE_URL)
    monkeypatch.setattr(indexer, "SessionLocal", sessionmaker(bind=engine, expire_on_commit=False))
    monkeypatch.setattr(indexer_scheduler, "drain_enrollment", lambda _s, **_k: 0)
    monkeypatch.setattr(indexer_scheduler, "drain_reconciliation", lambda _s, **_k: (0, 0))
    beats: list[dict] = []
    monkeypatch.setattr(indexer, "record_heartbeat", lambda _p, **kw: beats.append(kw.get("detail") or {}))
    stop = threading.Event()
    fetchers = _fetchers()
    loop = threading.Thread(
        target=indexer.run_event_log_indexer_loop,
        kwargs=dict(
            fetchers=fetchers[0],
            head_fetchers=fetchers[1],
            block_hash_fetchers=fetchers[2],
            interval=interval,
            stop_event=stop,
        ),
    )
    loop.start()
    max_lag_s = {chain: 0.0 for chain in rates}
    try:
        time.sleep(2 * interval)  # first sweep
        deadline = time.monotonic() + 8 * interval
        while time.monotonic() < deadline:
            with Session(engine) as probe:
                for chain, addrs in warm.items():
                    frontier = probe.scalar(
                        select(func.min(IndexedEventCursor.last_indexed_block)).where(
                            IndexedEventCursor.chain_id == chain, IndexedEventCursor.event_address.in_(addrs)
                        )
                    )
                    assert frontier is not None
                    lag_blocks = sim.head(chain) - depth[chain] - int(frontier)
                    max_lag_s[chain] = max(max_lag_s[chain], lag_blocks / rates[chain])
            time.sleep(interval / 6)
    finally:
        release.set()
        stop.set()
        loop.join(timeout=30)
        engine.dispose()

    assert not loop.is_alive()
    # The cold fetch was blocked across the whole sampling window.
    assert blocked and blocked[0][1] - blocked[0][0] >= 8 * interval
    for chain, lag_s in max_lag_s.items():
        assert lag_s <= 2 * interval, (chain, lag_s)
    published = [b["warm_max_lag_blocks"] for b in beats if b.get("warm_max_lag_blocks")]
    assert published and set(published[-1]) == {"1", "8453"}
