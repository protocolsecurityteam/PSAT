"""Offline differential: the legacy and paged engines index one simulated history to the same rows, cursors and
reconciliation marks.

Both runs drive the real ``scan_enrolled_events`` (warm sweep, then cold pass, as the daemon does) with only
``rpc_request`` stubbed. Sizes are scaled down from production: the upstream rejects responses over 7,000 logs (the
50k-style limit), one range is served whole up to 10,000 (the merged 150k-style page), and the paged ceiling and target
are 6,500 and 1,600. The fixture covers sparse and dense addresses, a 6,000-log single block, staggered topics,
a sibling enrolled late, a client timeout, a fringe reorg under a moving head, a shutdown between pages, and a Base
group. It runs with the result cap unset and set.
"""

from __future__ import annotations

import dataclasses
from threading import Event
from typing import Any

import pytest
from sqlalchemy import delete, select, update

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
    IndexerWork,
)
from tests.conftest import requires_postgres
from tests.support.sim_chain import MergeRange, SimChain, SimLog, address, topic, word
from utils.chains import chain_by_id
from workers.event_log_indexer import PageLimits, _build_indexer_fetchers, enroll_event_cursor, scan_enrolled_events

pytestmark = requires_postgres

MAINNET, BASE = 1, 8453
HEAD_1 = {MAINNET: 2_000_000, BASE: 30_000_000}
HEAD_2 = {MAINNET: 2_000_600, BASE: 30_000_400}
REORG_FROM = 1_999_985

SPARSE, DENSE, BIG_BLOCK, STAGGERED, ON_BASE = (address(0xA000 + i) for i in range(5))
TA1, TA2, TB1, TB2, TB3, TC, TD1, TD2, TD3, TE1, TE2 = (topic(0x100 + i) for i in range(11))
BIG_BLOCK_NUMBER = 1_500_000

PAGED_LIMITS = PageLimits(max_block_span=500_000, initial_span=50_000, target_page_logs=1_600, max_page_logs=6_500)

# (chain, address, topic, seed, starting position)
ENROLMENT = [
    (MAINNET, SPARSE, TA1, 1_200_000, 1_200_000),
    (MAINNET, SPARSE, TA2, 1_200_000, 1_200_000),
    (MAINNET, DENSE, TB1, 1_000_000, 1_000_000),
    (MAINNET, DENSE, TB2, 1_000_000, 1_000_000),
    (MAINNET, DENSE, TB3, 1_000_000, 1_000_000),
    (MAINNET, BIG_BLOCK, TC, 1_400_000, 1_400_000),
    (MAINNET, STAGGERED, TD1, 1_300_000, 1_300_000),
    (MAINNET, STAGGERED, TD2, 1_700_000, 1_700_000),
    (BASE, ON_BASE, TE1, 29_500_000, 29_500_000),
    (BASE, ON_BASE, TE2, 29_500_000, 29_500_000),
]
LATE_SIBLING = (MAINNET, STAGGERED, TD3, 1_300_000, 1_300_000)


def _every(addr: str, t: str, lo: int, hi: int, step: int, slot: int, tag: int = 0) -> list[SimLog]:
    return [
        SimLog(
            address=addr,
            topics=(t, "0x" + word(b)),
            data="0x" + word(b) + word(slot),
            block=b,
            tx_index=slot,
            log_index=slot,
            tag=tag,
        )
        for b in range(lo, hi + 1, step)
    ]


def build_chain() -> SimChain:
    sim = SimChain(heads=HEAD_1, reject_over=7_000)
    sim.add_many(MAINNET, _every(SPARSE, TA1, 1_200_100, 2_000_600, 997, 1))
    sim.add_many(MAINNET, _every(SPARSE, TA2, 1_200_300, 2_000_600, 4_001, 2))
    # Fringe logs the reorg replaces.
    sim.add_many(MAINNET, _every(SPARSE, TA1, 1_999_986, 1_999_988, 1, 3))
    sim.add_many(MAINNET, _every(DENSE, TB1, 1_000_001, 1_200_000, 80, 10))
    sim.add_many(MAINNET, _every(DENSE, TB2, 1_000_003, 1_200_000, 320, 11))
    sim.add_many(MAINNET, _every(DENSE, TB3, 1_000_007, 1_200_000, 800, 12))
    burst = [
        SimLog(address=DENSE, topics=(TB1,), data="0x", block=b, tx_index=20 + i, log_index=20 + i)
        for b in range(1_010_000, 1_020_000)
        for i in range(1 if b % 4 else 0)
    ]
    sim.add_many(MAINNET, burst)
    sim.merges.append(MergeRange(MAINNET, DENSE, 1_010_000, 1_019_999, 10_000))
    sim.add_many(MAINNET, _every(BIG_BLOCK, TC, 1_400_001, 2_000_600, 5_000, 30))
    sim.add_many(
        MAINNET,
        [
            SimLog(
                address=BIG_BLOCK,
                topics=(TC,),
                data="0x" + word(i),
                block=BIG_BLOCK_NUMBER,
                tx_index=i // 6,
                log_index=100 + i,
            )
            for i in range(6_000)
        ],
    )
    sim.add_many(MAINNET, _every(STAGGERED, TD1, 1_300_001, 2_000_600, 1_000, 40))
    sim.add_many(MAINNET, _every(STAGGERED, TD2, 1_300_001, 2_000_600, 1_400, 41))
    sim.add_many(MAINNET, _every(STAGGERED, TD3, 1_300_001, 2_000_600, 600, 42))
    sim.add_many(MAINNET, _every(STAGGERED, TD1, 1_999_984, 1_999_988, 1, 43))
    sim.add_many(BASE, _every(ON_BASE, TE1, 29_500_001, 30_000_400, 1_000, 50))
    sim.add_many(BASE, _every(ON_BASE, TE2, 29_500_001, 30_000_400, 1_000, 51))
    sim.pending_timeouts.append((MAINNET, STAGGERED))
    return sim


def _enroll(session, entries) -> None:
    for chain_id, addr, t, seed, position in entries:
        enroll_event_cursor(
            session,
            chain_id=chain_id,
            event_address=addr,
            topic0=t,
            start_block=position,
            first_indexed_block=seed,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
            enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
        )
    session.commit()


def _targets(heads: dict[int, int]) -> dict[int, int]:
    return {chain: head - chain_by_id(chain).confirmation_depth for chain, head in heads.items()}


def _caught_up(session, heads: dict[int, int]) -> bool:
    targets = _targets(heads)
    rows = session.execute(
        select(IndexedEventCursor.chain_id, IndexedEventCursor.last_indexed_block, IndexedEventCursor.backfill_complete)
    ).all()
    return all(complete and last >= targets[chain] for chain, last, complete in rows)


def _run_to_completion(session, engine: str, fetchers, heads: dict[int, int], stop: Event | None = None) -> None:
    for _ in range(300):
        for mode in ("warm", "cold"):
            scan_enrolled_events(
                session,
                fetchers=fetchers[0],
                head_fetchers=fetchers[1],
                block_hash_fetchers=fetchers[2],
                engine=engine,
                scan_mode=mode,
                page_limits=PAGED_LIMITS,
                stop_event=stop,
                group_budget_s=1e9,
                pass_budget_s=1e9,
            )
        if stop is not None and stop.is_set():
            stop.clear()
            continue
        if _caught_up(session, heads):
            return
    raise AssertionError(f"{engine} engine never caught up")


def _snapshot(session) -> dict[str, Any]:
    session.expire_all()
    log_columns = [c for c in IndexedEventLog.__table__.columns if c.name != "detected_at"]
    rows = session.execute(
        select(*log_columns).order_by(
            IndexedEventLog.chain_id,
            IndexedEventLog.event_address,
            IndexedEventLog.topic0,
            IndexedEventLog.block_number,
            IndexedEventLog.log_index,
        )
    ).all()
    excluded = {"last_run_at", "last_advanced_at", "recent_logs_per_block", "max_window_log_count"}
    cursor_columns = [c for c in IndexedEventCursor.__table__.columns if c.name not in excluded]
    cursors = session.execute(
        select(*cursor_columns).order_by(
            IndexedEventCursor.chain_id, IndexedEventCursor.event_address, IndexedEventCursor.topic0
        )
    ).all()
    max_counts = dict(
        session.execute(
            select(
                IndexedEventCursor.event_address + ":" + IndexedEventCursor.topic0,
                IndexedEventCursor.max_window_log_count,
            )
        ).all()
    )
    work = set(session.execute(select(IndexerWork.kind, IndexerWork.key).where(IndexerWork.dirty)).all())
    return {"rows": rows, "cursors": cursors, "max_counts": max_counts, "work": work}


def _expected_rows(sim: SimChain, heads: dict[int, int]) -> set[tuple[int, str, str, int, int]]:
    targets = _targets(heads)
    out = set()
    for chain_id, addr, t, seed, position in [*ENROLMENT, LATE_SIBLING]:
        lane = sim.lanes[(chain_id, addr)]
        for log in lane.between(position + 1, targets[chain_id]):
            if log.topics[0] == t:
                out.add((chain_id, addr, t, log.block, log.log_index))
    return out


def _wipe(session) -> None:
    for model in (IndexedEventLog, IndexedEventCursor, IndexerWork):
        session.query(model).delete()
    session.commit()


def _scenario(session, monkeypatch, engine: str) -> tuple[dict[str, Any], SimChain]:
    _wipe(session)
    sim = build_chain()
    monkeypatch.setattr(event_logs_rpc, "rpc_request", sim.rpc_request)
    base = dataclasses.replace(chain_by_id(BASE), hypersync_url="https://base.hypersync.xyz")
    fetchers = _build_indexer_fetchers(chains=(chain_by_id(MAINNET), base), engine=engine)
    _enroll(session, ENROLMENT)

    # Phase 1: backfill, with a shutdown delivered during the fourth eth_getLogs.
    stop = Event()
    fetches = 0

    def sigterm_on_fourth(method, _params):
        nonlocal fetches
        if method == "eth_getLogs":
            fetches += 1
            if fetches == 4:
                stop.set()

    sim.before_request = sigterm_on_fourth
    _run_to_completion(session, engine, fetchers, HEAD_1, stop)
    sim.before_request = None

    # Phase 2: a sibling topic enrolled late at an address whose topics are warm.
    _enroll(session, [LATE_SIBLING])
    _run_to_completion(session, engine, fetchers, HEAD_1)

    # Phase 3: the head moves and the fringe every mainnet stamp sits on is reorged.
    sim.heads.update(HEAD_2)
    sim.reorg(MAINNET, REORG_FROM)
    sim.remove(
        MAINNET, lambda log: log.address == SPARSE and REORG_FROM <= log.block <= 1_999_988 and log.tx_index == 3
    )
    sim.add_many(MAINNET, _every(SPARSE, TA1, 1_999_987, 1_999_987, 1, 4, tag=1))
    _run_to_completion(session, engine, fetchers, HEAD_2)
    return _snapshot(session), sim


# The set cap sits above every floor-sized span (a span at the floor that reaches the cap can never be proven whole) and
# below the merged page, so both engines take the cap's bisect path.
@pytest.mark.parametrize("cap", [None, "8500"], ids=["cap-unset", "cap-set"])
def test_legacy_and_paged_engines_index_identically(db_session, monkeypatch, cap):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.setattr(event_logs_rpc.time, "sleep", lambda _s: None)
    if cap is None:
        monkeypatch.delenv("PSAT_GETLOGS_RESULT_CAP", raising=False)
    else:
        monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", cap)

    legacy, legacy_sim = _scenario(db_session, monkeypatch, "legacy")
    paged, paged_sim = _scenario(db_session, monkeypatch, "paged")

    # Absolute correctness first, so a defect shared by both engines can't pass as parity.
    stored = {(r.chain_id, r.event_address, r.topic0, r.block_number, r.log_index) for r in legacy["rows"]}
    assert stored == _expected_rows(legacy_sim, HEAD_2)
    assert len(legacy["rows"]) == len(stored)

    assert paged["rows"] == legacy["rows"]
    assert paged["cursors"] == legacy["cursors"]
    assert paged["work"] == legacy["work"]
    for key, legacy_max in legacy["max_counts"].items():
        paged_max = paged["max_counts"][key]
        assert (paged_max is None) == (legacy_max is None)
        assert paged_max is None or paged_max <= legacy_max, key

    # The fixture really exercised what it claims to.
    targets = _targets(HEAD_2)
    assert all(c.last_indexed_block == targets[c.chain_id] and c.backfill_complete for c in paged["cursors"])
    assert {("reorg", f"{MAINNET}:{addr}") for addr in (SPARSE, DENSE, BIG_BLOCK, STAGGERED)} <= paged["work"]
    assert ("reconcile", str(BASE)) in paged["work"]
    big = [r for r in paged["rows"] if r.block_number == BIG_BLOCK_NUMBER]
    assert len(big) == 6_000
    # Legacy accepted the merged page whole; the paged engine's ceiling split it.
    ceiling = PAGED_LIMITS.max_page_logs or 0
    assert any(DENSE in r["addresses"] and (r["served"] or 0) > ceiling for r in legacy_sim.getlogs)
    assert any(DENSE in r["addresses"] and (r["served"] or 0) > ceiling for r in paged_sim.getlogs)
    assert any(r["served"] is None for r in legacy_sim.getlogs)  # upstream rejections happened
    assert max(v for v in paged["max_counts"].values() if v is not None) <= PAGED_LIMITS.max_page_logs
    expected_basis = "continuous_from_first_indexed_block" if cap else "not_determined"
    assert {c.window_stats_basis for c in paged["cursors"]} == {expected_basis}

    if cap is None:
        # The comparison isn't vacuous: an engine that dropped one topic's rows and a flag would be caught.
        db_session.execute(delete(IndexedEventLog).where(IndexedEventLog.topic0 == TD3))
        db_session.execute(
            update(IndexedEventCursor).where(IndexedEventCursor.topic0 == TD2).values(backfill_complete=False)
        )
        db_session.commit()
        tampered = _snapshot(db_session)
        assert tampered["rows"] != paged["rows"]
        assert tampered["cursors"] != paged["cursors"]
