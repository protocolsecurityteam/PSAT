"""Offline memory proxy: the paged engine's peak is bounded by its page ceiling, the legacy engine's by its window.

One dense address holds 300,000 logs over its span, served through the stubbed wire under tracemalloc. Both claims are
relative to the configured window and ceiling, so they're scaled down to keep row inserts (which dominate the runtime)
small: the legacy window holds 40,000 logs and is fetched and decoded whole before its first write, so its peak is
reached by its first commit; the paged run uses a 3,000-log ceiling and processes more than two ceilings' worth, so a
peak that grew with the volume processed would show.
"""

from __future__ import annotations

import dataclasses
import tracemalloc
from threading import Event

import pytest
from sqlalchemy import func, select

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from db.models import IndexedEventCursor, IndexedEventLog
from tests.conftest import requires_postgres
from tests.support.sim_chain import SimChain, SimLog, address, topic
from utils.chains import chain_by_id
from workers.event_log_indexer import (
    PageLimits,
    ScanSummary,
    _build_indexer_fetchers,
    enroll_event_cursor,
    scan_enrolled_events,
)

pytestmark = requires_postgres

_LOGS = 300_000
_SPAN = 400_000
_SEED = 1_000_000
_HEAD = 1_500_000
_ADDR = address(0xDE5E)
_TOPIC = topic(0x7A)
_LEGACY_WINDOW_BLOCKS = 53_334  # 40,000 logs at 0.75 per block
_PAGED = PageLimits(max_block_span=500_000, initial_span=1_000, target_page_logs=750, max_page_logs=3_000)
_PAGED_VOLUME = 7_000


@pytest.fixture(scope="module")
def dense_chain() -> SimChain:
    # Served whole, like an aggregator that never rejects, so the legacy window holds its whole range at once.
    sim = SimChain(heads={1: _HEAD}, reject_over=10**9)
    sim.add_many(1, [SimLog(_ADDR, (_TOPIC,), "0x", _SEED + 1 + (i * _SPAN) // _LOGS, i % 7, i) for i in range(_LOGS)])
    return sim


def _backfill(session, monkeypatch, sim: SimChain, engine: str, *, stop_after: int) -> tuple[int, int, int]:
    session.query(IndexedEventLog).delete()
    session.query(IndexedEventCursor).delete()
    session.commit()
    sim.getlogs.clear()
    monkeypatch.setattr(event_logs_rpc, "rpc_request", sim.rpc_request)
    base = dataclasses.replace(chain_by_id(8453), hypersync_url="https://base.hypersync.xyz")
    fetchers = _build_indexer_fetchers(chains=(chain_by_id(1), base), engine=engine)
    enroll_event_cursor(session, chain_id=1, event_address=_ADDR, topic0=_TOPIC, start_block=_SEED)
    session.commit()
    stop = Event()

    def stop_once_written(summary: ScanSummary) -> None:
        if summary.inserted >= stop_after:
            stop.set()

    tracemalloc.start()
    try:
        scan_enrolled_events(
            session,
            fetchers=fetchers[0],
            head_fetchers=fetchers[1],
            block_hash_fetchers=fetchers[2],
            engine=engine,
            max_block_span=_LEGACY_WINDOW_BLOCKS,
            page_limits=_PAGED,
            max_windows_per_cursor=1_000,
            group_budget_s=1e9,
            pass_budget_s=1e9,
            stop_event=stop,
            on_commit=stop_once_written,
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    stored = session.scalar(select(func.count()).select_from(IndexedEventLog))
    largest_page = max(r["served"] or 0 for r in sim.getlogs)
    return peak, largest_page, int(stored or 0)


def test_paged_peak_is_bounded_by_the_page_ceiling_and_legacy_peak_by_the_window(
    db_session, monkeypatch, capsys, dense_chain
):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.delenv("PSAT_GETLOGS_RESULT_CAP", raising=False)

    legacy_peak, legacy_page, legacy_stored = _backfill(db_session, monkeypatch, dense_chain, "legacy", stop_after=1)
    paged_peak, paged_page, paged_stored = _backfill(
        db_session, monkeypatch, dense_chain, "paged", stop_after=_PAGED_VOLUME
    )

    ceiling = _PAGED.max_page_logs or 0
    assert legacy_page == len(dense_chain.lanes[(1, _ADDR)].between(_SEED + 1, _SEED + _LEGACY_WINDOW_BLOCKS))
    assert 0 < legacy_stored < legacy_page
    assert paged_stored >= _PAGED_VOLUME > 2 * ceiling
    assert 0 < paged_page <= ceiling
    per_log = legacy_peak / legacy_page
    slack = 16 * 1024 * 1024  # fixed tracing overhead (ORM and SQL compile caches), independent of page size
    assert paged_peak <= ceiling * per_log + slack
    assert legacy_peak >= 3 * paged_peak
    with capsys.disabled():
        print(
            f"\nmemory proxy: legacy peak {legacy_peak / 2**20:.1f} MiB ({per_log:.0f} B/log, one {legacy_page}-log "
            f"window); paged peak {paged_peak / 2**20:.1f} MiB over {paged_stored} logs (largest page {paged_page}, "
            f"ceiling {ceiling})"
        )


@pytest.fixture(autouse=True)
def _restore_tracing():
    yield
    if tracemalloc.is_tracing():
        tracemalloc.stop()
