"""Offline proxy for the memory gate: the paged engine's peak is bounded by the page ceiling, the legacy engine's by the
window. One dense address with 300,000 logs over its span is served through the stubbed wire to each engine under
tracemalloc.

The legacy engine fetches and decodes its whole window before the first write, so its peak is reached by its first
commit and the run stops there. The paged engine runs on through several ceilings' worth of logs, so a peak that grew
with the volume processed would show. Both stop early only because row inserts dominate the runtime."""

from __future__ import annotations

import dataclasses
import tracemalloc
from threading import Event

import pytest
from sqlalchemy import func, select

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from db.models import IndexedEventCursor, IndexedEventLog
from services.resolution import indexer_settings
from tests.conftest import requires_postgres
from tests.support.sim_chain import SimChain, SimLog, address, topic
from utils.chains import chain_by_id
from workers.event_log_indexer import ScanSummary, _build_indexer_fetchers, enroll_event_cursor, scan_enrolled_events

pytestmark = requires_postgres

_LOGS = 300_000
_SEED = 1_000_000
_HEAD = 1_500_000
_ADDR = address(0xDE5E)
_TOPIC = topic(0x7A)


_PAGED_VOLUME = 120_000


def _backfill(session, monkeypatch, engine: str, *, stop_after: int) -> tuple[int, int, int]:
    session.query(IndexedEventLog).delete()
    session.query(IndexedEventCursor).delete()
    session.commit()
    # Served whole, like an aggregator that never rejects, so the legacy window holds the entire history at once.
    sim = SimChain(heads={1: _HEAD}, reject_over=10**9)
    span = 400_000
    sim.add_many(
        1,
        [SimLog(_ADDR, (_TOPIC,), "0x", _SEED + 1 + (i * span) // _LOGS, i % 7, i) for i in range(_LOGS)],
    )
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


def test_paged_peak_is_bounded_by_the_page_ceiling_and_legacy_peak_by_the_window(db_session, monkeypatch, capsys):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.delenv("PSAT_GETLOGS_RESULT_CAP", raising=False)

    legacy_peak, legacy_page, legacy_stored = _backfill(db_session, monkeypatch, "legacy", stop_after=1)
    paged_peak, paged_page, paged_stored = _backfill(db_session, monkeypatch, "paged", stop_after=_PAGED_VOLUME)

    assert legacy_page == _LOGS, "the legacy window must hold every log at once"
    assert 0 < legacy_stored < _LOGS
    assert paged_stored >= _PAGED_VOLUME > indexer_settings.MAX_PAGE_LOGS
    assert 0 < paged_page <= indexer_settings.MAX_PAGE_LOGS
    per_log = legacy_peak / _LOGS
    slack = 32 * 1024 * 1024
    assert paged_peak <= indexer_settings.MAX_PAGE_LOGS * per_log + slack
    assert legacy_peak >= 2.5 * paged_peak
    with capsys.disabled():
        print(
            f"\nmemory proxy ({_LOGS} logs): legacy peak {legacy_peak / 2**20:.1f} MiB "
            f"({per_log:.0f} B/log, one {legacy_page}-log window); paged peak {paged_peak / 2**20:.1f} MiB "
            f"over {paged_stored} logs (largest page {paged_page}, ceiling {indexer_settings.MAX_PAGE_LOGS})"
        )


@pytest.fixture(autouse=True)
def _restore_tracing():
    yield
    if tracemalloc.is_tracing():
        tracemalloc.stop()
