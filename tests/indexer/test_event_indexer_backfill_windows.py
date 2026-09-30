"""A fresh cursor's ~25M-block gap scanned in one shot dropped the Neon connection on LayerZero's endpoint, pinning
the cursor at 0 forever (PR #104 follow-up).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

import pytest
from sqlalchemy import delete, func, select, update

from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from workers.event_log_indexer import enroll_event_cursor, scan_enrolled_events

_MAX_SAFE_SPAN = 10_000
_HEAD = 1_000_000
_CONFIRMATIONS = 12
_TARGET = _HEAD - _CONFIRMATIONS  # 999_988
_DENSITY = 100  # one synthetic role event every 100 blocks
_AUTHORITY = "0x" + "39" * 20  # stand-in Solmate RolesAuthority
_TOPIC = "0x" + "ab" * 32  # stand-in RoleCapabilityUpdated topic


class _RangeCappedFetcher:

    def __init__(self) -> None:
        self.requested_spans: list[int] = []

    def fetch_logs(
        self, *, event_address: str | Sequence[str], topics, from_block: int, to_block: int
    ) -> list[FetchedEventLog]:
        span = to_block - from_block + 1
        self.requested_spans.append(span)
        if span > _MAX_SAFE_SPAN:
            raise RuntimeError(f"eth_getLogs window too large: {span} blocks (cap {_MAX_SAFE_SPAN})")
        out: list[FetchedEventLog] = []
        first = ((from_block + _DENSITY - 1) // _DENSITY) * _DENSITY
        for blk in range(first, to_block + 1, _DENSITY):
            out.append(
                FetchedEventLog(
                    tx_hash=blk.to_bytes(32, "big"),
                    log_index=0,
                    block_number=blk,
                    block_hash=blk.to_bytes(32, "big"),
                    transaction_index=0,
                    topics=[topics[0], "0x" + "00" * 31 + "01"],
                    data_words=["0x" + "00" * 31 + "01"],
                )
            )
        return out


class _FixedHead:
    def head_block(self) -> int:
        return _HEAD


class _DeterministicBlockHash:
    # Stored hash matches observed, so the reorg guard never rewinds.
    def block_hash(self, block_number: int) -> bytes:
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


def _maps(fetcher: _RangeCappedFetcher):
    return (
        {1: fetcher},
        {1: _FixedHead()},
        {1: _DeterministicBlockHash()},
    )


def _cursor_block(session, address: str) -> int:
    from db.models import IndexedEventCursor

    return session.execute(
        select(IndexedEventCursor.last_indexed_block).where(func.lower(IndexedEventCursor.event_address) == address)
    ).scalar_one()


def _log_count(session, address: str) -> int:
    from db.models import IndexedEventLog

    return session.execute(
        select(func.count()).select_from(IndexedEventLog).where(func.lower(IndexedEventLog.event_address) == address)
    ).scalar_one()


@requires_postgres
def test_backfills_full_history_in_bounded_windows(session):
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC)
    session.commit()

    fetcher = _RangeCappedFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    summary = scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_MAX_SAFE_SPAN,
        max_windows_per_cursor=500,
        max_windows_per_pass=500,  # decoupled from the prod default so the single cursor fully backfills here
        insert_batch_size=1000,
    )

    assert fetcher.requested_spans, "indexer never called the fetcher"
    assert max(fetcher.requested_spans) <= _MAX_SAFE_SPAN, (
        f"indexer requested a {max(fetcher.requested_spans)}-block window > {_MAX_SAFE_SPAN}; "
        "the unbounded full-range fetch is what crashed the DB connection"
    )

    expected_logs = _TARGET // _DENSITY  # 9_999
    assert _cursor_block(session, _AUTHORITY) == _TARGET
    assert _log_count(session, _AUTHORITY) == expected_logs
    assert summary.inserted == expected_logs
    assert summary.budget_exhausted is False  # drained within budget → loop returns to the poll interval


class _OrderRecordingFetcher:
    def __init__(self) -> None:
        self.order: list[str] = []

    def fetch_logs(
        self, *, event_address: str | Sequence[str], topics, from_block: int, to_block: int
    ) -> list[FetchedEventLog]:
        if not isinstance(event_address, str):
            event_address = event_address[0]
        self.order.append(event_address.lower())
        return []


def _set_last_run_at(session, address: str, when: datetime) -> None:
    # An explicit SET value suppresses onupdate, and a literal avoids a transaction-constant now().
    from db.models import IndexedEventCursor

    session.execute(
        update(IndexedEventCursor)
        .where(func.lower(IndexedEventCursor.event_address) == address.lower())
        .values(last_run_at=when)
    )


@requires_postgres
def test_scan_visits_least_recently_run_cursor_first(session):
    older = "0x" + "a1" * 20  # last scanned long ago → must be visited first
    newer = "0x" + "b2" * 20  # scanned recently → goes to the back
    enroll_event_cursor(session, chain_id=1, event_address=older, topic0=_TOPIC)
    enroll_event_cursor(session, chain_id=1, event_address=newer, topic0=_TOPIC)
    _set_last_run_at(session, older, datetime(2020, 1, 1, tzinfo=timezone.utc))
    _set_last_run_at(session, newer, datetime(2024, 1, 1, tzinfo=timezone.utc))
    session.commit()

    fetcher = _OrderRecordingFetcher()
    scan_enrolled_events(
        session,
        fetchers={1: fetcher},
        head_fetchers={1: _FixedHead()},
        block_hash_fetchers={1: _DeterministicBlockHash()},
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_MAX_SAFE_SPAN,
        max_windows_per_cursor=1,  # one window each, so order == cursor visit order
    )

    assert fetcher.order, "scan never fetched"
    assert fetcher.order[0] == older
    assert fetcher.order.index(older) < fetcher.order.index(newer)


@requires_postgres
def test_caught_up_cursor_stamps_last_run_at(session):
    """A warm cursor updates nothing, so onupdate never fires; last_run_at must be re-stamped or rotation stalls."""
    from db.models import IndexedEventCursor

    addr = "0x" + "c3" * 20
    enroll_event_cursor(session, chain_id=1, event_address=addr, topic0=_TOPIC, start_block=_TARGET)
    session.execute(
        update(IndexedEventCursor)
        .where(func.lower(IndexedEventCursor.event_address) == addr)
        .values(backfill_complete=True, last_run_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    )
    session.commit()
    before = session.execute(
        select(IndexedEventCursor.last_run_at).where(func.lower(IndexedEventCursor.event_address) == addr)
    ).scalar_one()

    fetcher = _RangeCappedFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_MAX_SAFE_SPAN,
        max_windows_per_cursor=5,
    )

    assert not fetcher.requested_spans, "a caught-up cursor must not fetch"
    after = session.execute(
        select(IndexedEventCursor.last_run_at).where(func.lower(IndexedEventCursor.event_address) == addr)
    ).scalar_one()
    assert after > before  # re-stamped on the no-fetch visit so rotation moves it to the back


@requires_postgres
def test_scan_respects_per_pass_window_budget(session):
    """Bounds a cold-start pass so the heartbeat can refresh; un-serviced cursors go first next pass."""
    a = "0x" + "a1" * 20  # oldest → serviced first
    b = "0x" + "b2" * 20
    c = "0x" + "c3" * 20  # newest → deferred past the budget this pass
    for addr in (a, b, c):
        enroll_event_cursor(session, chain_id=1, event_address=addr, topic0=_TOPIC)
    _set_last_run_at(session, a, datetime(2020, 1, 1, tzinfo=timezone.utc))
    _set_last_run_at(session, b, datetime(2021, 1, 1, tzinfo=timezone.utc))
    _set_last_run_at(session, c, datetime(2022, 1, 1, tzinfo=timezone.utc))
    session.commit()

    fetcher = _RangeCappedFetcher()
    fetchers, heads, hashes = _maps(fetcher)

    def run_pass():
        return scan_enrolled_events(
            session,
            fetchers=fetchers,
            head_fetchers=heads,
            block_hash_fetchers=hashes,
            confirmation_depth=_CONFIRMATIONS,
            max_block_span=_MAX_SAFE_SPAN,
            max_windows_per_cursor=2,
            max_windows_per_pass=4,
        )

    summary1 = run_pass()
    assert summary1.windows_scanned == 4  # capped at the budget, not 6 (all three)
    assert summary1.budget_exhausted is True  # stopped on the budget → backfill loop re-runs sooner
    assert _cursor_block(session, a) == 2 * _MAX_SAFE_SPAN
    assert _cursor_block(session, b) == 2 * _MAX_SAFE_SPAN
    assert _cursor_block(session, c) == 0  # never reached this pass

    # The rotation picks up the deferred cursor with no persisted offset.
    summary2 = run_pass()
    assert summary2.windows_scanned == 4
    assert summary2.budget_exhausted is True
    assert _cursor_block(session, c) == 2 * _MAX_SAFE_SPAN


@requires_postgres
def test_cursor_progress_counts_from_table(session):
    """Zero-address rows never emit logs, so they're excluded."""
    from db.models import IndexedEventCursor
    from workers.event_log_indexer import _cursor_progress

    enroll_event_cursor(session, chain_id=1, event_address="0x" + "11" * 20, topic0=_TOPIC, start_block=_TARGET)
    enroll_event_cursor(session, chain_id=1, event_address="0x" + "22" * 20, topic0=_TOPIC)
    enroll_event_cursor(session, chain_id=1, event_address="0x" + "33" * 20, topic0=_TOPIC)
    session.execute(
        update(IndexedEventCursor)
        .where(func.lower(IndexedEventCursor.event_address) == "0x" + "11" * 20)
        .values(backfill_complete=True)
    )
    enroll_event_cursor(session, chain_id=1, event_address="0x" + "00" * 20, topic0=_TOPIC)
    session.commit()

    assert _cursor_progress(session) == (1, 3)


@requires_postgres
def test_budgeted_backfill_is_identical_to_unbudgeted(session):
    """Budgets change when windows run, never which blocks are scanned."""
    from db.models import IndexedEventCursor, IndexedEventLog

    authorities = ["0x" + h * 20 for h in ("a1", "b2", "c3")]

    def drain_to_completion(max_windows_per_cursor: int, max_windows_per_pass: int):
        for addr in authorities:
            enroll_event_cursor(session, chain_id=1, event_address=addr, topic0=_TOPIC)
        session.commit()
        fetcher = _RangeCappedFetcher()
        fetchers, heads, hashes = _maps(fetcher)
        for _ in range(100_000):  # safety bound; the budgeted run really needs ~100 passes
            scan_enrolled_events(
                session,
                fetchers=fetchers,
                head_fetchers=heads,
                block_hash_fetchers=hashes,
                confirmation_depth=_CONFIRMATIONS,
                max_block_span=_MAX_SAFE_SPAN,
                max_windows_per_cursor=max_windows_per_cursor,
                max_windows_per_pass=max_windows_per_pass,
            )
            pending = session.execute(
                select(func.count()).select_from(IndexedEventCursor).where(~IndexedEventCursor.backfill_complete)
            ).scalar_one()
            if pending == 0:
                break
        else:
            raise AssertionError("backfill never completed within the pass bound")
        logs = session.execute(
            select(
                IndexedEventLog.event_address,
                IndexedEventLog.block_number,
                IndexedEventLog.tx_hash,
                IndexedEventLog.log_index,
            ).order_by(IndexedEventLog.event_address, IndexedEventLog.block_number, IndexedEventLog.log_index)
        ).all()
        cursors = session.execute(
            select(
                IndexedEventCursor.event_address,
                IndexedEventCursor.last_indexed_block,
                IndexedEventCursor.backfill_complete,
            ).order_by(IndexedEventCursor.event_address)
        ).all()
        return logs, cursors

    unbudgeted_logs, unbudgeted_cursors = drain_to_completion(10_000, 10_000)

    session.execute(delete(IndexedEventLog))
    session.execute(delete(IndexedEventCursor))
    session.commit()
    budgeted_logs, budgeted_cursors = drain_to_completion(max_windows_per_cursor=2, max_windows_per_pass=4)

    # Catches a bug that is wrong identically in both runs.
    assert len(unbudgeted_logs) == len(authorities) * (_TARGET // _DENSITY)
    assert budgeted_logs == unbudgeted_logs  # byte-identical index: no skipped/duplicated event
    assert budgeted_cursors == unbudgeted_cursors
    for _addr, last_block, complete in budgeted_cursors:
        assert complete is True  # no cursor starved short of completion
        assert last_block == _TARGET  # backfill_complete only at the confirmed head, never premature


@requires_postgres
def test_many_warm_groups_do_not_consume_windows_or_trigger_busy_cadence(session):
    for i in range(182):
        enroll_event_cursor(session, chain_id=1, event_address=f"0x{i + 1:040x}", topic0=_TOPIC, start_block=_TARGET)
    session.commit()
    fetcher = _RangeCappedFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    summary = scan_enrolled_events(
        session, fetchers=fetchers, head_fetchers=heads, block_hash_fetchers=hashes, max_windows_per_pass=100
    )
    assert summary.windows_scanned == 0
    assert summary.caught_up_cursors == 182
    assert not summary.budget_exhausted
    assert not fetcher.requested_spans


@requires_postgres
def test_warm_sweep_covers_more_than_backfill_budget_without_busy_repeats(session):
    from db.models import IndexedEventCursor

    addresses = [f"0x{i + 1:040x}" for i in range(182)]
    for address in addresses:
        enroll_event_cursor(session, chain_id=1, event_address=address, topic0=_TOPIC, start_block=_TARGET - 10)
    session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    cold_address = "0x" + "ff" * 20
    enroll_event_cursor(session, chain_id=1, event_address=cold_address, topic0=_TOPIC)
    session.commit()

    fetcher = _RangeCappedFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    warm = scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        scan_mode="warm",
        max_windows_per_pass=100,
    )
    # Batched: ceil(182 / 50) requests cover every warm group.
    assert warm.windows_scanned == 4
    assert not warm.budget_exhausted
    assert all(_cursor_block(session, address) == _TARGET for address in addresses)
    assert _cursor_block(session, cold_address) == 0

    cold = scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        scan_mode="cold",
        max_block_span=_MAX_SAFE_SPAN,
        max_windows_per_cursor=2,
        max_windows_per_pass=2,
    )
    assert cold.windows_scanned == 2
    assert cold.budget_exhausted
    assert _cursor_block(session, cold_address) == 2 * _MAX_SAFE_SPAN
    assert len(fetcher.requested_spans) == 6


@requires_postgres
def test_exact_budget_finishing_last_cold_group_is_not_busy(session):
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC, start_block=_TARGET - 10)
    session.commit()
    fetcher = _RangeCappedFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    summary = scan_enrolled_events(
        session, fetchers=fetchers, head_fetchers=heads, block_hash_fetchers=hashes, max_windows_per_pass=1
    )
    assert summary.windows_scanned == 1
    assert not summary.budget_exhausted


@requires_postgres
def test_shutdown_stops_after_current_page_and_preserves_committed_progress(session):
    from threading import Event

    stop = Event()
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC)
    session.commit()

    class StopAfterWindow(_RangeCappedFetcher):
        def fetch_logs(self, **kwargs):
            logs = super().fetch_logs(**kwargs)
            stop.set()
            return logs

    fetcher = StopAfterWindow()
    fetchers, heads, hashes = _maps(fetcher)
    summary = scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        max_block_span=_MAX_SAFE_SPAN,
        max_windows_per_cursor=100,
        stop_event=stop,
    )
    assert summary.windows_scanned == 1
    assert len(fetcher.requested_spans) == 1
    session.rollback()
    saved_block = _cursor_block(session, _AUTHORITY)
    assert 0 < saved_block < _TARGET
    saved_logs = _log_count(session, _AUTHORITY)
    assert saved_logs > 0

    # A new process resumes from the committed cursor without losing or duplicating the in-flight window.
    normal, heads, hashes = _maps(_RangeCappedFetcher())
    scan_enrolled_events(
        session,
        fetchers=normal,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        max_block_span=_MAX_SAFE_SPAN,
        max_windows_per_pass=1,
    )
    assert _cursor_block(session, _AUTHORITY) > saved_block
    assert _log_count(session, _AUTHORITY) > saved_logs


@requires_postgres
def test_shutdown_during_rpc_timeout_does_not_visit_remaining_groups(session):
    from threading import Event

    stop = Event()
    for i in range(10):
        enroll_event_cursor(session, chain_id=1, event_address=f"0x{i + 1:040x}", topic0=_TOPIC)
    session.commit()

    class TimeoutHead:
        calls = 0

        def head_block(self):
            self.calls += 1
            stop.set()
            raise TimeoutError("RPC unavailable during shutdown")

    head = TimeoutHead()
    summary = scan_enrolled_events(
        session,
        fetchers={1: _RangeCappedFetcher()},
        head_fetchers={1: head},
        block_hash_fetchers={1: _DeterministicBlockHash()},
        stop_event=stop,
    )
    assert head.calls == 1
    assert summary.failed_groups == 1 and summary.windows_scanned == 0
    assert _log_count(session, "0x" + "00" * 19 + "01") == 0


@requires_postgres
def test_time_budgeted_backfill_is_identical_to_unbudgeted(session, monkeypatch):
    """The group and pass time budgets change only when pages run, never which blocks are indexed."""
    import workers.event_log_indexer as indexer
    from db.models import IndexedEventCursor, IndexedEventLog

    authorities = ["0x" + h * 20 for h in ("a1", "b2", "c3")]

    def drain(clock_step_s: float) -> tuple[list, list, int]:
        now = [0.0]

        def fake_clock() -> float:
            now[0] += clock_step_s
            return now[0]

        monkeypatch.setattr(indexer, "_monotonic", fake_clock)
        for addr in authorities:
            enroll_event_cursor(session, chain_id=1, event_address=addr, topic0=_TOPIC, start_block=_TARGET - 200_000)
        session.commit()
        fetcher = _RangeCappedFetcher()
        fetchers, heads, hashes = _maps(fetcher)
        passes = 0
        while passes < 10_000:
            passes += 1
            scan_enrolled_events(
                session,
                fetchers=fetchers,
                head_fetchers=heads,
                block_hash_fetchers=hashes,
                max_block_span=_MAX_SAFE_SPAN,
                max_windows_per_cursor=10_000,
                max_windows_per_pass=10_000,
                group_budget_s=30,
                pass_budget_s=120,
            )
            pending = session.execute(
                select(func.count()).select_from(IndexedEventCursor).where(~IndexedEventCursor.backfill_complete)
            ).scalar_one()
            if pending == 0:
                break
        logs = session.execute(
            select(IndexedEventLog.event_address, IndexedEventLog.block_number, IndexedEventLog.tx_hash).order_by(
                IndexedEventLog.event_address, IndexedEventLog.block_number
            )
        ).all()
        cursors = session.execute(
            select(
                IndexedEventCursor.event_address,
                IndexedEventCursor.last_indexed_block,
                IndexedEventCursor.backfill_complete,
                IndexedEventCursor.max_window_log_count,
            ).order_by(IndexedEventCursor.event_address)
        ).all()
        session.execute(delete(IndexedEventLog))
        session.execute(delete(IndexedEventCursor))
        session.commit()
        return logs, cursors, passes

    unbudgeted_logs, unbudgeted_cursors, one_pass = drain(clock_step_s=0.0)
    budgeted_logs, budgeted_cursors, many_passes = drain(clock_step_s=11.0)

    assert one_pass == 1
    assert many_passes > 3  # the budgets really cut visits and passes short
    assert len(unbudgeted_logs) == len(authorities) * len(range(_TARGET - 199_900, _TARGET + 1, _DENSITY))
    assert budgeted_logs == unbudgeted_logs
    assert budgeted_cursors == unbudgeted_cursors
