"""Regression: the event-log indexer must backfill in bounded block windows.

Production incident (PR #104 follow-up): a freshly-enrolled cursor's gap to head
is ~25M blocks. ``index_event_log_step`` scanned the whole gap in one shot and
``_bulk_insert_logs`` inserted the entire result in a single statement. On a
high-volume authority (the LayerZero endpoint) that one insert dropped the Neon
connection — ``psycopg2.OperationalError: SSL connection has been closed
unexpectedly`` — so the cursor never left block 0 and the Solmate role events
were never indexed, which left ``SolmateRolesAuthorityAdapter`` permanently
failing closed.

These tests stand in for that blowup with a fetcher that *rejects* any request
spanning more than a safe number of blocks (the real RPC/insert ceiling). The
fix has to hand the fetcher only bounded windows and still backfill the full
history; the companion test pins the old single-shot behaviour so a revert
fails here instead of silently in prod.
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

# A single eth_getLogs / bulk insert blows up past this many blocks in one shot.
# The indexer must never hand the fetcher a wider window than this.
_MAX_SAFE_SPAN = 10_000
_HEAD = 1_000_000
_CONFIRMATIONS = 12
_TARGET = _HEAD - _CONFIRMATIONS  # 999_988
_DENSITY = 100  # one synthetic role event every 100 blocks
_AUTHORITY = "0x" + "39" * 20  # stand-in Solmate RolesAuthority
_TOPIC = "0x" + "ab" * 32  # stand-in RoleCapabilityUpdated topic


class _RangeCappedFetcher:
    """Emits one log per ``_DENSITY`` blocks but raises on an oversized span,
    the way mainnet RPCs / a giant INSERT do. Records every span requested."""

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
    # Observed hash == stored hash (block number as bytes), so the reorg guard
    # never spuriously rewinds during a backfill.
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
    """The fix: bounded windows backfill the whole gap without ever asking the
    fetcher for an oversized range."""
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

    # Fix engaged: every window the fetcher saw was within the safe cap. The old
    # single-shot fetch would have requested the full ~1M-block gap here.
    assert fetcher.requested_spans, "indexer never called the fetcher"
    assert max(fetcher.requested_spans) <= _MAX_SAFE_SPAN, (
        f"indexer requested a {max(fetcher.requested_spans)}-block window > {_MAX_SAFE_SPAN}; "
        "the unbounded full-range fetch is what crashed the DB connection"
    )

    # And it actually backfilled the whole history: cursor at head, every event in.
    expected_logs = _TARGET // _DENSITY  # 9_999
    assert _cursor_block(session, _AUTHORITY) == _TARGET
    assert _log_count(session, _AUTHORITY) == expected_logs
    assert summary.inserted == expected_logs
    assert summary.budget_exhausted is False  # drained within budget → loop returns to the poll interval


@requires_postgres
def test_unbounded_span_wedges_the_cursor_at_zero(session):
    """The bug, pinned: without the per-step span cap the indexer asks for the
    whole gap, the fetch blows up, and the cursor is wedged at block 0 with no
    events indexed — exactly the prod symptom."""
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC)
    session.commit()

    fetcher = _RangeCappedFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    # max_block_span wider than the whole gap == the old single-shot behaviour.
    summary = scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_HEAD * 2,
        max_windows_per_cursor=500,
    )

    assert max(fetcher.requested_spans) > _MAX_SAFE_SPAN  # it asked for an oversized range
    assert summary.inserted == 0
    assert _cursor_block(session, _AUTHORITY) == 0  # wedged, never advanced
    assert _log_count(session, _AUTHORITY) == 0


class _OrderRecordingFetcher:
    """Records the order of event addresses the scan asks it to fetch."""

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
    # Explicit timestamp via Core update: an explicit value in the SET clause
    # suppresses the column's onupdate=func.now(), and a literal avoids the
    # transaction-constant now() collapsing distinct rows to the same instant.
    from db.models import IndexedEventCursor

    session.execute(
        update(IndexedEventCursor)
        .where(func.lower(IndexedEventCursor.event_address) == address.lower())
        .values(last_run_at=when)
    )


@requires_postgres
def test_scan_visits_least_recently_run_cursor_first(session):
    """Fair rotation: cursors are scanned least-recently-run first, so a
    high-volume authority that was just scanned can't keep jumping ahead of one
    that's been waiting. Without this a single hog cursor monopolizes successive
    passes and a freshly-enrolled deferred authority starves behind hours of
    someone else's backfill."""
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
    """An already-warm cursor returns caught_up WITHOUT fetching and WITHOUT
    flipping backfill_complete — so nothing else marks the row dirty and the
    column's onupdate never fires. The scan must still re-stamp last_run_at
    explicitly, else the warm cursor's stale timestamp keeps re-sorting it ahead
    of cold cursors that actually need windows, defeating the rotation."""
    from db.models import IndexedEventCursor

    addr = "0x" + "c3" * 20
    enroll_event_cursor(session, chain_id=1, event_address=addr, topic0=_TOPIC, start_block=_TARGET)
    # Already backfilled and stamped in the past: only an explicit re-stamp on the
    # no-fetch caught_up visit can advance it (backfill_complete True→True is a
    # no-op update).
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
    """The per-pass global window budget bounds total windows scanned across all
    cursors, so a cold-start pass returns promptly instead of walking every
    cursor to completion. Un-serviced cursors keep their older last_run_at and
    are picked up first on the next pass (round-robin via the rotation), so none
    starves. Without the budget one pass would scan all three cold cursors here
    (6 windows); with it the pass stops at the budget and the third cursor waits.
    This is what lets the fleet heartbeat refresh mid-backfill instead of looking
    stalled behind one ~tens-of-minutes pass."""
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
        # budget 4 = two cursors × 2 windows
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

    # Pass 1: a, b advance two windows each; c is deferred past the budget.
    summary1 = run_pass()
    assert summary1.windows_scanned == 4  # capped at the budget, not 6 (all three)
    assert summary1.budget_exhausted is True  # stopped on the budget → backfill loop re-runs sooner
    assert _cursor_block(session, a) == 2 * _MAX_SAFE_SPAN
    assert _cursor_block(session, b) == 2 * _MAX_SAFE_SPAN
    assert _cursor_block(session, c) == 0  # never reached this pass

    # Pass 2: a, b were just stamped, so c is now least-recently-run → serviced
    # first. The rotation picks up the deferred cursor with no persisted offset.
    summary2 = run_pass()
    assert summary2.windows_scanned == 4
    assert summary2.budget_exhausted is True
    assert _cursor_block(session, c) == 2 * _MAX_SAFE_SPAN


@requires_postgres
def test_cursor_progress_counts_from_table(session):
    """``_cursor_progress`` reads the live (caught_up, total) straight from the
    table — this is what the heartbeat folds in so the fleet view reflects an
    in-progress backfill, not the backfill thread's stale last-completed summary.
    Zero-address rows (which can never emit logs) are excluded, matching the
    enroll-time guard."""
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
    # A zero-address cursor must not inflate the total.
    enroll_event_cursor(session, chain_id=1, event_address="0x" + "00" * 20, topic0=_TOPIC)
    session.commit()

    assert _cursor_progress(session) == (1, 3)


@requires_postgres
def test_budgeted_backfill_is_identical_to_unbudgeted(session):
    """Accuracy guard (parity): chunking the backfill across many small budgeted
    passes must produce the EXACT same durable index as a single unbudgeted pass —
    identical logs, identical final cursor state, every cursor caught up to head.

    The per-pass / per-cursor budget changes only WHEN windows run, never WHICH
    blocks are scanned (contiguous resume from last_indexed_block + on-conflict
    dedup), so the rotation can neither skip an event, duplicate one, mark a cursor
    complete short of head, nor starve one. A regression that broke any of those —
    e.g. advancing the cursor past an unscanned window, or a budget that drops a
    cursor permanently — diverges here."""
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

    # One unbudgeted pass: caps far exceed the work, so it drains in a single pass.
    unbudgeted_logs, unbudgeted_cursors = drain_to_completion(10_000, 10_000)

    # Reset, then re-run with tiny caps that force ~100 budgeted passes + rotation.
    session.execute(delete(IndexedEventLog))
    session.execute(delete(IndexedEventCursor))
    session.commit()
    budgeted_logs, budgeted_cursors = drain_to_completion(max_windows_per_cursor=2, max_windows_per_pass=4)

    # Absolute correctness (catches a bug wrong *identically* in both runs): one
    # log every _DENSITY blocks over (0, _TARGET], per authority.
    assert len(unbudgeted_logs) == len(authorities) * (_TARGET // _DENSITY)
    assert budgeted_logs == unbudgeted_logs  # byte-identical index: no skipped/duplicated event
    assert budgeted_cursors == unbudgeted_cursors
    for _addr, last_block, complete in budgeted_cursors:
        assert complete is True  # no cursor starved short of completion
        assert last_block == _TARGET  # backfill_complete only at the confirmed head, never premature
