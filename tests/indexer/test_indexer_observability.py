"""What the indexer reports while it runs: the per-visit INFO line, mid-pass progress, and warm lag."""

from __future__ import annotations

import logging

from sqlalchemy import update

from db.models import IndexedEventCursor
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import requires_postgres
from tests.support.one_page_fetch import OnePagePerFetch
from workers.event_log_indexer import ScanSummary, enroll_event_cursor, scan_enrolled_events

pytestmark = requires_postgres

_TOPIC = "0x" + "ab" * 32
_HEAD = 100_012
_TARGET = 100_000


class _SparseFetcher(OnePagePerFetch):
    def fetch_logs(self, *, event_address, topics, from_block, to_block, window_stats=None):
        return [
            FetchedEventLog(
                tx_hash=block.to_bytes(32, "big"),
                log_index=0,
                block_number=block,
                block_hash=block.to_bytes(32, "big"),
                transaction_index=0,
                topics=[topics[0]],
                data_words=[],
            )
            for block in range(((from_block + 999) // 1000) * 1000, to_block + 1, 1000)
        ]


class _Head:
    def head_block(self) -> int:
        return _HEAD

    def block_hash(self, block_number: int) -> bytes:
        return block_number.to_bytes(32, "big")


def _scan(session, **kwargs) -> ScanSummary:
    return scan_enrolled_events(
        session,
        fetchers={1: _SparseFetcher()},
        head_fetchers={1: _Head()},
        block_hash_fetchers={1: _Head()},
        max_block_span=10_000,
        **kwargs,
    )


def test_cold_visit_logs_one_info_line_with_its_range_and_counts(db_session, caplog):
    address = "0x" + "c1" * 20
    enroll_event_cursor(db_session, chain_id=1, event_address=address, topic0=_TOPIC)
    db_session.commit()

    with caplog.at_level(logging.INFO, logger="workers.event_log_indexer"):
        _scan(db_session, scan_mode="cold", max_windows_per_cursor=3)

    (line,) = [r for r in caplog.records if r.getMessage() == "event indexer group visit"]
    fields = line.__dict__
    assert fields["event_address"] == address
    assert (fields["scanned_from"], fields["scanned_to"]) == (1, 30_000)
    assert fields["pages"] == 3
    assert fields["logs"] == fields["inserted"] == 30
    assert fields["duration_s"] >= 0
    assert "process_rss_bytes" in fields


def test_progress_is_published_after_every_commit(db_session):
    address = "0x" + "c2" * 20
    enroll_event_cursor(db_session, chain_id=1, event_address=address, topic0=_TOPIC)
    db_session.commit()
    published: list[ScanSummary] = []

    final = _scan(db_session, scan_mode="cold", max_windows_per_cursor=4, on_commit=published.append)

    assert [p.inserted for p in published] == [10, 20, 30, 40]
    assert published[-1].windows_scanned == final.windows_scanned == 4


def test_warm_sweep_reports_the_largest_remaining_lag_per_chain(db_session):
    caught_up = "0x" + "c3" * 20
    lagging = "0x" + "c4" * 20
    for address in (caught_up, lagging):
        enroll_event_cursor(db_session, chain_id=1, event_address=address, topic0=_TOPIC, start_block=_TARGET - 50)
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    db_session.commit()

    class _FailsFor(_SparseFetcher):
        def fetch_logs(self, *, event_address, **kwargs):
            if event_address == lagging:
                raise RuntimeError("upstream down")
            return super().fetch_logs(event_address=event_address, **kwargs)

    summary = scan_enrolled_events(
        db_session,
        fetchers={1: _FailsFor()},
        head_fetchers={1: _Head()},
        block_hash_fetchers={1: _Head()},
        scan_mode="warm",
    )

    assert summary.warm_max_lag_blocks == {1: 50}


def test_the_cold_pass_line_reports_the_table_triad_not_just_the_groups_it_visited(db_session, monkeypatch):
    import threading

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import workers.event_log_indexer as indexer
    from services.resolution import indexer_scheduler
    from tests.conftest import DATABASE_URL

    for index in range(2):
        enroll_event_cursor(
            db_session, chain_id=1, event_address=f"0x{0xE600 + index:040x}", topic0=_TOPIC, start_block=_TARGET
        )
    db_session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    enroll_event_cursor(
        db_session, chain_id=1, event_address=f"0x{0xE6FF:040x}", topic0=_TOPIC, start_block=_TARGET - 5
    )
    db_session.commit()

    engine = create_engine(DATABASE_URL)
    monkeypatch.setattr(indexer, "SessionLocal", sessionmaker(bind=engine, expire_on_commit=False))
    monkeypatch.setattr(indexer_scheduler, "drain_enrollment", lambda _s, **_k: 0)
    monkeypatch.setattr(indexer_scheduler, "drain_reconciliation", lambda _s, **_k: (0, 0))
    monkeypatch.setattr(indexer, "record_heartbeat", lambda *_a, **_k: None)
    stop = threading.Event()
    cold_passes: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if record.getMessage() == "event log indexer pass complete" and getattr(record, "scan_mode", "") == "cold":
                cold_passes.append(record)
                stop.set()

    handler = _Capture()
    indexer.logger.addHandler(handler)
    level = indexer.logger.level
    indexer.logger.setLevel(logging.INFO)
    timer = threading.Timer(30, stop.set)
    timer.start()
    try:
        indexer.run_event_log_indexer_loop(
            fetchers={1: _SparseFetcher()},
            head_fetchers={1: _Head()},
            block_hash_fetchers={1: _Head()},
            interval=0.05,
            stop_event=stop,
        )
    finally:
        timer.cancel()
        indexer.logger.removeHandler(handler)
        indexer.logger.setLevel(level)
        engine.dispose()

    assert cold_passes, "no cold pass completed"
    record = cold_passes[0]
    assert getattr(record, "visited_caught_up_cursors") == 1
    assert tuple(getattr(record, f) for f in ("caught_up_cursors", "total_cursors", "pending_cursors")) == (3, 3, 0)
