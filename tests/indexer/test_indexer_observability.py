"""What the indexer reports while it runs: the per-visit INFO line, mid-pass progress, and warm lag."""

from __future__ import annotations

import logging

from sqlalchemy import update

from db.models import IndexedEventCursor
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import requires_postgres
from workers.event_log_indexer import ScanSummary, enroll_event_cursor, scan_enrolled_events

pytestmark = requires_postgres

_TOPIC = "0x" + "ab" * 32
_HEAD = 100_012
_TARGET = 100_000


class _SparseFetcher:
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
