"""Real PostgreSQL triggers: bounded index writes, admission, and crash recovery."""

from concurrent.futures import ThreadPoolExecutor
from threading import Condition, Event
from time import monotonic

import pytest
from sqlalchemy import event, func, select, text, update
from sqlalchemy.orm import Session

from db.models import IndexedEventCursor, IndexedEventLog, IndexerWork, Job
from db.queue.jobs import create_job
from services.resolution.repos.event_logs_rpc import FetchedEventLog, FetchWindowStat
from tests.conftest import requires_postgres
from workers import event_log_indexer as indexer

pytestmark = requires_postgres
ADDRESS = "0x" + "a9" * 20
TOPICS = ["0x" + f"{i:064x}" for i in (1, 2, 3)]


def make_log(block, topic=TOPICS[0], number=0):
    return FetchedEventLog(
        tx_hash=(block * 1_000_000 + number).to_bytes(32, "big"),
        log_index=number,
        block_number=block,
        block_hash=block.to_bytes(32, "big"),
        transaction_index=0,
        topics=[topic],
        data_words=["0x" + "00" * 32],
    )


class Fetcher:
    def __init__(self, logs):
        self.logs = logs
        self.calls = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block, window_stats=None):
        self.calls.append((from_block, to_block))
        logs = [log for log in self.logs if from_block <= log.block_number <= to_block and log.topics[0] in topics]
        if window_stats is not None:
            window_stats.append(FetchWindowStat(from_block, to_block, len(logs), 1_000_000))
        return logs


class Head:
    def __init__(self, target):
        self.target = target

    def head_block(self):
        return self.target + 12

    def block_hash(self, block_number: int) -> bytes:
        return block_number.to_bytes(32, "big")


def seed(session, topics=TOPICS):
    for topic in topics:
        indexer.enroll_event_cursor(session, chain_id=1, event_address=ADDRESS, topic0=topic)
    session.commit()


def scan(session, fetcher, target=6, **kwargs):
    return indexer.scan_enrolled_events(
        session,
        fetchers={1: fetcher},
        head_fetchers={1: Head(target)},
        block_hash_fetchers={1: Head(target)},
        max_windows_per_cursor=1,
        **kwargs,
    )


def steps(session, fetcher, target=6, **kwargs):
    return indexer.index_event_group_steps(
        session,
        chain_id=1,
        event_address=ADDRESS,
        topics=TOPICS,
        fetcher=fetcher,
        target=target,
        block_hash_fetcher=Head(target),
        **kwargs,
    )


def positions(session):
    session.expire_all()
    return session.scalars(select(IndexedEventCursor).order_by(IndexedEventCursor.topic0)).all()


def count_logs(session):
    return session.scalar(select(func.count()).select_from(IndexedEventLog))


def test_rollback_preserves_complete_prefix_then_restart_and_replay(db_session, monkeypatch):
    seed(db_session)
    logs = [make_log(block, topic) for block in range(1, 7) for topic in TOPICS]
    fetcher = Fetcher(logs)
    original = indexer._bulk_insert_logs

    def fail_second_prefix(session, chain, address, topic, logs, **kwargs):
        inserted = original(session, chain, address, topic, logs, **kwargs)
        if any(log.block_number == 3 for log in logs):
            raise RuntimeError("database write failed after INSERT")
        return inserted

    monkeypatch.setattr(indexer, "_bulk_insert_logs", fail_second_prefix)
    result = scan(db_session, fetcher, write_max_rows=6)
    assert result.failed_groups == 1
    assert result.inserted == 6
    assert count_logs(db_session) == 6
    for cursor in positions(db_session):
        assert cursor.last_indexed_block == 2
        assert not cursor.backfill_complete
        assert cursor.last_indexed_block_hash is None
        assert cursor.max_window_log_count == 18  # original page, not the six-row write
        assert cursor.window_stats_cap == 1_000_000
    work = db_session.get(IndexerWork, ("reconcile", "1"))
    assert work is not None and work.dirty
    # Each topic INSERT invalidates once; the failed prefix's invalidation rolled back.
    assert work.revision == 6  # three enrollment signals + three committed INSERTs

    monkeypatch.setattr(indexer, "_bulk_insert_logs", original)
    result = scan(db_session, fetcher, write_max_rows=6)
    assert result.failed_groups == 0
    assert result.inserted == 12
    assert fetcher.calls == [(1, 6), (3, 6)]
    assert count_logs(db_session) == 18
    assert all(c.last_indexed_block == 6 and c.backfill_complete for c in positions(db_session))

    # Retrying an already persisted range cannot duplicate events.
    db_session.execute(update(IndexedEventCursor).values(last_indexed_block=0, last_indexed_block_hash=None))
    db_session.commit()
    assert scan(db_session, fetcher, write_max_rows=6).inserted == 0
    assert count_logs(db_session) == 18


def test_mixed_frontiers_and_empty_topics_advance_atomically(db_session):
    seed(db_session)
    db_session.execute(
        update(IndexedEventCursor).where(IndexedEventCursor.topic0 == TOPICS[1]).values(last_indexed_block=4)
    )
    db_session.commit()
    logs = [make_log(b, TOPICS[0]) for b in (1, 2, 5)] + [make_log(5, TOPICS[1])]
    fetcher = Fetcher(logs)
    iterator = steps(db_session, fetcher, write_max_rows=2)
    first = next(iterator)
    db_session.commit()
    assert first.scanned_to == 4  # includes the empty gap before the next event
    assert [c.last_indexed_block for c in positions(db_session)] == [4, 4, 4]
    assert not any(c.backfill_complete for c in positions(db_session))
    for _ in iterator:
        db_session.commit()
    assert count_logs(db_session) == 4
    assert [c.last_indexed_block for c in positions(db_session)] == [6, 6, 6]
    assert fetcher.calls == [(1, 6)]


@pytest.mark.parametrize("changed_to", [0, 5])
def test_concurrent_rewind_or_advance_discards_retained_window(db_session, changed_to):
    seed(db_session)
    iterator = steps(db_session, Fetcher([make_log(b) for b in range(1, 7)]), write_max_rows=2)
    next(iterator)
    db_session.commit()
    with Session(db_session.get_bind()) as other:
        other.execute(update(IndexedEventCursor).values(last_indexed_block=changed_to, last_indexed_block_hash=None))
        other.commit()
    with pytest.raises(RuntimeError, match="refetch required"):
        next(iterator)
    db_session.rollback()
    assert count_logs(db_session) == 2
    assert all(c.last_indexed_block == changed_to for c in positions(db_session))


def test_shutdown_keeps_only_committed_prefix(db_session):
    seed(db_session)
    stop = Event()

    def after_commit(session):
        stop.set()

    event.listen(db_session, "after_commit", after_commit)
    try:
        result = scan(db_session, Fetcher([make_log(b) for b in range(1, 7)]), write_max_rows=2, stop_event=stop)
    finally:
        event.remove(db_session, "after_commit", after_commit)
    assert result.inserted == 2
    assert count_logs(db_session) == 2
    assert all(c.last_indexed_block == 2 and not c.backfill_complete for c in positions(db_session))


def test_reorg_and_final_hash_reads_do_not_hold_reconciliation_lock(db_session):
    seed(db_session)
    scan(db_session, Fetcher([make_log(b, t) for b in range(1, 7) for t in TOPICS]))
    db_session.execute(update(IndexedEventCursor).values(last_indexed_block_hash=b"old"))
    db_session.commit()
    submitted = []

    def submit_during_rpc():
        with Session(db_session.get_bind()) as other:
            other.execute(text("SET LOCAL lock_timeout = '250ms'"))
            submitted.append(str(create_job(other, {"address": ADDRESS}).id))

    class ReorgHashes:
        def block_hash(self, block_number: int) -> bytes:
            submit_during_rpc()
            return block_number.to_bytes(32, "big")

    class ReorgFetcher(Fetcher):
        def fetch_logs(self, **kwargs):
            submit_during_rpc()
            return super().fetch_logs(**kwargs)

    fetcher = ReorgFetcher([make_log(b, t, number=1) for b in range(1, 9) for t in TOPICS])
    iterator = indexer.index_event_group_steps(
        db_session,
        chain_id=1,
        event_address=ADDRESS,
        topics=TOPICS,
        fetcher=fetcher,
        target=8,
        block_hash_fetcher=ReorgHashes(),
        confirmation_depth=2,
        write_max_rows=3,
    )
    for _ in iterator:
        db_session.commit()
    assert fetcher.calls == [(5, 8)]
    assert len(submitted) == 4  # old stamp, rewind stamp, log fetch, final stamp
    assert count_logs(db_session) == 24
    assert all(c.last_indexed_block == 8 and c.backfill_complete for c in positions(db_session))
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(IndexedEventLog)
            .where(
                IndexedEventLog.block_number > 4,
                IndexedEventLog.log_index == 0,
            )
        )
        == 0
    )


def test_incident_sized_backfill_allows_repeated_concurrent_submissions(db_session):
    """The incident's 252,760 rows used to share one transaction (254 INSERTs)."""
    seed(db_session)
    counts = (35_240, 183_634, 33_886)
    logs = []
    for topic, count in zip(TOPICS, counts):
        logs.extend(make_log(i + 1, topic) for i in range(count))
    fetcher = Fetcher(logs)
    engine = db_session.get_bind()
    first_insert = Event()
    done = Event()
    lock_started = None
    lock_durations = []
    progress = Condition()

    def after_insert(conn, cursor, statement, parameters, context, executemany):
        nonlocal lock_started
        if statement.startswith("INSERT INTO indexed_event_logs"):
            if lock_started is None:
                lock_started = monotonic()
            first_insert.set()

    def after_commit(session):
        nonlocal lock_started
        if lock_started is not None:
            with progress:
                lock_durations.append(monotonic() - lock_started)
                lock_started = None
                progress.notify_all()

    def submit_repeatedly():
        assert first_insert.wait(30)
        outcomes = []
        for attempt in range(24):
            # Sample throughout the backfill, not just the initial lock release.
            # Only submitters wait; the writer runs without artificial delays.
            with progress:
                assert progress.wait_for(lambda: len(lock_durations) >= attempt * 2 or done.is_set(), timeout=30)
            with Session(engine) as session:
                session.execute(text("SET LOCAL lock_timeout = '10s'"))
                start = monotonic()
                job = create_job(session, {"address": ADDRESS})
                outcomes.append((str(job.id), monotonic() - start, not done.is_set(), len(lock_durations)))
        return outcomes

    event.listen(engine, "after_cursor_execute", after_insert)
    event.listen(db_session, "after_commit", after_commit)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            submissions = [pool.submit(submit_repeatedly) for _ in range(2)]
            try:
                result = scan(db_session, fetcher, target=200_000)
            finally:
                done.set()
                first_insert.set()
                with progress:
                    progress.notify_all()
            outcomes = [outcome for future in submissions for outcome in future.result(timeout=30)]
    finally:
        event.remove(engine, "after_cursor_execute", after_insert)
        event.remove(db_session, "after_commit", after_commit)
    assert result.failed_groups == 0
    assert result.inserted == sum(counts)
    assert len(fetcher.calls) == 1
    assert count_logs(db_session) == sum(counts)
    assert len({job_id for job_id, _, _, _ in outcomes}) == 48
    assert db_session.scalar(select(func.count()).select_from(Job)) == 48
    assert sum(during_scan for _, _, during_scan, _ in outcomes) >= 40
    assert len({prefix for _, _, _, prefix in outcomes}) >= 20
    assert max(elapsed for _, elapsed, _, _ in outcomes) < 10
    sizes = db_session.execute(text("SELECT count(*) FROM indexed_event_logs GROUP BY xmin")).scalars().all()
    assert len(sizes) > 50
    assert max(sizes) <= indexer.DEFAULT_WRITE_MAX_ROWS
    assert all(c.last_indexed_block == 200_000 and c.backfill_complete for c in positions(db_session))
    print(
        f"\n252760 rows: {len(sizes)} commits; max lock interval after first INSERT {max(lock_durations):.3f}s; "
        f"48 submissions, max {max(elapsed for _, elapsed, _, _ in outcomes):.3f}s"
    )


def test_reorg_partial_commit_failure_resumes_without_restoring_orphaned_logs(db_session, monkeypatch):
    seed(db_session)
    scan(db_session, Fetcher([make_log(b, t) for b in range(1, 7) for t in TOPICS]))
    db_session.execute(update(IndexedEventCursor).values(last_indexed_block_hash=b"old"))
    db_session.commit()
    replacement = Fetcher([make_log(b, t, number=1) for b in range(5, 9) for t in TOPICS])
    original = indexer._bulk_insert_logs

    def fail_at_six(session, chain, address, topic, logs, **kwargs):
        inserted = original(session, chain, address, topic, logs, **kwargs)
        if any(log.block_number == 6 for log in logs):
            raise RuntimeError("write failed after first reorg prefix committed")
        return inserted

    monkeypatch.setattr(indexer, "_bulk_insert_logs", fail_at_six)
    with pytest.raises(RuntimeError, match="first reorg prefix"):
        for _ in steps(db_session, replacement, target=8, confirmation_depth=2, write_max_rows=3):
            db_session.commit()
    db_session.rollback()
    assert count_logs(db_session) == 15  # old 1..4 plus replacement 5; orphaned 6 stays deleted
    assert all(c.last_indexed_block == 5 and not c.backfill_complete for c in positions(db_session))
    assert db_session.scalar(select(func.max(IndexedEventLog.block_number))) == 5
    monkeypatch.setattr(indexer, "_bulk_insert_logs", original)
    result = scan(db_session, replacement, target=8, write_max_rows=3)
    assert result.failed_groups == 0 and result.inserted == 9
    assert replacement.calls == [(5, 8), (6, 8)]
    assert count_logs(db_session) == 24
    assert all(c.last_indexed_block == 8 and c.backfill_complete for c in positions(db_session))
