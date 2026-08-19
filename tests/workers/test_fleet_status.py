"""Tests for the fleet / process-status backend.

Covers ``db.queue.record_heartbeat`` (upsert + best-effort),
``services.aggregations.build_fleet_status`` (liveness + work breakdown),
the ``/api/fleet`` endpoint, and the daemon-loop heartbeat wiring for the
reconciler and event-log indexer.
"""

from __future__ import annotations

import sys
import time
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    IndexedEventCursor,
    MonitoredContract,
    Protocol,
    WorkerHeartbeat,
)
from db.queue import (
    HEARTBEAT_AUDIT_SCOPE,
    HEARTBEAT_AUDIT_TEXT,
    HEARTBEAT_COVERAGE_VERIFY,
    HEARTBEAT_ENROLLMENT_RECONCILER,
    HEARTBEAT_EVENT_INDEXER,
    record_heartbeat,
)
from services.aggregations import build_fleet_status
from tests.conftest import SessionFactory, requires_postgres

_KNOWN_PROCESSES = {
    "coverage_verify",
    "audit_text_extraction",
    "audit_scope_extraction",
    "event_log_indexer",
    "enrollment_reconciler",
    "protocol_scanner",
    "protocol_poller",
    "protocol_tvl",
    "protocol_restaking",
    "role_holder_plane",
    "protocol_score",
    "ops_alerter",
}


def _addr(n: int) -> str:
    return "0x" + f"{n:040x}"


@pytest.fixture()
def _clean_heartbeats(db_session):
    """worker_heartbeats isn't in the conftest teardown sweep — clean it
    around each test so beats don't leak across cases."""
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()
    yield
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()


# ── record_heartbeat ────────────────────────────────────────────────────────


@requires_postgres
def test_record_heartbeat_insert_then_upsert(db_session, monkeypatch, _clean_heartbeats):
    import db.queue as queue_mod

    monkeypatch.setattr(queue_mod, "SessionLocal", SessionFactory(db_session))

    record_heartbeat(HEARTBEAT_COVERAGE_VERIFY, status="running", detail={"claimed": 1})
    rows = db_session.query(WorkerHeartbeat).all()
    assert len(rows) == 1
    assert rows[0].process == HEARTBEAT_COVERAGE_VERIFY
    assert rows[0].status == "running"
    assert rows[0].detail == {"claimed": 1}
    assert rows[0].beat_at is not None

    # Same process again → upsert (no duplicate row), status + detail updated.
    record_heartbeat(HEARTBEAT_COVERAGE_VERIFY, status="idle", detail={"claimed": 0})
    db_session.expire_all()
    rows = db_session.query(WorkerHeartbeat).all()
    assert len(rows) == 1
    assert rows[0].status == "idle"
    assert rows[0].detail == {"claimed": 0}


def test_record_heartbeat_is_best_effort(monkeypatch):
    """A DB failure must be swallowed — a heartbeat write can't crash a loop."""
    import db.queue as queue_mod

    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(queue_mod, "SessionLocal", _boom)
    record_heartbeat("anything", status="running")  # must not raise


# ── build_fleet_status ───────────────────────────────────────────────────────


@requires_postgres
def test_build_fleet_status_shape_when_idle(db_session, _clean_heartbeats):
    out = build_fleet_status(db_session)
    assert set(out) >= {"now", "jobs", "daemons", "watchers"}

    assert "queued" in out["jobs"] and "processing" in out["jobs"]
    assert isinstance(out["jobs"]["by_stage"], dict)

    procs = {d["process"] for d in out["daemons"]}
    assert procs == _KNOWN_PROCESSES

    cov = next(d for d in out["daemons"] if d["process"] == HEARTBEAT_COVERAGE_VERIFY)
    assert cov["status"] == "unknown"  # no heartbeat row yet
    assert cov["alive"] is False
    assert cov["stale"] is True
    assert cov["last_beat_at"] is None
    assert cov["work"] == {"by_equivalence_status": {}, "total": 0, "backlog": 0}

    assert set(out["watchers"]) >= {
        "monitored_contracts",
        "active",
        "last_update_at",
        "tvl_last_snapshot_at",
    }


@requires_postgres
def test_build_fleet_status_distinguishes_alive_from_stale(db_session, _clean_heartbeats):
    now = datetime(2026, 5, 28, 12, 0, 0, tzinfo=timezone.utc)
    db_session.add(
        WorkerHeartbeat(process=HEARTBEAT_COVERAGE_VERIFY, status="running", beat_at=now - timedelta(seconds=5))
    )
    db_session.add(WorkerHeartbeat(process=HEARTBEAT_EVENT_INDEXER, status="running", beat_at=now - timedelta(hours=1)))
    db_session.commit()

    out = build_fleet_status(db_session, now=now)
    cov = next(d for d in out["daemons"] if d["process"] == HEARTBEAT_COVERAGE_VERIFY)
    idx = next(d for d in out["daemons"] if d["process"] == HEARTBEAT_EVENT_INDEXER)

    assert cov["status"] == "running"
    assert cov["alive"] is True and cov["stale"] is False
    assert cov["beat_age_s"] == 5.0
    assert cov["last_beat_at"] is not None

    # 1h old, well past the indexer's 3×90s staleness window.
    assert idx["alive"] is False and idx["stale"] is True


@requires_postgres
def test_build_fleet_status_reports_work_and_watchers(db_session, _clean_heartbeats):
    db_session.add(
        IndexedEventCursor(chain_id=1, event_address=_addr(1), topic0="0x" + "ab" * 32, last_indexed_block=123)
    )
    db_session.add(MonitoredContract(address=_addr(2), chain="ethereum"))
    db_session.commit()

    out = build_fleet_status(db_session)
    idx = next(d for d in out["daemons"] if d["process"] == HEARTBEAT_EVENT_INDEXER)
    assert idx["work"]["cursors"] >= 1
    assert idx["work"]["max_indexed_block"] >= 123

    assert out["watchers"]["monitored_contracts"] >= 1
    assert out["watchers"]["active"] >= 1
    assert out["watchers"]["last_update_at"] is not None


@requires_postgres
def test_build_fleet_status_surfaces_cursor_backfill_lag(db_session, _clean_heartbeats):
    # One cursor at head + one cursor still at block 0 (the creation-block seed
    # fell back to 0 on a lookup miss, so it backfills the whole chain).
    # max_indexed_block alone reads "healthy" because the leader is at head —
    # min/spread/lagging expose it.
    db_session.add(
        IndexedEventCursor(chain_id=1, event_address=_addr(10), topic0="0x" + "aa" * 32, last_indexed_block=19_000_000)
    )
    db_session.add(
        IndexedEventCursor(chain_id=1, event_address=_addr(11), topic0="0x" + "bb" * 32, last_indexed_block=0)
    )
    db_session.add(MonitoredContract(address=_addr(12), chain="ethereum", last_scanned_block=0))
    db_session.add(MonitoredContract(address=_addr(13), chain="ethereum", last_scanned_block=19_000_000))
    db_session.commit()

    out = build_fleet_status(db_session)
    work = next(d for d in out["daemons"] if d["process"] == HEARTBEAT_EVENT_INDEXER)["work"]
    assert work["min_indexed_block"] == 0
    assert work["max_indexed_block"] >= 19_000_000
    assert work["block_spread"] >= 19_000_000
    assert work["lagging_cursors"] >= 1  # the block-0 cursor

    watchers = out["watchers"]
    assert watchers["min_scanned_block"] == 0
    assert watchers["scan_block_spread"] >= 19_000_000


@requires_postgres
def test_build_fleet_status_cursor_lag_is_chain_scoped(db_session, _clean_heartbeats):
    """Two chains each internally at their own head must read as zero lagging:
    base's naturally higher block numbers are not a backfill signal for mainnet
    cursors — lag is measured against each chain's own leader."""
    for i in (20, 21):
        db_session.add(
            IndexedEventCursor(
                chain_id=1, event_address=_addr(i), topic0="0x" + "aa" * 32, last_indexed_block=25_000_000
            )
        )
    db_session.add(
        IndexedEventCursor(
            chain_id=8453, event_address=_addr(22), topic0="0x" + "bb" * 32, last_indexed_block=48_000_000
        )
    )
    db_session.add(MonitoredContract(address=_addr(23), chain="ethereum", last_scanned_block=25_000_000))
    db_session.add(MonitoredContract(address=_addr(24), chain="base", last_scanned_block=48_000_000))
    db_session.commit()

    out = build_fleet_status(db_session)
    work = next(d for d in out["daemons"] if d["process"] == HEARTBEAT_EVENT_INDEXER)["work"]
    assert work["lagging_cursors"] == 0
    # Spread is a within-chain figure; the cross-chain height gap is not spread.
    assert work["block_spread"] == 0
    # Same for the scan-block spread over monitored contracts.
    assert out["watchers"]["scan_block_spread"] == 0


@requires_postgres
def test_build_fleet_status_surfaces_backlog_and_oldest_pending_age(db_session, _clean_heartbeats):
    # The Option B triad: backlog (drainable depth) + oldest_pending_age_s
    # (how long the oldest waiter has sat) come from cheap aggregate SQL.
    now = datetime(2026, 5, 28, 12, 0, 0, tzinfo=timezone.utc)

    p = Protocol(name=f"fleet-triad-{_addr(99)[-8:]}")
    db_session.add(p)
    db_session.commit()

    def _audit(**kw):
        ar = AuditReport(protocol_id=p.id, url=f"https://x/{_addr(kw.pop('n'))}.pdf", auditor="A", title="T", **kw)
        db_session.add(ar)
        return ar

    # Two rows awaiting text extraction; the oldest discovered 600s ago.
    _audit(n=1, text_extraction_status=None, discovered_at=now - timedelta(seconds=600))
    _audit(n=2, text_extraction_status=None, discovered_at=now - timedelta(seconds=120))
    # One row past text, awaiting scope, text extracted 300s ago.
    _audit(
        n=3,
        text_extraction_status="success",
        scope_extraction_status=None,
        text_extracted_at=now - timedelta(seconds=300),
    )
    # One fully-extracted row — counts toward neither backlog.
    _audit(
        n=4,
        text_extraction_status="success",
        scope_extraction_status="success",
        text_extracted_at=now - timedelta(seconds=900),
    )
    db_session.commit()

    # A non-proxy contract + one pending coverage row (the coverage backlog).
    c = Contract(protocol_id=p.id, address=_addr(5), chain="ethereum", contract_name="Pool")
    db_session.add(c)
    db_session.commit()
    audit_for_cov = _audit(n=6, text_extraction_status="success", scope_extraction_status="success")
    db_session.commit()
    db_session.add(
        AuditContractCoverage(
            contract_id=c.id,
            audit_report_id=audit_for_cov.id,
            protocol_id=p.id,
            matched_name="Pool",
            match_type="direct",
            match_confidence="high",
            equivalence_status="pending",
        )
    )
    db_session.commit()

    out = build_fleet_status(db_session, now=now)
    work = {d["process"]: d["work"] for d in out["daemons"]}

    text_work = work[HEARTBEAT_AUDIT_TEXT]
    assert text_work["backlog"] == 2
    assert text_work["oldest_pending_age_s"] == 600.0

    scope_work = work[HEARTBEAT_AUDIT_SCOPE]
    assert scope_work["backlog"] == 1
    assert scope_work["oldest_pending_age_s"] == 300.0

    cov_work = work[HEARTBEAT_COVERAGE_VERIFY]
    assert cov_work["backlog"] == 1
    assert cov_work["by_equivalence_status"].get("pending") == 1


@requires_postgres
def test_build_fleet_status_per_chain_indexer_and_monitoring(db_session, _clean_heartbeats):
    # Two chains present: mainnet (1) and Base (8453). Per-chain rollups must
    # separate them so a stalled Base indexer is visible without spelunking.
    import uuid as _uuid
    from datetime import timedelta as _td

    from db.models import DaemonLease

    now = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
    db_session.add(
        IndexedEventCursor(chain_id=1, event_address=_addr(1), topic0="0x" + "a1" * 32, last_indexed_block=100)
    )
    db_session.add(
        IndexedEventCursor(chain_id=8453, event_address=_addr(2), topic0="0x" + "b2" * 32, last_indexed_block=50)
    )
    db_session.add(
        IndexedEventCursor(chain_id=8453, event_address=_addr(3), topic0="0x" + "c3" * 32, last_indexed_block=60)
    )
    db_session.add(MonitoredContract(address=_addr(4), chain="ethereum", last_scanned_block=100))
    db_session.add(MonitoredContract(address=_addr(5), chain="base", last_scanned_block=50))
    # A live scanner lease for Base — the per-chain lease naming is what gives
    # monitoring visibility without a heartbeat schema change.
    db_session.add(DaemonLease(name="protocol_scanner:base", holder=_uuid.uuid4(), expires_at=now + _td(seconds=60)))
    db_session.commit()

    out = build_fleet_status(db_session, now=now)

    idx_by_chain = {
        c["chain_id"]: c
        for c in next(d for d in out["daemons"] if d["process"] == HEARTBEAT_EVENT_INDEXER)["work"]["by_chain"]
    }
    assert set(idx_by_chain) >= {1, 8453}
    assert idx_by_chain[1]["cursors"] == 1
    assert idx_by_chain[1]["chain"] == "ethereum"
    assert idx_by_chain[8453]["cursors"] == 2
    assert idx_by_chain[8453]["chain"] == "base"

    mon_by_chain = {c["chain"]: c for c in out["watchers"]["by_chain"]}
    assert set(mon_by_chain) >= {"ethereum", "base"}
    assert mon_by_chain["ethereum"]["monitored_contracts"] == 1
    assert mon_by_chain["base"]["monitored_contracts"] == 1
    # Base holds a live scanner lease; mainnet does not.
    assert mon_by_chain["base"]["scanner_lease_held"] is True
    assert mon_by_chain["ethereum"]["scanner_lease_held"] is False


@requires_postgres
def test_fleet_endpoint_exposes_per_chain_breakdowns(api_client, db_session, _clean_heartbeats):
    db_session.add(
        IndexedEventCursor(chain_id=8453, event_address=_addr(7), topic0="0x" + "d4" * 32, last_indexed_block=10)
    )
    db_session.add(MonitoredContract(address=_addr(8), chain="base"))
    db_session.commit()

    resp = api_client.get("/api/fleet")
    assert resp.status_code == 200
    data = resp.json()
    idx = next(d for d in data["daemons"] if d["process"] == HEARTBEAT_EVENT_INDEXER)
    assert any(c["chain_id"] == 8453 for c in idx["work"]["by_chain"])
    assert any(c["chain"] == "base" for c in data["watchers"]["by_chain"])


@requires_postgres
def test_fleet_endpoint_returns_all_groups(api_client, db_session, _clean_heartbeats):
    resp = api_client.get("/api/fleet")
    assert resp.status_code == 200
    data = resp.json()
    assert set(data) >= {"now", "jobs", "daemons", "watchers"}
    assert {d["process"] for d in data["daemons"]} == _KNOWN_PROCESSES


# ── daemon-loop heartbeat wiring (no DB) ─────────────────────────────────────


def test_reconciler_loop_records_heartbeat(monkeypatch):
    from services.monitoring import reconciler

    stop = Event()
    beats: list[tuple[str, dict]] = []

    # The loop now drives the dirty-queue drain (+ K-sweep enqueue) rather than a
    # walk-all reconcile; the drain stub ends the loop after one tick.
    monkeypatch.setattr(reconciler, "sweep_enqueue_stale", lambda session, *a, **k: [])

    def fake_drain(_rpc, _chain, **kw):
        stop.set()  # one pass only
        return {"drained": 7, "failed": 0}

    monkeypatch.setattr(reconciler, "drain_enrollment_queue", fake_drain)
    monkeypatch.setattr(reconciler, "_queue_depth", lambda session: 3)
    monkeypatch.setattr(reconciler, "SessionLocal", lambda: nullcontext(MagicMock()))
    monkeypatch.setattr(reconciler, "record_heartbeat", lambda process, **kw: beats.append((process, kw)))

    reconciler.run_enrollment_reconciler_loop("rpc://x", "ethereum", interval=0, stop_event=stop)

    assert len(beats) == 1
    process, kw = beats[0]
    assert process == HEARTBEAT_ENROLLMENT_RECONCILER
    assert kw["status"] == "running"
    assert kw["detail"] == {"drained": 7, "failures": 0, "queue_depth": 3}


def test_event_indexer_loop_records_heartbeat(monkeypatch):
    # The backfill thread publishes its scan summary; the main loop folds it into
    # the heartbeat alongside the reconcile re-enqueue count. (Backfill and
    # reconcile run on separate threads now, so wait for a heartbeat that reflects
    # the published scan — the very first beat can predate the first scan.)
    from workers import event_log_indexer as idx

    stop = Event()
    beats: list[tuple[str, dict]] = []
    beat_lock = Lock()

    def fake_scan(_session, **_kw):
        # budget_exhausted=True exercises the backfill loop's short-wait branch.
        return idx.ScanSummary(
            inserted=5, windows_scanned=3, caught_up_cursors=1, total_cursors=2, budget_exhausted=True
        )

    def record(process, **kw):
        with beat_lock:
            beats.append((process, kw))

    monkeypatch.setattr(idx, "SessionLocal", lambda: nullcontext(MagicMock()))
    monkeypatch.setattr(idx, "enroll_from_completed_jobs", lambda _session: 2)
    monkeypatch.setattr(idx, "scan_enrolled_events", fake_scan)
    # Fix B: the heartbeat triad is read from the table via _cursor_progress, not
    # the published ScanSummary — stub it (the MagicMock session can't run SQL).
    monkeypatch.setattr(idx, "_cursor_progress", lambda _session: (1, 2))
    monkeypatch.setattr(idx, "reconcile_deferred_resolutions", lambda _session, *, chain_id=1: 4)
    monkeypatch.setattr(idx, "reconcile_role_set_drift", lambda _session, *, chain_id=1: 1)
    monkeypatch.setattr(idx, "record_heartbeat", record)

    t = Thread(
        target=idx.run_event_log_indexer_loop,
        kwargs=dict(fetchers={}, head_fetchers={}, block_hash_fetchers={}, interval=0.01, stop_event=stop),
        daemon=True,
    )
    t.start()
    try:
        match = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with beat_lock:
                match = next(
                    (
                        (p, kw)
                        for p, kw in beats
                        if p == HEARTBEAT_EVENT_INDEXER and kw["detail"].get("inserted_last_pass") == 5
                    ),
                    None,
                )
            if match:
                break
            time.sleep(0.01)
    finally:
        stop.set()
        t.join(timeout=5)

    assert match is not None, "no heartbeat reflected the published scan summary"
    process, kw = match
    assert process == HEARTBEAT_EVENT_INDEXER
    assert kw["status"] == "running"
    assert kw["detail"] == {
        "enrolled_last_pass": 2,
        "inserted_last_pass": 5,
        "windows_scanned": 3,
        "caught_up_cursors": 1,  # from _cursor_progress (the live table), not the summary
        "total_cursors": 2,
        "pending_cursors": 1,
        "deferred_reenqueued_last_pass": 4,
        "role_drift_reenqueued_last_pass": 1,
    }


def test_reconcile_and_heartbeat_run_while_scan_blocks(monkeypatch):
    """Regression pin for the reconciler-starvation bug.

    The old loop ran enroll → scan → reconcile → heartbeat serially, so a scan
    that blocked on a cold from-scratch backfill (the LayerZero endpoint cursor
    grinding for hours) starved both the deferred-resolution reconcile and the
    fleet heartbeat — completed etherfi jobs whose authorities had already warmed
    sat un-reconciled the entire time. The fix runs backfill on its own thread, so
    reconcile + heartbeat fire every ``interval`` no matter how long scan blocks.

    Block scan indefinitely and assert reconcile + heartbeat still run. On the old
    serial loop the ``reconcile_called`` wait times out (reconcile is unreachable
    while scan blocks); on the fix it fires within an interval.
    """
    from workers import event_log_indexer as idx

    stop = Event()
    scan_entered = Event()
    release_scan = Event()
    reconcile_called = Event()
    beats: list[tuple[str, dict]] = []
    beat_lock = Lock()

    def blocking_scan(_session, **_kw):
        scan_entered.set()
        release_scan.wait(timeout=10)  # bounded so a wiring bug can't hang the suite
        return idx.ScanSummary()

    def fake_reconcile(_session, *, chain_id=1):
        reconcile_called.set()
        return 0

    def record(process, **kw):
        with beat_lock:
            beats.append((process, kw))

    monkeypatch.setattr(idx, "SessionLocal", lambda: nullcontext(MagicMock()))
    monkeypatch.setattr(idx, "enroll_from_completed_jobs", lambda _session: 0)
    monkeypatch.setattr(idx, "scan_enrolled_events", blocking_scan)
    monkeypatch.setattr(idx, "_cursor_progress", lambda _session: (0, 0))
    monkeypatch.setattr(idx, "reconcile_deferred_resolutions", fake_reconcile)
    monkeypatch.setattr(idx, "reconcile_role_set_drift", lambda _session, *, chain_id=1: 0)
    monkeypatch.setattr(idx, "record_heartbeat", record)

    t = Thread(
        target=idx.run_event_log_indexer_loop,
        kwargs=dict(fetchers={}, head_fetchers={}, block_hash_fetchers={}, interval=0.01, stop_event=stop),
        daemon=True,
    )
    t.start()
    try:
        assert scan_entered.wait(timeout=5), "backfill thread never entered scan"
        # Scan is now blocked. These two are the whole point of the fix.
        assert reconcile_called.wait(timeout=5), "reconcile was starved while scan was blocked (regression)"
        beat_deadline = time.monotonic() + 5
        while time.monotonic() < beat_deadline:
            with beat_lock:
                if any(p == HEARTBEAT_EVENT_INDEXER for p, _ in beats):
                    break
            time.sleep(0.01)
        with beat_lock:
            assert any(p == HEARTBEAT_EVENT_INDEXER for p, _ in beats), "heartbeat was starved while scan was blocked"
    finally:
        release_scan.set()
        stop.set()
        t.join(timeout=5)
    assert not t.is_alive()


# ── audit serializer error fields ────────────────────────────────────────────


def test_audit_serializer_includes_extraction_errors():
    from services.audits.serializers import _audit_report_to_dict

    ar = SimpleNamespace(
        id=1,
        url="u",
        pdf_url=None,
        auditor="a",
        title="t",
        date="2026-01-01",
        confidence=None,
        text_extraction_status="failed",
        text_extracted_at=None,
        text_size_bytes=None,
        text_extraction_error="boom-text",
        scope_extraction_status=None,
        scope_extracted_at=None,
        scope_contracts=None,
        scope_extraction_error="boom-scope",
        reviewed_commits=None,
        classified_commits=None,
        referenced_repos=None,
    )
    out = _audit_report_to_dict(ar)
    assert out["text_extraction_error"] == "boom-text"
    assert out["scope_extraction_error"] == "boom-scope"
