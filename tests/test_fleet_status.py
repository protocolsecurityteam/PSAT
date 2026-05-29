"""Tests for the fleet / process-status backend.

Covers ``db.queue.record_heartbeat`` (upsert + best-effort),
``services.aggregations.build_fleet_status`` (liveness + work breakdown),
the ``/api/fleet`` endpoint, and the daemon-loop heartbeat wiring for the
reconciler and event-log indexer.
"""

from __future__ import annotations

import sys
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import IndexedEventCursor, MonitoredContract, WorkerHeartbeat
from db.queue import (
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
    assert cov["work"] == {"by_equivalence_status": {}, "total": 0}

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

    def fake_reconcile(_session, _rpc, _chain):
        stop.set()  # one pass only
        return 7

    monkeypatch.setattr(reconciler, "reconcile_enrollments", fake_reconcile)
    monkeypatch.setattr(reconciler, "SessionLocal", lambda: nullcontext(MagicMock()))
    monkeypatch.setattr(reconciler, "record_heartbeat", lambda process, **kw: beats.append((process, kw)))

    reconciler.run_enrollment_reconciler_loop("rpc://x", interval=0, stop_event=stop)

    assert len(beats) == 1
    process, kw = beats[0]
    assert process == HEARTBEAT_ENROLLMENT_RECONCILER
    assert kw["status"] == "running"
    assert kw["detail"] == {"protocols_reconciled_last_pass": 7}


def test_event_indexer_loop_records_heartbeat(monkeypatch):
    from workers import event_log_indexer as idx

    stop = Event()
    beats: list[tuple[str, dict]] = []

    def fake_scan(_session, **_kw):
        stop.set()  # one pass only
        return 5

    monkeypatch.setattr(idx, "SessionLocal", lambda: nullcontext(MagicMock()))
    monkeypatch.setattr(idx, "enroll_from_completed_jobs", lambda _session: 2)
    monkeypatch.setattr(idx, "scan_enrolled_events", fake_scan)
    monkeypatch.setattr(idx, "record_heartbeat", lambda process, **kw: beats.append((process, kw)))

    idx.run_event_log_indexer_loop(fetchers={}, head_fetchers={}, block_hash_fetchers={}, interval=0, stop_event=stop)

    assert len(beats) == 1
    process, kw = beats[0]
    assert process == HEARTBEAT_EVENT_INDEXER
    assert kw["status"] == "running"
    assert kw["detail"] == {"enrolled_last_pass": 2, "inserted_last_pass": 5}


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
