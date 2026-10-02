from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

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
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()
    yield
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()


@requires_postgres
def test_record_heartbeat_insert_then_upsert(db_session, monkeypatch, _clean_heartbeats):
    import db.queue.heartbeats as queue_mod

    monkeypatch.setattr(queue_mod, "SessionLocal", SessionFactory(db_session))

    record_heartbeat(HEARTBEAT_COVERAGE_VERIFY, status="running", detail={"claimed": 1})
    rows = db_session.query(WorkerHeartbeat).all()
    assert len(rows) == 1
    assert rows[0].process == HEARTBEAT_COVERAGE_VERIFY
    assert rows[0].status == "running"
    assert rows[0].detail == {"claimed": 1}
    assert rows[0].beat_at is not None

    record_heartbeat(HEARTBEAT_COVERAGE_VERIFY, status="idle", detail={"claimed": 0})
    db_session.expire_all()
    rows = db_session.query(WorkerHeartbeat).all()
    assert len(rows) == 1
    assert rows[0].status == "idle"
    assert rows[0].detail == {"claimed": 0}


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

    # The indexer's staleness window is 3×90s.
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
    # The creation-block seed fell back to 0 on a lookup miss; ``max_indexed_block`` alone reads healthy because the
    # leader is at head.
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
    assert work["block_spread"] == 0
    assert out["watchers"]["scan_block_spread"] == 0


@requires_postgres
def test_build_fleet_status_surfaces_backlog_and_oldest_pending_age(db_session, _clean_heartbeats):
    now = datetime(2026, 5, 28, 12, 0, 0, tzinfo=timezone.utc)

    p = Protocol(name=f"fleet-triad-{_addr(99)[-8:]}")
    db_session.add(p)
    db_session.commit()

    def _audit(**kw):
        ar = AuditReport(protocol_id=p.id, url=f"https://x/{_addr(kw.pop('n'))}.pdf", auditor="A", title="T", **kw)
        db_session.add(ar)
        return ar

    _audit(n=1, text_extraction_status=None, discovered_at=now - timedelta(seconds=600))
    _audit(n=2, text_extraction_status=None, discovered_at=now - timedelta(seconds=120))
    _audit(
        n=3,
        text_extraction_status="success",
        scope_extraction_status=None,
        text_extracted_at=now - timedelta(seconds=300),
    )
    _audit(
        n=4,
        text_extraction_status="success",
        scope_extraction_status="success",
        text_extracted_at=now - timedelta(seconds=900),
    )
    db_session.commit()

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
    # Per-chain rollups make a stalled Base indexer visible.
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
    # Per-chain lease naming gives visibility without a heartbeat schema change.
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
    assert mon_by_chain["base"]["scanner_lease_held"] is True
    assert mon_by_chain["ethereum"]["scanner_lease_held"] is False
