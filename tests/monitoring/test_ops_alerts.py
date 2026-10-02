"""Tests for the ops watchdog + monitoring health endpoint.

Real integration against the test DB with synthetic ``worker_heartbeats`` rows;
only the Discord HTTP wire (``requests.post`` inside ``notifier._send_discord``)
is stubbed. Covers: fresh→down transition fires once (dedupe) + recovery once +
cooldown re-alert; the CAS primitive that stops two racing web machines from
double-posting; ``/api/health/monitoring`` 200/503 semantics + body; staleness
boundaries (3×interval, 120s floor, missing heartbeat = stale); and the scanner
lag ("behind") alert with its own dedupe key.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from db.models import IndexedEventCursor, MonitoredContract, WorkerHeartbeat
from db.queue import HEARTBEAT_PROTOCOL_SCANNER
from services.monitoring import process_meta
from services.monitoring.ops_alerts import (
    collect_chain_health,
    run_ops_alert_tick,
)
from services.monitoring.process_meta import ERROR, FRESH, PROCESS_META, STALE, classify
from tests.conftest import requires_postgres

_WEBHOOK = "https://discord.com/api/webhooks/123456789/abcDEF-token"


@pytest.fixture()
def _clean_heartbeats(db_session):
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()
    yield
    db_session.rollback()
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()


@pytest.fixture()
def posts(monkeypatch):
    captured: list[dict] = []

    def fake_post(url, json=None, timeout=None):
        captured.append({"url": url, "json": json})
        return SimpleNamespace(ok=True, status_code=200, text="")

    monkeypatch.setattr("services.monitoring.notifier.requests.post", fake_post)
    monkeypatch.setenv("PSAT_OPS_WEBHOOK_URL", _WEBHOOK)
    return captured


def _seed(db_session, process: str, *, age_s: float, now: datetime, status: str = "running", detail=None) -> None:
    db_session.add(
        WorkerHeartbeat(
            process=process,
            status=status,
            detail=detail,
            beat_at=now - timedelta(seconds=age_s),
        )
    )


def _seed_all_fresh(db_session, now: datetime, *, exclude: set[str] | None = None) -> None:
    exclude = exclude or set()
    for process in PROCESS_META:
        if process not in exclude:
            _seed(db_session, process, age_s=5, now=now)
    db_session.commit()


def _restamp_fresh(db_session, now: datetime, *, exclude: set[str] | None = None) -> None:
    """Short-cadence daemons have a 120s window, so healthy ones are re-stamped."""
    exclude = (exclude or set()) | {"ops_alerter"}
    for process in PROCESS_META:
        if process in exclude:
            continue
        db_session.query(WorkerHeartbeat).filter_by(process=process).update({"beat_at": now - timedelta(seconds=5)})
    db_session.commit()


def test_classify_boundaries():
    assert classify("running", 1799.9, 600) == FRESH
    assert classify("running", 1800.0, 600) == STALE
    assert classify("running", 119.0, 30) == FRESH
    assert classify("running", 120.0, 30) == STALE
    assert classify(None, None, 600) == STALE
    assert classify(ERROR, 5.0, 600) == ERROR
    assert classify(ERROR, 5000.0, 600) == STALE


@requires_postgres
def test_down_dedupe_recovery_transition_graph(db_session, _clean_heartbeats, posts):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    _seed(db_session, HEARTBEAT_PROTOCOL_SCANNER, age_s=100_000, now=now)
    db_session.commit()

    out1 = run_ops_alert_tick(db_session, now=now)
    assert out1["posted_down"] == 1
    assert len(posts) == 1
    assert "Monitoring down: protocol_scanner" in posts[0]["json"]["embeds"][0]["title"]

    t2 = now + timedelta(seconds=120)
    _restamp_fresh(db_session, t2, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    out2 = run_ops_alert_tick(db_session, now=t2)
    assert out2["posted_down"] == 0
    assert len(posts) == 1

    t3 = now + timedelta(seconds=205)
    _restamp_fresh(db_session, t3)  # includes the scanner now → all healthy
    out3 = run_ops_alert_tick(db_session, now=t3)
    assert out3["posted_recovery"] == 1
    assert len(posts) == 2
    assert "recovered" in posts[1]["json"]["embeds"][0]["title"]

    t4 = t3 + timedelta(seconds=1)
    _restamp_fresh(db_session, t4)
    out4 = run_ops_alert_tick(db_session, now=t4)
    assert out4["posted_recovery"] == 0
    assert len(posts) == 2


@requires_postgres
def test_cooldown_re_alerts_after_window(db_session, _clean_heartbeats, posts, monkeypatch):
    monkeypatch.setenv("PSAT_OPS_ALERT_COOLDOWN_S", "300")
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    _seed(db_session, HEARTBEAT_PROTOCOL_SCANNER, age_s=100_000, now=now)
    db_session.commit()

    run_ops_alert_tick(db_session, now=now)
    assert len(posts) == 1

    t2 = now + timedelta(seconds=299)
    _restamp_fresh(db_session, t2, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    run_ops_alert_tick(db_session, now=t2)
    assert len(posts) == 1

    t3 = now + timedelta(seconds=301)
    _restamp_fresh(db_session, t3, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    run_ops_alert_tick(db_session, now=t3)
    assert len(posts) == 2


@requires_postgres
def test_lag_alert_absent_or_below_threshold_is_silent(db_session, _clean_heartbeats, posts):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    _seed(db_session, HEARTBEAT_PROTOCOL_SCANNER, age_s=5, now=now, detail={"max_lag_blocks": 10})
    db_session.commit()
    out = run_ops_alert_tick(db_session, now=now)
    assert out["posted_down"] == 0
    assert posts == []

    db_session.query(WorkerHeartbeat).filter_by(process=HEARTBEAT_PROTOCOL_SCANNER).update({"detail": {}})
    db_session.commit()
    out2 = run_ops_alert_tick(db_session, now=now + timedelta(seconds=1))
    assert out2["posted_down"] == 0
    assert posts == []


def test_daemon_down_is_error_only_when_it_died_on_our_watch(monkeypatch, caplog):
    import logging as _logging

    from services.monitoring import ops_alerts

    problem = {"kind": "dead", "daemon": HEARTBEAT_PROTOCOL_SCANNER, "status": "stale", "beat_age_s": 100_000.0}

    monkeypatch.setattr(ops_alerts, "_uptime_s", lambda: 5.0)
    with caplog.at_level(_logging.WARNING, logger="services.monitoring.ops_alerts"):
        ops_alerts._emit_down(dict(problem), webhook_url=None)
    rec = [r for r in caplog.records if r.msg == "ops: daemon %s is down"][-1]
    assert rec.levelno == _logging.WARNING
    assert rec.cold_start is True

    caplog.clear()
    monkeypatch.setattr(ops_alerts, "_uptime_s", lambda: 200_000.0)
    with caplog.at_level(_logging.WARNING, logger="services.monitoring.ops_alerts"):
        ops_alerts._emit_down(dict(problem), webhook_url=None)
    rec = [r for r in caplog.records if r.msg == "ops: daemon %s is down"][-1]
    assert rec.levelno == _logging.ERROR
    assert rec.cold_start is False

    caplog.clear()
    # Past the cold-start window a never-beaten daemon is an incident.
    monkeypatch.setattr(ops_alerts, "_uptime_s", lambda: 10_000.0)
    with caplog.at_level(_logging.WARNING, logger="services.monitoring.ops_alerts"):
        ops_alerts._emit_down({**problem, "beat_age_s": None}, webhook_url=None)
    rec = [r for r in caplog.records if r.msg == "ops: daemon %s is down"][-1]
    assert rec.levelno == _logging.ERROR
    assert rec.cold_start is False


@requires_postgres
def test_health_monitoring_200_when_all_fresh(api_client, db_session, _clean_heartbeats):
    now = datetime.now(timezone.utc)
    _seed_all_fresh(db_session, now)

    resp = api_client.get("/api/health/monitoring")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["stale"] == []


@requires_postgres
def test_health_monitoring_503_lists_stale(api_client, db_session, _clean_heartbeats):
    now = datetime.now(timezone.utc)
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    _seed(db_session, HEARTBEAT_PROTOCOL_SCANNER, age_s=100_000, now=now)
    db_session.commit()

    resp = api_client.get("/api/health/monitoring")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "unavailable"
    names = {s["name"] for s in body["stale"]}
    assert HEARTBEAT_PROTOCOL_SCANNER in names
    entry = next(s for s in body["stale"] if s["name"] == HEARTBEAT_PROTOCOL_SCANNER)
    assert entry["status"] == STALE
    assert entry["beat_age_s"] is not None


def _addr(n: int) -> str:
    return "0x" + f"{n:040x}"


# ── per-chain health ───────────────────────────────────────────


@requires_postgres
def test_collect_chain_health_flags_one_chain_stale(db_session, _clean_heartbeats):
    now = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=_addr(1),
            topic0="0x" + "a1" * 32,
            last_indexed_block=100,
            last_run_at=now - timedelta(seconds=5),
        )
    )
    db_session.add(
        IndexedEventCursor(
            chain_id=8453,
            event_address=_addr(2),
            topic0="0x" + "b2" * 32,
            last_indexed_block=50,
            last_run_at=now - timedelta(seconds=100_000),
        )
    )
    db_session.commit()

    by_id = {c["chain_id"]: c for c in collect_chain_health(db_session, now=now)}
    assert by_id[1]["indexer"] == "fresh"
    assert by_id[1]["stale"] is False
    assert by_id[8453]["indexer"] == process_meta.STALE
    assert by_id[8453]["stale"] is True
    assert by_id[8453]["name"] == "base"


@requires_postgres
def test_collect_chain_health_all_fresh(db_session, _clean_heartbeats):
    now = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=_addr(1),
            topic0="0x" + "a1" * 32,
            last_run_at=now - timedelta(seconds=5),
        )
    )
    db_session.add(
        MonitoredContract(address=_addr(3), chain="base", is_active=True, updated_at=now - timedelta(seconds=5))
    )
    db_session.commit()

    chains = collect_chain_health(db_session, now=now)
    assert chains  # both chains present
    assert all(c["stale"] is False for c in chains)


@requires_postgres
def test_health_monitoring_flags_stale_chain(api_client, db_session, _clean_heartbeats):
    now = datetime.now(timezone.utc)
    # A per-chain stall is the only thing that can degrade health here.
    _seed_all_fresh(db_session, now)
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=_addr(1),
            topic0="0x" + "a1" * 32,
            last_run_at=now - timedelta(seconds=5),
        )
    )
    db_session.add(
        IndexedEventCursor(
            chain_id=8453,
            event_address=_addr(2),
            topic0="0x" + "b2" * 32,
            last_run_at=now - timedelta(seconds=100_000),
        )
    )
    db_session.commit()

    resp = api_client.get("/api/health/monitoring")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "unavailable"
    assert body["stale"] == []  # no process-level staleness
    stale_chains = {c["chain_id"] for c in body["chains"] if c["stale"]}
    assert stale_chains == {8453}
