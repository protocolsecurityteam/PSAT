"""Tests for the ops watchdog + monitoring health endpoint (design §2.6, Stage 2).

Real integration against the test DB with synthetic ``worker_heartbeats`` rows;
only the Discord HTTP wire (``requests.post`` inside ``notifier._send_discord``)
is stubbed. Covers: fresh→down transition fires once (dedupe) + recovery once +
cooldown re-alert; the CAS primitive that stops two racing web machines from
double-posting; ``/api/health/monitoring`` 200/503 semantics + body; staleness
boundaries (3×interval, 120s floor, missing heartbeat = stale); and the scanner
lag ("behind") alert with its own dedupe key.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session as SASession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import IndexedEventCursor, MonitoredContract, WorkerHeartbeat
from db.queue import HEARTBEAT_PROTOCOL_POLLER, HEARTBEAT_PROTOCOL_SCANNER
from services.monitoring import ops_alerts, process_meta
from services.monitoring.ops_alerts import (
    _cas_write,
    collect_chain_health,
    collect_stale_processes,
    run_ops_alert_tick,
)
from services.monitoring.process_meta import ERROR, FRESH, PROCESS_META, STALE, classify, stale_after_seconds
from tests.conftest import requires_postgres

_WEBHOOK = "https://discord.example/webhook/abc"


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
    """Capture Discord posts by stubbing the HTTP wire (requests.post) only."""
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
    """Re-stamp the healthy processes fresh against a new tick clock, so
    advancing ``now`` in a multi-tick test doesn't silently age them into
    stale (the short-cadence daemons have a 120s window)."""
    exclude = (exclude or set()) | {"ops_alerter"}
    for process in PROCESS_META:
        if process in exclude:
            continue
        db_session.query(WorkerHeartbeat).filter_by(process=process).update({"beat_at": now - timedelta(seconds=5)})
    db_session.commit()


# ── process_meta: staleness rule ─────────────────────────────────────────────


def test_stale_after_seconds_rule():
    # 3×interval above the floor.
    assert stale_after_seconds(600) == 1800.0
    # Floor dominates for short-cadence daemons.
    assert stale_after_seconds(30) == 120.0
    assert stale_after_seconds(40) == 120.0  # 3×40=120 == floor
    assert stale_after_seconds(41) == 123.0  # just over the floor


def test_classify_boundaries():
    # interval 600 → window 1800.
    assert classify("running", 1799.9, 600) == FRESH
    assert classify("running", 1800.0, 600) == STALE
    # 120s floor for a 30s-cadence daemon.
    assert classify("running", 119.0, 30) == FRESH
    assert classify("running", 120.0, 30) == STALE
    # Missing heartbeat is stale regardless of interval.
    assert classify(None, None, 600) == STALE
    # A live beat with an explicit error status surfaces as error, not fresh.
    assert classify(ERROR, 5.0, 600) == ERROR
    # Staleness dominates an error status once the beat goes silent.
    assert classify(ERROR, 5000.0, 600) == STALE


@requires_postgres
def test_collect_stale_processes_missing_and_old(db_session, _clean_heartbeats):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Everything fresh except: poller old (stale) and one errored fresh beat.
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_POLLER})
    _seed(db_session, HEARTBEAT_PROTOCOL_POLLER, age_s=100_000, now=now)
    db_session.commit()

    stale = {s["name"]: s for s in collect_stale_processes(db_session, now=now)}
    assert HEARTBEAT_PROTOCOL_POLLER in stale
    assert stale[HEARTBEAT_PROTOCOL_POLLER]["status"] == STALE
    # A fresh, healthy process is absent.
    assert HEARTBEAT_PROTOCOL_SCANNER not in stale


# ── watchdog transitions: dedupe / recovery / cooldown ───────────────────────


@requires_postgres
def test_down_dedupe_recovery_transition_graph(db_session, _clean_heartbeats, posts):
    """The full watchdog state machine over one shared world: down fires once,
    a still-stale tick dedupes, a recovered tick posts recovery once, and a
    subsequent healthy tick does not repeat it."""
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    _seed(db_session, HEARTBEAT_PROTOCOL_SCANNER, age_s=100_000, now=now)
    db_session.commit()

    # 1) fresh → down: one alert.
    out1 = run_ops_alert_tick(db_session, now=now)
    assert out1["posted_down"] == 1
    assert len(posts) == 1
    assert "Monitoring down: protocol_scanner" in posts[0]["json"]["embeds"][0]["title"]

    # 2) still stale → deduped (no second down post).
    t2 = now + timedelta(seconds=120)
    _restamp_fresh(db_session, t2, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    out2 = run_ops_alert_tick(db_session, now=t2)
    assert out2["posted_down"] == 0
    assert len(posts) == 1

    # 3) scanner beats again → recovery fires once.
    t3 = now + timedelta(seconds=205)
    _restamp_fresh(db_session, t3)  # includes the scanner now → all healthy
    out3 = run_ops_alert_tick(db_session, now=t3)
    assert out3["posted_recovery"] == 1
    assert len(posts) == 2
    assert "recovered" in posts[1]["json"]["embeds"][0]["title"]

    # 4) still healthy → no repeat recovery.
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

    # Inside the cooldown → still deduped.
    t2 = now + timedelta(seconds=299)
    _restamp_fresh(db_session, t2, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    run_ops_alert_tick(db_session, now=t2)
    assert len(posts) == 1

    # Past the cooldown, still down → one reminder.
    t3 = now + timedelta(seconds=301)
    _restamp_fresh(db_session, t3, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    run_ops_alert_tick(db_session, now=t3)
    assert len(posts) == 2


# ── CAS: two racing web machines ─────────────────────────────────────────────


@requires_postgres
def test_cas_prevents_double_write(db_session, _clean_heartbeats):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    row = WorkerHeartbeat(process="ops_alerter", status="running", detail={"alerts": {}}, beat_at=now)
    db_session.add(row)
    db_session.commit()

    prior_beat_at = db_session.query(WorkerHeartbeat).filter_by(process="ops_alerter").one().beat_at

    # Two instances read the same prior beat_at, then both try to advance it.
    other = SASession(db_session.get_bind(), expire_on_commit=False)
    try:
        won_a = _cas_write(db_session, prior_beat_at, {"alerts": {"x": {"kind": "dead"}}})
        won_b = _cas_write(other, prior_beat_at, {"alerts": {"y": {"kind": "dead"}}})
    finally:
        other.close()

    assert won_a is True
    assert won_b is False  # stale expected beat_at → lost the race


@requires_postgres
def test_cas_insert_when_absent(db_session, _clean_heartbeats):
    # No ops_alerter row yet → INSERT-claim path wins.
    assert _cas_write(db_session, None, {"alerts": {}}) is True
    assert db_session.query(WorkerHeartbeat).filter_by(process="ops_alerter").count() == 1


# ── scanner lag ("behind") alert ─────────────────────────────────────────────


@requires_postgres
def test_lag_alert_fires_only_above_threshold_with_own_dedupe(db_session, _clean_heartbeats, posts):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Scanner fresh (not "dead") but reporting a large head-lag.
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    _seed(db_session, HEARTBEAT_PROTOCOL_SCANNER, age_s=5, now=now, detail={"max_lag_blocks": 60_000})
    db_session.commit()

    out = run_ops_alert_tick(db_session, now=now)
    assert out["posted_down"] == 1  # the behind alert, distinct from any dead alert
    assert len(posts) == 1
    assert "behind" in posts[0]["json"]["embeds"][0]["title"].lower()

    # Same lag next tick → deduped on its own key.
    out2 = run_ops_alert_tick(db_session, now=now + timedelta(seconds=60))
    assert out2["posted_down"] == 0
    assert len(posts) == 1


@requires_postgres
def test_lag_alert_absent_or_below_threshold_is_silent(db_session, _clean_heartbeats, posts):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    # Below threshold, and (separately) absent — neither should alert.
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


@requires_postgres
def test_no_webhook_still_logs_no_post(db_session, _clean_heartbeats, monkeypatch):
    """PSAT_OPS_WEBHOOK_URL unset → the transition still processes (logs) but
    posts nothing to Discord."""
    monkeypatch.delenv("PSAT_OPS_WEBHOOK_URL", raising=False)
    calls: list = []
    monkeypatch.setattr("services.monitoring.notifier.requests.post", lambda *a, **k: calls.append(1))

    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    _seed_all_fresh(db_session, now, exclude={HEARTBEAT_PROTOCOL_SCANNER})
    _seed(db_session, HEARTBEAT_PROTOCOL_SCANNER, age_s=100_000, now=now)
    db_session.commit()

    out = run_ops_alert_tick(db_session, now=now)
    assert out["posted_down"] == 1  # the transition still fired (logged)
    assert calls == []  # but no Discord POST


@requires_postgres
def test_discord_transport_failure_does_not_suppress_other_daemons(db_session, _clean_heartbeats, monkeypatch, caplog):
    """A ConnectionError/Timeout on one daemon's Discord post must not abort the
    emit loop and silence the others: their ERROR log + post still fire, and
    their persisted state is only meaningful if the alert actually went out."""
    import requests

    captured: list[dict] = []
    calls = {"n": 0}

    def flaky_post(url, json=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.exceptions.ConnectionError("boom")
        captured.append({"url": url, "json": json})
        return SimpleNamespace(ok=True, status_code=200, text="")

    monkeypatch.setattr("services.monitoring.notifier.requests.post", flaky_post)
    monkeypatch.setenv("PSAT_OPS_WEBHOOK_URL", _WEBHOOK)

    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Two daemons go stale together (a monitor VM crash pattern).
    down = {HEARTBEAT_PROTOCOL_SCANNER, HEARTBEAT_PROTOCOL_POLLER}
    _seed_all_fresh(db_session, now, exclude=down)
    for process in down:
        _seed(db_session, process, age_s=100_000, now=now)
    db_session.commit()

    # WARNING, not ERROR: these beats are older than the watchdog's own uptime,
    # which is the cold-start shape (see ``_emit_down``). The level is asserted
    # on its own below; what this test is about is that every daemon got a line.
    with caplog.at_level("WARNING", logger="services.monitoring.ops_alerts"):
        out = run_ops_alert_tick(db_session, now=now)

    # Both transitions were emitted despite the first post raising.
    assert out["posted_down"] == 2
    assert calls["n"] == 2  # the second post was attempted, not skipped
    assert len(captured) == 1  # first raised, second succeeded
    down_logs = [r for r in caplog.records if r.msg == "ops: daemon %s is down"]
    assert {r.args[0] for r in down_logs} == down  # every daemon got its log


def test_daemon_down_is_error_only_when_it_died_on_our_watch(monkeypatch, caplog):
    """Cold start is a routine condition; a death while we watch is an incident."""
    import logging as _logging

    from services.monitoring import ops_alerts

    problem = {"kind": "dead", "daemon": HEARTBEAT_PROTOCOL_SCANNER, "status": "stale", "beat_age_s": 100_000.0}

    # Freshly started process: the staleness predates every second we watched.
    with caplog.at_level(_logging.WARNING, logger="services.monitoring.ops_alerts"):
        ops_alerts._emit_down(dict(problem), webhook_url=None)
    rec = [r for r in caplog.records if r.msg == "ops: daemon %s is down"][-1]
    assert rec.levelno == _logging.WARNING
    assert rec.cold_start is True

    caplog.clear()
    # Same staleness, but this watchdog has been up longer than it.
    monkeypatch.setattr(ops_alerts, "_uptime_s", lambda: 200_000.0)
    with caplog.at_level(_logging.WARNING, logger="services.monitoring.ops_alerts"):
        ops_alerts._emit_down(dict(problem), webhook_url=None)
    rec = [r for r in caplog.records if r.msg == "ops: daemon %s is down"][-1]
    assert rec.levelno == _logging.ERROR
    assert rec.cold_start is False


# ── /api/health/monitoring ───────────────────────────────────────────────────


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


@requires_postgres
def test_health_monitoring_503_when_no_heartbeats(api_client, db_session, _clean_heartbeats):
    # No rows at all → every process missing → stale → 503.
    resp = api_client.get("/api/health/monitoring")
    assert resp.status_code == 503
    body = resp.json()
    assert {s["name"] for s in body["stale"]} == set(process_meta.PROCESS_META)


def _addr(n: int) -> str:
    return "0x" + f"{n:040x}"


# ── per-chain health (invariant 4) ───────────────────────────────────────────


@requires_postgres
def test_collect_chain_health_flags_one_chain_stale(db_session, _clean_heartbeats):
    now = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
    # Mainnet cursor scanned just now; Base cursor stalest run long ago.
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
    # Every process fresh → process-level check is clean; a per-chain stall is
    # the only thing that can degrade health here.
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


@requires_postgres
def test_health_monitoring_ok_when_chains_fresh(api_client, db_session, _clean_heartbeats):
    now = datetime.now(timezone.utc)
    _seed_all_fresh(db_session, now)
    db_session.add(
        IndexedEventCursor(
            chain_id=8453,
            event_address=_addr(2),
            topic0="0x" + "b2" * 32,
            last_run_at=now - timedelta(seconds=5),
        )
    )
    db_session.commit()

    resp = api_client.get("/api/health/monitoring")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert all(not c["stale"] for c in body["chains"])


@requires_postgres
def test_watchdog_reads_same_meta_as_fleet(db_session, _clean_heartbeats):
    # The whole point of the shared module: fleet + watchdog key off one dict.
    from services.aggregations import fleet

    assert fleet.PROCESS_META is ops_alerts.PROCESS_META
