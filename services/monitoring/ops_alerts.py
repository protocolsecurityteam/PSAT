"""Ops watchdog: a consumer for ``worker_heartbeats``.

The monitoring loops emit heartbeats (``db.queue.record_heartbeat``) but nothing
routes on their silence — a dead scanner or a stopped monitor VM produces no
page, only an absence. This module closes that blind spot. It runs as a task in
the web app's lifespan (``api.py``) — web is the only fly group that is
health-checked and auto-started, so it is the one process guaranteed to be up to
watch the others.

Every ``PSAT_OPS_ALERT_INTERVAL_S`` it classifies each :data:`PROCESS_META`
process fresh/stale/error off the same staleness rule the fleet view uses (one
rule, one module — :mod:`services.monitoring.process_meta`), and on a
``fresh → stale/error`` transition emits exactly one ERROR log (→ a Loki alert
rule) plus one Discord post to ``PSAT_OPS_WEBHOOK_URL``; on recovery, one of each.

Dedupe/cooldown state lives in the alerter's own ``ops_alerter`` heartbeat row
detail (which doubles as this task's heartbeat), written under a compare-and-swap
guard so two web machines racing the same tick rarely double-post.

Only the wire is external here — ``_send_discord`` (reused from
:mod:`services.monitoring.notifier`) is the single HTTP call.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from db.queue import HEARTBEAT_OPS_ALERTER, HEARTBEAT_PROTOCOL_SCANNER
from services.monitoring.notifier import _send_discord
from services.monitoring.process_meta import ERROR, PROCESS_META, STALE, classify

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_S = 120
DEFAULT_COOLDOWN_S = 3600
DEFAULT_SCAN_LAG_ALERT = 50_000

# Distinct dedupe-key suffix for the scanner "behind" (lagging) alert so it never
# collides with the scanner "dead" (stale) alert — they are independent alarms.
_BEHIND_SUFFIX = ":behind"


def _interval_s() -> int:
    return int(os.getenv("PSAT_OPS_ALERT_INTERVAL_S", str(DEFAULT_INTERVAL_S)))


def _cooldown_s() -> int:
    return int(os.getenv("PSAT_OPS_ALERT_COOLDOWN_S", str(DEFAULT_COOLDOWN_S)))


def _scan_lag_alert() -> int:
    return int(os.getenv("PSAT_SCAN_LAG_ALERT", str(DEFAULT_SCAN_LAG_ALERT)))


def _webhook_url() -> str | None:
    url = os.getenv("PSAT_OPS_WEBHOOK_URL")
    return url or None


def _age_seconds(ts: datetime | None, now: datetime) -> float | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max(0.0, (now - ts).total_seconds())


def _read_heartbeats(session: Session, now: datetime) -> dict[str, dict[str, Any]]:
    """Every ``worker_heartbeats`` row as ``{process: {status, beat_age_s, detail}}``.

    Read via raw SQL rather than the ORM so a long-lived session's identity map
    can't hand back a stale in-flight object (each tick wants committed truth)."""
    rows = session.execute(text("SELECT process, status, detail, beat_at FROM worker_heartbeats")).all()
    out: dict[str, dict[str, Any]] = {}
    for process, status, detail, beat_at in rows:
        out[process] = {
            "status": status,
            "beat_age_s": _age_seconds(beat_at, now),
            "detail": detail if isinstance(detail, dict) else {},
        }
    return out


def collect_stale_processes(session: Session, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Every :data:`PROCESS_META` process currently stale or errored.

    The single source of truth behind both the watchdog's down-detection and
    the ``GET /api/health/monitoring`` endpoint, so the page an external uptime
    checker sees and the page the alerter acts on can't disagree. A process with
    no heartbeat row (``beat_age_s is None``) classifies stale.
    """
    now = now or datetime.now(timezone.utc)
    beats = _read_heartbeats(session, now)
    stale: list[dict[str, Any]] = []
    for process, meta in PROCESS_META.items():
        hb = beats.get(process)
        status = hb["status"] if hb else None
        beat_age_s = hb["beat_age_s"] if hb else None
        cls = classify(status, beat_age_s, meta["interval_s"])
        if cls in (STALE, ERROR):
            stale.append({"name": process, "beat_age_s": beat_age_s, "status": cls})
    return stale


def _current_problems(beats: dict[str, dict[str, Any]], now: datetime) -> dict[str, dict[str, Any]]:
    """Map dedupe-key → problem info for every process currently in trouble.

    Two independent alarm families, each its own key:
      * ``<process>``            — a daemon gone stale/error ("dead").
      * ``<scanner>:behind``     — the scanner's head-lag over threshold.
    The alerter never pages on its own silence (it is the thing running).
    """
    problems: dict[str, dict[str, Any]] = {}
    for process, meta in PROCESS_META.items():
        if process == HEARTBEAT_OPS_ALERTER:
            continue
        hb = beats.get(process)
        status = hb["status"] if hb else None
        beat_age_s = hb["beat_age_s"] if hb else None
        cls = classify(status, beat_age_s, meta["interval_s"])
        if cls in (STALE, ERROR):
            problems[process] = {
                "kind": "dead",
                "daemon": process,
                "status": cls,
                "beat_age_s": beat_age_s,
            }

    scanner = beats.get(HEARTBEAT_PROTOCOL_SCANNER)
    lag = scanner["detail"].get("max_lag_blocks") if scanner else None
    if isinstance(lag, (int, float)) and lag > _scan_lag_alert():
        problems[HEARTBEAT_PROTOCOL_SCANNER + _BEHIND_SUFFIX] = {
            "kind": "behind",
            "daemon": HEARTBEAT_PROTOCOL_SCANNER,
            "status": "behind",
            "max_lag_blocks": int(lag),
        }
    return problems


def _post_discord(webhook_url: str, embed: dict[str, Any]) -> None:
    """Send one Discord embed, swallowing transport failures.

    ``_send_discord`` only handles a non-ok HTTP *response*; a ConnectionError /
    Timeout from ``requests.post`` still propagates. The emit loops iterate one
    problem per daemon, so an unguarded raise here would abort mid-loop and leave
    every later daemon un-logged and un-posted while their state is already
    persisted as notified — they'd stay silent until the cooldown. Contain the
    wire failure to its own problem: the per-problem ERROR log already fired
    before this call, so the belt-and-braces Loki alert survives for all."""
    try:
        _send_discord(webhook_url, embed)
    except Exception:
        logger.warning("ops: Discord post failed", exc_info=True)


def _emit_down(problem: dict[str, Any], *, webhook_url: str | None) -> None:
    """One ERROR log (always) + one Discord post (if a webhook is configured)."""
    daemon = problem["daemon"]
    if problem["kind"] == "behind":
        logger.error(
            "ops: scanner %s is behind head",
            daemon,
            extra={"daemon": daemon, "status": problem["status"], "max_lag_blocks": problem["max_lag_blocks"]},
        )
        fields = [
            {"name": "Daemon", "value": daemon, "inline": True},
            {"name": "Lag (blocks)", "value": str(problem["max_lag_blocks"]), "inline": True},
        ]
        title = f"Monitoring behind: {daemon}"
    else:
        logger.error(
            "ops: daemon %s is down",
            daemon,
            extra={"daemon": daemon, "beat_age_s": problem["beat_age_s"], "status": problem["status"]},
        )
        beat_age = problem["beat_age_s"]
        fields = [
            {"name": "Daemon", "value": daemon, "inline": True},
            {"name": "Status", "value": problem["status"], "inline": True},
            {"name": "Beat age (s)", "value": "n/a" if beat_age is None else f"{beat_age:.0f}", "inline": True},
        ]
        title = f"Monitoring down: {daemon}"

    if webhook_url:
        _post_discord(webhook_url, {"title": title, "color": 0xCC0000, "fields": fields})


def _emit_recovery(key: str, prior: dict[str, Any], *, webhook_url: str | None) -> None:
    daemon = prior.get("daemon", key)
    logger.info("ops: daemon %s recovered", daemon, extra={"daemon": daemon})
    if webhook_url:
        _post_discord(
            webhook_url,
            {
                "title": f"Monitoring recovered: {daemon}",
                "color": 0x2ECC71,
                "fields": [{"name": "Daemon", "value": daemon, "inline": True}],
            },
        )


def _cas_write(session: Session, expected_beat_at: datetime | None, detail: dict[str, Any]) -> bool:
    """Persist alert state + refresh the alerter's heartbeat, compare-and-swap.

    Returns True iff this caller won the write. When the row is absent an
    ``INSERT ... ON CONFLICT DO NOTHING`` claims it; otherwise an ``UPDATE``
    guarded on the ``beat_at`` this tick read wins only if no competitor has
    bumped the row since — so of two web machines racing the same transition,
    exactly one advances the row and posts.
    """
    payload = json.dumps(detail)
    if expected_beat_at is None:
        res = session.execute(
            text(
                "INSERT INTO worker_heartbeats (process, status, detail, beat_at) "
                "VALUES (:p, 'running', CAST(:detail AS jsonb), NOW()) "
                "ON CONFLICT (process) DO NOTHING RETURNING process"
            ),
            {"p": HEARTBEAT_OPS_ALERTER, "detail": payload},
        )
    else:
        res = session.execute(
            text(
                "UPDATE worker_heartbeats SET status='running', detail=CAST(:detail AS jsonb), beat_at=NOW() "
                "WHERE process=:p AND beat_at=:prev RETURNING process"
            ),
            {"p": HEARTBEAT_OPS_ALERTER, "detail": payload, "prev": expected_beat_at},
        )
    won = res.first() is not None
    session.commit()
    return won


def run_ops_alert_tick(session: Session, *, now: datetime | None = None) -> dict[str, Any]:
    """One watchdog pass. Returns a summary (posts emitted) for tests/logging.

    Reads heartbeats + prior alert state, diffs against the current problem set,
    and — only if the CAS write of the new state wins — emits the down/recovery
    events. A tick with nothing to report still refreshes the ``ops_alerter``
    heartbeat so the watchdog is itself observable.
    """
    now = now or datetime.now(timezone.utc)
    session.expire_all()

    beats = _read_heartbeats(session, now)
    own = beats.get(HEARTBEAT_OPS_ALERTER)
    prior_beat_at = None
    prior_alerts: dict[str, Any] = {}
    if own is not None:
        prior_alerts = dict(own["detail"].get("alerts", {}))
        # Re-read our own beat_at raw for the CAS guard (identity-map-proof).
        prior_beat_at = session.execute(
            text("SELECT beat_at FROM worker_heartbeats WHERE process=:p"),
            {"p": HEARTBEAT_OPS_ALERTER},
        ).scalar()

    problems = _current_problems(beats, now)
    cooldown = _cooldown_s()

    new_alerts: dict[str, Any] = {}
    to_alert: list[dict[str, Any]] = []
    for key, problem in problems.items():
        prev = prior_alerts.get(key)
        notified_at = now
        fire = False
        if prev is None:
            fire = True  # fresh → down transition
        else:
            last = _parse_iso(prev.get("notified_at"))
            if last is None or (now - last).total_seconds() >= cooldown:
                fire = True  # still down past the cooldown → remind
            else:
                notified_at = last  # dedupe: keep the original alert time
        new_alerts[key] = {
            "kind": problem["kind"],
            "daemon": problem["daemon"],
            "status": problem["status"],
            "notified_at": notified_at.isoformat(),
        }
        if fire:
            to_alert.append(problem)

    recovered = [(key, prior_alerts[key]) for key in prior_alerts if key not in problems]

    if not to_alert and not recovered and new_alerts == prior_alerts:
        # Nothing changed — just refresh our own heartbeat (best-effort, no CAS
        # needed since there is nothing to guard).
        _cas_write(session, prior_beat_at, {"alerts": new_alerts})
        return {"posted_down": 0, "posted_recovery": 0, "skipped": False}

    won = _cas_write(session, prior_beat_at, {"alerts": new_alerts})
    if not won:
        # A racing web machine advanced the row first; it owns this transition.
        return {"posted_down": 0, "posted_recovery": 0, "skipped": True}

    webhook_url = _webhook_url()
    for problem in to_alert:
        _emit_down(problem, webhook_url=webhook_url)
    for key, prior in recovered:
        _emit_recovery(key, prior, webhook_url=webhook_url)

    return {"posted_down": len(to_alert), "posted_recovery": len(recovered), "skipped": False}


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _tick_once() -> None:
    from db.models import SessionLocal

    with SessionLocal() as session:
        run_ops_alert_tick(session)


async def run_ops_alerter_loop(stop_event: asyncio.Event, *, interval: float | None = None) -> None:
    """Lifespan task: run :func:`run_ops_alert_tick` every interval until stopped.

    The DB work runs in a worker thread so a slow tick never blocks the event
    loop; every exception is swallowed so a transient DB hiccup can't kill the
    watchdog (its own stale heartbeat would then be the alarm)."""
    interval = interval if interval is not None else _interval_s()
    while not stop_event.is_set():
        try:
            await asyncio.to_thread(_tick_once)
        except Exception:
            logger.warning("ops watchdog tick failed", exc_info=True)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
