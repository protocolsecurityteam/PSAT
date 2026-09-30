"""Ops watchdog over ``worker_heartbeats``: a dead daemon otherwise produces only silence.

Runs in the web app's lifespan (the only health-checked, auto-started group). On a fresh-to-stale/error transition it
emits one ERROR log (the Loki alert hook) and one Discord post, and one of each on recovery, using the fleet view's
staleness rule. Dedupe state lives in its own heartbeat row, written by compare-and-swap so racing web machines rarely
double-post.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from db.models import IndexedEventCursor, MonitoredContract
from db.queue import (
    HEARTBEAT_EVENT_INDEXER,
    HEARTBEAT_OPS_ALERTER,
    HEARTBEAT_PROTOCOL_SCANNER,
)
from services.monitoring.materialization_reconciler import materialization_backlog
from services.monitoring.notifier import _send_discord
from services.monitoring.process_meta import ERROR, PROCESS_META, STALE, classify, planned_sleep, stale_after_seconds
from services.monitoring.tracking_plan_state import CONFIG_SUPPLIED_BY_CALLER, plan_coverage_counts
from services.monitoring.verify_status import count_verification_read_gaps
from utils.chains import UnknownChainError, chain_by_id, chain_cache_token

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_S = 120
DEFAULT_COOLDOWN_S = 3600
DEFAULT_SCAN_LAG_ALERT = 50_000

# Independent of the scanner "dead" alarm.
_BEHIND_SUFFIX = ":behind"

# Contracts watching without a current tracking plan; the daemons are fresh, what they watch for has degraded.
_COVERAGE_KEY = "tracking_plan_coverage"

# Log-only; see :func:`collect_verification_gaps`.
_VERIFICATION_GAP_KEY = "verification_read_gaps"

# Log-only; see :func:`collect_materialization_backlog`.
_MATERIALIZATION_BACKLOG_KEY = "materialization_backlog"


# A beat older than this can't have gone stale on our watch: cold start, not death.
_STARTED_MONOTONIC = time.monotonic()


def _uptime_s() -> float:
    return time.monotonic() - _STARTED_MONOTONIC


def _interval_s() -> int:
    return int(os.getenv("PSAT_OPS_ALERT_INTERVAL_S", str(DEFAULT_INTERVAL_S)))


def _cooldown_s() -> int:
    return int(os.getenv("PSAT_OPS_ALERT_COOLDOWN_S", str(DEFAULT_COOLDOWN_S)))


def _scan_lag_alert() -> int:
    return int(os.getenv("PSAT_SCAN_LAG_ALERT", str(DEFAULT_SCAN_LAG_ALERT)))


def _coverage_alert_threshold() -> int:
    """Contracts allowed to watch without a current plan before paging.

    Default 0 means no threshold (silent) until an operator decides the policy; the census is published regardless.
    """
    try:
        return max(0, int(os.getenv("PSAT_PLAN_COVERAGE_ALERT", "0")))
    except ValueError:
        return 0


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
    """Every heartbeat row as ``{process: {status, beat_age_s, detail}}``, via raw SQL so a long-lived identity map
    can't return stale objects.
    """
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
    """Every :data:`PROCESS_META` process stale or errored (no row counts as stale).

    Shared with ``GET /api/health/monitoring`` so they can't disagree.
    """
    now = now or datetime.now(timezone.utc)
    beats = _read_heartbeats(session, now)
    stale: list[dict[str, Any]] = []
    for process, meta in PROCESS_META.items():
        if planned_sleep(process, beats.get("worker_lifecycle")):
            continue
        hb = beats.get(process)
        status = hb["status"] if hb else None
        beat_age_s = hb["beat_age_s"] if hb else None
        cls = classify(status, beat_age_s, meta["interval_s"])
        if cls in (STALE, ERROR):
            stale.append({"name": process, "beat_age_s": beat_age_s, "status": cls})
    return stale


def _chain_name_for_token(token: str) -> str:
    """Canonical name for a chain-id *token*, else the token; never raises on unregistered chains."""
    if token.isdigit():
        try:
            return chain_by_id(int(token)).name
        except UnknownChainError:
            pass
    return token


def collect_chain_health(session: Session, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Per-chain indexer and scanner staleness, keyed by chain-id token, so one stalled chain isn't hidden by a fresh
    one. No rows on a chain is ``idle``, not a fault.
    """
    now = now or datetime.now(timezone.utc)
    indexer_window = stale_after_seconds(PROCESS_META[HEARTBEAT_EVENT_INDEXER]["interval_s"])
    scanner_window = stale_after_seconds(PROCESS_META[HEARTBEAT_PROTOCOL_SCANNER]["interval_s"])

    per_chain: dict[str, dict[str, Any]] = {}

    def _entry(token: str) -> dict[str, Any]:
        return per_chain.setdefault(
            token,
            {
                "chain_id": int(token) if token.isdigit() else None,
                "name": _chain_name_for_token(token),
                "indexer": "idle",
                "monitoring": "idle",
            },
        )

    for chain_id, cursors, oldest_run in session.execute(
        select(
            IndexedEventCursor.chain_id,
            func.count(),
            func.min(IndexedEventCursor.last_run_at),
        ).group_by(IndexedEventCursor.chain_id)
    ).all():
        if not cursors:
            continue
        age = _age_seconds(oldest_run, now)
        entry = _entry(chain_cache_token(chain_id))
        entry["indexer"] = STALE if (age is None or age >= indexer_window) else "fresh"

    for chain, active, latest in session.execute(
        select(
            MonitoredContract.chain,
            func.count(),
            func.max(MonitoredContract.updated_at),
        )
        .where(MonitoredContract.is_active.is_(True))
        .group_by(MonitoredContract.chain)
    ).all():
        if not active:
            continue
        age = _age_seconds(latest, now)
        entry = _entry(chain_cache_token(chain))
        entry["monitoring"] = STALE if (age is None or age >= scanner_window) else "fresh"

    out: list[dict[str, Any]] = []
    for entry in per_chain.values():
        entry["stale"] = STALE in (entry["indexer"], entry["monitoring"])
        out.append(entry)
    return sorted(out, key=lambda d: (d["chain_id"] is None, d["chain_id"] or 0, d["name"]))


def collect_plan_coverage(session: Session) -> dict[str, Any]:
    """Pass-through to :func:`plan_coverage_counts` so watchdog and fleet view share one implementation."""
    return plan_coverage_counts(session)


def collect_verification_gaps(session: Session) -> dict[str, Any]:
    """Verification-read gap census.

    Deliberately not an alarm: it counts markers present now, not gaps that happened. Logged when non-zero so the
    condition has a timestamp.
    """
    return count_verification_read_gaps(session)


def collect_materialization_backlog(session: Session) -> dict[str, Any]:
    """Materialization backlog census. Not an alarm: the coverage alarm already covers this condition."""
    return materialization_backlog(session)


def _log_materialization_backlog(backlog: dict[str, Any]) -> None:
    contracts = backlog.get("contracts")
    if not isinstance(contracts, int) or contracts <= 0:
        return
    logger.info(
        "ops: %d monitored contract(s) without a current materialization (%d queueable today)",
        contracts,
        backlog.get("queueable_now", 0),
        extra={"daemon": _MATERIALIZATION_BACKLOG_KEY, **backlog},
    )


def _log_verification_gaps(gaps: dict[str, Any]) -> None:
    """One INFO per tick when any marker exists; ``contracts_affected`` isn't summed (it counts contracts)."""
    marked = sum(v for key, v in gaps.items() if isinstance(v, int) and key != "contracts_affected")
    if not marked:
        return
    logger.info(
        "ops: %d verification read(s) currently marked not determined",
        marked,
        extra={"daemon": _VERIFICATION_GAP_KEY, **gaps},
    )


def _current_problems(
    beats: dict[str, dict[str, Any]],
    now: datetime,
    coverage: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Dedupe key -> problem for everything in trouble: ``<process>`` (dead), ``<scanner>:behind`` (lag),
    ``tracking_plan_coverage`` (over an operator threshold). The alerter never pages on itself.
    """
    problems: dict[str, dict[str, Any]] = {}
    for process, meta in PROCESS_META.items():
        if process == HEARTBEAT_OPS_ALERTER:
            continue
        if planned_sleep(process, beats.get("worker_lifecycle")):
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

    threshold = _coverage_alert_threshold()
    if threshold and coverage:
        # Dated and missing plans count together for the alarm. Caller-authored configs are excluded: operators
        # shouldn't be paged for their own choice.
        not_determined = coverage.get("not_determined") or {}
        uncovered = int(coverage.get("ready_stale", 0)) + sum(
            int(n) for token, n in not_determined.items() if token != CONFIG_SUPPLIED_BY_CALLER
        )
        if uncovered > threshold:
            problems[_COVERAGE_KEY] = {
                "kind": "coverage",
                "daemon": _COVERAGE_KEY,
                "status": "degraded",
                "uncovered": uncovered,
                "contracts": int(coverage.get("contracts", 0)),
            }
    return problems


def _post_discord(webhook_url: str, embed: dict[str, Any]) -> None:
    """Send one Discord embed, swallowing transport errors so one failure can't silence the remaining problems
    (already marked notified). The ERROR log has already fired.
    """
    try:
        _send_discord(webhook_url, embed)
    except Exception:
        logger.warning("ops: Discord post failed", exc_info=True)


def _emit_down(problem: dict[str, Any], *, webhook_url: str | None) -> None:
    daemon = problem["daemon"]
    if problem["kind"] == "coverage":
        logger.error(
            "ops: %d monitored contract(s) are watching without a current tracking plan",
            problem["uncovered"],
            extra={
                "daemon": daemon,
                "status": problem["status"],
                "uncovered": problem["uncovered"],
                "contracts": problem["contracts"],
            },
        )
        fields = [
            {"name": "Without a current plan", "value": str(problem["uncovered"]), "inline": True},
            {"name": "Monitored contracts", "value": str(problem["contracts"]), "inline": True},
        ]
        title = "Monitoring coverage degraded"
    elif problem["kind"] == "behind":
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
        beat_age = problem["beat_age_s"]
        # A staleness older than this watchdog's uptime is a cold start, not an incident: WARNING instead of ERROR,
        # still posted. Only the first two ticks count as cold start; otherwise a daemon that died just before a restart
        # would read cold-start forever.
        watchdog_is_young = _uptime_s() < 2 * _interval_s()
        cold_start = watchdog_is_young and (beat_age is None or beat_age > _uptime_s())
        logger.log(
            logging.WARNING if cold_start else logging.ERROR,
            "ops: daemon %s is down",
            daemon,
            extra={
                "daemon": daemon,
                "beat_age_s": beat_age,
                "status": problem["status"],
                "cold_start": cold_start,
                "watchdog_uptime_s": round(_uptime_s(), 1),
            },
        )
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
    # The coverage alarm recovers as a subject, not a process.
    subject = "coverage" if prior.get("kind") == "coverage" else "daemon"
    logger.info("ops: %s %s recovered", subject, daemon, extra={"daemon": daemon})
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
    """Persist alert state and refresh our heartbeat by compare-and-swap on the read ``beat_at``; returns whether we
    won, so one of two racing machines posts.
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
    """One watchdog pass; returns posts emitted.

    Posts only if the CAS write wins, and always refreshes the ``ops_alerter`` heartbeat.
    """
    now = now or datetime.now(timezone.utc)
    session.expire_all()

    beats = _read_heartbeats(session, now)
    own = beats.get(HEARTBEAT_OPS_ALERTER)
    prior_beat_at = None
    prior_alerts: dict[str, Any] = {}
    if own is not None:
        prior_alerts = dict(own["detail"].get("alerts", {}))
        # Raw re-read for the CAS guard (identity-map-proof).
        prior_beat_at = session.execute(
            text("SELECT beat_at FROM worker_heartbeats WHERE process=:p"),
            {"p": HEARTBEAT_OPS_ALERTER},
        ).scalar()

    coverage = collect_plan_coverage(session) if _coverage_alert_threshold() else None
    _log_verification_gaps(collect_verification_gaps(session))
    _log_materialization_backlog(collect_materialization_backlog(session))
    problems = _current_problems(beats, now, coverage)
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
        # Nothing changed; just refresh our heartbeat.
        _cas_write(session, prior_beat_at, {"alerts": new_alerts})
        return {"posted_down": 0, "posted_recovery": 0, "skipped": False}

    won = _cas_write(session, prior_beat_at, {"alerts": new_alerts})
    if not won:
        # A racing machine won; it owns this transition.
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
    """Lifespan task running :func:`run_ops_alert_tick` each interval in a thread, swallowing errors (a dead
    watchdog's stale heartbeat is its own alarm).
    """
    interval = interval if interval is not None else _interval_s()
    while not stop_event.is_set():
        try:
            await asyncio.to_thread(_tick_once)
        except Exception:
            logger.warning("ops watchdog tick failed", exc_info=True)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
