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
from services.monitoring.process_meta import ERROR, PROCESS_META, STALE, classify, stale_after_seconds
from services.monitoring.tracking_plan_state import CONFIG_SUPPLIED_BY_CALLER, plan_coverage_counts
from services.monitoring.verify_status import count_verification_read_gaps
from utils.chains import UnknownChainError, chain_by_id, chain_cache_token

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_S = 120
DEFAULT_COOLDOWN_S = 3600
DEFAULT_SCAN_LAG_ALERT = 50_000

# Distinct dedupe-key suffix for the scanner "behind" (lagging) alert so it never
# collides with the scanner "dead" (stale) alert — they are independent alarms.
_BEHIND_SUFFIX = ":behind"

# Third alarm family: monitored contracts watching without a current tracking
# plan (dated, or none at all). Not a daemon — the processes are all fresh; the
# thing that has degraded is what they are watching FOR.
_COVERAGE_KEY = "tracking_plan_coverage"

# Log-only, never an alert dedupe key — see :func:`collect_verification_gaps`.
_VERIFICATION_GAP_KEY = "verification_read_gaps"

# Log-only for the same reason — see :func:`collect_materialization_backlog`.
_MATERIALIZATION_BACKLOG_KEY = "materialization_backlog"


def _interval_s() -> int:
    return int(os.getenv("PSAT_OPS_ALERT_INTERVAL_S", str(DEFAULT_INTERVAL_S)))


def _cooldown_s() -> int:
    return int(os.getenv("PSAT_OPS_ALERT_COOLDOWN_S", str(DEFAULT_COOLDOWN_S)))


def _scan_lag_alert() -> int:
    return int(os.getenv("PSAT_SCAN_LAG_ALERT", str(DEFAULT_SCAN_LAG_ALERT)))


def _coverage_alert_threshold() -> int:
    """How many contracts may watch without a current plan before it pages.

    Default 0 = **no threshold asserted**, so the alarm is silent until an
    operator sets one. What counts as an acceptable coverage shortfall is a
    policy nobody has decided yet, and a built-in default would be this module
    inventing one. The census itself is published unconditionally (``/api/fleet``
    and :func:`collect_plan_coverage`) — visibility is not gated on the alarm.
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


def _chain_name_for_token(token: str) -> str:
    """Registry canonical name for a decimal chain-id *token*, else the token
    itself — a health read must never raise on a legacy/unregistered chain."""
    if token.isdigit():
        try:
            return chain_by_id(int(token)).name
        except UnknownChainError:
            pass
    return token


def collect_chain_health(session: Session, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Per-chain staleness for the chain-scoped subsystems (invariant 4).

    A fleet-global "monitoring OK" hides a chain whose indexer or scanner has
    stalled while another chain stays fresh. This reads the freshness of the
    per-chain rows those subsystems already write — indexer cursors carry
    ``chain_id``; monitored contracts carry ``chain`` — and flags a chain stale
    on the same ``stale_after_seconds`` rule the process-level check uses. A
    subsystem with no rows on a chain is ``idle`` (not a fault).

    Returns one entry per chain, keyed by canonical chain-id token, each with
    the two subsystems' status and an aggregate ``stale`` flag.
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

    # Indexer: stalest cursor run per chain. A chain whose cursors haven't been
    # scanned within the indexer window is a stalled per-chain indexer.
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

    # Monitoring: freshest scan-frontier advance per chain among active
    # contracts. A chain enrolled but not advancing within the scanner window is
    # a stalled per-chain scanner.
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
    """Tracking-plan census for the monitored fleet.

    Thin pass-through to :func:`plan_coverage_counts` so the watchdog and the
    fleet view read one implementation — "quiet because nothing happened" and
    "quiet because nothing is being watched" must not be a per-surface judgment.
    """
    return plan_coverage_counts(session)


def collect_verification_gaps(session: Session) -> dict[str, Any]:
    """Verification-read gap census for the monitored fleet (F9b on the F9a
    surface).

    Same pass-through role :func:`collect_plan_coverage` plays, and deliberately
    **not** a fourth alarm family: the census counts markers present at read
    time, not gaps that occurred, so a threshold over it would fire on when the
    poller last rewrote a status map as much as on anything about the reads. The
    counts are published unconditionally instead — here, on ``/api/fleet``, and
    per-pass on the scanner heartbeat — and the tick logs them when non-zero so
    the condition has a timestamped record even after the markers are erased.
    """
    return count_verification_read_gaps(session)


def collect_materialization_backlog(session: Session) -> dict[str, Any]:
    """Materialization-supply backlog for the monitored fleet (F9c).

    The same pass-through role :func:`collect_plan_coverage` plays, and the same
    deliberate non-alarm: the existing coverage alarm already fires on contracts
    watching without a current plan, and this counts the rebuild work behind
    that number. A second threshold over the same condition would double-alert
    on one fact, so the counts are published unconditionally instead — here, on
    ``/api/fleet``, and in the tick log while the backlog is non-empty.
    """
    return materialization_backlog(session)


def _log_materialization_backlog(backlog: dict[str, Any]) -> None:
    """One INFO per tick while any monitored contract lacks a current row."""
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
    """One INFO per tick carrying the census, only when something is marked.

    Sums every marker bucket — ``contracts_affected`` is excluded because it
    counts contracts, not markers.
    """
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
    """Map dedupe-key → problem info for every process currently in trouble.

    Three independent alarm families, each its own key:
      * ``<process>``               — a daemon gone stale/error ("dead").
      * ``<scanner>:behind``        — the scanner's head-lag over threshold.
      * ``tracking_plan_coverage``  — contracts watching without a current plan,
        over an operator-set threshold (off by default).
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

    threshold = _coverage_alert_threshold()
    if threshold and coverage:
        # Dated plans and no plan at all are both "not watching what the
        # analysis says to watch"; they are counted together for the alarm and
        # stay separate in the payload. A caller-authored config is excluded: an
        # operator chose it, so paging on it would page them for their own
        # decision (the bucket stays in the payload either way).
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
    # The coverage alarm is not a daemon, so it recovers as a subject, not a
    # process — same machinery, honest wording.
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
