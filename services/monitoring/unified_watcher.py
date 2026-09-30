"""Unified protocol monitoring: the event scanner and the state poller for governance and proxy changes."""

from __future__ import annotations

import logging
import os
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, make_transient_to_detached
from sqlalchemy.orm.attributes import flag_modified

from db.models import (
    CONTROLLER_OBSERVED_VIA_EVENT_LOG,
    CONTROLLER_OBSERVED_VIA_STORAGE_POLL,
    UPGRADE_SOURCE_EVENT_SCAN,
    UPGRADE_SOURCE_POLL,
    Contract,
    ControllerValue,
    MonitoredContract,
    MonitoredEvent,
    ProxyUpgradeEvent,
    SessionLocal,
    UpgradeEvent,
    WatchedProxy,
)
from db.queue import (
    DEFAULT_DAEMON_LEASE_TTL_S,
    record_heartbeat,
    renew_daemon_lease,
    try_acquire_daemon_lease,
)
from services.clients.rpc import (
    MAX_BATCH_SIZE,
    rpc_batch_request_classified,
    rpc_request,
)
from services.monitoring import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_SCANNER,
    emit_monitor_cycle,
)
from services.monitoring.chain_rpc import chain_id_for, rpc_for_chain
from services.monitoring.enrichment import enrich_events
from services.monitoring.enrollment import mark_enrollment_dirty
from services.monitoring.event_state import (
    _WRITE_TARGET_TO_CONFIG_KEYS as _WRITE_TARGET_TO_CONFIG_KEYS,
)
from services.monitoring.event_state import (
    _new_value_for_write_target,
    _should_watch,
    _update_state_from_event,
    _write_through_proxy_event,
)
from services.monitoring.event_topics import (
    _HANDROLLED_EVENT_TYPE_TO_TAGS,
    ALL_EVENT_TOPICS,
    PROXY_EVENT_TOPICS,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
    WITNESS_TIERS,
    classify_witness_tier,
    is_member_changed_event_type,
    parse_any_log,
    parse_tracked_log,
    read_spec_is_scalar_slot,
    value_changed_event_type,
)
from services.monitoring.polling_plan import decode_poll_outcome, project_entry_return
from services.monitoring.reanalysis import maybe_queue_reanalysis
from services.monitoring.salience import assign_salience, stamp_signal_class
from services.monitoring.tracking_plan_state import TRACKED_TOPICS_STALE_SINCE_KEY
from services.monitoring.verify_status import (
    VERIFY_ERROR,
    VERIFY_NO_VALUE,
    VERIFY_OVER_BUDGET,
    VERIFY_UNANSWERED,
    record_unresolvable_read,
    record_verify_status,
)
from services.monitoring.watcher_config import (
    _AUTHORITY_CONTROLLER_IDS as _AUTHORITY_CONTROLLER_IDS,
)
from services.monitoring.watcher_config import (
    _DB_ERROR_TYPES,
    _GOVERNANCE_ROTATION_REASON,
    _GOVERNANCE_ROTATION_WRITE_TARGETS,
    _LEASE_HOLDER,
    DEFAULT_MAX_VERIFY_READS_PER_PASS,
    DEFAULT_POLL_CONTRACTS_PER_PASS,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_RUNAWAY_WINDOWS_PER_PASS,
    DEFAULT_SCAN_INTERVAL,
    FETCHER_MIN_BISECT_SPAN,
    _confirmation_depth_for,
    _is_deadlock_error,
    _max_getlogs_range_for,
    _poll_startup_offset,
    _poller_lease_name,
    _runaway_lag_blocks_for,
    _scan_float_env,
    _scan_int_env,
    _scanner_lease_name,
)
from services.monitoring.watcher_config import (
    _OWNER_CONTROLLER_IDS as _OWNER_CONTROLLER_IDS,
)
from services.monitoring.watcher_config import (
    DEFAULT_CONFIRMATION_DEPTH as DEFAULT_CONFIRMATION_DEPTH,
)
from services.monitoring.watcher_config import (
    DEFAULT_RUNAWAY_LAG_SECONDS as DEFAULT_RUNAWAY_LAG_SECONDS,
)
from services.monitoring.watcher_config import (
    MAX_BLOCK_RANGE as MAX_BLOCK_RANGE,
)
from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)


def get_latest_block(rpc_url: str, *, chain_id: int | None = None) -> int:
    result = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
    return int(result, 16)


@dataclass
class _Cohort:
    """Contracts scanned together: one chain and block bucket, capped at ``PSAT_SCAN_ADDRESS_BATCH`` addresses per
    eth_getLogs. ``cursor`` only advances in the transaction that persisted a window's events.
    """

    chain: str
    member_ids: list[uuid.UUID]
    addresses: list[str]
    cursor: int
    done: bool = False
    failed: bool = False
    # Read only by the runaway backstop.
    windows_this_pass: int = 0
    # Lag exceeds the chain's runaway threshold.
    runaway: bool = False


class ScanResult(list):
    """A pass's new events plus heartbeat metrics; a ``list`` subclass so callers can treat it as events."""

    def __init__(
        self,
        events: list[MonitoredEvent],
        *,
        budget_exhausted: bool = False,
        windows_scanned: int = 0,
        cohorts: int = 0,
        max_lag_blocks: int = 0,
        degraded: bool = False,
        runaway_cohorts: int = 0,
    ) -> None:
        super().__init__(events)
        self.budget_exhausted = budget_exhausted
        self.windows_scanned = windows_scanned
        self.cohorts = cohorts
        self.max_lag_blocks = max_lag_blocks
        self.degraded = degraded
        self.runaway_cohorts = runaway_cohorts


def _scan_topics_union(session: Session) -> list[str]:
    """Registry topic0s plus the distinct per-contract tracked topic0s (read without hydrating rows)."""
    rows = session.execute(
        text(
            """
            SELECT DISTINCT lower(elem ->> 'topic0') AS topic0
            FROM monitored_contracts,
                 LATERAL jsonb_array_elements(
                     CASE
                         WHEN jsonb_typeof(monitoring_config -> 'tracked_topics') = 'array'
                         THEN monitoring_config -> 'tracked_topics'
                         ELSE '[]'::jsonb
                     END
                 ) AS elem
            WHERE is_active = true
            """
        )
    ).all()
    extra = {row[0] for row in rows if row[0]}
    return sorted({t.lower() for t in ALL_EVENT_TOPICS.keys()} | extra)


def _notify_committed_events(session: Session, events: list[MonitoredEvent]) -> None:
    """Notify already-committed events, swallowing failures so the pass continues."""
    if not events:
        return
    try:
        from services.monitoring.notifier import notify_protocol_events

        notify_protocol_events(session, events)
    except Exception as exc:
        logger.warning("Protocol notification failed: %s", exc, extra={"exc_type": type(exc).__name__})
        # Events are committed; don't leave the session pending-rollback.
        session.rollback()


def _poll_entry_for_controller(mc: MonitoredContract, controller_id: str | None) -> dict | None:
    """The polling-plan entry proven to read *controller_id* (``source == "analyzer:<id>"``), or None.

    No name matching: an analyzer controller called ``implementation`` would match the vendored EIP-1967 entry and
    publish one slot's value under another's id. Unmatched controllers are recorded not-determined; the rotation poller
    is the backstop.
    """
    plan = (mc.monitoring_config or {}).get("polling_plan")
    if not isinstance(plan, list) or not controller_id:
        return None
    wanted_source = f"analyzer:{controller_id}"
    for entry in plan:
        if isinstance(entry, dict) and entry.get("source") == wanted_source:
            return entry
    return None


@dataclass
class _DirtyController:
    """A controller a hint marked for verification this pass.

    Repeats coalesce; in-memory only (the poller is the backstop after a crash).
    """

    monitored_contract_id: uuid.UUID
    controller_id: str
    chain: str
    address: str
    entry: dict
    block_number: int


# Monotonic time of each controller's last verification read, for fair budget ordering. Process-local (the scanner is a
# per-chain singleton); never a witness.
_LAST_VERIFIED_AT: dict[tuple[uuid.UUID, str], float] = {}
_LAST_VERIFIED_MAX = 4096


def _prune_verification_cursors() -> None:
    if len(_LAST_VERIFIED_AT) <= _LAST_VERIFIED_MAX * 2:
        return
    keep = sorted(_LAST_VERIFIED_AT.items(), key=lambda kv: kv[1], reverse=True)[:_LAST_VERIFIED_MAX]
    _LAST_VERIFIED_AT.clear()
    _LAST_VERIFIED_AT.update(keep)


def _resolve_spec_tier(spec: dict, mc: MonitoredContract) -> str:
    """The witness tier of one tracked-topic *spec*.

    Enrollment's stamp wins. Unstamped legacy specs are re-classified with readability from the persisted polling plan,
    so they can only demote.
    """
    tier = spec.get("witness_tier")
    if tier in WITNESS_TIERS:
        return tier
    event_type = spec.get("event_type")
    poll_entry = _poll_entry_for_controller(mc, spec.get("controller_id"))
    return classify_witness_tier(
        event_type=event_type,
        controller_id=spec.get("controller_id"),
        inputs=spec.get("inputs"),
        effect_tags=spec.get("effect_tags"),
        # The member witness only counts for specs that publish as member changes; enrollment refused that type when it
        # couldn't be published.
        member_witness=spec.get("member_witness") if is_member_changed_event_type(event_type) else None,
        writer_openness=spec.get("writer_openness"),
        poll_decodable=poll_entry is not None,
        # Legacy specs have no read_spec; the projected polling entry is the only scalar proof, and no entry refuses.
        controller_scalar_proven=read_spec_is_scalar_slot(poll_entry),
    )


def _process_window(
    session: Session,
    cohort: _Cohort,
    fetched_logs: list,
    window_start: int,
    window_end: int,
    dirty: dict[tuple[uuid.UUID, str], _DirtyController] | None = None,
    counters: dict[str, int] | None = None,
) -> list[MonitoredEvent]:
    """Decode a window's logs and run the side-effect pipeline, without committing (the caller commits with the
    cursor).

    Only members that emitted a log are hydrated. Per-contract events are gated on witness tier: ``self_describing``
    inserts, ``hint`` marks *dirty* for a verification read, ``activity`` publishes nothing. Hand-rolled events are
    unaffected. *counters* records logs that matched a spec but wouldn't decode, which would otherwise look like a quiet
    contract.
    """
    if not fetched_logs:
        return []

    emitter_addrs = {fl.address for fl in fetched_logs if fl.address}
    if not emitter_addrs:
        return []

    hydrated = (
        session.execute(
            select(MonitoredContract).where(
                MonitoredContract.id.in_(cohort.member_ids),
                func.lower(MonitoredContract.address).in_(emitter_addrs),
            )
        )
        .scalars()
        .all()
    )
    mc_by_addr: dict[str, MonitoredContract] = {c.address.lower(): c for c in hydrated}
    if not mc_by_addr:
        return []

    # Per emitter: topic0 -> tracked-topic spec.
    tracked_specs_by_emitter: dict[str, dict[str, dict]] = {}
    for addr, mc in mc_by_addr.items():
        topics_list = (mc.monitoring_config or {}).get("tracked_topics") or []
        spec_map: dict[str, dict] = {}
        for topic_spec in topics_list:
            t0 = (topic_spec.get("topic0") or "").lower()
            if t0:
                spec_map[t0] = topic_spec
        if spec_map:
            tracked_specs_by_emitter[addr] = spec_map

    # No pre-read dedupe: the partial unique index (monitored_contract_id, tx_hash, log_index, event_type) is the
    # identity, so the insert uses ON CONFLICT DO NOTHING and every side effect is gated on winning it. Batch timelock
    # ops differ by log_index.
    new_events: list[MonitoredEvent] = []

    for fl in fetched_logs:
        raw = fl.raw
        if raw is None:
            continue
        emitter = fl.address
        spec: dict | None = None
        parsed = parse_any_log(raw)
        if not parsed:
            emitter_specs = tracked_specs_by_emitter.get(emitter)
            if not emitter_specs:
                continue
            if not fl.topics:
                continue
            spec = emitter_specs.get(fl.topics[0])
            if not spec:
                continue
            parsed = parse_tracked_log(raw, spec)
            if not parsed:
                if counters is not None:
                    counters["undecodable_tracked_logs"] = counters.get("undecodable_tracked_logs", 0) + 1
                logger.debug(
                    "scan: tracked log matched an enrolled spec but did not decode",
                    extra={"address": emitter, "topic0": fl.topics[0], "chain": cohort.chain},
                )
                continue

        mc = mc_by_addr.get(emitter)
        if not mc:
            continue

        event_type = parsed["event_type"]

        if mc.monitoring_config and not _should_watch(mc, parsed):
            continue

        # Events before enrollment_block predate monitoring (a low-cursor cohort-mate can drag them in): recorded with a
        # marker but never notified, synced or reanalyzed. NULL floors (legacy) don't suppress.
        is_historical = mc.enrollment_block is not None and parsed["block_number"] < mc.enrollment_block

        witness_tier: str | None = None
        if spec is not None:
            witness_tier = _resolve_spec_tier(spec, mc)
            if witness_tier != WITNESS_TIER_SELF_DESCRIBING:
                # An occurrence isn't a change: a hint earns one coalesced verification read; activity has no witness.
                # Historical hints never mark, since the read would publish current state as a live change.
                if witness_tier == WITNESS_TIER_HINT and dirty is not None and not is_historical:
                    controller_id = spec.get("controller_id")
                    entry = _poll_entry_for_controller(mc, controller_id)
                    if isinstance(controller_id, str) and controller_id:
                        if entry is not None:
                            dirty.setdefault(
                                (mc.id, controller_id),
                                _DirtyController(
                                    monitored_contract_id=mc.id,
                                    controller_id=controller_id,
                                    chain=mc.chain,
                                    address=mc.address,
                                    entry=entry,
                                    block_number=parsed["block_number"],
                                ),
                            )
                        elif record_unresolvable_read(mc, controller_id):
                            # Hint with no proven read binding: record the skip instead of looking quiet.
                            flag_modified(mc, "last_poll_status")
                continue

        event_data = {
            k: v
            for k, v in parsed.items()
            if k not in ("event_type", "block_number", "tx_hash", "log_index", "_emitter")
        }
        if witness_tier is not None:
            # Carried on the row so consumers needn't re-derive it from a config that may have changed.
            event_data["witness_tier"] = witness_tier
            # The spec came from a plan that couldn't be re-read at the last enrollment; the event carries that
            # timestamp. Read-verified events don't need it.
            stale_since = (mc.monitoring_config or {}).get(TRACKED_TOPICS_STALE_SINCE_KEY)
            if stale_since:
                event_data["plan_stale_since"] = stale_since

        if is_historical:
            event_data = dict(event_data)
            event_data["historical"] = True

        # Mint site 1 of 3. Assigned before the insert so the level lands with the row; provisional for enrichable
        # types.
        salience, salience_basis = assign_salience(session, event_type, event_data, mc)
        event_data["salience"] = salience
        event_data["salience_basis"] = salience_basis

        event_id = uuid.uuid4()
        insert_stmt = (
            pg_insert(MonitoredEvent)
            .values(
                id=event_id,
                monitored_contract_id=mc.id,
                event_type=event_type,
                block_number=parsed["block_number"],
                tx_hash=parsed.get("tx_hash", ""),
                log_index=fl.log_index,
                data=event_data if event_data else None,
            )
            .on_conflict_do_nothing(
                index_elements=["monitored_contract_id", "tx_hash", "log_index", "event_type"],
                index_where=text("log_index IS NOT NULL"),
            )
            .returning(MonitoredEvent.id)
        )
        # Gate every side effect on winning the insert: no double Discord posts, reanalysis or sync.
        if session.execute(insert_stmt).first() is None:
            continue

        # Rehydrate the inserted row as a persistent instance (no SELECT) so later data changes flush as an UPDATE.
        monitored_event = MonitoredEvent(
            id=event_id,
            monitored_contract_id=mc.id,
            event_type=event_type,
            block_number=parsed["block_number"],
            tx_hash=parsed.get("tx_hash", ""),
            log_index=fl.log_index,
            data=event_data if event_data else None,
        )
        make_transient_to_detached(monitored_event)
        session.add(monitored_event)

        if is_historical:
            # Stored with its ``historical`` marker but no notification or side effects.
            logger.info(
                "Recorded historical %s on %s (block %d < enrollment %s) — not notified",
                event_type,
                mc.address,
                parsed["block_number"],
                mc.enrollment_block,
            )
            continue

        new_events.append(monitored_event)

        logger.info(
            "Detected %s on %s (block %d)",
            event_type,
            mc.address,
            parsed["block_number"],
        )

        topic0 = fl.topics[0] if fl.topics else ""
        if topic0 in PROXY_EVENT_TOPICS and mc.watched_proxy_id:
            _write_through_proxy_event(session, mc, parsed)

        _update_state_from_event(mc, parsed)
        _sync_relational_tables(session, mc, parsed)

        try:
            reanalysis_job = maybe_queue_reanalysis(session, mc, event_type, event_data)
            if reanalysis_job:
                updated = dict(monitored_event.data or {})
                updated["reanalysis_job_id"] = str(reanalysis_job.id)
                monitored_event.data = updated
                flag_modified(monitored_event, "data")
        except Exception as exc:
            logger.warning(
                "Failed to queue re-analysis for %s: %s",
                mc.address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

    return new_events


def _verification_read_order(dirty: dict[tuple[uuid.UUID, str], _DirtyController]) -> list[_DirtyController]:
    """Dirty controllers, least-recently-verified first (never-verified first), so a fixed order can't starve the
    tail.

    Address and id only break ties.
    """
    return sorted(
        dirty.values(),
        key=lambda d: (
            _LAST_VERIFIED_AT.get((d.monitored_contract_id, d.controller_id), 0.0),
            d.address.lower(),
            d.controller_id,
        ),
    )


@dataclass
class _VerificationOutcome:
    """One verification pass: events to notify and what was lost.

    ``units_failed`` exists because a deadlocked unit rolls back its rows and markers together, leaving no other signal;
    the caller marks the pass degraded. ``reads_failed``/``reads_over_budget`` count this pass's outcomes (the DB
    markers get erased by the poller). ``None`` means the pass didn't get far enough, not zero.
    """

    events: list[MonitoredEvent]
    units_failed: int = 0
    reads_failed: int | None = 0
    reads_over_budget: int | None = 0


def _resolve_verification_reads(
    session: Session,
    dirty: dict[tuple[uuid.UUID, str], _DirtyController],
    rpc_by_chain: dict[str, str],
) -> _VerificationOutcome:
    """Read back every controller a hint marked this pass and publish only what the read proves.

    Moved: a ``value_changed:<controller_id>`` event with old/new plus the poll path's side effects. Held: nothing
    published. First observation: baseline seeded, nothing published. No observation: a not-determined marker
    (verify_status).

    All RPC for a chain precedes its writes, and each chain commits separately under deadlock isolation (row locks held
    across network IO deadlock with the scanner). Events are committed here and returned for notification.
    """
    if not dirty:
        return _VerificationOutcome([])

    budget = max(0, _scan_int_env("PSAT_SCAN_MAX_VERIFY_READS_PER_PASS", DEFAULT_MAX_VERIFY_READS_PER_PASS))
    ordered = _verification_read_order(dirty)
    within, over = ordered[:budget], ordered[budget:]

    mcs = {
        mc.id: mc
        for mc in session.execute(
            select(MonitoredContract).where(MonitoredContract.id.in_([d.monitored_contract_id for d in ordered]))
        )
        .scalars()
        .all()
    }

    # Read phase: all network IO, no staged writes.
    by_chain: dict[str, list[_DirtyController]] = defaultdict(list)
    for member in within:
        by_chain[member.chain].append(member)

    answers: dict[str, list[tuple[_DirtyController, tuple[object, str]]]] = {}
    for chain, members in by_chain.items():
        calls: list[tuple[str, list]] = []
        dispatch: list[_DirtyController] = []
        for member in members:
            call = _rpc_call_for_entry(member.address, member.entry)
            if call is None:
                continue
            dispatch.append(member)
            calls.append(call)
        if not calls:
            continue
        chain_rpc_url = rpc_by_chain.get(chain) or rpc_for_chain(chain, "")
        try:
            results = rpc_batch_request_classified(chain_rpc_url, calls)
        except Exception as exc:
            logger.warning(
                "Verification-read batch failed for %s: %s",
                chain,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            results = [(None, "transport")] * len(calls)
        answers[chain] = list(zip(dispatch, results))

    # Write phase: one committed unit per chain.
    new_events: list[MonitoredEvent] = []
    units_failed = 0
    reads_failed = 0
    # Declined reads are counted before any write lands.
    reads_over_budget = len(over)
    now = time.monotonic()

    if over:
        logger.warning(
            "Verification-read budget exhausted; %d controller(s) recorded as not determined",
            len(over),
            extra={"budget": budget, "dirty": len(ordered)},
        )
    write_units: list[tuple[str, list[tuple[_DirtyController, tuple[object, str]]]]] = list(answers.items())
    if over:
        write_units.append(("__over_budget__", [(member, (None, "__skipped__")) for member in over]))

    for unit, members in write_units:
        unit_events: list[MonitoredEvent] = []
        try:
            for member, (raw, status) in members:
                mc = mcs.get(member.monitored_contract_id)
                if mc is None:
                    continue
                field = member.entry.get("field")
                if status == "__skipped__":
                    if record_verify_status(mc, field, VERIFY_OVER_BUDGET):
                        flag_modified(mc, "last_poll_status")
                    continue
                _LAST_VERIFIED_AT[(member.monitored_contract_id, member.controller_id)] = now
                if status != "ok":
                    marker = VERIFY_ERROR if status == "error" else VERIFY_UNANSWERED
                    reads_failed += 1
                    if record_verify_status(mc, field, marker):
                        flag_modified(mc, "last_poll_status")
                    continue
                new_value, parsed_ok = decode_poll_outcome(
                    project_entry_return(raw if isinstance(raw, str) else None, member.entry),
                    member.entry.get("type_kind"),
                    member.entry.get("type"),
                )
                if new_value is None:
                    # A parsed zero address stays out of last_known_state, matching the poller.
                    if not parsed_ok:
                        reads_failed += 1
                        if record_verify_status(mc, field, VERIFY_NO_VALUE):
                            flag_modified(mc, "last_poll_status")
                    continue
                if not isinstance(field, str) or not field:
                    continue

                state = dict(mc.last_known_state or {})
                old_value = state.get(field)
                if new_value == old_value:
                    continue  # earned negative — the hint did not correspond to a change
                state[field] = new_value
                mc.last_known_state = state
                flag_modified(mc, "last_known_state")
                if old_value is None:
                    continue  # first observation is a baseline, not a transition

                event_type = value_changed_event_type(member.controller_id)
                event_data = {
                    "field": field,
                    "controller_id": member.controller_id,
                    "old": str(old_value),
                    "new": str(new_value),
                    # The witness is the read, not the triggering log.
                    "witness": "read_verified",
                    # Which plan entry answered.
                    "read_entry_source": member.entry.get("source"),
                    "hint_block_number": member.block_number,
                }
                # Mint site 2 of 3: the answering entry's signal_class is only in scope here. No class stamps nothing
                # (visible not_determined).
                stamp_signal_class(event_data, member.entry)
                salience, salience_basis = assign_salience(session, event_type, event_data, mc)
                event_data["salience"] = salience
                event_data["salience_basis"] = salience_basis
                event = MonitoredEvent(
                    id=uuid.uuid4(),
                    monitored_contract_id=mc.id,
                    event_type=event_type,
                    # A read has no block or tx; NULL ``log_index`` keeps it out of the identity index, like poll rows.
                    block_number=0,
                    tx_hash="",
                    data=event_data,
                )
                session.add(event)
                unit_events.append(event)
                logger.info(
                    "Verification read detected %s change on %s: %s -> %s",
                    field,
                    mc.address,
                    old_value,
                    new_value,
                )
                _write_through_proxy_read(session, mc, field, new_value, old_value)
                _sync_relational_from_poll(session, mc, field, new_value, old_value)
                try:
                    reanalysis_job = maybe_queue_reanalysis(session, mc, event_type, event_data)
                    if reanalysis_job:
                        updated = dict(event.data or {})
                        updated["reanalysis_job_id"] = str(reanalysis_job.id)
                        event.data = updated
                except _DB_ERROR_TYPES:
                    # The reanalysis Job SELECT autoflushes the staged UPDATE (a deadlock candidate). DB errors have
                    # poisoned the session: re-raise to the unit handler, which owns rollback.
                    raise
                except Exception as exc:
                    logger.warning(
                        "Failed to queue re-analysis for %s: %s",
                        mc.address,
                        exc,
                        extra={"exc_type": type(exc).__name__},
                    )
            session.commit()
        except _DB_ERROR_TYPES as exc:
            if not _is_deadlock_error(exc):
                # Not recoverable per unit.
                raise
            session.rollback()
            logger.warning(
                "Verification-read unit deadlocked; rolled back, retrying next pass: %s",
                unit,
                extra={"exc_type": type(getattr(exc, "orig", None) or exc).__name__},
            )
            # The unit's rows rolled back, so none are notified.
            units_failed += 1
            for member, _answer in members:
                _LAST_VERIFIED_AT.pop((member.monitored_contract_id, member.controller_id), None)
            continue
        new_events.extend(unit_events)

    _prune_verification_cursors()
    return _VerificationOutcome(
        new_events,
        units_failed=units_failed,
        reads_failed=reads_failed,
        reads_over_budget=reads_over_budget,
    )


def scan_for_events(session: Session, rpc_url: str) -> ScanResult:
    """Scan new blocks for governance and proxy events, bounded per pass.

    Contracts load columns-only, group into cohorts, and scan most-behind-first under per-cohort and per-pass window
    budgets. Each window is one multi-address eth_getLogs up to ``head - CONFIRMATION_DEPTH``; events and the cursor
    commit together, then notify. A failed window ends the cohort's turn without advancing (behind is not skipped).
    """
    started = time.monotonic()

    address_batch = max(1, _scan_int_env("PSAT_SCAN_ADDRESS_BATCH", 200))
    max_windows_cohort = max(1, _scan_int_env("PSAT_SCAN_MAX_WINDOWS_PER_COHORT", 25))
    max_windows_pass = max(1, _scan_int_env("PSAT_SCAN_MAX_WINDOWS_PER_PASS", 50))
    # A cohort further behind than its chain's wall-clock budget has a broken cursor, not a backfill. It runs last,
    # capped at ``runaway_windows`` per pass, and is counted on the heartbeat. Operators repair it with cursor-clamp
    # tooling.
    runaway_windows = max(1, _scan_int_env("PSAT_SCAN_RUNAWAY_WINDOWS_PER_PASS", DEFAULT_RUNAWAY_WINDOWS_PER_PASS))

    index_rows = session.execute(
        select(
            MonitoredContract.id,
            MonitoredContract.address,
            MonitoredContract.chain,
            MonitoredContract.last_scanned_block,
        ).where(MonitoredContract.is_active == True)  # noqa: E712
    ).all()

    if not index_rows:
        # Beat even with nothing enrolled, so dead and idle differ.
        emit_monitor_cycle(
            HEARTBEAT_PROTOCOL_SCANNER,
            started=started,
            contracts_scanned=0,
            blocks_scanned=0,
            events_found=0,
            partial=False,
            note="no_active_contracts",
        )
        return ScanResult([])

    # Cohorts are (chain, block bucket) groups split at the batch size; buckets use the chain's getLogs range.
    grouped: dict[tuple[str, int], list] = defaultdict(list)
    for row in index_rows:
        grouped[(row.chain, row.last_scanned_block // _max_getlogs_range_for(row.chain))].append(row)

    cohorts: list[_Cohort] = []
    for (chain, _bucket), members in grouped.items():
        for i in range(0, len(members), address_batch):
            batch = members[i : i + address_batch]
            cohorts.append(
                _Cohort(
                    chain=chain,
                    member_ids=[r.id for r in batch],
                    addresses=[r.address.lower() for r in batch],
                    cursor=min(r.last_scanned_block for r in batch),
                )
            )

    # Scan only under the per-chain daemon lease; with none held, still beat (``lease_lost``).
    lease_holder = _LEASE_HOLDER
    lease_ttl = _scan_int_env("PSAT_DAEMON_LEASE_TTL_S", DEFAULT_DAEMON_LEASE_TTL_S)
    held_chains = {
        chain
        for chain in {c.chain for c in cohorts}
        if try_acquire_daemon_lease(session, _scanner_lease_name(chain), lease_holder, lease_ttl)
    }
    if not held_chains:
        emit_monitor_cycle(
            HEARTBEAT_PROTOCOL_SCANNER,
            started=started,
            contracts_scanned=len(index_rows),
            blocks_scanned=0,
            events_found=0,
            partial=False,
            note="lease_lost",
        )
        return ScanResult([])
    cohorts = [c for c in cohorts if c.chain in held_chains]

    # Resolved per chain, since block time differs.
    runaway_lag_by_chain = {chain: _runaway_lag_blocks_for(chain) for chain in {c.chain for c in cohorts}}

    # Each chain resolves its own route; mainnet keeps the incoming URL.
    rpc_by_chain = {chain: rpc_for_chain(chain, rpc_url) for chain in {c.chain for c in cohorts}}
    fetchers: dict[str, RpcEventLogFetcher] = {}
    head_by_chain: dict[str, int] = {}

    def _head_for(chain: str) -> int:
        if chain not in head_by_chain:
            head_by_chain[chain] = get_latest_block(rpc_by_chain[chain], chain_id=chain_id_for(chain))
        return head_by_chain[chain]

    def _fetcher_for(chain: str) -> RpcEventLogFetcher:
        if chain not in fetchers:
            fetchers[chain] = RpcEventLogFetcher(
                rpc_by_chain[chain],
                max_block_range=_max_getlogs_range_for(chain),
                min_bisect_span=FETCHER_MIN_BISECT_SPAN,
                chain_id=chain_id_for(chain),
            )
        return fetchers[chain]

    topics_union = _scan_topics_union(session)

    total_new_events: list[MonitoredEvent] = []
    windows_scanned = 0
    blocks_scanned = 0
    degraded = False
    budget_exhausted = False
    # Accumulated across the pass so repeated hints on one controller cost one read.
    dirty_controllers: dict[tuple[uuid.UUID, str], _DirtyController] = {}
    # Pass-scoped decode drops (see ``_process_window``).
    scan_counters: dict[str, int] = {}

    while windows_scanned < max_windows_pass:
        eligible: list[tuple[_Cohort, int]] = []
        for cohort in cohorts:
            if cohort.done or cohort.failed:
                continue
            if cohort.chain not in held_chains:
                continue
            confirmed_head = _head_for(cohort.chain) - _confirmation_depth_for(cohort.chain)
            if cohort.cursor >= confirmed_head:
                cohort.done = True
                continue
            runaway_lag = runaway_lag_by_chain.get(cohort.chain, 0)
            cohort.runaway = runaway_lag > 0 and (confirmed_head - cohort.cursor) > runaway_lag
            if cohort.runaway and cohort.windows_this_pass >= runaway_windows:
                continue  # already served its capped slice this pass
            eligible.append((cohort, confirmed_head))
        if not eligible:
            break

        # Healthy cohorts first, most-behind-first; runaways only when nothing else waits.
        eligible.sort(key=lambda item: (item[0].runaway, -(item[1] - item[0].cursor)))
        cohort, confirmed_head = eligible[0]

        turn_cap = max_windows_cohort
        if cohort.runaway:
            turn_cap = min(turn_cap, runaway_windows - cohort.windows_this_pass)

        turn_windows = 0
        while turn_windows < turn_cap and windows_scanned < max_windows_pass:
            window_start = cohort.cursor + 1
            if window_start > confirmed_head:
                cohort.done = True
                break
            window_end = min(cohort.cursor + _max_getlogs_range_for(cohort.chain), confirmed_head)

            # An empty address list would match any address.
            if not cohort.addresses:
                cohort.done = True
                break

            try:
                fetched_logs = _fetcher_for(cohort.chain).fetch_logs(
                    event_address=cohort.addresses,
                    topics=topics_union,
                    from_block=window_start,
                    to_block=window_end,
                )
            except Exception as exc:
                # The fetcher's bisect gave up; don't advance the cursor.
                logger.warning(
                    "eth_getLogs failed for blocks %d-%d: %s",
                    window_start,
                    window_end,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                degraded = True
                cohort.failed = True
                break

            window_events = _process_window(
                session, cohort, fetched_logs, window_start, window_end, dirty_controllers, scan_counters
            )

            # Enrich after the insert decides which rows are real, before the commit that precedes notification.
            # Reanalysis doesn't depend on enrichment.
            enrich_events(session, window_events, rpc_by_chain)

            # Advance cursors in the same transaction as the events; GREATEST means stale writers can't rewind.
            session.execute(
                update(MonitoredContract)
                .where(MonitoredContract.id.in_(cohort.member_ids))
                .values(last_scanned_block=func.greatest(MonitoredContract.last_scanned_block, window_end))
                .execution_options(synchronize_session=False)
            )
            session.commit()

            # Per window, so long catch-ups don't buffer notifications.
            _notify_committed_events(session, window_events)

            cohort.cursor = window_end
            total_new_events.extend(window_events)
            blocks_scanned += window_end - window_start + 1
            windows_scanned += 1
            turn_windows += 1
            cohort.windows_this_pass += 1

            # Renew after the durable commit; a lost renew ends the chain's cohorts without undoing this window.
            if not renew_daemon_lease(session, _scanner_lease_name(cohort.chain), lease_holder, lease_ttl):
                held_chains.discard(cohort.chain)
                break

    # Resolve hints once per pass, only for chains whose lease is still held: ``value_changed`` rows have NULL
    # ``log_index`` and no ON CONFLICT guard, so a second scanner would double-post.
    held_dirty = {key: member for key, member in dirty_controllers.items() if member.chain in held_chains}
    if len(held_dirty) != len(dirty_controllers):
        logger.info(
            "Dropping %d dirty controller(s) on chains whose scanner lease was lost",
            len(dirty_controllers) - len(held_dirty),
        )
    try:
        verification = _resolve_verification_reads(session, held_dirty, rpc_by_chain)
    except Exception as exc:
        logger.warning(
            "Verification-read pass failed: %s",
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        # Windows are committed; don't roll them back.
        session.rollback()
        degraded = True
        # Not zero: the pass stopped before outcomes were countable.
        verification = _VerificationOutcome([], reads_failed=None, reads_over_budget=None)
    if verification.units_failed:
        # A deadlocked unit left no other trace; don't report clean.
        degraded = True
    if verification.events:
        _notify_committed_events(session, verification.events)
        total_new_events.extend(verification.events)

    # Only when stopped at the hard cap with work left.
    if windows_scanned >= max_windows_pass:
        budget_exhausted = any(
            not c.done and not c.failed and c.cursor < (_head_for(c.chain) - _confirmation_depth_for(c.chain))
            for c in cohorts
        )

    # Head minus min cursor across contracts, against raw head.
    max_lag = 0
    for cohort in cohorts:
        max_lag = max(max_lag, _head_for(cohort.chain) - cohort.cursor)
    max_lag = max(0, max_lag)

    runaway_cohorts = sum(1 for c in cohorts if c.runaway and not c.done and not c.failed)
    if runaway_cohorts:
        logger.warning(
            "scan: %d cohort(s) past the runaway lag threshold — capped at %d window(s) this pass",
            runaway_cohorts,
            runaway_windows,
            extra={
                "runaway_cohorts": runaway_cohorts,
                "runaway_lag_blocks_by_chain": runaway_lag_by_chain,
                "max_lag_blocks": max_lag,
                "reason": "cursor_runaway",
            },
        )

    emit_monitor_cycle(
        HEARTBEAT_PROTOCOL_SCANNER,
        started=started,
        contracts_scanned=len(index_rows),
        blocks_scanned=blocks_scanned,
        events_found=len(total_new_events),
        partial=degraded,
        note="no_new_blocks" if windows_scanned == 0 and not degraded else None,
        extra_detail={
            "max_lag_blocks": max_lag,
            "windows_scanned": windows_scanned,
            "cohorts": len(cohorts),
            "budget_exhausted": budget_exhausted,
            "runaway_cohorts": runaway_cohorts,
            "verification_units_failed": verification.units_failed,
            # Per-pass complement to the markers, which the poller erases. ``None`` means the verification pass didn't
            # complete.
            "verification_reads_failed": verification.reads_failed,
            "verification_reads_over_budget": verification.reads_over_budget,
            # Not partial (nothing observed was withheld), but reveals spec/decoder drift.
            "undecodable_tracked_logs": scan_counters.get("undecodable_tracked_logs", 0),
        },
    )
    return ScanResult(
        total_new_events,
        budget_exhausted=budget_exhausted,
        windows_scanned=windows_scanned,
        cohorts=len(cohorts),
        max_lag_blocks=max_lag,
        degraded=degraded,
        runaway_cohorts=runaway_cohorts,
    )


def _sync_relational_tables(
    session: Session,
    mc: MonitoredContract,
    parsed: dict,
) -> None:
    """Propagate a detected event to Contract / ControllerValue / UpgradeEvent, one update per ``effect_tags.writes``
    target (legacy events synthesize tags).

    Needs a linked contract_id. A controller rotation marks the protocol dirty so a new governance Safe is enrolled
    within one drain tick.
    """
    if not mc.contract_id:
        return

    event_type = parsed["event_type"]
    # A mapping entry is not the slot's value; the entry change stops at its own event.
    if is_member_changed_event_type(event_type):
        return

    tags = parsed.get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = tags.get("writes") or []
    delegates = bool(tags.get("delegates"))

    contract: Contract | None = None
    rotated = False

    def _get_contract() -> Contract | None:
        nonlocal contract
        if contract is None:
            contract = session.get(Contract, mc.contract_id)
        return contract

    # Delegate-target swaps update Contract.implementation, add an UpgradeEvent and refresh coverage.
    impl_writes = {"implementation", "beacon", "facets"}
    if delegates and any(w in impl_writes for w in writes if isinstance(w, str)):
        new_impl = parsed.get("implementation") or parsed.get("beacon")
        if new_impl:
            c = _get_contract()
            if c is not None:
                old_impl = c.implementation
                if (old_impl or "").lower() != str(new_impl).lower():
                    rotated = True
                c.implementation = new_impl
                session.add(
                    UpgradeEvent(
                        contract_id=c.id,
                        proxy_address=mc.address,
                        old_impl=old_impl,
                        new_impl=new_impl,
                        block_number=parsed.get("block_number"),
                        tx_hash=parsed.get("tx_hash"),
                        # A log has a block, not a block time, and historical windows make detection time meaningless:
                        # NULL (not determined).
                        source=UPGRADE_SOURCE_EVENT_SCAN,
                    )
                )
                # Coverage windows derive from upgrade history; rebuild for the protocol (idempotent).
                _refresh_coverage_after_upgrade(session, c.protocol_id)

    # Contract.admin shadow plus ControllerValue rows in all three id forms.
    for write_target in writes:
        if not isinstance(write_target, str):
            continue
        new_value = _new_value_for_write_target(write_target, parsed)
        if new_value is None:
            continue

        if write_target == "admin":
            c = _get_contract()
            if c is not None:
                if (c.admin or "").lower() != str(new_value).lower():
                    rotated = True
                c.admin = str(new_value)

        if _update_controller_value_rows(
            session,
            mc,
            write_target,
            new_value,
            observed_via=CONTROLLER_OBSERVED_VIA_EVENT_LOG,
            block_number=parsed.get("block_number"),
        ):
            if write_target in _GOVERNANCE_ROTATION_WRITE_TARGETS:
                rotated = True

    if rotated:
        c = _get_contract()
        if c is not None and c.protocol_id:
            mark_enrollment_dirty(session, c.protocol_id, _GOVERNANCE_ROTATION_REASON)


def _refresh_coverage_after_upgrade(session: Session, protocol_id: int | None) -> None:
    """Rebuild ``audit_contract_coverage`` after an upgrade, swallowing errors so a coverage bug can't block
    recording the upgrade.
    """
    if not protocol_id:
        return
    # Local import keeps coverage off the hot path.
    from services.audits.coverage import upsert_coverage_for_protocol

    try:
        # Source-equivalence is deferred to ``CoverageVerifyWorker``; inline verification caused Etherscan/GitHub
        # rate-limit cascades (#82).
        upsert_coverage_for_protocol(session, protocol_id, verify_source_equivalence=False)
    except Exception as exc:
        logger.warning(
            "Failed to refresh audit coverage for protocol %s after upgrade: %s",
            protocol_id,
            exc,
            extra={"exc_type": type(exc).__name__},
        )


def _update_controller_value_rows(
    session: Session,
    mc: MonitoredContract,
    write_target: str,
    new_value: object,
    *,
    observed_via: str,
    block_number: int | None = None,
) -> bool:
    """Write *new_value* into the ControllerValue rows for all three controller_id forms; True iff a value moved.

    Shared by event and poll sync so custom slots work through either. On a move, ``resolved_type`` and ``details`` are
    cleared: they describe the old address and this code can't re-classify. Keeping them once published a new EOA as
    ``timelock`` with the old delay (a false scoring credit), and gave a new Safe the old one's owners.
    ``block_number``/``observed_via`` are reset too (None from polls).

    Rows update in place: consumers read ``controller_values`` as current state without dedup. History lives in
    ``upgrade_events`` and ``principal_history``.
    """
    if not mc.contract_id:
        return False
    controller_ids = (
        write_target,
        f"state_variable:{write_target}",
        f"external_contract:{write_target}",
    )
    cv_rows = (
        session.execute(
            select(ControllerValue).where(
                ControllerValue.contract_id == mc.contract_id,
                ControllerValue.controller_id.in_(controller_ids),
            )
        )
        .scalars()
        .all()
    )
    changed = False
    nv = str(new_value)
    for cv in cv_rows:
        if cv.value != nv:
            cv.value = nv
            cv.resolved_type = None
            cv.details = None
            cv.block_number = block_number
            cv.observed_via = observed_via
            changed = True
    return changed


def _write_through_proxy_read(
    session: Session,
    mc: MonitoredContract,
    field_name: str,
    new_value: object,
    old_value: object,
) -> None:
    """Record a slot-read implementation change on WatchedProxy.

    Shared by the poller and verification reads, since whichever sees the change first silences the other. Skipping it
    freezes ``last_known_implementation``, which every later scanner-detected upgrade publishes as its old value.
    """
    if field_name != "implementation" or not mc.watched_proxy_id:
        return
    wp = session.get(WatchedProxy, mc.watched_proxy_id)
    if not wp:
        return
    session.add(
        ProxyUpgradeEvent(
            watched_proxy_id=wp.id,
            # A read has no block or tx.
            block_number=0,
            tx_hash="",
            old_implementation=str(old_value) if old_value else None,
            new_implementation=str(new_value),
            event_type="storage_poll",
        )
    )
    wp.last_known_implementation = str(new_value)


def _sync_relational_from_poll(
    session: Session,
    mc: MonitoredContract,
    field_name: str,
    new_value: object,
    old_value: object,
) -> None:
    """Propagate a poll-detected change to relational tables.

    ``implementation`` keeps its dedicated branch (shadow column, UpgradeEvent, coverage refresh); everything else goes
    through the generic ControllerValue updater. A rotation marks the protocol dirty. Only called when the value
    actually changed.
    """
    if not mc.contract_id:
        return

    if field_name == "implementation":
        contract = session.get(Contract, mc.contract_id)
        if contract:
            contract.implementation = str(new_value)
            session.add(
                UpgradeEvent(
                    contract_id=contract.id,
                    proxy_address=mc.address,
                    old_impl=str(old_value) if old_value else None,
                    new_impl=str(new_value),
                    # No block is knowable. NULL, not 0: 0 would sort first among NULLS LAST and shift every impl
                    # window.
                    block_number=None,
                    tx_hash=None,
                    # Detection time (within one poll interval), distinguished by ``source``. NULL here once collapsed
                    # post-upgrade audit confidence.
                    timestamp=datetime.now(timezone.utc),
                    source=UPGRADE_SOURCE_POLL,
                )
            )
            _refresh_coverage_after_upgrade(session, contract.protocol_id)
            if contract.protocol_id:
                mark_enrollment_dirty(session, contract.protocol_id, _GOVERNANCE_ROTATION_REASON)
        return

    # NULL block rather than the previous read's.
    if _update_controller_value_rows(
        session,
        mc,
        field_name,
        new_value,
        observed_via=CONTROLLER_OBSERVED_VIA_STORAGE_POLL,
        block_number=None,
    ):
        if field_name in _GOVERNANCE_ROTATION_WRITE_TARGETS:
            contract = session.get(Contract, mc.contract_id)
            if contract is not None and contract.protocol_id:
                mark_enrollment_dirty(session, contract.protocol_id, _GOVERNANCE_ROTATION_REASON)


def _rpc_call_for_entry(address: str, entry: dict) -> tuple[str, list] | None:
    """Polling-plan entry to JSON-RPC ``(method, params)``; ``None`` for unknown kinds, which are skipped so schema
    additions can't break a running watcher.
    """
    kind = entry.get("kind")
    if kind == "getter_call":
        selector = entry.get("selector")
        if not selector:
            return None
        return ("eth_call", [{"to": address, "data": selector}, "latest"])
    if kind == "storage_slot":
        slot = entry.get("slot")
        if not slot:
            return None
        return ("eth_getStorageAt", [address, slot, "latest"])
    return None


def _apply_poll_result(
    session: Session,
    mc: MonitoredContract,
    entry: dict,
    raw: str | None,
    new_events: list[MonitoredEvent],
) -> bool:
    """Decode one poll result; on change, persist ``last_known_state``, emit ``state_changed_poll``, and run
    downstream sync.

    Only answered, error-free results arrive here, so an unparsed decode means an empty or unparseable body. Returns
    True iff the body parsed as the declared type (including a zero address); False tells the caller to publish
    ``no_value``.
    """
    field_name = entry.get("field")
    if not isinstance(field_name, str) or not field_name:
        return False
    new_value, parsed = decode_poll_outcome(project_entry_return(raw, entry), entry.get("type_kind"), entry.get("type"))
    if new_value is None:
        return parsed

    state = dict(mc.last_known_state or {})
    old_value = state.get(field_name)
    if new_value == old_value:
        return True

    # Recorded even on first observation, as the baseline.
    state[field_name] = new_value
    mc.last_known_state = state
    flag_modified(mc, "last_known_state")

    if old_value is None:
        logger.debug(
            "Initial %s observation on %s: %s (no event emitted)",
            field_name,
            mc.address,
            new_value,
        )
        return True

    # Skip if the scanner already recorded this mutation (per-entry suppress lists from enrollment).
    scan_types = entry.get("suppress_when_scan_event_types") or []
    if isinstance(scan_types, list) and scan_types:
        suppression_cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=DEFAULT_POLL_INTERVAL * 2,
        )
        already = session.execute(
            select(MonitoredEvent.id)
            .where(
                MonitoredEvent.monitored_contract_id == mc.id,
                MonitoredEvent.event_type.in_(scan_types),
                MonitoredEvent.detected_at >= suppression_cutoff,
            )
            .limit(1)
        ).scalar_one_or_none()
        if already is not None:
            logger.debug(
                "Suppressing poll event for %s/%s — scanner already detected it",
                mc.address,
                field_name,
            )
            return True

    # Mint site 3 of 3: stamp the entry's signal_class for salience.
    event_data: dict[str, Any] = {
        "field": field_name,
        "old_value": str(old_value),
        "new_value": str(new_value),
    }
    stamp_signal_class(event_data, entry)
    salience, salience_basis = assign_salience(session, "state_changed_poll", event_data, mc)
    event_data["salience"] = salience
    event_data["salience_basis"] = salience_basis

    event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type="state_changed_poll",
        block_number=0,
        tx_hash="",
        data=event_data,
    )
    session.add(event)
    new_events.append(event)

    logger.info(
        "Poll detected %s change on %s: %s -> %s",
        field_name,
        mc.address,
        old_value,
        new_value,
    )

    _write_through_proxy_read(session, mc, field_name, new_value, old_value)

    _sync_relational_from_poll(session, mc, field_name, new_value, old_value)

    try:
        poll_data = {
            "field": field_name,
            "old_value": str(old_value),
            "new_value": str(new_value),
        }
        reanalysis_job = maybe_queue_reanalysis(
            session,
            mc,
            "state_changed_poll",
            poll_data,
        )
        if reanalysis_job:
            updated = dict(event.data or {})
            updated["reanalysis_job_id"] = str(reanalysis_job.id)
            event.data = updated
    except _DB_ERROR_TYPES:
        # The reanalysis Job SELECT autoflushes the staged UPDATE (a deadlock candidate). DB errors re-raise to the
        # chunk handler; only local reanalysis failures fall through to the warning.
        raise
    except Exception as exc:
        logger.warning(
            "Failed to queue re-analysis for %s: %s",
            mc.address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
    return True


def poll_for_state_changes(session: Session, rpc_url: str) -> list[MonitoredEvent]:
    """Poll for state changes by walking each contract's persisted ``polling_plan``.

    Each pass claims the ``PSAT_POLL_CONTRACTS_PER_PASS`` least-recently-polled contracts and packs their entries into
    ``MAX_BATCH_SIZE`` chunks (never splitting a contract). Each chunk is decoded, synced, stamped, committed and
    notified on its own.

    Answered chunks overwrite ``last_poll_status`` with ``{field: "ok" | "error" | "no_value"}``: ``ok`` parsed
    (including a zero address), ``error`` a per-call JSON-RPC error, ``no_value`` an empty or unparseable body. A
    missing field wasn't polled. Transport failures observed nothing: no status, no stamp, retry first next pass.
    Per-call errors stamp and rotate, otherwise always-reverting legacy entries would pin the front forever. Any error,
    no_value or transport failure marks the pass partial.

    A chunk that deadlocks with the scanner rolls back and retries first; other DB errors end the pass. Contracts
    without a plan still rotate until the reconciler backfills one.

    The ``protocol_poller:<chain>`` lease is load-bearing: poll rows have NULL ``log_index`` and no identity-index
    protection, so concurrent passes could double-insert. The same holds for the scanner's verification reads.
    """
    started = time.monotonic()
    slice_size = int(os.getenv("PSAT_POLL_CONTRACTS_PER_PASS", str(DEFAULT_POLL_CONTRACTS_PER_PASS)))
    contracts = (
        session.execute(
            select(MonitoredContract)
            .where(
                MonitoredContract.is_active == True,  # noqa: E712
                MonitoredContract.needs_polling == True,  # noqa: E712
            )
            .order_by(MonitoredContract.last_polled_at.asc().nullsfirst())
            .limit(slice_size)
        )
        .scalars()
        .all()
    )
    if not contracts:
        emit_monitor_cycle(
            HEARTBEAT_PROTOCOL_POLLER,
            started=started,
            contracts_scanned=0,
            blocks_scanned=0,
            events_found=0,
            partial=False,
            note="no_active_contracts",
        )
        return []

    # Acquire the per-chain lease before any RPC; with none held, yield (``lease_lost``) but still beat.
    lease_holder = _LEASE_HOLDER
    lease_ttl = int(os.getenv("PSAT_DAEMON_LEASE_TTL_S", str(DEFAULT_DAEMON_LEASE_TTL_S)))
    held_chains = {
        chain
        for chain in {mc.chain for mc in contracts}
        if try_acquire_daemon_lease(session, _poller_lease_name(chain), lease_holder, lease_ttl)
    }
    if not held_chains:
        emit_monitor_cycle(
            HEARTBEAT_PROTOCOL_POLLER,
            started=started,
            contracts_scanned=len(contracts),
            blocks_scanned=0,
            events_found=0,
            partial=False,
            note="lease_lost",
        )
        return []
    contracts = [mc for mc in contracts if mc.chain in held_chains]

    # Oldest cursor in the slice before stamping; never-polled reads as None.
    now = datetime.now(timezone.utc)
    polled_ats = [mc.last_polled_at for mc in contracts]
    if any(ts is None for ts in polled_ats):
        oldest_age_s = None
    else:
        oldest_age_s = int((now - min(ts for ts in polled_ats if ts)).total_seconds())

    # Partition by chain so a chunk's batch goes to one chain; pack whole contracts into chunks.
    contracts_by_chain: dict[str, list[MonitoredContract]] = defaultdict(list)
    for mc in contracts:
        contracts_by_chain[mc.chain].append(mc)

    chunks: list[tuple[str, list[tuple[MonitoredContract, list[tuple[dict, tuple[str, list]]]]]]] = []
    # Entries that couldn't become calls: skipped deliberately, but counted so a plan in an unknown kind doesn't look
    # like nothing to poll.
    entries_unrecognized = 0
    for chunk_chain, chain_contracts in contracts_by_chain.items():
        current: list[tuple[MonitoredContract, list[tuple[dict, tuple[str, list]]]]] = []
        current_calls = 0
        for mc in chain_contracts:
            plan = (mc.monitoring_config or {}).get("polling_plan") or []
            entries: list[tuple[dict, tuple[str, list]]] = []
            if isinstance(plan, list):
                for entry in plan:
                    if not isinstance(entry, dict):
                        entries_unrecognized += 1
                        continue
                    call = _rpc_call_for_entry(mc.address, entry)
                    if call is None:
                        entries_unrecognized += 1
                        continue
                    entries.append((entry, call))
            if current and current_calls + len(entries) > MAX_BATCH_SIZE:
                chunks.append((chunk_chain, current))
                current = []
                current_calls = 0
            current.append((mc, entries))
            current_calls += len(entries)
        if current:
            chunks.append((chunk_chain, current))

    new_events: list[MonitoredEvent] = []
    chunks_failed = 0
    chunks_transport_failed = 0
    entry_errors = 0
    entries_no_value = 0

    for chunk_chain, chunk in chunks:
        chunk_ids = [mc.id for mc, _ in chunk]
        chunk_rpc_url = rpc_for_chain(chunk_chain, rpc_url)
        batch_calls: list[tuple[str, list]] = []
        # (contract, batch_index, entry_dict)
        dispatch: list[tuple[MonitoredContract, int, dict]] = []
        for mc, entries in chunk:
            for entry, call in entries:
                dispatch.append((mc, len(batch_calls), entry))
                batch_calls.append(call)

        # Keeps reverts (``error``, an answered negative) apart from unanswered slots (``transport``); never raises.
        results = rpc_batch_request_classified(chunk_rpc_url, batch_calls) if batch_calls else []

        if any(status == "transport" for _raw, status in results):
            # Some slot unobserved: publish nothing for the chunk and leave it unstamped to retry first.
            chunks_transport_failed += 1
            logger.warning(
                "Poll chunk transport-failed; nothing published, retrying next pass: %s",
                [mc.address for mc, _ in chunk],
                extra={"chain": chunk_chain, "calls": len(batch_calls)},
            )
            continue

        # Decode, apply, stamp and commit as one unit under deadlock isolation; any of those can lose to the scanner's
        # cursor UPDATE. Events are collected locally so a rollback discards exactly its detections.
        chunk_events: list[MonitoredEvent] = []
        chunk_entry_errors = 0
        chunk_entries_no_value = 0
        try:
            statuses: dict[uuid.UUID, dict[str, str]] = {mc.id: {} for mc, _ in chunk}
            for mc, idx, entry in dispatch:
                raw, status = results[idx]
                field_name = entry.get("field")
                if status == "error":
                    chunk_entry_errors += 1
                    if isinstance(field_name, str) and field_name:
                        statuses[mc.id][field_name] = "error"
                    continue
                decoded = _apply_poll_result(session, mc, entry, raw, chunk_events)
                if not decoded:
                    chunk_entries_no_value += 1
                if isinstance(field_name, str) and field_name:
                    statuses[mc.id][field_name] = "ok" if decoded else "no_value"
            # Overwrite wholesale: this pass dispatched every recognizable entry.
            for mc, _entries in chunk:
                mc.last_poll_status = statuses[mc.id]
                flag_modified(mc, "last_poll_status")
            session.execute(
                update(MonitoredContract).where(MonitoredContract.id.in_(chunk_ids)).values(last_polled_at=func.now())
            )
            session.commit()
        except _DB_ERROR_TYPES as exc:
            if not _is_deadlock_error(exc):
                # Not recoverable per chunk; let the pass die and record an honest degraded cycle.
                raise
            # Deadlock: roll back (including staged state mutations), leave unstamped, continue.
            session.rollback()
            chunks_failed += 1
            logger.warning(
                "Poll chunk deadlocked; rolled back, retrying next pass: %s",
                [mc.address for mc, _ in chunk],
                extra={"exc_type": type(getattr(exc, "orig", None) or exc).__name__},
            )
            continue

        # Durable: notify now so a later chunk's failure can't strand these.
        entry_errors += chunk_entry_errors
        entries_no_value += chunk_entries_no_value
        _notify_committed_events(session, chunk_events)
        new_events.extend(chunk_events)

        # Renew after the durable commit; a lost renew stops the remaining chunks without rollback.
        renewed = [
            renew_daemon_lease(session, _poller_lease_name(chain), lease_holder, lease_ttl) for chain in held_chains
        ]
        if not all(renewed):
            break

    emit_monitor_cycle(
        HEARTBEAT_PROTOCOL_POLLER,
        started=started,
        contracts_scanned=len(contracts),
        blocks_scanned=0,
        events_found=len(new_events),
        # Partial iff some entry produced no observation (deadlock, transport, error, no_value); an answered zero
        # address is ``ok``.
        partial=chunks_failed > 0 or chunks_transport_failed > 0 or entry_errors > 0 or entries_no_value > 0,
        extra_detail={
            "contracts_selected": len(contracts),
            "chunks": len(chunks),
            "chunks_failed": chunks_failed,
            "chunks_transport_failed": chunks_transport_failed,
            "entry_errors": entry_errors,
            "entries_no_value": entries_no_value,
            # Not partial: never dispatched, so nothing failed to be observed.
            "entries_unrecognized": entries_unrecognized,
            "oldest_last_polled_age_s": oldest_age_s,
        },
    )
    return new_events


def run_scan_loop(
    rpc_url: str,
    interval: float = DEFAULT_SCAN_INTERVAL,
    stop_event: Event | None = None,
) -> None:
    """Run the event scanner in a blocking loop, re-running after the short busy interval when a pass exhausts its
    window budget. *stop_event* interrupts the wait on shutdown.
    """
    stop_event = stop_event or Event()
    logger.info("Starting unified protocol monitor (interval=%ss)", interval)
    busy_interval = _scan_float_env("PSAT_SCAN_BUSY_INTERVAL_S", 5.0)
    while not stop_event.is_set():
        sleep_for = interval
        try:
            with SessionLocal() as session:
                result = scan_for_events(session, rpc_url)
            if result:
                logger.info("Detected %d new event(s)", len(result))
            if result.budget_exhausted:
                sleep_for = busy_interval
        except Exception as exc:
            logger.warning("Scan cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
            # It raised before its own summary; still beat as degraded.
            record_heartbeat(
                HEARTBEAT_PROTOCOL_SCANNER,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        stop_event.wait(sleep_for)


def run_poll_loop(
    rpc_url: str,
    interval: float = DEFAULT_POLL_INTERVAL,
    stop_event: Event | None = None,
    startup_offset_s: float | None = None,
) -> None:
    """Run the state polling loop; notification happens per chunk inside ``poll_for_state_changes``.

    The first pass is offset from the scanner's (``_poll_startup_offset``) so the equal-interval loops don't deadlock in
    lockstep; ``startup_offset_s=0`` for the standalone ``--poll`` runner. *stop_event* interrupts the wait on shutdown.
    """
    stop_event = stop_event or Event()
    logger.info("Starting unified protocol poller (interval=%ss)", interval)
    offset = _poll_startup_offset(interval) if startup_offset_s is None else max(0.0, startup_offset_s)
    # Beat before the offset wait; an unbeaten heartbeat reads stale and would page on fresh deploys.
    record_heartbeat(HEARTBEAT_PROTOCOL_POLLER, status="starting", detail={"note": "starting", "partial": False})
    if offset and stop_event.wait(offset):
        return
    while not stop_event.is_set():
        try:
            with SessionLocal() as session:
                new_events = poll_for_state_changes(session, rpc_url)
                if new_events:
                    logger.info("Poll detected %d state change(s)", len(new_events))
        except Exception as exc:
            logger.warning("Poll cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
            # It raised before its own summary; still beat as degraded.
            record_heartbeat(
                HEARTBEAT_PROTOCOL_POLLER,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        stop_event.wait(interval)
