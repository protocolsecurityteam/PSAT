"""Unified protocol monitoring — scans blocks for all governance + proxy events."""

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
from typing import Callable

from dotenv import load_dotenv
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import OperationalError
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
from services.monitoring import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_SCANNER,
    emit_monitor_cycle,
)
from services.monitoring.chain_rpc import chain_id_for, rpc_for_chain
from services.monitoring.enrollment import mark_enrollment_dirty
from services.monitoring.event_topics import (
    _HANDROLLED_EVENT_TYPE_TO_TAGS,
    ALL_EVENT_TOPICS,
    PROXY_EVENT_TOPICS,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
    WITNESS_TIERS,
    classify_witness_tier,
    parse_any_log,
    parse_tracked_log,
    value_changed_event_type,
)
from services.monitoring.polling_plan import decode_poll_outcome
from services.monitoring.reanalysis import maybe_queue_reanalysis
from services.monitoring.verify_status import (
    VERIFY_ERROR,
    VERIFY_NO_VALUE,
    VERIFY_OVER_BUDGET,
    VERIFY_UNANSWERED,
    record_verify_status,
)
from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher
from utils.chains import UnknownChainError, chain_by_name
from utils.rpc import (
    MAX_BATCH_SIZE,
    rpc_batch_request_classified,
    rpc_request,
)

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)

MAX_BLOCK_RANGE = 2000
DEFAULT_SCAN_INTERVAL = int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600"))
DEFAULT_POLL_INTERVAL = int(os.getenv("PROTOCOL_POLL_INTERVAL", "600"))
# Poller rotation slice — how many needs_polling contracts one pass claims,
# ordered oldest-cursor-first. Bounds the pass to O(slice) memory.
DEFAULT_POLL_CONTRACTS_PER_PASS = 500

# monitored_events must only ingest confirmed logs — a reorg-rewound event
# would have already fired a Discord notification and a reanalysis job that
# cannot be un-sent. Every window end is clamped to head − this depth.
DEFAULT_CONFIRMATION_DEPTH = 12
# The shared getLogs fetcher bisects a rejected window down to this floor
# before re-raising. It must sit well below MAX_BLOCK_RANGE so a provider
# range/response-cap rejection actually bisects instead of failing the cohort.
FETCHER_MIN_BISECT_SPAN = 125

# One read per dirty controller per scan pass. Reads beyond this are RECORDED
# as skipped (services/monitoring/verify_status.py), never silently dropped —
# a skipped read is a not-determined interval, not an earned negative.
DEFAULT_MAX_VERIFY_READS_PER_PASS = 25

# Reason stamped on the enrollment-queue row when the watcher's relational sync
# observes an on-chain controller rotation (owner/admin/authority/implementation).
# Closes the gap where a rotation installs a new governance Safe that would
# otherwise stay unmonitored until the slow sweep.
_GOVERNANCE_ROTATION_REASON = "governance_rotation"

# Write targets whose sync actually installs a new privileged controller — the
# only changes that can bring a new governance principal into scope and so
# warrant re-enrolling the protocol. Pause/threshold/roles writes mutate state
# but don't add a controller address, so they don't mark.
_GOVERNANCE_ROTATION_WRITE_TARGETS = frozenset(
    {"owner", "_owner", "admin", "_admin", "authority", "implementation", "beacon"}
)


# Stable per-process lease holder. Generated once at import so every pass this
# interpreter runs re-acquires its OWN lease (the ``holder = EXCLUDED.holder``
# branch always wins), and a genuinely separate process — the thing the
# singleton lease exists to exclude — carries a different uuid and loses.
_LEASE_HOLDER = uuid.uuid4()


def _scanner_lease_name(chain: str) -> str:
    return f"protocol_scanner:{chain}"


def _poller_lease_name(chain: str) -> str:
    return f"protocol_poller:{chain}"


def _scan_int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _scan_float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _max_getlogs_range_for(chain: str) -> int:
    """Per-chain getLogs window width from the registry. Mainnet's
    registry value equals ``MAX_BLOCK_RANGE`` so mainnet is unchanged; an
    unresolvable chain falls back to the fleet-wide constant."""
    try:
        return chain_by_name(chain).max_getlogs_range
    except UnknownChainError:
        return MAX_BLOCK_RANGE


def _confirmation_depth_for(chain: str) -> int:
    """Per-chain reorg-confirmation depth. An explicit
    ``PSAT_SCAN_CONFIRMATION_DEPTH`` override still wins fleet-wide (operator
    lever); otherwise the registry's per-chain depth applies. Mainnet's registry
    value equals ``DEFAULT_CONFIRMATION_DEPTH`` so mainnet is unchanged."""
    raw = os.getenv("PSAT_SCAN_CONFIRMATION_DEPTH")
    if raw is not None:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    try:
        return chain_by_name(chain).confirmation_depth
    except UnknownChainError:
        return DEFAULT_CONFIRMATION_DEPTH


# psycopg2 raises DeadlockDetected (SQLSTATE 40P01) when Postgres aborts one
# side of a lock cycle. Driver errors from real cursor executes (including
# autoflush) always arrive wrapped in a SQLAlchemy OperationalError (``.orig``);
# the raw psycopg2 form only occurs when an error is raised from an event
# listener (e.g. before_cursor_execute in tests), which SQLAlchemy does not
# wrap. Both shapes are recognized as belt-and-braces. The
# defensive import mirrors workers/retry_policy.py so a psycopg2-less test env
# still imports the module.
try:
    import psycopg2  # type: ignore[import-untyped]
    from psycopg2.errors import DeadlockDetected as _PgDeadlockDetected  # type: ignore[import-untyped]

    _DEADLOCK_TYPES: tuple[type[BaseException], ...] = (_PgDeadlockDetected,)
    _PSYCOPG2_ERROR: tuple[type[BaseException], ...] = (psycopg2.Error,)
except Exception:  # pragma: no cover — psycopg2 is a hard dep in production
    _DEADLOCK_TYPES = ()
    _PSYCOPG2_ERROR = ()

_DEADLOCK_PGCODE = "40P01"

# Every DB error shape a chunk's writes can raise: SQLAlchemy's wrapper plus the
# raw psycopg2 error (which is NOT a subclass of SQLAlchemy's). Both poison the
# session, so both must reach the chunk handler rather than a bare
# ``except Exception`` that would swallow them into a pending-rollback session.
_DB_ERROR_TYPES: tuple[type[BaseException], ...] = (OperationalError,) + _PSYCOPG2_ERROR


def _is_deadlock_error(exc: BaseException) -> bool:
    """True iff *exc* is (or wraps) a Postgres deadlock — only ONE side is
    aborted and the aborted side can simply retry, everything else stays
    committed.

    Handles both the SQLAlchemy-wrapped form (psycopg2 error on ``.orig``) and
    the raw psycopg2 form. Deliberately narrow otherwise: a connection-loss
    error returns False so the caller re-raises it and the pass dies honestly
    instead of masking a lost database as a per-chunk hiccup.
    """
    if _DEADLOCK_TYPES and isinstance(exc, _DEADLOCK_TYPES):
        return True
    if getattr(exc, "pgcode", None) == _DEADLOCK_PGCODE:
        return True
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    if _DEADLOCK_TYPES and isinstance(orig, _DEADLOCK_TYPES):
        return True
    return getattr(orig, "pgcode", None) == _DEADLOCK_PGCODE


def _poll_startup_offset(interval: float) -> float:
    """Delay before the poller's FIRST pass so it doesn't fire in lockstep with
    the scanner.

    The scan and poll loops share the same interval and the supervisor boots
    them together, so without a phase shift both write ``monitored_contracts``
    at the same instant every cycle. A half-interval offset de-phases them for
    the whole run (equal periods stay half a cycle apart). Only the poller
    shifts — the scanner's first pass must not be delayed, since watchers care
    about scan latency, not poll latency. The offset stays well under the
    poller's staleness window (``3 × interval``, process_meta) so the delayed
    first heartbeat never reads as dead. Overridable via
    ``PSAT_POLL_STARTUP_OFFSET_S`` (0 disables the shift).
    """
    raw = os.getenv("PSAT_POLL_STARTUP_OFFSET_S")
    if raw is not None:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return max(0.0, interval / 2.0)


# Controller IDs that represent the contract owner. Used by relational sync
# to update only the real owner row, not unrelated controller values that
# happen to contain "owner" in their name (e.g. token_owner_registry).
_OWNER_CONTROLLER_IDS = ("owner", "state_variable:owner")
# Solmate-Auth / DSAuth-style authority pointer. Sync target for the
# ``authority_updated`` event emitted by Solmate's ``Auth.setAuthority``.
_AUTHORITY_CONTROLLER_IDS = ("authority", "state_variable:authority", "external_contract:authority")


def get_latest_block(rpc_url: str, *, chain_id: int | None = None) -> int:
    result = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
    return int(result, 16)


@dataclass
class _Cohort:
    """A block-aligned batch of monitored contracts scanned together.

    Members share a chain and a ``last_scanned_block // MAX_BLOCK_RANGE``
    bucket, and are capped at ``PSAT_SCAN_ADDRESS_BATCH`` addresses so one
    eth_getLogs request stays under provider multi-address caps. ``cursor``
    is the running max-scanned block for the batch; it only advances in the
    transaction that persisted a window's events.
    """

    chain: str
    member_ids: list[uuid.UUID]
    addresses: list[str]
    cursor: int
    done: bool = False
    failed: bool = False


class ScanResult(list):
    """The new events from one scan pass, plus pass-level heartbeat metrics.

    Subclasses ``list`` so every existing caller that treats the return as a
    list of ``MonitoredEvent`` (``len``, iteration, indexing, truthiness) keeps
    working, while ``run_scan_loop`` reads ``budget_exhausted`` to pick the
    busy vs. full re-run interval.
    """

    def __init__(
        self,
        events: list[MonitoredEvent],
        *,
        budget_exhausted: bool = False,
        windows_scanned: int = 0,
        cohorts: int = 0,
        max_lag_blocks: int = 0,
        degraded: bool = False,
    ) -> None:
        super().__init__(events)
        self.budget_exhausted = budget_exhausted
        self.windows_scanned = windows_scanned
        self.cohorts = cohorts
        self.max_lag_blocks = max_lag_blocks
        self.degraded = degraded


def _scan_topics_union(session: Session) -> list[str]:
    """Registry topic0s ∪ the per-pass set of tracked-topic topic0s.

    The hand-rolled registry owns OZ / Safe / Timelock / proxy events
    (semantics beyond raw decode); the ``SELECT DISTINCT`` over
    ``monitoring_config->'tracked_topics'`` covers the long tail of per-emitter
    ABI variants (Solmate, DSAuth, Compound, …) without hydrating any row.
    """
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
    """Notify a batch of already-committed events, swallowing failures.

    Shared by the scanner (per window) and the poller (per chunk): both notify
    only after the events are durable, so a notification failure must not leave
    the session pending-rollback and abort the rest of the pass.
    """
    if not events:
        return
    try:
        from services.monitoring.notifier import notify_protocol_events

        notify_protocol_events(session, events)
    except Exception as exc:
        logger.warning("Protocol notification failed: %s", exc, extra={"exc_type": type(exc).__name__})
        # The events are already committed; a failed read here must not leave
        # the session in a pending-rollback state that would abort the pass.
        session.rollback()


def _poll_entry_for_controller(mc: MonitoredContract, controller_id: str | None) -> dict | None:
    """The persisted polling-plan entry that reads *controller_id*, or None.

    Matched on the entry's ``source`` first — ``build_polling_plan`` stamps
    ``analyzer:<controller_id>`` there, so that is an exact identity — then on
    the entry's ``field`` against the controller's state-variable name, which
    covers vendored entries and plans persisted before the source stamp.
    """
    plan = (mc.monitoring_config or {}).get("polling_plan")
    if not isinstance(plan, list) or not controller_id:
        return None
    wanted_source = f"analyzer:{controller_id}"
    state_var = controller_id.split(":", 1)[1] if ":" in controller_id else controller_id
    by_field: dict | None = None
    for entry in plan:
        if not isinstance(entry, dict):
            continue
        if entry.get("source") == wanted_source:
            return entry
        if by_field is None and state_var and entry.get("field") == state_var:
            by_field = entry
    return by_field


@dataclass
class _DirtyController:
    """One controller a hint occurrence marked for verification this pass.

    Repeat occurrences within the pass coalesce onto the same key, so the read
    count is bounded by distinct controllers rather than by traffic. The
    marking is in-memory only: a crash before the read loses the hint, the next
    occurrence re-marks, and the regular poller remains the backstop.
    """

    monitored_contract_id: uuid.UUID
    controller_id: str
    chain: str
    address: str
    entry: dict
    block_number: int


def _resolve_spec_tier(spec: dict, mc: MonitoredContract) -> str:
    """The witness tier of one enrolled tracked-topic *spec*.

    Enrollment stamps ``witness_tier``; that value wins. A spec persisted
    before the taxonomy landed carries none, so it is re-classified here from
    what the row does carry — with the controller's readability taken from the
    persisted polling plan, which is the same projection
    ``_is_poll_decodable`` produced at enrollment. Re-classifying rather than
    grandfathering is the demotion-only rule applied to legacy rows: an
    unclassified spec has no proof, and a bare occurrence must not publish a
    change claim just because nobody has re-enrolled the contract yet.
    """
    tier = spec.get("witness_tier")
    if tier in WITNESS_TIERS:
        return tier
    return classify_witness_tier(
        event_type=spec.get("event_type"),
        controller_id=spec.get("controller_id"),
        inputs=spec.get("inputs"),
        effect_tags=spec.get("effect_tags"),
        member_witness=spec.get("member_witness"),
        writer_openness=spec.get("writer_openness"),
        poll_decodable=_poll_entry_for_controller(mc, spec.get("controller_id")) is not None,
    )


def _process_window(
    session: Session,
    cohort: _Cohort,
    fetched_logs: list,
    window_start: int,
    window_end: int,
    dirty: dict[tuple[uuid.UUID, str], _DirtyController] | None = None,
) -> list[MonitoredEvent]:
    """Decode a window's logs and run the full side-effect pipeline.

    Hydrates only the cohort members that actually emitted a log, then reuses
    the existing decode / watch-gate / state-update / relational-sync /
    reanalysis pipeline. Events are added to ``session`` but not committed —
    the caller advances the cursor and commits in one transaction.

    Per-contract events are gated on their spec's witness tier: only
    ``self_describing`` occurrences reach the insert. A ``hint`` occurrence
    marks its controller in *dirty* for the pass's verification read and
    publishes nothing here; an ``activity`` occurrence publishes nothing at
    all. Hand-rolled OZ / Safe / Timelock / proxy events decode through
    ``parse_any_log``, carry no spec, and are unchanged.
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

    # Per-emitter topic0 → tracked-topic spec, built from the hydrated rows'
    # monitoring_config (the analysis tracking_plan persisted at enrollment).
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

    # No pre-read dedupe: the partial unique index (monitored_contract_id,
    # tx_hash, log_index, event_type) is the identity of a scan event, so the
    # insert below uses ON CONFLICT DO NOTHING and gates every side effect on
    # winning the row. That subsumes both the old pass-wide preload AND the
    # in-scan 5-tuple guard — a duplicate within the window (provider echo) or
    # across passes (overlap after a failed window) loses the ON CONFLICT and
    # is skipped. Batch timelock ops share tx+block+type but carry distinct
    # log_index, so their identities differ and all rows land.
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
                continue

        mc = mc_by_addr.get(emitter)
        if not mc:
            continue

        event_type = parsed["event_type"]

        if mc.monitoring_config and not _should_watch(mc, parsed):
            continue

        witness_tier: str | None = None
        if spec is not None:
            witness_tier = _resolve_spec_tier(spec, mc)
            if witness_tier != WITNESS_TIER_SELF_DESCRIBING:
                # An occurrence is not a change. A hint controller earns one
                # coalesced verification read this pass whose diff — or
                # earned negative — is the witness; an activity occurrence has
                # no readable witness at all. Neither publishes a row here.
                if witness_tier == WITNESS_TIER_HINT and dirty is not None:
                    controller_id = spec.get("controller_id")
                    entry = _poll_entry_for_controller(mc, controller_id)
                    if entry is not None and isinstance(controller_id, str):
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
                continue

        event_data = {
            k: v
            for k, v in parsed.items()
            if k not in ("event_type", "block_number", "tx_hash", "log_index", "_emitter")
        }
        if witness_tier is not None:
            # Rides on the row so a consumer reads the claim's strength off
            # the event rather than re-deriving it from a config that may
            # since have been re-enrolled.
            event_data["witness_tier"] = witness_tier

        # Pre-enrollment floor: an event below the contract's enrollment_block
        # predates monitoring (a cohort scans from its MIN member cursor, so a
        # low-cursor cohort-mate can drag this contract's ancient events into a
        # window). Record it for the timeline with a marker, but never notify,
        # sync, or reanalyze — those are for changes since we started watching.
        # A NULL floor (legacy rows) disables suppression: notify, as before.
        is_historical = mc.enrollment_block is not None and parsed["block_number"] < mc.enrollment_block
        if is_historical:
            event_data = dict(event_data)
            event_data["historical"] = True

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
        # Gate EVERY side effect on the insert winning: a duplicate (lost to a
        # concurrent/replayed pass) must not double-post Discord, double-queue
        # reanalysis, or re-sync relational tables (design HR2).
        if session.execute(insert_stmt).first() is None:
            continue

        # The core insert wrote the row but left the ORM identity map empty.
        # Rehydrate it as a persistent instance from the values we already hold
        # (make_transient_to_detached + add: no SELECT round-trip) so the later
        # data mutation flushes as an UPDATE.
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
            # Persisted with its ``historical`` marker, but excluded from the
            # notify list and all side effects: applying a pre-enrollment event
            # would page on 8-year-old news and overwrite current state.
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


def _resolve_verification_reads(
    session: Session,
    dirty: dict[tuple[uuid.UUID, str], _DirtyController],
    rpc_by_chain: dict[str, str],
) -> list[MonitoredEvent]:
    """Read back every controller a hint occurrence marked this pass and
    publish only what the read proves.

    One read per dirty controller — occurrences coalesced onto the same key
    upstream, so traffic volume does not multiply reads. Outcomes:

      * the value moved      → a witnessed ``value_changed:<controller_id>``
        event carrying ``old``/``new``, plus the same relational sync and
        reanalysis dispatch a poll-detected change drives;
      * the value held       → an earned negative. Nothing is published: the
        absence of a row IS the statement that nothing changed;
      * first observation    → the baseline is seeded and nothing is
        published. There is no old value to have moved from;
      * no observation       → a not-determined marker on the contract's
        poll-status map (verify_status.py). Never a change claim, never a
        silent drop.

    Events are committed here, then returned for the caller to notify.
    """
    if not dirty:
        return []

    budget = max(0, _scan_int_env("PSAT_SCAN_MAX_VERIFY_READS_PER_PASS", DEFAULT_MAX_VERIFY_READS_PER_PASS))
    # Deterministic order so which controllers fall outside the budget is a
    # property of the pass, not of dict insertion luck.
    ordered = sorted(dirty.values(), key=lambda d: (d.address.lower(), d.controller_id))
    within, over = ordered[:budget], ordered[budget:]

    mcs = {
        mc.id: mc
        for mc in session.execute(
            select(MonitoredContract).where(MonitoredContract.id.in_([d.monitored_contract_id for d in ordered]))
        )
        .scalars()
        .all()
    }

    for skipped in over:
        mc = mcs.get(skipped.monitored_contract_id)
        if mc is not None and record_verify_status(mc, skipped.entry.get("field"), VERIFY_OVER_BUDGET):
            flag_modified(mc, "last_poll_status")
    if over:
        logger.warning(
            "Verification-read budget exhausted; %d controller(s) recorded as not determined",
            len(over),
            extra={"budget": budget, "dirty": len(ordered)},
        )

    by_chain: dict[str, list[_DirtyController]] = defaultdict(list)
    for entry in within:
        by_chain[entry.chain].append(entry)

    new_events: list[MonitoredEvent] = []
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

        for member, (raw, status) in zip(dispatch, results):
            mc = mcs.get(member.monitored_contract_id)
            if mc is None:
                continue
            field = member.entry.get("field")
            if status != "ok":
                marker = VERIFY_ERROR if status == "error" else VERIFY_UNANSWERED
                if record_verify_status(mc, field, marker):
                    flag_modified(mc, "last_poll_status")
                continue
            new_value, parsed_ok = decode_poll_outcome(raw, member.entry.get("type_kind"), member.entry.get("type"))
            if new_value is None:
                # ``parsed_ok`` True is the type's conventional empty (a zero
                # address), which the poller's own storage convention keeps out
                # of last_known_state; matching it keeps the two readers of the
                # same slot from disagreeing about what is stored.
                if not parsed_ok and record_verify_status(mc, field, VERIFY_NO_VALUE):
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
                # The witness is the read, not the log that triggered it.
                "witness": "read_verified",
                "hint_block_number": member.block_number,
            }
            event = MonitoredEvent(
                id=uuid.uuid4(),
                monitored_contract_id=mc.id,
                event_type=event_type,
                # A read observes a slot, not a log: no block and no tx are
                # knowable. ``log_index`` stays NULL, which keeps these rows
                # outside the partial identity index exactly like the poll
                # path's rows (invariant 12 is preserved, not extended).
                block_number=0,
                tx_hash="",
                data=event_data,
            )
            session.add(event)
            new_events.append(event)
            logger.info(
                "Verification read detected %s change on %s: %s -> %s",
                field,
                mc.address,
                old_value,
                new_value,
            )
            _sync_relational_from_poll(session, mc, field, new_value, old_value)
            try:
                reanalysis_job = maybe_queue_reanalysis(session, mc, event_type, event_data)
                if reanalysis_job:
                    updated = dict(event.data or {})
                    updated["reanalysis_job_id"] = str(reanalysis_job.id)
                    event.data = updated
            except Exception as exc:
                logger.warning(
                    "Failed to queue re-analysis for %s: %s",
                    mc.address,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )

    session.commit()
    return new_events


def scan_for_events(session: Session, rpc_url: str) -> ScanResult:
    """Scan new blocks for all governance and proxy events, bounded per pass.

    Contracts are loaded columns-only (no ORM hydration, no ``monitoring_config``
    JSONB), grouped into block-aligned address-capped cohorts, and scanned
    most-behind-first under per-cohort and per-pass window budgets. Each window
    is one multi-address eth_getLogs (via the shared bisect-on-reject fetcher)
    clamped to ``head − CONFIRMATION_DEPTH``; its events + monotonic cursor
    advance commit together, then notify. A failed window ends that cohort's
    turn without advancing its cursor (behind ≠ skipped); other cohorts
    continue. Returns the pass's new events plus heartbeat metrics.
    """
    started = time.monotonic()

    address_batch = max(1, _scan_int_env("PSAT_SCAN_ADDRESS_BATCH", 200))
    max_windows_cohort = max(1, _scan_int_env("PSAT_SCAN_MAX_WINDOWS_PER_COHORT", 25))
    max_windows_pass = max(1, _scan_int_env("PSAT_SCAN_MAX_WINDOWS_PER_PASS", 50))

    index_rows = session.execute(
        select(
            MonitoredContract.id,
            MonitoredContract.address,
            MonitoredContract.chain,
            MonitoredContract.last_scanned_block,
        ).where(MonitoredContract.is_active == True)  # noqa: E712
    ).all()

    if not index_rows:
        # Nothing enrolled yet — still emit a cycle so a dead watcher (or a
        # never-populated monitored_contracts table) is distinguishable from
        # a healthy idle one.
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

    # Cohorts: (chain, block bucket) groups, split at the address batch size.
    # The bucket width is the chain's own getLogs range (mainnet == MAX_BLOCK_RANGE).
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

    # Layer-1 singleton gate: a scan pass runs only under the
    # per-chain daemon lease. Acquire at pass start; a chain whose lease is
    # held elsewhere is skipped. If none are held we still beat (note=
    # 'lease_lost') so the fleet view sees a live-but-yielding process, not a
    # dead one.
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

    # Each cohort's chain resolves its OWN eRPC route from the registry
    # (``rpc_url`` is the mainnet seed / local-fork override). Mainnet keeps the
    # incoming URL verbatim, so its head reads and getLogs are unchanged.
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
    # Hint occurrences accumulate across the whole pass so repeats on the same
    # controller — the exact shape of the crowd-traffic problem — collapse to
    # one read. In-memory only, by design: no persistence, no migration.
    dirty_controllers: dict[tuple[uuid.UUID, str], _DirtyController] = {}

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
            eligible.append((cohort, confirmed_head))
        if not eligible:
            break

        # Most-behind cohort first (largest confirmed_head − cursor).
        eligible.sort(key=lambda item: item[1] - item[0].cursor, reverse=True)
        cohort, confirmed_head = eligible[0]

        turn_windows = 0
        while turn_windows < max_windows_cohort and windows_scanned < max_windows_pass:
            window_start = cohort.cursor + 1
            if window_start > confirmed_head:
                cohort.done = True
                break
            window_end = min(cohort.cursor + _max_getlogs_range_for(cohort.chain), confirmed_head)

            # A cohort always has ≥1 address — an empty list would match ANY
            # address on the wire, so the getLogs is never issued without one.
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
                # The fetcher's own bisect already gave up. End this cohort's
                # turn WITHOUT advancing its cursor — behind ≠ skipped.
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

            window_events = _process_window(session, cohort, fetched_logs, window_start, window_end, dirty_controllers)

            # Advance cursors monotonically in the SAME transaction that
            # persists this window's events. GREATEST means a stale or zombie
            # writer can only no-op, never rewind.
            session.execute(
                update(MonitoredContract)
                .where(MonitoredContract.id.in_(cohort.member_ids))
                .values(last_scanned_block=func.greatest(MonitoredContract.last_scanned_block, window_end))
                .execution_options(synchronize_session=False)
            )
            session.commit()

            # Notify per window so a long catch-up doesn't buffer thousands of
            # notifications; the events are already durably committed.
            _notify_committed_events(session, window_events)

            cohort.cursor = window_end
            total_new_events.extend(window_events)
            blocks_scanned += window_end - window_start + 1
            windows_scanned += 1
            turn_windows += 1

            # Renew now that this window is durably committed. renew_daemon_lease
            # commits even when it LOSES, so a lost renew aborts the pass AFTER
            # this committed window (never rewind, never fetch again). Dropping
            # the chain from held_chains ends its cohorts' eligibility above.
            if not renew_daemon_lease(session, _scanner_lease_name(cohort.chain), lease_holder, lease_ttl):
                held_chains.discard(cohort.chain)
                break

    # Hint resolution runs once, after the window loop, so a controller hit in
    # several windows is read once for the whole pass.
    try:
        verified_events = _resolve_verification_reads(session, dirty_controllers, rpc_by_chain)
    except Exception as exc:
        logger.warning(
            "Verification-read pass failed: %s",
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        # The windows above are already committed; a failure here must not
        # roll them back or abort the pass summary.
        session.rollback()
        degraded = True
        verified_events = []
    if verified_events:
        _notify_committed_events(session, verified_events)
        total_new_events.extend(verified_events)

    # Budget-exhausted only if we stopped at the hard pass cap with work left.
    if windows_scanned >= max_windows_pass:
        budget_exhausted = any(
            not c.done and not c.failed and c.cursor < (_head_for(c.chain) - _confirmation_depth_for(c.chain))
            for c in cohorts
        )

    # max_lag_blocks: head − min cursor across all contracts (raw head, so
    # "behind" is the operator-facing number, independent of confirmation depth).
    max_lag = 0
    for cohort in cohorts:
        max_lag = max(max_lag, _head_for(cohort.chain) - cohort.cursor)
    max_lag = max(0, max_lag)

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
        },
    )
    return ScanResult(
        total_new_events,
        budget_exhausted=budget_exhausted,
        windows_scanned=windows_scanned,
        cohorts=len(cohorts),
        max_lag_blocks=max_lag,
        degraded=degraded,
    )


# Per-write-target → monitoring_config flag gates. Tag-driven dispatch
# routes each ``effect_tags.writes`` entry through this map; if any of
# the resulting flags is enabled the event passes the watch filter.
#
# ``admin``-family writes route to both watch_upgrades (EIP-1967 proxy
# admin slot is the upgrader role) AND watch_ownership (Compound/Aave/
# Curve "admin" is the principal owner) because the underlying mutation
# is "the privileged controller changed" — the monitoring intent depends
# on what the contract IS, not what the event is named.
_WRITE_TARGET_TO_CONFIG_KEYS: dict[str, tuple[str, ...]] = {
    # Ownership
    "owner": ("watch_ownership",),
    "_owner": ("watch_ownership",),
    "pendingOwner": ("watch_ownership",),
    "_pendingOwner": ("watch_ownership",),
    # Admin family — both upgrade- and ownership-gated
    "admin": ("watch_upgrades", "watch_ownership"),
    "_admin": ("watch_upgrades", "watch_ownership"),
    "pendingAdmin": ("watch_upgrades", "watch_ownership"),
    "future_admin": ("watch_upgrades", "watch_ownership"),
    # Upgrade-relevant slot writes (also any delegates=True event)
    "implementation": ("watch_upgrades",),
    "beacon": ("watch_upgrades",),
    "facets": ("watch_upgrades",),
    "pendingImplementation": ("watch_upgrades",),
    "_initialized": ("watch_upgrades",),
    "_initializing": ("watch_upgrades",),
    # Authority
    "authority": ("watch_authority",),
    # Pause
    "paused": ("watch_pause",),
    # Roles
    "_roles": ("watch_roles",),
    # Safe signers / Safe + Timelock activity
    "owners": ("watch_safe_signers",),
    "threshold": ("watch_safe_signers",),
    "_safe_op": ("watch_safe_signers",),
    "_safe_module_op": ("watch_safe_signers",),
    "_safe_modules": ("watch_safe_modules",),
    "_safe_guard": ("watch_safe_modules",),
    "_timelock_op": ("watch_timelock",),
    "min_delay": ("watch_timelock",),
}


def _should_watch(mc: MonitoredContract, parsed: dict) -> bool:
    """Check if the monitoring config allows this event.

    Tag-driven: derive the set of monitoring_config flags this event is
    gated on from ``effect_tags.writes`` + ``effect_tags.delegates``,
    then pass if any flag is enabled (or defaults on). Legacy events
    without tags synthesize them from event_type via
    ``_HANDROLLED_EVENT_TYPE_TO_TAGS``.
    """
    config = mc.monitoring_config or {}
    event_type = parsed.get("event_type", "")

    tags = parsed.get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = tags.get("writes") or []
    delegates = bool(tags.get("delegates"))

    config_keys: set[str] = set()
    if delegates:
        config_keys.add("watch_upgrades")
    for write_target in writes:
        if not isinstance(write_target, str):
            continue
        keys = _WRITE_TARGET_TO_CONFIG_KEYS.get(write_target)
        if keys:
            config_keys.update(keys)

    if not config_keys:
        return True  # Unrecognized event — allow rather than silently drop.

    # Legacy alias: ``watch_signers`` predates the rename to
    # ``watch_safe_signers``. Accept either flag so historic
    # MonitoredContract rows written before the rename keep working
    # without a migration. Only kicks in when the event's gating
    # reduces to watch_safe_signers alone — multi-gate events
    # (admin_changed) flow through the general path.
    if config_keys == {"watch_safe_signers"}:
        if config.get("watch_safe_signers") or config.get("watch_signers"):
            return True
        if "watch_safe_signers" in config or "watch_signers" in config:
            return False
        # Neither key set — default-on, fall through to the general path.

    # Allow if ANY relevant flag is set (or defaults to True via .get()).
    return any(config.get(key, True) for key in config_keys)


def _write_through_proxy_event(
    session: Session,
    mc: MonitoredContract,
    parsed: dict,
) -> None:
    """Write a ProxyUpgradeEvent for backward compatibility."""
    new_impl = parsed.get("implementation") or parsed.get("beacon") or parsed.get("new_admin")
    if not new_impl:
        return

    # Load the WatchedProxy to get old implementation
    wp = session.get(WatchedProxy, mc.watched_proxy_id)
    if not wp:
        return

    upgrade_event = ProxyUpgradeEvent(
        watched_proxy_id=wp.id,
        block_number=parsed["block_number"],
        tx_hash=parsed.get("tx_hash", ""),
        old_implementation=wp.last_known_implementation,
        new_implementation=new_impl,
        event_type=parsed["event_type"],
    )
    session.add(upgrade_event)

    wp.last_known_implementation = new_impl
    if parsed["block_number"] > wp.last_scanned_block:
        wp.last_scanned_block = parsed["block_number"]


def _extract_new_owner(parsed: dict) -> object:
    return parsed.get("new_owner")


def _extract_new_authority(parsed: dict) -> object:
    return parsed.get("new_authority")


def _extract_paused_bool(parsed: dict) -> object:
    # paused/unpaused share writes=["paused"]; the event_type discriminates
    # the new state. The arg on the wire is the account that flipped the
    # flag, not the flag value — so we ignore parsed["account"] and read
    # the semantic from event_type.
    et = parsed.get("event_type")
    if et == "paused":
        return True
    if et == "unpaused":
        return False
    return None


def _extract_threshold(parsed: dict) -> object:
    # GnosisSafe ChangedThreshold(uint256 threshold) decodes to ``threshold``.
    # Tracked Safe-shaped ABIs may use new_threshold via semantic-key aliasing.
    val = parsed.get("threshold")
    if val is None:
        val = parsed.get("new_threshold")
    return val


def _extract_implementation(parsed: dict) -> object:
    return parsed.get("implementation")


def _extract_new_admin(parsed: dict) -> object:
    return parsed.get("new_admin")


def _extract_beacon(parsed: dict) -> object:
    return parsed.get("beacon")


def _extract_new_delay(parsed: dict) -> object:
    return parsed.get("new_delay")


def _extract_initialized_version(parsed: dict) -> object:
    # OZ Initializable Initialized(uint64 version). Canonical ABI names
    # the arg ``version``; some forks use ``initVersion``. Either way the
    # value goes into last_known_state so reanalysis can compare against
    # the next observation.
    version = parsed.get("version")
    if version is None:
        version = parsed.get("initVersion")
    return version


_StateExtractor = Callable[[dict], object]

# Per-write-target dispatch for ``_update_state_from_event``. Maps a tag
# write target → (state_key, extractor). The state_key may differ from
# the write target (``_initialized`` writes to ``initialized_version``);
# the extractor pulls the right value out of the decoded event. Targets
# absent here fall through to the generic name-match reflection so
# custom slots (e.g. ``protocolAdmin``) work without per-slot code.
_WRITE_TARGET_TO_STATE: dict[str, tuple[str, _StateExtractor]] = {
    "owner": ("owner", _extract_new_owner),
    "authority": ("authority", _extract_new_authority),
    "paused": ("paused", _extract_paused_bool),
    "threshold": ("threshold", _extract_threshold),
    "implementation": ("implementation", _extract_implementation),
    "admin": ("admin", _extract_new_admin),
    "beacon": ("beacon", _extract_beacon),
    "min_delay": ("min_delay", _extract_new_delay),
    "_initialized": ("initialized_version", _extract_initialized_version),
}


def _resolve_value_for_write_target(parsed: dict, write_target: str) -> object | None:
    """Pull the new value an event reports for *write_target* using the
    most specific signal available, falling back to ABI conventions
    when the analyzer's tag is the only structural pin.

    Resolution order:

      1. **Bare-name match** — ``parsed[write_target]`` works for
         single-arg events whose only arg is the new value
         (DSAuth ``LogSetOwner(address indexed owner)`` with
         write_target ``owner``).
      2. **OZ ``new<Cap>`` convention** — ``parsed[f"new{Cap}"]`` covers
         the OZ family (``newOwner``, ``newAdmin``, ``newImplementation``).
      3. **Tag-pinned ``new*`` arg from the ABI inputs spec** — when the
         analyzer attached ``_inputs`` (per-contract tracked events via
         ``parse_tracked_log``), find any input whose name starts with
         "new" (case-insensitive) and return its value. Catches
         Compound-shape ``NewAdmin(address newAdmin)`` /
         ``ProtocolAdminChanged(previousAdmin, newAdmin)`` for a
         write_target like ``protocolAdmin`` where neither the bare
         name nor the OZ ``new<Cap>`` convention applies.
      4. **Positional last-arg fallback** — for single-write events the
         "new value" is conventionally the last arg even when no naming
         convention applies (Solady, custom ABIs that just name the
         arg ``account`` or ``to``). Only fires when ``_inputs`` is
         present and (3) didn't match.

    Underscore-prefixed write_targets (``_roles``, ``_timelock_op``,
    ``_safe_op``, ``_safe_module_op``) are synthetic activity markers
    not real slots; they short-circuit to ``None`` so the fallback
    doesn't false-positive on the third-arg ``sender`` of a RoleGranted
    event (which has no canonical extractor and would otherwise hit
    pass (4) and overwrite ``state["_roles"]`` with a sender address).
    """
    if write_target.startswith("_"):
        return None

    candidate = parsed.get(write_target)
    if candidate is not None:
        return candidate

    cap = write_target[:1].upper() + write_target[1:]
    candidate = parsed.get(f"new{cap}")
    if candidate is not None:
        return candidate

    inputs = parsed.get("_inputs")
    if not isinstance(inputs, list) or not inputs:
        return None

    # Pass 3: any input whose name starts with "new" (case-insensitive).
    # First match wins; the analyzer's tag tells us there's a single
    # write target here, so the convention "the new value of THAT slot
    # is named new<something>" is reliable.
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = inp.get("name") or ""
        if name.lower().startswith("new") and name in parsed:
            return parsed[name]

    # Pass 4: positional last-arg. The analyzer's tag pins this event
    # as writing exactly one slot, so the last arg is the conventional
    # location of the new value across every governance ABI we've seen
    # (Solady, custom). Skipped when (3) matched.
    last = inputs[-1]
    if isinstance(last, dict):
        name = last.get("name") or ""
        if name and name in parsed:
            return parsed[name]
    return None


def _update_state_from_event(mc: MonitoredContract, parsed: dict) -> None:
    """Reflect the event's mutations into ``last_known_state``.

    Tag-driven: each ``effect_tags.writes`` target either resolves to a
    canonical (state_key, extractor) in ``_WRITE_TARGET_TO_STATE`` or
    falls back to generic name-match reflection so custom slots like
    ``protocolAdmin`` flow through without per-slot code.

    Legacy events without ``effect_tags`` synthesize them from event_type
    via ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` — covers monitoring_config
    rows persisted before tag synthesis landed.
    """
    state = dict(mc.last_known_state or {})
    event_type = parsed["event_type"]

    tags = parsed.get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = tags.get("writes") or []

    for write_target in writes:
        if not isinstance(write_target, str):
            continue
        mapping = _WRITE_TARGET_TO_STATE.get(write_target)
        if mapping is not None:
            state_key, extractor = mapping
            value = extractor(parsed)
            if value is not None:
                state[state_key] = value
            continue
        # Generic resolution for custom slots — uses bare-name match,
        # OZ ``new<Cap>`` convention, ABI-pinned ``new*`` arg, and last-
        # arg positional fallback. Unlike the canonical branch we DO
        # overwrite an existing state entry — this path is the only one
        # that updates custom slots, so a subsequent observation must
        # take precedence.
        candidate = _resolve_value_for_write_target(parsed, write_target)
        if candidate is not None:
            state[write_target] = candidate

    mc.last_known_state = state
    flag_modified(mc, "last_known_state")


def _new_value_for_write_target(write_target: str, parsed: dict) -> object | None:
    """Pull the new value for *write_target* out of a parsed event.

    Tries the canonical extractor in ``_WRITE_TARGET_TO_STATE`` first,
    then defers to ``_resolve_value_for_write_target`` for custom slots
    so the event-side relational sync and the state-update sync share
    one resolution chain.
    """
    mapping = _WRITE_TARGET_TO_STATE.get(write_target)
    if mapping is not None:
        _, extractor = mapping
        return extractor(parsed)
    return _resolve_value_for_write_target(parsed, write_target)


def _sync_relational_tables(
    session: Session,
    mc: MonitoredContract,
    parsed: dict,
) -> None:
    """Propagate a detected event to the relational Contract / ControllerValue /
    UpgradeEvent tables so the API serves up-to-date data.

    Tag-driven: each ``effect_tags.writes`` target drives one row update.
    Legacy events without tags synthesize them from event_type via
    ``_HANDROLLED_EVENT_TYPE_TO_TAGS``.

    Only updates rows when the MonitoredContract has a linked contract_id.

    A controller rotation (owner/admin/authority/implementation actually
    moving) marks the protocol dirty so the enrollment reconciler picks up any
    newly-installed governance Safe within one drain tick instead of waiting
    for the slow sweep.
    """
    if not mc.contract_id:
        return

    event_type = parsed["event_type"]
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

    # Upgrade path: a delegate-target swap → Contract.implementation,
    # UpgradeEvent row, coverage refresh. Load-bearing semantics that
    # generic ControllerValue reflection can't reproduce.
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
                        # timestamp stays NULL: a log carries a block, not a
                        # block time, and the scanner reads historical windows
                        # so detection time is not a usable stand-in. NULL is
                        # read as "not determined" by every consumer.
                        source=UPGRADE_SOURCE_EVENT_SCAN,
                    )
                )
                # Coverage windows are derived from UpgradeEvent history, so a
                # new upgrade can change which audits apply to the previous impl
                # (it's now bounded) and the new one (newly current). Rebuild
                # coverage for every audit in the protocol — it's idempotent.
                _refresh_coverage_after_upgrade(session, c.protocol_id)

    # Per-write-target row sync: top-level Contract.admin shadow for
    # admin writes, plus ControllerValue rows keyed by any of the common
    # prefix forms ({target}, state_variable:{target}, external_contract:{target}).
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
    """Rebuild ``audit_contract_coverage`` for a protocol after an upgrade.

    Called from the event- and poll-sync paths so impl_era windows stay in
    sync with the live upgrade history. Swallows exceptions so a coverage
    bug can never block a detected upgrade from being recorded.
    """
    if not protocol_id:
        return
    # Local import keeps the coverage module off the hot path at
    # module-load time and avoids the import cycle
    # unified_watcher → audits.coverage → db.models (which is fine) but
    # keeps the surface clean.
    from services.audits.coverage import upsert_coverage_for_protocol

    try:
        # Defer source-equivalence to ``CoverageVerifyWorker``: matches the
        # coverage_worker / audit_scope_extraction / upgrade_history call
        # sites which also pass False. Holding verify inline on every
        # detected upgrade fanned out 4-way Etherscan + GitHub bursts that
        # cascaded into the shared rate-limit window (#82). The verify
        # worker drains the resulting ``pending`` rows at a controlled rate.
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
    """Write *new_value* into every ControllerValue row keyed by the
    three canonical controller_id forms the analyzer emits
    (``{name}``, ``state_variable:{name}``, ``external_contract:{name}``).

    Shared between event-driven sync (``_sync_relational_tables``) and
    poll-driven sync (``_sync_relational_from_poll``) so the two paths
    converge on the same row-keying rules and a custom slot like
    ``protocolAdmin`` propagates through either path without per-slot
    code. Returns True iff a row's value actually moved — the caller uses
    that to decide whether a governance rotation needs re-enrollment.

    When the value moves, ``resolved_type`` and ``details`` are CLEARED, not
    carried over. They are the classifier's answer about the OLD address:
    ``("safe", {"address", "owners", "threshold"})`` or
    ``("timelock", {"address", "delay", "owner"})``. This function has no RPC
    and cannot re-classify, so the only honest states are NULL — not
    determined, re-derived by the next resolution run.

    Carrying them is not a cosmetic staleness. ``company_overview`` republishes
    the stale payload under the NEW address (``_record_principal_lookup`` keys
    on ``cv.value`` while merging ``cv.details``), and
    ``_principal_lookup_type`` promotes on ``details`` alone via
    ``_has_timelock_delay`` — so a Timelock -> EOA rotation publishes a
    freshly-installed EOA as ``resolved_type="timelock"`` carrying the old
    ``delay``, which is a credit-bearing scoring input. That is a safety-inflating
    false credit, on top of a false statement about a named individual's keys.
    A Safe -> Safe rotation is the milder half: the new Safe inherits the old
    one's ``owners``/``threshold`` and ``details["address"]`` stays the OLD
    Safe, which ``setdefault("address", addr)`` downstream cannot correct
    because the key is already present.

    ``block_number``/``observed_via`` are reassigned for the same reason: they
    described the old read. The poll path knows no block, so it passes None —
    "not determined", never the stale one.

    Rows are updated in place rather than appended. ``controller_values`` is
    read as CURRENT state by every consumer (company_overview's ``controllers``
    map, capability_resolver, enrollment, chat) with no ordering or dedup, and
    the resolution worker deletes-then-reinserts the whole per-contract set on
    each run, so an append-only key would multiply every existing read without
    accumulating coherent history. The history planes are ``upgrade_events``
    and the ``principal_history`` artifact.
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


def _sync_relational_from_poll(
    session: Session,
    mc: MonitoredContract,
    field_name: str,
    new_value: object,
    old_value: object,
) -> None:
    """Propagate a polling-detected state change to relational tables.

    ``implementation`` keeps the dedicated branch — the
    Contract.implementation shadow + UpgradeEvent row + coverage refresh
    are side effects ControllerValue can't reproduce. Every other field
    flows through the generic ControllerValue updater so custom slots
    (``protocolAdmin``, ``feeRecipient``) sync without per-slot code.

    A controller rotation marks the protocol dirty so a newly-installed
    governance Safe is enrolled within one drain tick.
    The caller only reaches here when ``new_value != old_value``, so an
    implementation swap (or a governance-relevant slot moving) is always a real
    change.
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
                    # A poll reads a slot, not a log: no block and no tx are
                    # knowable here. NULL says that; 0 would claim the upgrade
                    # happened before the genesis deployment, and since every
                    # consumer orders by block_number NULLS LAST, this row
                    # would sort to the front of the era sequence and shift
                    # every impl window by one.
                    block_number=None,
                    tx_hash=None,
                    # Detection time, not a block time — bounded above by one
                    # poll interval. Only ``source`` distinguishes the two
                    # readings of this column; leaving it NULL is what
                    # collapsed every post-upgrade audit to low confidence
                    # once before (upgrade_history.project_to_events).
                    timestamp=datetime.now(timezone.utc),
                    source=UPGRADE_SOURCE_POLL,
                )
            )
            _refresh_coverage_after_upgrade(session, contract.protocol_id)
            if contract.protocol_id:
                mark_enrollment_dirty(session, contract.protocol_id, _GOVERNANCE_ROTATION_REASON)
        return

    # A poll reads a slot; no block is knowable here, so block_number goes
    # NULL rather than keeping the block of the previous (now wrong) read.
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


# ---------------------------------------------------------------------------
# State polling
# ---------------------------------------------------------------------------


def _rpc_call_for_entry(address: str, entry: dict) -> tuple[str, list] | None:
    """Translate a polling-plan entry into a JSON-RPC ``(method, params)``
    pair. Returns ``None`` for unrecognized entry kinds — the loop drops
    those silently so a forward-compatible schema addition can't break
    a running watcher."""
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
    """Decode one poll result and, when the value changed, persist the new
    ``last_known_state``, emit a ``state_changed_poll`` event, and run the
    downstream sync (proxy write-through, relational, reanalysis, per-entry
    scanner-duplicate suppression).

    The computation is identical to the pre-rotation inline driver; only the
    framing moved from a single flat loop to per-chunk dispatch.

    Only answered, error-free RPC results reach here — the poll loop routes
    errored calls to the contract's ``last_poll_status`` map instead — so an
    unparsed decode below means exactly "the call returned nothing
    parseable" (empty ``0x`` / short body / undecodable type), never a
    swallowed revert.

    Returns True iff the response parsed as the entry's declared type — an
    observed outcome. That includes a parse to the type's conventional
    empty (the zero address), which by ``decode_poll_outcome``'s contract
    stays out of ``last_known_state``: an answered zero is a value the
    wire delivered, not a missing one. False means the answer contained
    nothing parseable and is the caller's signal to publish the entry as
    ``no_value`` rather than ``ok``.
    """
    field_name = entry.get("field")
    if not isinstance(field_name, str) or not field_name:
        return False
    new_value, parsed = decode_poll_outcome(raw, entry.get("type_kind"), entry.get("type"))
    if new_value is None:
        return parsed

    state = dict(mc.last_known_state or {})
    old_value = state.get(field_name)
    if new_value == old_value:
        return True

    # Always record the new value in last_known_state, even on the
    # first observation — subsequent polls then have a baseline.
    state[field_name] = new_value
    mc.last_known_state = state
    flag_modified(mc, "last_known_state")

    # First observation after enrollment isn't a real state change.
    if old_value is None:
        logger.debug(
            "Initial %s observation on %s: %s (no event emitted)",
            field_name,
            mc.address,
            new_value,
        )
        return True

    # Suppress when the event scanner already recorded the same
    # mutation. Per-entry suppress lists come from the enrollment-
    # time projection: vendored entries carry the canonical
    # event_types for their slot, analyzer-derived entries carry
    # event_types whose ``effect_tags.writes`` includes this field.
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

    event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type="state_changed_poll",
        block_number=0,
        tx_hash="",
        data={
            "field": field_name,
            "old_value": str(old_value),
            "new_value": str(new_value),
        },
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

    # Write-through for proxy implementation changes
    if field_name == "implementation" and mc.watched_proxy_id:
        wp = session.get(WatchedProxy, mc.watched_proxy_id)
        if wp:
            upgrade_event = ProxyUpgradeEvent(
                watched_proxy_id=wp.id,
                block_number=0,
                tx_hash="",
                old_implementation=str(old_value) if old_value else None,
                new_implementation=str(new_value),
                event_type="storage_poll",
            )
            session.add(upgrade_event)
            wp.last_known_implementation = str(new_value)

    # Propagate to relational tables
    _sync_relational_from_poll(session, mc, field_name, new_value, old_value)

    # Queue a re-analysis job if the state change warrants it
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
        # maybe_queue_reanalysis's first statement is a Job SELECT whose
        # autoflush flushes the staged last_known_state UPDATE — the same row
        # the scanner's cohort UPDATE locks, so this is a deadlock candidate.
        # Any DB error here has already poisoned the session; let it reach the
        # chunk handler, which owns rollback + retry-first. Swallowing it would
        # leave the session pending-rollback and the next statement would raise
        # PendingRollbackError (not a DB error) past that handler, killing the
        # pass. Only genuinely local reanalysis-logic failures fall through to
        # the warn-and-continue below so they can't block a real detection.
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
    """Poll for state changes by walking each contract's persisted
    ``polling_plan``.

    The plan is built at enrollment (``polling_plan.build_polling_plan``)
    from the static analyzer's tracked_controllers, plus vendored proxy
    storage slots and Safe/Timelock standard ABIs.

    Rotation: each pass claims only the
    ``PSAT_POLL_CONTRACTS_PER_PASS`` least-recently-polled active
    ``needs_polling`` contracts (``last_polled_at ASC NULLS FIRST``), so the
    pass is O(slice) in memory rather than O(all monitored contracts). Their
    plan entries are expanded and packed into ``MAX_BATCH_SIZE``-call chunks —
    a contract's calls never split across a chunk — and each chunk is decoded,
    synced, stamped (``last_polled_at`` = server ``now()``), committed, and its
    events notified, all on its own.

    Per-entry outcomes are published: an answered chunk overwrites each of
    its contracts' ``last_poll_status`` with
    ``{field: "ok" | "error" | "no_value"}`` for every entry dispatched
    this pass — ``ok`` = the call answered and its body parsed as the
    entry's declared type, INCLUDING the type's conventional empty (a
    zero-address ``owner()`` on a renounced contract is an observed
    value, published ``ok``, even though ``decode_poll_outcome``'s
    storage convention keeps it out of ``last_known_state``); ``error`` =
    the node answered THIS call with a per-call JSON-RPC error (e.g. a
    revert on a getter the address doesn't expose); ``no_value`` = the
    call answered without error but returned nothing that parses as the
    declared type (empty ``0x`` from a codeless address or permissive
    fallback, short body, undecodable type). A field absent from the map
    was not polled. The status map is what keeps a dead entry
    distinguishable from a never-polled one.

    Statuses are written only from batches the node actually answered. A
    wholesale transport failure (``rpc_batch_request_classified`` reports
    those slots as ``transport`` instead of raising) observed nothing, so
    it publishes nothing: the chunk neither overwrites statuses nor
    stamps, its contracts sort first next pass (retry-first — an outage
    self-heals and must not masquerade as an earned per-entry negative).
    Per-call ``error`` entries DO stamp and rotate normally:
    always-reverting entries exist in persisted pre-``unknown``-strategy
    plans, and an unstamped-on-revert rule would pin their contracts to
    the front of the rotation forever — their outcome is published, not
    retried. Any errored, unparseable, or transport-failed entry marks
    the pass ``partial``; an answered conventional-empty does not — it
    is a successful observation, and a pass made only of those is a
    healthy (``running``) pass.

    A chunk whose write side deadlocks against the scanner's cohort UPDATE
    is rolled back and left unstamped so its contracts sort first next pass
    (retry-first), and the pass continues with the remaining chunks,
    reporting ``partial``. Only a Postgres deadlock is recovered per-chunk;
    any other database error (e.g. a lost connection) is re-raised to end
    the pass honestly.

    Contracts whose ``monitoring_config`` lacks a ``polling_plan`` still
    rotate (they get stamped with an empty chunk) — the reconciler
    (``services/monitoring/reconciler.py``) backfills the plan within its
    interval so this is a bounded transient on freshly-migrated rows.

    Singleton correctness: the poll path is gated by the
    ``protocol_poller:<chain>`` daemon lease and — unlike the scan path — the
    lease is **load-bearing, not belt-and-braces**. ``state_changed_poll`` rows
    carry ``tx_hash=''`` / block 0 and stay ``log_index NULL``, so they sit
    outside the partial identity index by design; there is no Layer-2 idempotency
    to catch a duplicate poll detection. Two concurrent poll passes without the
    lease MAY double-insert poll events — an accepted risk.
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

    # Acquire the per-chain poll lease before any RPC. A chain held elsewhere is
    # dropped; if none are held, yield the pass (note='lease_lost') so the fleet
    # view sees a live process, not a dead one.
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

    # Oldest rotation cursor in the selected slice, measured before we stamp —
    # a NULL (never-polled) member reads as unbounded age (reported as None).
    now = datetime.now(timezone.utc)
    polled_ats = [mc.last_polled_at for mc in contracts]
    if any(ts is None for ts in polled_ats):
        oldest_age_s = None
    else:
        oldest_age_s = int((now - min(ts for ts in polled_ats if ts)).total_seconds())

    # Partition by chain FIRST so a chunk never mixes chains — its single batch
    # RPC goes to that chunk's own chain (mainnet keeps the incoming ``rpc_url``).
    # Within a chain, pack whole contracts into <=MAX_BATCH_SIZE-call chunks — a
    # contract's calls never split across a chunk boundary, so its dispatch
    # indexes stay contiguous within one batch. Single-chain (the common case)
    # packs identically to before, since contract order within a chain is kept.
    contracts_by_chain: dict[str, list[MonitoredContract]] = defaultdict(list)
    for mc in contracts:
        contracts_by_chain[mc.chain].append(mc)

    chunks: list[tuple[str, list[tuple[MonitoredContract, list[tuple[dict, tuple[str, list]]]]]]] = []
    for chunk_chain, chain_contracts in contracts_by_chain.items():
        current: list[tuple[MonitoredContract, list[tuple[dict, tuple[str, list]]]]] = []
        current_calls = 0
        for mc in chain_contracts:
            plan = (mc.monitoring_config or {}).get("polling_plan") or []
            entries: list[tuple[dict, tuple[str, list]]] = []
            if isinstance(plan, list):
                for entry in plan:
                    if not isinstance(entry, dict):
                        continue
                    call = _rpc_call_for_entry(mc.address, entry)
                    if call is None:
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

        # ``_classified`` keeps the two failure shapes apart: a reverting
        # getter is an answered call (``"error"``, an earned per-entry
        # negative), while a batch the node never answered leaves its
        # slots ``"transport"`` (outcome unobserved; the helper never
        # raises).
        results = rpc_batch_request_classified(chunk_rpc_url, batch_calls) if batch_calls else []

        if any(status == "transport" for _raw, status in results):
            # Nothing was observed for at least one slot, so nothing is
            # published for the whole chunk (a >MAX_BATCH_SIZE plan can
            # split across posts; partially-answered chunks are treated
            # the same, conservatively): statuses stay as they were,
            # ``last_polled_at`` is NOT stamped, so these contracts sort
            # first next pass — retry-first for outages, which self-heal,
            # unlike per-call reverts which stamp and rotate below.
            chunks_transport_failed += 1
            logger.warning(
                "Poll chunk transport-failed; nothing published, retrying next pass: %s",
                [mc.address for mc, _ in chunk],
                extra={"chain": chunk_chain, "calls": len(batch_calls)},
            )
            continue

        # Decode + apply + stamp + commit as one unit under deadlock isolation.
        # The scanner advances cursors with a bulk UPDATE over the same
        # monitored_contracts rows this chunk touches, so any of the apply-loop
        # autoflush, the suppression SELECT, the stamp, or the commit can be the
        # side Postgres aborts. Collect the chunk's events locally so a rollback
        # discards exactly the detections that rolled back with it.
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
            # Overwrite wholesale: the chunk dispatches every recognizable
            # entry of each contract's plan, so this pass's outcomes ARE
            # the full per-field truth; a field absent from the map was
            # not polled (unrecognized kind, missing selector, no plan).
            for mc, _entries in chunk:
                mc.last_poll_status = statuses[mc.id]
                flag_modified(mc, "last_poll_status")
            session.execute(
                update(MonitoredContract).where(MonitoredContract.id.in_(chunk_ids)).values(last_polled_at=func.now())
            )
            session.commit()
        except _DB_ERROR_TYPES as exc:
            if not _is_deadlock_error(exc):
                # Connection loss and other DB failures aren't per-chunk
                # recoverable — let the pass die so run_poll_loop records an
                # honest degraded cycle rather than masking it.
                raise
            # Postgres aborted this chunk. Roll back (which also reverts the
            # in-memory last_known_state mutations the apply loop staged) and
            # leave the chunk unstamped so it sorts first next pass; press on.
            session.rollback()
            chunks_failed += 1
            logger.warning(
                "Poll chunk deadlocked; rolled back, retrying next pass: %s",
                [mc.address for mc, _ in chunk],
                extra={"exc_type": type(getattr(exc, "orig", None) or exc).__name__},
            )
            continue

        # Chunk is durable. Notify its events now — mirroring the scanner's
        # per-window notify — so a later chunk's failure can't strand
        # already-committed detections. A chunk that rolled back never reaches
        # here, so its events are never notified (and its entry errors were
        # discarded with it — chunks_failed already marks the pass partial).
        entry_errors += chunk_entry_errors
        entries_no_value += chunk_entries_no_value
        _notify_committed_events(session, chunk_events)
        new_events.extend(chunk_events)

        # Renew now that this chunk is durable. renew commits even when it
        # LOSES, so a lost renew aborts the remaining chunks AFTER this one —
        # never roll back. Conservative for multi-chain (any chain's loss ends
        # the pass; those contracts just retry next pass); ships ethereum-only.
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
        # A pass is partial iff some dispatched entry produced no
        # observation this tick: the chunk rolled back (deadlock), was
        # never answered (transport), a call errored, or an answered call
        # parsed to nothing (``no_value``). An answered conventional-empty
        # (zero address) counts as ``ok`` upstream and does NOT mark the
        # pass partial — the basis for ``partial`` is a failure to
        # observe, never the observed value itself.
        partial=chunks_failed > 0 or chunks_transport_failed > 0 or entry_errors > 0 or entries_no_value > 0,
        extra_detail={
            "contracts_selected": len(contracts),
            "chunks": len(chunks),
            "chunks_failed": chunks_failed,
            "chunks_transport_failed": chunks_transport_failed,
            "entry_errors": entry_errors,
            "entries_no_value": entries_no_value,
            "oldest_last_polled_age_s": oldest_age_s,
        },
    )
    return new_events


# ---------------------------------------------------------------------------
# Blocking loops
# ---------------------------------------------------------------------------


def run_scan_loop(
    rpc_url: str,
    interval: float = DEFAULT_SCAN_INTERVAL,
    stop_event: Event | None = None,
) -> None:
    """Run the unified event scanner in a blocking loop.

    ``scan_for_events`` now commits and notifies per window, so a long
    catch-up drains at RPC speed without buffering. When a pass exhausts its
    window budget with work still queued, re-run after the short busy interval
    instead of the full scan interval.

    ``stop_event`` (supplied by the thread supervisor) lets a shutdown break the
    inter-pass wait mid-interval instead of sleeping out the full interval;
    callers that omit it keep the original blocking-forever behaviour.
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
            # ``scan_for_events`` raised before it could emit its own cycle
            # summary — still beat so the fleet view sees a degraded cycle.
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
    """Run the unified state polling loop.

    ``stop_event`` lets the supervisor cut the inter-pass wait short on
    shutdown; omitting it preserves the original blocking-forever behaviour.

    Notification happens per chunk inside ``poll_for_state_changes`` (so a later
    chunk's failure can't strand committed detections); this loop only schedules
    passes. Its first pass is offset from the scanner's (``_poll_startup_offset``)
    so the two equal-interval loops don't fire in lockstep and deadlock on
    ``monitored_contracts`` every cycle. ``startup_offset_s`` overrides that shift
    — the standalone ``--poll`` runner passes 0 because there is no co-scheduled
    scanner in its process to de-phase from.
    """
    stop_event = stop_event or Event()
    logger.info("Starting unified protocol poller (interval=%ss)", interval)
    offset = _poll_startup_offset(interval) if startup_offset_s is None else max(0.0, startup_offset_s)
    # One beat before the offset wait: a never-beaten heartbeat classifies as
    # stale (process_meta.is_stale(None)) and the ops watchdog pages on the
    # first tick, so on a fresh DB the offset gap would otherwise emit a false
    # "poller down" + "recovered" pair on every preview deploy.
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
            # ``poll_for_state_changes`` raised before it could emit its own
            # cycle summary — still beat so the fleet view sees a degraded cycle.
            record_heartbeat(
                HEARTBEAT_PROTOCOL_POLLER,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        stop_event.wait(interval)
