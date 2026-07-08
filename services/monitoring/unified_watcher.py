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
from typing import Callable

from dotenv import load_dotenv
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from db.models import (
    Contract,
    ControllerValue,
    MonitoredContract,
    MonitoredEvent,
    ProxyUpgradeEvent,
    SessionLocal,
    UpgradeEvent,
    WatchedProxy,
)
from db.queue import record_heartbeat
from services.monitoring import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_SCANNER,
    emit_monitor_cycle,
)
from services.monitoring.event_topics import (
    _HANDROLLED_EVENT_TYPE_TO_TAGS,
    ALL_EVENT_TOPICS,
    PROXY_EVENT_TOPICS,
    parse_any_log,
    parse_tracked_log,
)
from services.monitoring.polling_plan import decode_poll_value
from services.monitoring.reanalysis import maybe_queue_reanalysis
from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher
from utils.rpc import (
    MAX_BATCH_SIZE,
    rpc_batch_request,
    rpc_request,
)

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)

MAX_BLOCK_RANGE = 2000
DEFAULT_SCAN_INTERVAL = int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600"))
DEFAULT_POLL_INTERVAL = int(os.getenv("PROTOCOL_POLL_INTERVAL", "600"))
# Poller rotation slice — how many needs_polling contracts one pass claims,
# ordered oldest-cursor-first. Bounds the pass to O(slice) memory (design §1.3).
DEFAULT_POLL_CONTRACTS_PER_PASS = 500

# monitored_events must only ingest confirmed logs — a reorg-rewound event
# would have already fired a Discord notification and a reanalysis job that
# cannot be un-sent. Every window end is clamped to head − this depth.
DEFAULT_CONFIRMATION_DEPTH = 12
# The shared getLogs fetcher bisects a rejected window down to this floor
# before re-raising. It must sit well below MAX_BLOCK_RANGE so a provider
# range/response-cap rejection actually bisects instead of failing the cohort.
FETCHER_MIN_BISECT_SPAN = 125


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


# Controller IDs that represent the contract owner. Used by relational sync
# to update only the real owner row, not unrelated controller values that
# happen to contain "owner" in their name (e.g. token_owner_registry).
_OWNER_CONTROLLER_IDS = ("owner", "state_variable:owner")
# Solmate-Auth / DSAuth-style authority pointer. Sync target for the
# ``authority_updated`` event emitted by Solmate's ``Auth.setAuthority``.
_AUTHORITY_CONTROLLER_IDS = ("authority", "state_variable:authority", "external_contract:authority")


def get_latest_block(rpc_url: str) -> int:
    result = rpc_request(rpc_url, "eth_blockNumber", [])
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


def _notify_window(session: Session, events: list[MonitoredEvent]) -> None:
    if not events:
        return
    try:
        from services.monitoring.notifier import notify_protocol_events

        notify_protocol_events(session, events)
    except Exception as exc:
        logger.warning("Protocol notification failed: %s", exc, extra={"exc_type": type(exc).__name__})
        # The window is already committed; a failed read here must not leave
        # the session in a pending-rollback state that would abort the pass.
        session.rollback()


def _process_window(
    session: Session,
    cohort: _Cohort,
    fetched_logs: list,
    window_start: int,
    window_end: int,
) -> list[MonitoredEvent]:
    """Decode a window's logs and run the full side-effect pipeline.

    Hydrates only the cohort members that actually emitted a log, then reuses
    the existing decode / watch-gate / state-update / relational-sync /
    reanalysis pipeline. Events are added to ``session`` but not committed —
    the caller advances the cursor and commits in one transaction.
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
        for spec in topics_list:
            t0 = (spec.get("topic0") or "").lower()
            if t0:
                spec_map[t0] = spec
        if spec_map:
            tracked_specs_by_emitter[addr] = spec_map

    # Bounded per-window dedupe: the 4-tuple already-stored guard, scoped to
    # this window's block range and the emitting members. Replaces the old
    # pass-wide preload; guards the overlap re-scanned after a failed window.
    hydrated_ids = [mc.id for mc in hydrated]
    existing_rows = session.execute(
        select(
            MonitoredEvent.monitored_contract_id,
            MonitoredEvent.tx_hash,
            MonitoredEvent.block_number,
            MonitoredEvent.event_type,
        ).where(
            MonitoredEvent.monitored_contract_id.in_(hydrated_ids),
            MonitoredEvent.block_number >= window_start,
            MonitoredEvent.block_number <= window_end,
        )
    ).all()
    db_events = {(str(r[0]), r[1], r[2], r[3]) for r in existing_rows}
    # In-scan 5-tuple key (incl. log_index) so batch timelock ops
    # (scheduleBatch / executeBatch — one CallScheduled / CallExecuted per
    # call, sharing tx+block+type) land as distinct rows within one window.
    in_scan_events: set[tuple] = set()

    new_events: list[MonitoredEvent] = []

    for fl in fetched_logs:
        raw = fl.raw
        if raw is None:
            continue
        emitter = fl.address
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

        db_key = (
            str(mc.id),
            parsed.get("tx_hash", ""),
            parsed["block_number"],
            event_type,
        )
        if db_key in db_events:
            continue

        in_scan_key = (*db_key, parsed.get("log_index", 0))
        if in_scan_key in in_scan_events:
            continue
        in_scan_events.add(in_scan_key)

        event_data = {
            k: v
            for k, v in parsed.items()
            if k not in ("event_type", "block_number", "tx_hash", "log_index", "_emitter")
        }

        monitored_event = MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type=event_type,
            block_number=parsed["block_number"],
            tx_hash=parsed.get("tx_hash", ""),
            data=event_data if event_data else None,
        )
        session.add(monitored_event)
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
    confirmation_depth = max(0, _scan_int_env("PSAT_SCAN_CONFIRMATION_DEPTH", DEFAULT_CONFIRMATION_DEPTH))

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
    grouped: dict[tuple[str, int], list] = defaultdict(list)
    for row in index_rows:
        grouped[(row.chain, row.last_scanned_block // MAX_BLOCK_RANGE)].append(row)

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

    # Ships ethereum-only: the single rpc_url arg serves every chain present.
    # Cohort keys already carry chain so a per-chain rpc map is the only change
    # a second chain needs.
    rpc_by_chain = {chain: rpc_url for chain in {c.chain for c in cohorts}}
    fetchers: dict[str, RpcEventLogFetcher] = {}
    head_by_chain: dict[str, int] = {}

    def _head_for(chain: str) -> int:
        if chain not in head_by_chain:
            head_by_chain[chain] = get_latest_block(rpc_by_chain[chain])
        return head_by_chain[chain]

    def _fetcher_for(chain: str) -> RpcEventLogFetcher:
        if chain not in fetchers:
            fetchers[chain] = RpcEventLogFetcher(
                rpc_by_chain[chain],
                max_block_range=MAX_BLOCK_RANGE,
                min_bisect_span=FETCHER_MIN_BISECT_SPAN,
            )
        return fetchers[chain]

    topics_union = _scan_topics_union(session)

    total_new_events: list[MonitoredEvent] = []
    windows_scanned = 0
    blocks_scanned = 0
    degraded = False
    budget_exhausted = False

    while windows_scanned < max_windows_pass:
        eligible: list[tuple[_Cohort, int]] = []
        for cohort in cohorts:
            if cohort.done or cohort.failed:
                continue
            confirmed_head = _head_for(cohort.chain) - confirmation_depth
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
            window_end = min(cohort.cursor + MAX_BLOCK_RANGE, confirmed_head)

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

            window_events = _process_window(session, cohort, fetched_logs, window_start, window_end)

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
            _notify_window(session, window_events)

            cohort.cursor = window_end
            total_new_events.extend(window_events)
            blocks_scanned += window_end - window_start + 1
            windows_scanned += 1
            turn_windows += 1

    # Budget-exhausted only if we stopped at the hard pass cap with work left.
    if windows_scanned >= max_windows_pass:
        budget_exhausted = any(
            not c.done and not c.failed and c.cursor < (_head_for(c.chain) - confirmation_depth) for c in cohorts
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
    """
    if not mc.contract_id:
        return

    event_type = parsed["event_type"]
    tags = parsed.get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = tags.get("writes") or []
    delegates = bool(tags.get("delegates"))

    contract: Contract | None = None

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
                c.implementation = new_impl
                session.add(
                    UpgradeEvent(
                        contract_id=c.id,
                        proxy_address=mc.address,
                        old_impl=old_impl,
                        new_impl=new_impl,
                        block_number=parsed.get("block_number"),
                        tx_hash=parsed.get("tx_hash"),
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
                c.admin = str(new_value)

        _update_controller_value_rows(session, mc, write_target, new_value)


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
) -> None:
    """Write *new_value* into every ControllerValue row keyed by the
    three canonical controller_id forms the analyzer emits
    (``{name}``, ``state_variable:{name}``, ``external_contract:{name}``).

    Shared between event-driven sync (``_sync_relational_tables``) and
    poll-driven sync (``_sync_relational_from_poll``) so the two paths
    converge on the same row-keying rules and a custom slot like
    ``protocolAdmin`` propagates through either path without per-slot
    code.
    """
    if not mc.contract_id:
        return
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
    for cv in cv_rows:
        cv.value = str(new_value)


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
                    block_number=0,
                    tx_hash="",
                )
            )
            _refresh_coverage_after_upgrade(session, contract.protocol_id)
        return

    _update_controller_value_rows(session, mc, field_name, new_value)


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
) -> None:
    """Decode one poll result and, when the value changed, persist the new
    ``last_known_state``, emit a ``state_changed_poll`` event, and run the
    downstream sync (proxy write-through, relational, reanalysis, per-entry
    scanner-duplicate suppression).

    The computation is identical to the pre-rotation inline driver; only the
    framing moved from a single flat loop to per-chunk dispatch.
    """
    field_name = entry.get("field")
    if not isinstance(field_name, str) or not field_name:
        return
    new_value = decode_poll_value(raw, entry.get("type_kind"), entry.get("type"))
    if new_value is None:
        return

    state = dict(mc.last_known_state or {})
    old_value = state.get(field_name)
    if new_value == old_value:
        return

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
        return

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
            return

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
    except Exception as exc:
        logger.warning(
            "Failed to queue re-analysis for %s: %s",
            mc.address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )


def poll_for_state_changes(session: Session, rpc_url: str) -> list[MonitoredEvent]:
    """Poll for state changes by walking each contract's persisted
    ``polling_plan``.

    The plan is built at enrollment (``polling_plan.build_polling_plan``)
    from the static analyzer's tracked_controllers, plus vendored proxy
    storage slots and Safe/Timelock standard ABIs.

    Rotation (design §2.2): each pass claims only the
    ``PSAT_POLL_CONTRACTS_PER_PASS`` least-recently-polled active
    ``needs_polling`` contracts (``last_polled_at ASC NULLS FIRST``), so the
    pass is O(slice) in memory rather than O(all monitored contracts). Their
    plan entries are expanded and packed into ``MAX_BATCH_SIZE``-call chunks —
    a contract's calls never split across a chunk — and each chunk is decoded,
    synced, stamped (``last_polled_at`` = server ``now()``), and committed on
    its own. A chunk whose batch RPC fails is left unstamped so its contracts
    sort first next pass (retry-first), and the pass continues with the
    remaining chunks, reporting ``partial``.

    Contracts whose ``monitoring_config`` lacks a ``polling_plan`` still
    rotate (they get stamped with an empty chunk) — the reconciler
    (``services/monitoring/reconciler.py``) backfills the plan within its
    interval so this is a bounded transient on freshly-migrated rows.
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

    # Oldest rotation cursor in the selected slice, measured before we stamp —
    # a NULL (never-polled) member reads as unbounded age (reported as None).
    now = datetime.now(timezone.utc)
    polled_ats = [mc.last_polled_at for mc in contracts]
    if any(ts is None for ts in polled_ats):
        oldest_age_s = None
    else:
        oldest_age_s = int((now - min(ts for ts in polled_ats if ts)).total_seconds())

    # Expand each contract's polling plan, then pack whole contracts into
    # <=MAX_BATCH_SIZE-call chunks — a contract's calls never split across a
    # chunk boundary, so its dispatch indexes stay contiguous within one batch.
    chunks: list[list[tuple[MonitoredContract, list[tuple[dict, tuple[str, list]]]]]] = []
    current: list[tuple[MonitoredContract, list[tuple[dict, tuple[str, list]]]]] = []
    current_calls = 0
    for mc in contracts:
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
            chunks.append(current)
            current = []
            current_calls = 0
        current.append((mc, entries))
        current_calls += len(entries)
    if current:
        chunks.append(current)

    new_events: list[MonitoredEvent] = []
    chunks_failed = 0

    for chunk in chunks:
        batch_calls: list[tuple[str, list]] = []
        # (contract, batch_index, entry_dict)
        dispatch: list[tuple[MonitoredContract, int, dict]] = []
        for mc, entries in chunk:
            for entry, call in entries:
                dispatch.append((mc, len(batch_calls), entry))
                batch_calls.append(call)

        if batch_calls:
            try:
                results = rpc_batch_request(rpc_url, batch_calls)
            except Exception as exc:
                logger.warning("Batch RPC failed during poll: %s", exc, extra={"exc_type": type(exc).__name__})
                # Leave this chunk's contracts unstamped so they sort first
                # (retry-first) next pass; press on with the remaining chunks.
                chunks_failed += 1
                continue
            for mc, idx, entry in dispatch:
                _apply_poll_result(session, mc, entry, results[idx], new_events)

        # Stamp the rotation cursor (server clock) for every contract in the
        # chunk and commit — durable per chunk, so a later chunk's failure
        # cannot roll back an earlier chunk's detections or stamps.
        session.execute(
            update(MonitoredContract)
            .where(MonitoredContract.id.in_([mc.id for mc, _ in chunk]))
            .values(last_polled_at=func.now())
        )
        session.commit()

    emit_monitor_cycle(
        HEARTBEAT_PROTOCOL_POLLER,
        started=started,
        contracts_scanned=len(contracts),
        blocks_scanned=0,
        events_found=len(new_events),
        partial=chunks_failed > 0,
        extra_detail={
            "contracts_selected": len(contracts),
            "chunks": len(chunks),
            "chunks_failed": chunks_failed,
            "oldest_last_polled_age_s": oldest_age_s,
        },
    )
    return new_events


# ---------------------------------------------------------------------------
# Blocking loops
# ---------------------------------------------------------------------------


def run_scan_loop(rpc_url: str, interval: float = DEFAULT_SCAN_INTERVAL) -> None:
    """Run the unified event scanner in a blocking loop.

    ``scan_for_events`` now commits and notifies per window, so a long
    catch-up drains at RPC speed without buffering. When a pass exhausts its
    window budget with work still queued, re-run after the short busy interval
    instead of the full scan interval.
    """
    logger.info("Starting unified protocol monitor (interval=%ss)", interval)
    busy_interval = _scan_float_env("PSAT_SCAN_BUSY_INTERVAL_S", 5.0)
    while True:
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
        time.sleep(sleep_for)


def run_poll_loop(rpc_url: str, interval: float = DEFAULT_POLL_INTERVAL) -> None:
    """Run the unified state polling loop."""
    logger.info("Starting unified protocol poller (interval=%ss)", interval)
    while True:
        try:
            with SessionLocal() as session:
                new_events = poll_for_state_changes(session, rpc_url)
                if new_events:
                    logger.info("Poll detected %d state change(s)", len(new_events))
                    try:
                        from services.monitoring.notifier import notify_protocol_events

                        notify_protocol_events(session, new_events)
                    except Exception as exc:
                        logger.warning("Protocol notification failed: %s", exc, extra={"exc_type": type(exc).__name__})
        except Exception as exc:
            logger.warning("Poll cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
            # ``poll_for_state_changes`` raised before it could emit its own
            # cycle summary — still beat so the fleet view sees a degraded cycle.
            record_heartbeat(
                HEARTBEAT_PROTOCOL_POLLER,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        time.sleep(interval)
