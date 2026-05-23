"""Unified protocol monitoring — scans blocks for all governance + proxy events."""

from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from dotenv import load_dotenv
from sqlalchemy import select
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
from services.monitoring.event_topics import (
    _HANDROLLED_EVENT_TYPE_TO_TAGS,
    ALL_EVENT_TOPICS,
    PROXY_EVENT_TOPICS,
    parse_any_log,
    parse_tracked_log,
)
from services.monitoring.polling_plan import decode_poll_value
from services.monitoring.reanalysis import maybe_queue_reanalysis
from utils.rpc import (
    normalize_hex,
    rpc_batch_request,
    rpc_request,
)

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)

MAX_BLOCK_RANGE = 2000
DEFAULT_SCAN_INTERVAL = int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600"))
DEFAULT_POLL_INTERVAL = int(os.getenv("PROTOCOL_POLL_INTERVAL", "600"))

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


def scan_for_events(session: Session, rpc_url: str) -> list[MonitoredEvent]:
    """Scan new blocks for all governance and proxy events.

    Uses a single eth_getLogs call per block chunk with all monitored
    addresses and all event topic0s. Returns list of new MonitoredEvent
    records created.
    """
    contracts = (
        session.execute(
            select(MonitoredContract).where(MonitoredContract.is_active == True)  # noqa: E712
        )
        .scalars()
        .all()
    )
    if not contracts:
        return []

    contract_by_address: dict[str, MonitoredContract] = {c.address.lower(): c for c in contracts}

    # Per-emitter map of topic0 → tracked-topic spec (from the static
    # analysis ``tracking_plan``, persisted onto monitoring_config by
    # enrollment). Lets the dispatcher decode events from ABIs the
    # hand-rolled registry doesn't know about — Solmate OwnerUpdated /
    # AuthorityUpdated, DSAuth LogSetOwner, Compound NewAdmin, etc.
    tracked_specs_by_emitter: dict[str, dict[str, dict]] = {}
    extra_topic0s: set[str] = set()
    for addr, mc in contract_by_address.items():
        topics_list = (mc.monitoring_config or {}).get("tracked_topics") or []
        if not topics_list:
            continue
        spec_map: dict[str, dict] = {}
        for spec in topics_list:
            t0 = (spec.get("topic0") or "").lower()
            if not t0:
                continue
            spec_map[t0] = spec
            extra_topic0s.add(t0)
        if spec_map:
            tracked_specs_by_emitter[addr] = spec_map

    from_block = min(c.last_scanned_block for c in contracts)
    latest_block = get_latest_block(rpc_url)

    if from_block >= latest_block:
        logger.debug("Scan: no new blocks (from=%d, latest=%d)", from_block, latest_block)
        return []

    logger.debug(
        "Scan: %d contracts, block range %d->%d (%d blocks)",
        len(contracts),
        from_block + 1,
        latest_block,
        latest_block - from_block,
    )

    new_events: list[MonitoredEvent] = []
    # Union the hand-rolled global registry with per-contract topic0s
    # discovered from the analysis tracking_plan. The hand-rolled set
    # owns OZ / Safe / Timelock / proxy events (semantics beyond raw
    # decode); per-contract topics cover the long tail of ABI variants.
    topics = [sorted(set(ALL_EVENT_TOPICS.keys()) | extra_topic0s)]

    # Two-tier dedupe:
    #   ``db_events`` is loaded from already-persisted MonitoredEvent rows
    #   keyed by the 4-tuple the table can express today (no log_index
    #   column). It guards against duplicating rows we've already stored.
    #   ``in_scan_events`` is the 5-tuple key used within a single scan
    #   pass; the extra log_index lets batch timelock ops (scheduleBatch /
    #   executeBatch emit one CallScheduled / CallExecuted per call,
    #   sharing tx + block + event_type) all land as distinct rows.
    db_events: set[tuple] = set()
    in_scan_events: set[tuple] = set()
    max_scanned = max(c.last_scanned_block for c in contracts)
    if from_block < max_scanned:
        existing_rows = session.execute(
            select(
                MonitoredEvent.monitored_contract_id,
                MonitoredEvent.tx_hash,
                MonitoredEvent.block_number,
                MonitoredEvent.event_type,
            ).where(
                MonitoredEvent.block_number > from_block,
                MonitoredEvent.block_number <= max_scanned,
            )
        ).all()
        for row in existing_rows:
            db_events.add((str(row[0]), row[1], row[2], row[3]))

    last_successful_block = from_block
    cursor = from_block + 1

    while cursor <= latest_block:
        to_block = min(cursor + MAX_BLOCK_RANGE - 1, latest_block)

        # Only include addresses that still need blocks in this chunk.
        # A contract with last_scanned_block >= to_block has already
        # processed all blocks in this range — no need to re-scan for it.
        chunk_addresses = [addr for addr, mc in contract_by_address.items() if mc.last_scanned_block < to_block]
        if not chunk_addresses:
            cursor = to_block + 1
            last_successful_block = to_block
            continue

        filter_params = {
            "fromBlock": hex(cursor),
            "toBlock": hex(to_block),
            "address": chunk_addresses,
            "topics": topics,
        }

        try:
            logs = rpc_request(rpc_url, "eth_getLogs", [filter_params])
        except Exception as exc:
            logger.warning(
                "eth_getLogs failed for blocks %d-%d: %s",
                cursor,
                to_block,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            break

        if not isinstance(logs, list):
            logs = []

        for log in logs:
            emitter = normalize_hex(log.get("address", "")).lower()
            parsed = parse_any_log(log)
            if not parsed:
                # Fall through to the per-contract tracked-topic
                # dispatcher: events from non-OZ ABIs (Solmate,
                # DSAuth, Compound, …) the hand-rolled registry
                # doesn't know about. Spec was attached at enrollment
                # time from the analysis tracking_plan.
                emitter_specs = tracked_specs_by_emitter.get(emitter)
                if not emitter_specs:
                    continue
                log_topics = log.get("topics") or []
                if not log_topics:
                    continue
                spec = emitter_specs.get((log_topics[0] or "").lower())
                if not spec:
                    continue
                parsed = parse_tracked_log(log, spec)
                if not parsed:
                    continue

            mc = contract_by_address.get(emitter)
            if not mc:
                continue

            event_type = parsed["event_type"]

            # Check monitoring config
            if mc.monitoring_config and not _should_watch(mc, parsed):
                continue

            # First gate: have we already stored ANY row for this
            # (mc, tx, block, type) combo in a previous scan? If so,
            # skip — re-scanning shouldn't duplicate. Note this means
            # historically-collapsed batch rows stay collapsed; the
            # log_index dimension only helps NEW scans onward.
            db_key = (
                str(mc.id),
                parsed.get("tx_hash", ""),
                parsed["block_number"],
                event_type,
            )
            if db_key in db_events:
                continue

            # Second gate: in-scan dedup keyed on log_index so batch
            # timelock ops (``scheduleBatch`` / ``executeBatch`` emit
            # one CallScheduled / CallExecuted per call with identical
            # tx+block+type but distinct logIndex) all land as separate
            # rows in the SAME scan.
            in_scan_key = (*db_key, parsed.get("log_index", 0))
            if in_scan_key in in_scan_events:
                continue
            in_scan_events.add(in_scan_key)

            # Build event data (everything except standard fields)
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

            # Write-through to ProxyUpgradeEvent for proxy events
            topic0 = log.get("topics", [""])[0].lower()
            if topic0 in PROXY_EVENT_TOPICS and mc.watched_proxy_id:
                _write_through_proxy_event(session, mc, parsed)

            # Update last_known_state
            _update_state_from_event(mc, parsed)

            # Propagate to relational tables (Contract, ControllerValue, UpgradeEvent)
            _sync_relational_tables(session, mc, parsed)

            # Queue a re-analysis job if the event warrants it
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

        last_successful_block = to_block
        cursor = to_block + 1

    # Advance last_scanned_block
    for mc in contracts:
        if last_successful_block > mc.last_scanned_block:
            mc.last_scanned_block = last_successful_block

    session.commit()
    return new_events


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
        # Generic name-match fallback for custom slots — the decoder
        # populated ``parsed[input_name]`` for every input; try the bare
        # target name, then the OZ ``new<Cap>`` convention. Unlike the
        # canonical branch we DO overwrite an existing state entry —
        # this path is the only one that updates custom slots, so a
        # subsequent observation must take precedence.
        candidate = parsed.get(write_target)
        if candidate is None:
            cap = write_target[:1].upper() + write_target[1:]
            candidate = parsed.get(f"new{cap}")
        if candidate is not None:
            state[write_target] = candidate

    mc.last_known_state = state
    flag_modified(mc, "last_known_state")


def _new_value_for_write_target(write_target: str, parsed: dict) -> object | None:
    """Pull the new value for *write_target* out of a parsed event.

    Tries the canonical extractor in ``_WRITE_TARGET_TO_STATE`` first,
    then falls back to generic name-match (bare name + OZ ``new<Cap>``
    convention) so custom slots resolve without per-slot code.
    """
    mapping = _WRITE_TARGET_TO_STATE.get(write_target)
    if mapping is not None:
        _, extractor = mapping
        return extractor(parsed)
    candidate = parsed.get(write_target)
    if candidate is None:
        cap = write_target[:1].upper() + write_target[1:]
        candidate = parsed.get(f"new{cap}")
    return candidate


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


def poll_for_state_changes(session: Session, rpc_url: str) -> list[MonitoredEvent]:
    """Poll for state changes by walking each contract's persisted
    ``polling_plan``.

    The plan is built at enrollment (``polling_plan.build_polling_plan``)
    from the static analyzer's tracked_controllers, plus vendored proxy
    storage slots and Safe/Timelock standard ABIs. Each tick:

      1. Expand every entry into a batched RPC call.
      2. Decode each result by the entry's ``type_kind`` / ``type``.
      3. Compare against ``mc.last_known_state[entry["field"]]``; if it
         changed, persist the new value, emit a ``state_changed_poll``
         event, and run downstream sync (relational, reanalysis,
         per-entry suppression of scanner duplicates).

    Contracts whose ``monitoring_config`` lacks a ``polling_plan`` are
    skipped — the reconciler (``services/monitoring/reconciler.py``)
    backfills the plan within its interval (default 600s) so this is a
    bounded transient on freshly-migrated rows.
    """
    contracts = (
        session.execute(
            select(MonitoredContract).where(
                MonitoredContract.is_active == True,  # noqa: E712
                MonitoredContract.needs_polling == True,  # noqa: E712
            )
        )
        .scalars()
        .all()
    )
    if not contracts:
        return []

    batch_calls: list[tuple[str, list]] = []
    # (contract, batch_index, entry_dict)
    poll_dispatch: list[tuple[MonitoredContract, int, dict]] = []

    for mc in contracts:
        plan = (mc.monitoring_config or {}).get("polling_plan") or []
        if not isinstance(plan, list):
            continue
        for entry in plan:
            if not isinstance(entry, dict):
                continue
            call = _rpc_call_for_entry(mc.address, entry)
            if call is None:
                continue
            poll_dispatch.append((mc, len(batch_calls), entry))
            batch_calls.append(call)

    if not batch_calls:
        return []

    try:
        results = rpc_batch_request(rpc_url, batch_calls)
    except Exception as exc:
        logger.warning("Batch RPC failed during poll: %s", exc, extra={"exc_type": type(exc).__name__})
        return []

    new_events: list[MonitoredEvent] = []

    for mc, idx, entry in poll_dispatch:
        raw = results[idx]
        field_name = entry.get("field")
        if not isinstance(field_name, str) or not field_name:
            continue
        new_value = decode_poll_value(raw, entry.get("type_kind"), entry.get("type"))
        if new_value is None:
            continue

        state = dict(mc.last_known_state or {})
        old_value = state.get(field_name)
        if new_value == old_value:
            continue

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
            continue

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
                continue

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

    session.commit()
    return new_events


# ---------------------------------------------------------------------------
# Blocking loops
# ---------------------------------------------------------------------------


def _boot_reconcile(rpc_url: str) -> None:
    """Best-effort enrollment reconcile on watcher startup.

    Catches the case where a migration / admin fix-up landed while the
    watcher was down. The reconciler converges on every tick anyway, so
    a failure here is non-fatal — but the boot pass closes the deploy-
    window gap so monitored_contracts is correct before the first scan.
    """
    try:
        from services.monitoring.reconciler import reconcile_enrollments

        with SessionLocal() as session:
            reconcile_enrollments(session, rpc_url)
    except Exception as exc:
        logger.warning("Boot reconcile failed: %s", exc, extra={"exc_type": type(exc).__name__})


def run_scan_loop(rpc_url: str, interval: float = DEFAULT_SCAN_INTERVAL) -> None:
    """Run the unified event scanner in a blocking loop."""
    logger.info("Starting unified protocol monitor (interval=%ss)", interval)
    _boot_reconcile(rpc_url)
    while True:
        try:
            with SessionLocal() as session:
                new_events = scan_for_events(session, rpc_url)
                if new_events:
                    logger.info("Detected %d new event(s)", len(new_events))
                    try:
                        from services.monitoring.notifier import notify_protocol_events

                        notify_protocol_events(session, new_events)
                    except Exception as exc:
                        logger.warning("Protocol notification failed: %s", exc, extra={"exc_type": type(exc).__name__})
        except Exception as exc:
            logger.warning("Scan cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
        time.sleep(interval)


def run_poll_loop(rpc_url: str, interval: float = DEFAULT_POLL_INTERVAL) -> None:
    """Run the unified state polling loop."""
    logger.info("Starting unified protocol poller (interval=%ss)", interval)
    _boot_reconcile(rpc_url)
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
        time.sleep(interval)
