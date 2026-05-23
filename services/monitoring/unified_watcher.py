"""Unified protocol monitoring — scans blocks for all governance + proxy events."""

from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    ALL_EVENT_TOPICS,
    PROXY_EVENT_TOPICS,
    parse_any_log,
    parse_tracked_log,
)
from services.monitoring.reanalysis import maybe_queue_reanalysis
from utils.rpc import (
    normalize_hex,
    parse_address_result,
    rpc_batch_request,
    rpc_request,
)

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)

MAX_BLOCK_RANGE = 2000
DEFAULT_SCAN_INTERVAL = int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600"))
DEFAULT_POLL_INTERVAL = int(os.getenv("PROTOCOL_POLL_INTERVAL", "600"))

# Storage slots for proxy resolution
_EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# Selectors for state polling
_OWNER_SEL = "0x8da5cb5b"  # owner()
_PAUSED_SEL = "0x5c975abb"  # paused()
_GET_THRESHOLD_SEL = "0xe75235b8"  # getThreshold()
_GET_MIN_DELAY_SEL = "0xf27a0c92"  # getMinDelay()

# Controller IDs that represent the contract owner. Used by relational sync
# to update only the real owner row, not unrelated controller values that
# happen to contain "owner" in their name (e.g. token_owner_registry).
_OWNER_CONTROLLER_IDS = ("owner", "state_variable:owner")
# Solmate-Auth / DSAuth-style authority pointer. Sync target for the
# ``authority_updated`` event emitted by Solmate's ``Auth.setAuthority``.
_AUTHORITY_CONTROLLER_IDS = ("authority", "state_variable:authority", "external_contract:authority")

# Mapping from poll field names to scanner event types that detect the same
# underlying state change.  Used by the poller to suppress duplicate events
# when the event scanner has already recorded the change via an on-chain log.
_POLL_FIELD_TO_SCAN_EVENTS: dict[str, frozenset[str]] = {
    "implementation": frozenset(
        {
            "upgraded",
            "new_implementation",
            "changed_master_copy",
            "target_updated",
            "beacon_upgraded",
        }
    ),
    "owner": frozenset({"ownership_transferred"}),
    "paused": frozenset({"paused", "unpaused"}),
    "threshold": frozenset({"threshold_changed"}),
    "min_delay": frozenset({"delay_changed"}),
}


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
            if mc.monitoring_config and not _should_watch(mc, event_type):
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


def _should_watch(mc: MonitoredContract, event_type: str) -> bool:
    """Check if the monitoring config allows this event type."""
    config = mc.monitoring_config or {}

    # admin_changed routes to both watch_upgrades (EIP-1967 proxy admin)
    # and watch_ownership (Compound/Aave/Curve governance admin — same
    # semantic role as ownership for non-proxy contracts). The event_type
    # is identical across both cases because the underlying mutation is
    # "the privileged controller changed"; the monitoring intent depends
    # on what the contract IS. Accept either flag rather than splitting
    # the event_type, which would force every config consumer to
    # disambiguate.
    type_to_config_keys = {
        "upgraded": ("watch_upgrades",),
        "admin_changed": ("watch_upgrades", "watch_ownership"),
        "beacon_upgraded": ("watch_upgrades",),
        "changed_master_copy": ("watch_upgrades",),
        "new_implementation": ("watch_upgrades",),
        "new_pending_implementation": ("watch_upgrades",),
        "target_updated": ("watch_upgrades",),
        "upgraded_revision": ("watch_upgrades",),
        "diamond_cut": ("watch_upgrades",),
        "ownership_transferred": ("watch_ownership",),
        "ownership_transfer_started": ("watch_ownership",),
        "authority_updated": ("watch_authority",),
        "paused": ("watch_pause",),
        "unpaused": ("watch_pause",),
        "role_granted": ("watch_roles",),
        "role_revoked": ("watch_roles",),
        "signer_added": ("watch_safe_signers",),
        "signer_removed": ("watch_safe_signers",),
        # signer_updated comes from the tag-driven path when a non-Safe
        # contract writes its custom "owners" array. Route through the
        # same flag as the Safe-native events.
        "signer_updated": ("watch_safe_signers",),
        "threshold_changed": ("watch_safe_signers",),
        "timelock_scheduled": ("watch_timelock",),
        "timelock_executed": ("watch_timelock",),
        "delay_changed": ("watch_timelock",),
        "safe_tx_executed": ("watch_safe_signers",),
        "safe_tx_failed": ("watch_safe_signers",),
        "safe_module_executed": ("watch_safe_signers",),
        "safe_module_failed": ("watch_safe_signers",),
    }

    config_keys = type_to_config_keys.get(event_type)
    if config_keys is None:
        return True  # Unknown event type — allow

    # Legacy alias support: `watch_signers` predates the rename to
    # `watch_safe_signers`. Accept either flag so historic
    # MonitoredContract rows written before the rename keep working
    # without a migration.
    if "watch_safe_signers" in config_keys:
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


def _update_state_from_event(mc: MonitoredContract, parsed: dict) -> None:
    """Update last_known_state based on a detected event."""
    state = dict(mc.last_known_state or {})
    event_type = parsed["event_type"]

    if event_type == "ownership_transferred" and parsed.get("new_owner"):
        state["owner"] = parsed["new_owner"]
    elif event_type == "authority_updated" and parsed.get("new_authority"):
        state["authority"] = parsed["new_authority"]
    elif event_type in ("paused", "unpaused"):
        state["paused"] = event_type == "paused"
    elif event_type == "threshold_changed" and parsed.get("threshold"):
        state["threshold"] = parsed["threshold"]
    elif event_type in ("upgraded", "new_implementation", "changed_master_copy", "target_updated"):
        impl = parsed.get("implementation")
        if impl:
            state["implementation"] = impl
    elif event_type == "admin_changed" and parsed.get("new_admin"):
        state["admin"] = parsed["new_admin"]
    elif event_type == "beacon_upgraded" and parsed.get("beacon"):
        state["beacon"] = parsed["beacon"]
    elif event_type == "delay_changed" and parsed.get("new_delay") is not None:
        state["min_delay"] = parsed["new_delay"]
    elif event_type == "initialized":
        # OZ Initializable Initialized(uint64 version). The version arg is
        # named ``version`` in the canonical ABI; some forks use
        # ``initVersion``. Either way the value goes into last_known_state
        # so reanalysis can compare against the next observation.
        version = parsed.get("version")
        if version is None:
            version = parsed.get("initVersion")
        if version is not None:
            state["initialized_version"] = version

    # Tag-driven generic reflection: for each state var the emitter wrote
    # that doesn't have a canonical branch above, capture the new value
    # by name match. Covers custom controller slots (e.g. ``protocolAdmin``,
    # ``feeRecipient``) without requiring per-slot code. Skips when the
    # canonical branch already populated the slot.
    tags = parsed.get("effect_tags") or {}
    for write_target in tags.get("writes") or []:
        if not isinstance(write_target, str) or write_target in state:
            continue
        # Look for an arg matching the write target's name, with or
        # without the OZ ``new`` prefix. The decoder populated
        # ``parsed[input_name]`` for every input.
        candidate = parsed.get(write_target)
        if candidate is None:
            cap = write_target[:1].upper() + write_target[1:] if write_target else ""
            candidate = parsed.get(f"new{cap}")
        if candidate is not None:
            state[write_target] = candidate

    mc.last_known_state = state
    flag_modified(mc, "last_known_state")


def _sync_relational_tables(
    session: Session,
    mc: MonitoredContract,
    parsed: dict,
) -> None:
    """Propagate a detected event to the relational Contract / ControllerValue /
    UpgradeEvent tables so the API serves up-to-date data.

    Only updates rows when the MonitoredContract has a linked contract_id.
    """
    if not mc.contract_id:
        return

    event_type = parsed["event_type"]

    # --- Proxy upgrade events → Contract.implementation + UpgradeEvent row ---
    if event_type in (
        "upgraded",
        "new_implementation",
        "changed_master_copy",
        "target_updated",
    ):
        new_impl = parsed.get("implementation")
        if not new_impl:
            return
        contract = session.get(Contract, mc.contract_id)
        if not contract:
            return

        old_impl = contract.implementation
        contract.implementation = new_impl

        session.add(
            UpgradeEvent(
                contract_id=contract.id,
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
        _refresh_coverage_after_upgrade(session, contract.protocol_id)

    # --- AdminChanged → Contract.admin ---
    elif event_type == "admin_changed":
        new_admin = parsed.get("new_admin")
        if not new_admin:
            return
        contract = session.get(Contract, mc.contract_id)
        if contract:
            contract.admin = new_admin

    # --- OwnershipTransferred → ControllerValue where controller_id is 'owner' ---
    elif event_type == "ownership_transferred":
        new_owner = parsed.get("new_owner")
        if not new_owner:
            return
        cv_rows = (
            session.execute(
                select(ControllerValue).where(
                    ControllerValue.contract_id == mc.contract_id,
                    ControllerValue.controller_id.in_(_OWNER_CONTROLLER_IDS),
                )
            )
            .scalars()
            .all()
        )
        for cv in cv_rows:
            cv.value = new_owner

    # --- AuthorityUpdated → ControllerValue where controller_id is 'authority' ---
    elif event_type == "authority_updated":
        new_authority = parsed.get("new_authority")
        if not new_authority:
            return
        cv_rows = (
            session.execute(
                select(ControllerValue).where(
                    ControllerValue.contract_id == mc.contract_id,
                    ControllerValue.controller_id.in_(_AUTHORITY_CONTROLLER_IDS),
                )
            )
            .scalars()
            .all()
        )
        for cv in cv_rows:
            cv.value = new_authority


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


def _sync_relational_from_poll(
    session: Session,
    mc: MonitoredContract,
    field_name: str,
    new_value: object,
    old_value: object,
) -> None:
    """Propagate a polling-detected state change to relational tables."""
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

    elif field_name == "owner":
        cv_rows = (
            session.execute(
                select(ControllerValue).where(
                    ControllerValue.contract_id == mc.contract_id,
                    ControllerValue.controller_id.in_(_OWNER_CONTROLLER_IDS),
                )
            )
            .scalars()
            .all()
        )
        for cv in cv_rows:
            cv.value = str(new_value)


# ---------------------------------------------------------------------------
# State polling
# ---------------------------------------------------------------------------


def poll_for_state_changes(session: Session, rpc_url: str) -> list[MonitoredEvent]:
    """Poll for state changes on contracts that need polling.

    Batches RPC calls based on contract_type and compares against
    last_known_state. Returns list of new MonitoredEvent records for changes.
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

    # Build batch calls
    batch_calls: list[tuple[str, list]] = []
    # (contract, start_idx, field_name)
    poll_plan: list[tuple[MonitoredContract, int, str]] = []

    for mc in contracts:
        ct = mc.contract_type
        if ct == "proxy":
            start = len(batch_calls)
            batch_calls.append(("eth_getStorageAt", [mc.address, _EIP1967_IMPL_SLOT, "latest"]))
            poll_plan.append((mc, start, "implementation"))
        if ct in ("proxy", "regular", "pausable", "role_control"):
            start = len(batch_calls)
            batch_calls.append(("eth_call", [{"to": mc.address, "data": _OWNER_SEL}, "latest"]))
            poll_plan.append((mc, start, "owner"))
        if ct in ("pausable",):
            start = len(batch_calls)
            batch_calls.append(("eth_call", [{"to": mc.address, "data": _PAUSED_SEL}, "latest"]))
            poll_plan.append((mc, start, "paused"))
        if ct == "safe":
            start = len(batch_calls)
            batch_calls.append(("eth_call", [{"to": mc.address, "data": _GET_THRESHOLD_SEL}, "latest"]))
            poll_plan.append((mc, start, "threshold"))
        if ct == "timelock":
            start = len(batch_calls)
            batch_calls.append(("eth_call", [{"to": mc.address, "data": _GET_MIN_DELAY_SEL}, "latest"]))
            poll_plan.append((mc, start, "min_delay"))

    if not batch_calls:
        return []

    try:
        results = rpc_batch_request(rpc_url, batch_calls)
    except Exception as exc:
        logger.warning("Batch RPC failed during poll: %s", exc, extra={"exc_type": type(exc).__name__})
        return []

    new_events: list[MonitoredEvent] = []

    for mc, idx, field_name in poll_plan:
        raw = results[idx]
        state = dict(mc.last_known_state or {})
        old_value = state.get(field_name)

        if field_name == "implementation":
            new_value = parse_address_result(raw)
        elif field_name == "owner":
            new_value = parse_address_result(raw)
        elif field_name == "paused":
            if not raw:
                new_value = None
            elif raw != "0x" + "0" * 64:
                new_value = True
            else:
                new_value = False
        elif field_name in ("threshold", "min_delay"):
            if raw and raw != "0x":
                try:
                    new_value = int(raw, 16)
                except (ValueError, TypeError):
                    new_value = None
            else:
                new_value = None
        else:
            new_value = None

        if new_value is None:
            continue

        if new_value != old_value:
            # Always record the new value in last_known_state
            state[field_name] = new_value
            mc.last_known_state = state
            flag_modified(mc, "last_known_state")

            # Skip emitting an event when old_value is None — that's the
            # first observation after enrollment, not an actual state change.
            if old_value is None:
                logger.debug(
                    "Initial %s observation on %s: %s (no event emitted)",
                    field_name,
                    mc.address,
                    new_value,
                )
                continue

            # Suppress if the event scanner already recorded this change.
            # This handles the race condition where the scanner and poller
            # processes both detect the same underlying change (e.g., a proxy
            # upgrade is visible as both an Upgraded log and a storage-slot
            # change).
            scan_types = _POLL_FIELD_TO_SCAN_EVENTS.get(field_name)
            if scan_types:
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
