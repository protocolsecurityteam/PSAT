"""Proxy upgrade monitor — scans blocks for upgrade events and polls storage."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import ProxyUpgradeEvent, SessionLocal, WatchedProxy
from services.discovery.upgrade_history import (
    EVENT_TOPICS,
    parse_upgrade_log,
)
from services.monitoring.notifier import notify_upgrades
from utils.rpc import normalize_hex, parse_address_result, rpc_batch_request, rpc_request

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# Storage slots used for implementation resolution
_EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_EIP1822_LOGIC_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
_OZ_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
_GNOSIS_SLOT = "0x0"

# Getter selectors for protocol-specific proxies
_IMPLEMENTATION_SEL = "0x5c60da1b"  # implementation()
_COMPTROLLER_IMPL_SEL = "0xbb82aa5e"  # comptrollerImplementation()
_TARGET_SEL = "0xd4b83992"  # target()
_MASTER_COPY_SEL = "0xa619486e"  # masterCopy()

logger = logging.getLogger(__name__)

# Maximum block range per eth_getLogs call (stay under node limits)
MAX_BLOCK_RANGE = 2000
# Default scan interval in seconds
DEFAULT_SCAN_INTERVAL = int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600"))


def get_latest_block(rpc_url: str) -> int:
    # No chain_id declared: the only callers are the legacy single-chain
    # ``run_scan_loop`` / ``run_poll_loop`` CLI scanner, which is handed a bare
    # ``--rpc-url`` and scans ALL WatchedProxy rows (mixed chains) against it —
    # there is no single chain in scope to declare. The per-chain scanner is
    # ``unified_watcher`` (armed). Reported as a finding, not papered over.
    result = rpc_request(rpc_url, "eth_blockNumber", [])
    return int(result, 16)


def scan_for_upgrades(session: Session, rpc_url: str) -> list[ProxyUpgradeEvent]:
    """Scan new blocks for Upgraded events across all watched proxies.

    Uses a single eth_getLogs call per block range with all watched proxy
    addresses, making this O(1) RPC calls regardless of proxy count.

    Returns list of new ProxyUpgradeEvent records created.
    """
    # Get all watched proxies for this chain
    proxies = session.execute(select(WatchedProxy)).scalars().all()
    if not proxies:
        return []

    proxy_by_address: dict[str, WatchedProxy] = {p.proxy_address.lower(): p for p in proxies}
    addresses = list(proxy_by_address.keys())

    # Determine block range: from the minimum last_scanned_block across all proxies
    from_block = min(p.last_scanned_block for p in proxies)
    latest_block = get_latest_block(rpc_url)

    if from_block >= latest_block:
        logger.debug("Scan: no new blocks (from=%d, latest=%d)", from_block, latest_block)
        return []

    logger.debug(
        "Scan: %d proxies, block range %d→%d (%d blocks)",
        len(proxies),
        from_block + 1,
        latest_block,
        latest_block - from_block,
    )
    new_events: list[ProxyUpgradeEvent] = []
    topics = [list(EVENT_TOPICS.keys())]  # topic0 = any of the 3 event types

    # Pre-load existing events for deduplication — only need the overlap
    # window where proxies have different last_scanned_block values.
    # Once all proxies converge (normal steady state), this set is empty.
    max_scanned = max(p.last_scanned_block for p in proxies)
    existing_events: set[tuple] = set()
    if from_block < max_scanned:
        existing_rows = session.execute(
            select(
                ProxyUpgradeEvent.watched_proxy_id,
                ProxyUpgradeEvent.tx_hash,
                ProxyUpgradeEvent.block_number,
                ProxyUpgradeEvent.new_implementation,
            ).where(
                ProxyUpgradeEvent.block_number > from_block,
                ProxyUpgradeEvent.block_number <= max_scanned,
            )
        ).all()
        for row in existing_rows:
            existing_events.add((str(row[0]), row[1], row[2], row[3]))

    # Scan in chunks to stay under node limits
    last_successful_block = from_block
    cursor = from_block + 1
    while cursor <= latest_block:
        to_block = min(cursor + MAX_BLOCK_RANGE - 1, latest_block)

        filter_params = {
            "fromBlock": hex(cursor),
            "toBlock": hex(to_block),
            "address": addresses,
            "topics": topics,
        }

        try:
            # No chain_id declared: this legacy single-chain scanner (only reached
            # via run_scan_loop CLI) filters ALL WatchedProxy rows (mixed chains)
            # against one bare rpc_url — no single chain in scope. Reported as a
            # finding; the per-chain scanner is unified_watcher (armed).
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
            event = parse_upgrade_log(log)
            if not event:
                continue

            emitter = normalize_hex(log.get("address", "")).lower()
            proxy = proxy_by_address.get(emitter)
            if not proxy:
                continue

            new_impl = event.get("implementation") or event.get("beacon") or event.get("new_admin")
            if not new_impl:
                # Aave V2 Upgraded(uint256) has no implementation address in the event;
                # fall back to reading the current impl from the EIP-1967 storage slot.
                if event.get("event_type") == "upgraded_revision":
                    resolved = resolve_current_implementation(
                        proxy.proxy_address, rpc_url, block=hex(event["block_number"])
                    )
                    if resolved:
                        new_impl = resolved
                    else:
                        continue
                else:
                    continue

            # Skip duplicates: same proxy, tx, block, and target already recorded
            dedup_key = (str(proxy.id), event.get("tx_hash", ""), event["block_number"], new_impl)
            if dedup_key in existing_events:
                continue
            existing_events.add(dedup_key)

            upgrade_event = ProxyUpgradeEvent(
                watched_proxy_id=proxy.id,
                block_number=event["block_number"],
                tx_hash=event.get("tx_hash", ""),
                old_implementation=proxy.last_known_implementation,
                new_implementation=new_impl,
                event_type=event["event_type"],
            )
            session.add(upgrade_event)
            new_events.append(upgrade_event)

            logger.info(
                "Detected %s on %s: %s -> %s (block %d)",
                event["event_type"],
                proxy.proxy_address,
                proxy.last_known_implementation,
                new_impl,
                event["block_number"],
            )
            proxy.last_known_implementation = new_impl

        last_successful_block = to_block
        cursor = to_block + 1

    # Only advance last_scanned_block, never regress
    for proxy in proxies:
        if last_successful_block > proxy.last_scanned_block:
            proxy.last_scanned_block = last_successful_block

    session.commit()
    return new_events


def _read_slot(
    rpc_url: str, address: str, slot: str, block: str = "latest", *, chain_id: int | None = None
) -> str | None:
    """Read a storage slot and return the address if non-zero, else None."""
    try:
        result = rpc_request(rpc_url, "eth_getStorageAt", [address, slot, block], chain_id=chain_id)
        if result and result != "0x" + "0" * 64:
            addr = "0x" + result[-40:]
            if addr != "0x" + "0" * 40:
                return normalize_hex(addr)
    except Exception:
        pass
    return None


def _call_getter(rpc_url: str, address: str, selector: str, *, chain_id: int | None = None) -> str | None:
    """Call a view function that returns a single address.  Returns None on revert."""
    try:
        result = rpc_request(rpc_url, "eth_call", [{"to": address, "data": selector}, "latest"], chain_id=chain_id)
        if result and result != "0x" + "0" * 64:
            addr = "0x" + result[-40:]
            if addr != "0x" + "0" * 40:
                return normalize_hex(addr)
    except Exception:
        pass
    return None


# Maps proxy_type to the single resolution method needed.  Each entry is
# either ("slot", slot_hex) for eth_getStorageAt or ("call", selector)
# for eth_call.  This lets poll_for_upgrades make exactly 1 RPC call per
# proxy instead of trying up to 8.
_RESOLVE_BY_TYPE: dict[str, tuple[str, str]] = {
    "eip1967": ("slot", _EIP1967_IMPL_SLOT),
    "beacon_proxy": ("slot", _EIP1967_IMPL_SLOT),
    "eip1822": ("slot", _EIP1822_LOGIC_SLOT),
    "oz_legacy": ("slot", _OZ_IMPL_SLOT),
    "custom": ("call", _IMPLEMENTATION_SEL),
    "gnosis_safe": ("slot", _GNOSIS_SLOT),
    "compound": ("call", _COMPTROLLER_IMPL_SEL),
    "synthetix": ("call", _TARGET_SEL),
    # eip2535 and eip1167 don't have a single implementation address
    # (diamond has facets, 1167 is immutable) — omitted intentionally.
}

# Prioritised resolution attempts for proxies with unknown type.
# All are sent in a single batch; the first hit (in order) wins and its
# proxy_type is saved so future polls take the fast path.
_DISCOVERY_METHODS: list[tuple[str, str, str]] = [
    ("slot", _EIP1967_IMPL_SLOT, "eip1967"),
    ("slot", _EIP1822_LOGIC_SLOT, "eip1822"),
    ("slot", _OZ_IMPL_SLOT, "oz_legacy"),
    ("call", _IMPLEMENTATION_SEL, "custom"),
    ("call", _MASTER_COPY_SEL, "gnosis_safe"),
    ("call", _COMPTROLLER_IMPL_SEL, "compound"),
    ("call", _TARGET_SEL, "synthetix"),
    ("slot", _GNOSIS_SLOT, "gnosis_safe"),
]


def _build_rpc_call(method_type: str, address: str, arg: str) -> tuple[str, list]:
    """Return a ``(method, params)`` tuple for use in a JSON-RPC batch."""
    if method_type == "slot":
        return ("eth_getStorageAt", [address, arg, "latest"])
    return ("eth_call", [{"to": address, "data": arg}, "latest"])


def resolve_current_implementation(
    proxy_address: str,
    rpc_url: str,
    block: str = "latest",
    proxy_type: str | None = None,
    *,
    chain_id: int | None = None,
) -> str | None:
    """Resolve the current implementation for a proxy.

    When *proxy_type* is provided, dispatches directly to the right
    resolution method — O(1) RPC call.  When omitted, falls back to
    trying all methods in priority order (used at registration time
    before the type is known, and for the Aave V2 fast path).

    When *block* is not ``"latest"`` only the EIP-1967 slot is read —
    this is the fast path used by scan_for_upgrades for Aave V2's
    ``Upgraded(uint256)`` events.

    *chain_id* (the proxy's chain, threaded from the static worker) arms the
    inv-7 URL↔chain_id guard on every underlying read; None keeps it a no-op.
    """
    # Fast path: historical block lookup (Aave V2 scan loop)
    if block != "latest":
        return _read_slot(rpc_url, proxy_address, _EIP1967_IMPL_SLOT, block, chain_id=chain_id)

    # Fast path: known proxy_type → single targeted RPC call
    if proxy_type and proxy_type in _RESOLVE_BY_TYPE:
        method, arg = _RESOLVE_BY_TYPE[proxy_type]
        if method == "slot":
            return _read_slot(rpc_url, proxy_address, arg, chain_id=chain_id)
        return _call_getter(rpc_url, proxy_address, arg, chain_id=chain_id)

    # Fallback: try all methods in priority order (registration, unknown type)
    for slot in (_EIP1967_IMPL_SLOT, _EIP1822_LOGIC_SLOT, _OZ_IMPL_SLOT):
        addr = _read_slot(rpc_url, proxy_address, slot, chain_id=chain_id)
        if addr:
            return addr

    addr = _call_getter(rpc_url, proxy_address, _IMPLEMENTATION_SEL, chain_id=chain_id)
    if addr:
        return addr

    for sel in (_MASTER_COPY_SEL, _COMPTROLLER_IMPL_SEL, _TARGET_SEL):
        addr = _call_getter(rpc_url, proxy_address, sel, chain_id=chain_id)
        if addr:
            return addr

    addr = _read_slot(rpc_url, proxy_address, _GNOSIS_SLOT, chain_id=chain_id)
    if addr:
        return addr

    return None


def poll_for_upgrades(session: Session, rpc_url: str) -> list[ProxyUpgradeEvent]:
    """Poll for implementation changes on proxies that need polling.

    Builds a single JSON-RPC batch for all watched proxies:
    - Known-type proxies get 1 targeted call each.
    - Unknown-type proxies get ``len(_DISCOVERY_METHODS)`` calls to discover
      the right resolution method, which is then saved for future polls.
    - If no method resolves for an unknown proxy, polling is disabled.

    Returns list of new ProxyUpgradeEvent records created.
    """
    proxies = (
        session.execute(select(WatchedProxy).where(WatchedProxy.needs_polling == True))  # noqa: E712
        .scalars()
        .all()
    )
    if not proxies:
        return []

    # -- Phase 1: build batch -------------------------------------------------
    batch_calls: list[tuple[str, list]] = []
    # (proxy, start_index_in_batch, call_count, is_discovery)
    proxy_plan: list[tuple[WatchedProxy, int, int, bool]] = []
    known_count = 0
    discovery_count = 0

    for proxy in proxies:
        start = len(batch_calls)
        if proxy.proxy_type and proxy.proxy_type in _RESOLVE_BY_TYPE:
            # Known type — single targeted call
            method_type, arg = _RESOLVE_BY_TYPE[proxy.proxy_type]
            batch_calls.append(_build_rpc_call(method_type, proxy.proxy_address, arg))
            proxy_plan.append((proxy, start, 1, False))
            known_count += 1
        else:
            # Unknown type — try all methods in one batch
            for method_type, arg, _ in _DISCOVERY_METHODS:
                batch_calls.append(_build_rpc_call(method_type, proxy.proxy_address, arg))
            proxy_plan.append((proxy, start, len(_DISCOVERY_METHODS), True))
            discovery_count += 1

    if not batch_calls:
        return []

    logger.debug(
        "Poll batch: %d calls (%d known-type proxies, %d discovery proxies)",
        len(batch_calls),
        known_count,
        discovery_count,
    )

    # -- Phase 2: send batch ---------------------------------------------------
    try:
        results = rpc_batch_request(rpc_url, batch_calls)
    except Exception as exc:
        logger.warning("Batch RPC request failed during poll: %s", exc, extra={"exc_type": type(exc).__name__})
        return []

    # -- Phase 3: process results ----------------------------------------------
    new_events: list[ProxyUpgradeEvent] = []

    for proxy, start, count, is_discovery in proxy_plan:
        current_impl: str | None = None

        if is_discovery:
            # Check results in priority order; first hit wins.
            for i, (_, _, ptype) in enumerate(_DISCOVERY_METHODS):
                addr = parse_address_result(results[start + i])
                if addr:
                    current_impl = addr
                    proxy.proxy_type = ptype
                    logger.info(
                        "Learned proxy type for %s: %s",
                        proxy.proxy_address,
                        ptype,
                    )
                    break
                logger.debug("%s: discovery method %s returned nothing", proxy.proxy_address, ptype)
            else:
                # No method resolved — stop polling this proxy.
                proxy.needs_polling = False
                logger.info(
                    "No resolution method found for %s, disabling polling",
                    proxy.proxy_address,
                )
                continue
        else:
            # Known type — single result
            current_impl = parse_address_result(results[start])
            if current_impl is None:
                logger.debug(
                    "%s: known type %s returned nothing",
                    proxy.proxy_address,
                    proxy.proxy_type,
                )

        if current_impl is None:
            continue

        if current_impl != proxy.last_known_implementation:
            upgrade_event = ProxyUpgradeEvent(
                watched_proxy_id=proxy.id,
                block_number=0,
                tx_hash="",
                old_implementation=proxy.last_known_implementation,
                new_implementation=current_impl,
                event_type="storage_poll",
            )
            session.add(upgrade_event)
            new_events.append(upgrade_event)

            logger.info(
                "Poll detected implementation change on %s: %s -> %s",
                proxy.proxy_address,
                proxy.last_known_implementation,
                current_impl,
            )

            proxy.last_known_implementation = current_impl

    session.commit()
    return new_events


def run_scan_loop(rpc_url: str, interval: float = DEFAULT_SCAN_INTERVAL) -> None:
    """Run the proxy upgrade scanner in a blocking loop."""
    logger.info("Starting proxy upgrade monitor (interval=%ss)", interval)
    while True:
        try:
            with SessionLocal() as session:
                new_events = scan_for_upgrades(session, rpc_url)
                if new_events:
                    logger.info("Detected %d new upgrade event(s)", len(new_events))
                    notify_upgrades(session, new_events)
        except Exception as exc:
            logger.warning("Scan cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
        time.sleep(interval)


DEFAULT_POLL_INTERVAL = int(os.getenv("PROTOCOL_POLL_INTERVAL", "600"))


def run_poll_loop(rpc_url: str, interval: float = DEFAULT_POLL_INTERVAL) -> None:
    """Run the storage-slot polling loop for silent proxies."""
    logger.info("Starting proxy poll monitor (interval=%ss)", interval)
    while True:
        try:
            with SessionLocal() as session:
                new_events = poll_for_upgrades(session, rpc_url)
                if new_events:
                    logger.info("Poll detected %d new upgrade(s)", len(new_events))
                    notify_upgrades(session, new_events)
        except Exception as exc:
            logger.warning("Poll cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
        time.sleep(interval)
