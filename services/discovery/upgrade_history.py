#!/usr/bin/env python3
"""Fetch upgrade history for proxy contracts via Etherscan event logs.

For each proxy in dependencies.json, queries Upgraded(address),
AdminChanged(address,address), and BeaconUpgraded(address) events across
the contract's lifetime.  Produces a timeline of implementation changes.

Designed to run *after* dependencies.json is written so that proxy
metadata (type, current implementation) is already available.

Uses Etherscan's getLogs endpoint which is indexed by address+topic
and returns results in <1s regardless of chain history length.
"""

from __future__ import annotations

import logging

from services.discovery.static_dependencies import normalize_address
from utils.chains import require_chain

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EIP-1967 event topic0 hashes (keccak256 of signature)
# ---------------------------------------------------------------------------

# Upgraded(address indexed implementation)
UPGRADED_TOPIC0 = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"

# AdminChanged(address previousAdmin, address newAdmin)
ADMIN_CHANGED_TOPIC0 = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"

# BeaconUpgraded(address indexed beacon)
BEACON_UPGRADED_TOPIC0 = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e"

# GnosisSafe — ChangedMasterCopy(address)
CHANGED_MASTER_COPY_TOPIC0 = "0x75e41bc35ff1bf14d81d1d2f649c0084a0f974f9289c803ec9898eeec4c8d0b8"

# Compound — NewImplementation(address oldImplementation, address newImplementation)
NEW_IMPLEMENTATION_TOPIC0 = "0xd604de94d45953f9138079ec1b82d533cb2160c906d1076d1f7ed54befbca97a"

# Compound — NewPendingImplementation(address oldPendingImplementation, address newPendingImplementation)
NEW_PENDING_IMPLEMENTATION_TOPIC0 = "0xe945ccee5d701fc83f9b8aa8ca94ea4219ec1fcbd4f4cab4f0ea57c5c3e1d815"

# Synthetix — TargetUpdated(address newTarget)
TARGET_UPDATED_TOPIC0 = "0x814250a3b8c79fcbe2ead2c131c952a278491c8f4322a79fe84b5040a810373e"

# Aave V2 — Upgraded(uint256 revision)
UPGRADED_REVISION_TOPIC0 = "0x65a5e70879738a94a00f00947edae8111ae0aed9175ce342db680bf1e0fb87fc"

# Diamond (EIP-2535) — DiamondCut((address,uint8,bytes4[])[],address,bytes)
DIAMOND_CUT_TOPIC0 = "0x8faa70878671ccd212d20771b795c50af8fd3ff6cf27f4bde57e5d4de0aeb673"

EVENT_TOPICS = {
    UPGRADED_TOPIC0: "upgraded",
    ADMIN_CHANGED_TOPIC0: "admin_changed",
    BEACON_UPGRADED_TOPIC0: "beacon_upgraded",
    CHANGED_MASTER_COPY_TOPIC0: "changed_master_copy",
    NEW_IMPLEMENTATION_TOPIC0: "new_implementation",
    NEW_PENDING_IMPLEMENTATION_TOPIC0: "new_pending_implementation",
    TARGET_UPDATED_TOPIC0: "target_updated",
    UPGRADED_REVISION_TOPIC0: "upgraded_revision",
    DIAMOND_CUT_TOPIC0: "diamond_cut",
}

# ---------------------------------------------------------------------------
# Log parsing helpers
# ---------------------------------------------------------------------------


def _hex_to_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    if value in ("0x", "0x0", ""):
        return 0
    return int(value, 16) if value.startswith("0x") else int(value)


def _topic_to_address(topic: str) -> str:
    """Extract a 20-byte address from a 32-byte log topic."""
    raw = topic.replace("0x", "").zfill(64)
    return normalize_address("0x" + raw[-40:])


def _data_to_addresses(data: str, count: int) -> list[str]:
    """Decode *count* consecutive ABI-encoded addresses from log data."""
    raw = data.replace("0x", "").zfill(64 * count)
    addresses = []
    for i in range(count):
        chunk = raw[i * 64 : (i + 1) * 64]
        addresses.append(normalize_address("0x" + chunk[-40:]))
    return addresses


def parse_upgrade_log(log: dict) -> dict | None:
    """Parse an Etherscan log entry into an UpgradeEvent dict."""
    topics = log.get("topics", [])
    if not topics:
        return None

    topic0 = topics[0].lower()
    event_type = EVENT_TOPICS.get(topic0)
    if not event_type:
        return None

    event: dict = {
        "event_type": event_type,
        "block_number": _hex_to_int(log.get("blockNumber", "0x0")),
        "tx_hash": log.get("transactionHash"),
        "log_index": _hex_to_int(log.get("logIndex", "0x0")),
    }

    # Etherscan getLogs returns timeStamp as hex
    ts = log.get("timeStamp")
    if ts:
        event["timestamp"] = _hex_to_int(ts)

    # Emitting contract address for grouping multi-proxy queries
    emitter = log.get("address")
    if emitter:
        event["_emitter"] = normalize_address(emitter)

    if event_type == "upgraded":
        if len(topics) >= 2 and topics[1]:
            event["implementation"] = _topic_to_address(topics[1])
        else:
            # Some proxies (e.g. OZ legacy) emit Upgraded(address) with the
            # implementation as a non-indexed parameter, stored in data.
            data = log.get("data", "0x")
            if data and data != "0x" and len(data.replace("0x", "")) >= 40:
                addrs = _data_to_addresses(data, 1)
                event["implementation"] = addrs[0]

    elif event_type == "admin_changed":
        # Standard: both addresses in data (non-indexed)
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            addrs = _data_to_addresses(data, 2)
            event["previous_admin"] = addrs[0]
            event["new_admin"] = addrs[1]
        elif len(topics) >= 3 and topics[1] and topics[2]:
            # Variant: indexed parameters in topics
            event["previous_admin"] = _topic_to_address(topics[1])
            event["new_admin"] = _topic_to_address(topics[2])

    elif event_type == "beacon_upgraded":
        if len(topics) >= 2 and topics[1]:
            event["beacon"] = _topic_to_address(topics[1])
        else:
            # Fallback: non-indexed parameter in data
            data = log.get("data", "0x")
            if data and data != "0x" and len(data.replace("0x", "")) >= 40:
                addrs = _data_to_addresses(data, 1)
                event["beacon"] = addrs[0]

    elif event_type == "changed_master_copy":
        # GnosisSafe: single non-indexed address in data
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["implementation"] = addrs[0]

    elif event_type == "new_implementation":
        # Compound: two ABI-encoded addresses in data (old impl, new impl)
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            addrs = _data_to_addresses(data, 2)
            event["old_implementation"] = addrs[0]
            event["implementation"] = addrs[1]

    elif event_type == "new_pending_implementation":
        # Compound: two ABI-encoded addresses in data (old pending impl, new pending impl)
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            addrs = _data_to_addresses(data, 2)
            event["implementation"] = addrs[1]

    elif event_type == "target_updated":
        # Synthetix: single non-indexed address in data
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["implementation"] = addrs[0]

    elif event_type == "upgraded_revision":
        # Aave V2: uint256 revision number in data — NOT an implementation address
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 2:
            event["revision"] = _hex_to_int(data)

    elif event_type == "diamond_cut":
        # EIP-2535 DiamondCut: ABI-encoded FacetCut[] + _init address + _calldata
        # Extract facet addresses from the FacetCut[] array, filtering out Remove actions.
        try:
            data = log.get("data", "0x")
            raw = data.replace("0x", "")
            if len(raw) >= 192:  # minimum: 3 words (offsets) + at least array length
                # bytes 0-63: offset to FacetCut[] array
                array_offset = int(raw[0:64], 16) * 2  # convert byte offset to hex-char offset
                # At array_offset: uint256 count of FacetCut entries
                count_start = array_offset
                if len(raw) >= count_start + 64:
                    count = int(raw[count_start : count_start + 64], 16)
                    if count > 1000:  # cap to prevent DoS from crafted events
                        count = 0
                    # After count: `count` uint256 offsets (relative to array_offset)
                    entry_offsets_start = count_start + 64
                    facets: list[str] = []
                    for i in range(count):
                        off_pos = entry_offsets_start + i * 64
                        if len(raw) < off_pos + 64:
                            break
                        entry_offset = int(raw[off_pos : off_pos + 64], 16) * 2
                        # Entry is relative to array_offset
                        entry_start = array_offset + entry_offset
                        # Each FacetCut entry: address (32 bytes) + action (32 bytes) + ...
                        if len(raw) < entry_start + 128:
                            break
                        facet_addr = normalize_address("0x" + raw[entry_start + 24 : entry_start + 64])
                        action = int(raw[entry_start + 64 : entry_start + 128], 16)
                        # action: 0=Add, 1=Replace, 2=Remove — skip Remove
                        if action != 2 and facet_addr != normalize_address("0x" + "0" * 40):
                            facets.append(facet_addr)
                    if facets:
                        event["implementation"] = facets[0]
                        event["facets"] = facets
        except (ValueError, IndexError):
            pass  # malformed data — return event without implementation

    return event


# ---------------------------------------------------------------------------
# Etherscan getLogs fetching
# ---------------------------------------------------------------------------


def _fetch_logs_etherscan(proxy_address: str, topic0: str, from_block: int = 0, chain_id: int = 1) -> list[dict]:
    """Fetch all logs for a given address and topic0 via Etherscan getLogs."""
    from utils.etherscan import get

    try:
        data = get(
            "logs",
            "getLogs",
            chain_id=chain_id,
            address=proxy_address,
            topic0=topic0,
            fromBlock=str(from_block),
            toBlock="99999999",
        )
        result = data.get("result", [])
        return result if isinstance(result, list) else []
    except RuntimeError:
        return []


def fetch_upgrade_events(proxy_addresses: list[str], from_block: int = 0, chain_id: int = 1) -> list[dict]:
    """Fetch all EIP-1967 upgrade events for proxy addresses via Etherscan.

    Queries each proxy for all three event types (Upgraded, AdminChanged,
    BeaconUpgraded). Returns a chronologically sorted list of parsed events.
    Rate-limited centrally by ``utils.etherscan``.

    Args:
        proxy_addresses: List of proxy contract addresses to query.
        from_block: Only fetch events from this block number onwards.
            Defaults to 0 (fetch all history).
        chain_id: Chain the proxies live on; threaded to the Etherscan getLogs
            query so L2 upgrade events resolve against the right explorer.
    """
    all_events: list[dict] = []

    # Flatten the address × topic matrix into one task list. Each
    # ``_fetch_logs_etherscan`` call goes through the global Etherscan rate
    # lock so threading only stacks RTTs — the limiter still serialises wire
    # calls.
    tasks: list[tuple[str, str]] = []
    for addr in proxy_addresses:
        addr = normalize_address(addr)
        for topic0 in EVENT_TOPICS:
            tasks.append((addr, topic0))

    if tasks:
        from utils.etherscan import parallel_get

        calls = {
            f"{addr}|{topic0}": (
                lambda a=addr, t=topic0: _fetch_logs_etherscan(a, t, from_block=from_block, chain_id=chain_id)
            )
            for addr, topic0 in tasks
        }
        results = parallel_get(calls)

        # Iterate tasks in their original (addr, topic) order so the parsed
        # events list is reconstructed deterministically before sorting.
        for addr, topic0 in tasks:
            raw_logs = results.get(f"{addr}|{topic0}", [])
            if isinstance(raw_logs, BaseException) or not isinstance(raw_logs, list):
                continue
            for log in raw_logs:
                event = parse_upgrade_log(log)
                if event:
                    all_events.append(event)

    all_events.sort(key=lambda e: (e.get("block_number", 0), e.get("log_index", 0)))
    return all_events


# ---------------------------------------------------------------------------
# Building the implementation timeline
# ---------------------------------------------------------------------------


def _build_implementation_timeline(
    events: list[dict],
    current_impl: str | None,
) -> list[dict]:
    """Build an ordered list of ImplementationRecords from upgrade events."""
    upgrade_events = [e for e in events if e["event_type"] == "upgraded" and e.get("implementation")]

    if not upgrade_events:
        if current_impl:
            return [{"address": current_impl}]
        return []

    records: list[dict] = []
    for i, event in enumerate(upgrade_events):
        record: dict = {
            "address": event["implementation"],
            "block_introduced": event["block_number"],
            "tx_hash": event["tx_hash"],
        }
        if "timestamp" in event:
            record["timestamp_introduced"] = event["timestamp"]
        if i + 1 < len(upgrade_events):
            record["block_replaced"] = upgrade_events[i + 1]["block_number"]
            if "timestamp" in upgrade_events[i + 1]:
                record["timestamp_replaced"] = upgrade_events[i + 1]["timestamp"]
        records.append(record)

    return records


# ---------------------------------------------------------------------------
# Reading proxy metadata from dependencies.json
# ---------------------------------------------------------------------------


def _enrich_implementations(implementations: list[dict], known_names: dict[str, str], *, chain_id: int) -> None:
    """Add contract names to historical implementations not already named in dependencies.json."""
    from utils.etherscan import get_contract_info, parallel_get

    addrs_to_fetch = sorted({impl["address"] for impl in implementations if impl["address"] not in known_names})
    fetched: dict[str, str | None] = {}
    if addrs_to_fetch:
        calls = {addr: (lambda a=addr: get_contract_info(a, chain_id=chain_id)) for addr in addrs_to_fetch}
        results = parallel_get(calls)
        for addr in addrs_to_fetch:
            value = results.get(addr)
            if isinstance(value, tuple) and len(value) == 2:
                fetched[addr] = value[0]
            else:
                fetched[addr] = None

    for impl in implementations:
        addr = impl["address"]
        if addr in known_names:
            impl["contract_name"] = known_names[addr]
            continue
        if fetched.get(addr):
            impl["contract_name"] = fetched[addr]


def _extract_proxies_from_dependencies(
    deps: dict,
) -> tuple[str, dict[str, tuple[str, str | None]], dict[str, str]]:
    """Extract proxy metadata for the TARGET only from a unified deps dict.

    Dependency proxies are intentionally ignored — each dependency gets its
    own analysis job later, and the upgrade history for that dependency is
    built when it's the target of its own run. Processing dependency proxies
    here would duplicate work and conflate unrelated contracts' histories.

    Returns (target_address, {proxy_addr: (proxy_type, current_impl)}, {addr: name}).
    The proxy_meta dict contains at most one entry — the target itself, if
    it's classified as a proxy.
    """
    target = normalize_address(deps["address"])

    proxy_meta: dict[str, tuple[str, str | None]] = {}
    known_names: dict[str, str] = {}

    # Only the target contract's upgrade history is built here.
    target_cls = deps.get("target_classification", {})
    if target_cls.get("type") == "proxy":
        proxy_type = target_cls.get("proxy_type", "unknown")
        impl = target_cls.get("implementation")
        if isinstance(impl, dict):
            current_impl = impl.get("address")
        elif isinstance(impl, str):
            current_impl = impl
        else:
            current_impl = None
        proxy_meta[target] = (proxy_type, current_impl)

    # Still harvest known names from dependencies so historical impl
    # enrichment can reuse them without extra Etherscan calls.
    for addr, info in deps.get("dependencies", {}).items():
        if info.get("contract_name"):
            known_names[normalize_address(addr)] = info["contract_name"]
        impl = info.get("implementation")
        if isinstance(impl, dict) and impl.get("contract_name"):
            known_names[normalize_address(impl["address"])] = impl["contract_name"]

    return target, proxy_meta, known_names


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _strip_internal(event: dict) -> dict:
    """Remove internal keys (prefixed with _) before serialization."""
    return {k: v for k, v in event.items() if not k.startswith("_")}


def build_upgrade_history(dependencies: dict, *, enrich: bool = True, from_block: int = 0, chain_id: int = 1) -> dict:
    """Build upgrade history for all proxy contracts in a unified deps dict.

    Args:
        dependencies: Unified dependency payload as produced by
            ``services.discovery.unified_dependencies.build_unified_dependencies``.
        enrich: If True (default), resolve contract names for historical
            implementations via Etherscan.  Set to False for faster runs
            when names are not needed.
        from_block: Only fetch events from this block number onwards.
            Defaults to 0 (fetch all history).  Used for incremental
            fetching when previous upgrade history is available.
        chain_id: Chain the target proxy lives on; threaded to the Etherscan
            getLogs query. Name enrichment still routes through the shared
            ``get_contract_info`` wrapper, which carries no chain param yet
            (mainnet only until the wrapper gains one).
    """
    target_address, proxy_meta, known_names = _extract_proxies_from_dependencies(dependencies)

    if not proxy_meta:
        return {
            "schema_version": "0.1",
            "target_address": target_address,
            "proxies": {},
            "total_upgrades": 0,
        }

    # Etherscan getLogs — indexed by address+topic, <1s per query
    all_events = fetch_upgrade_events(list(proxy_meta.keys()), from_block=from_block, chain_id=chain_id)

    # Group events by emitting proxy address
    events_by_proxy: dict[str, list[dict]] = {addr: [] for addr in proxy_meta}
    for event in all_events:
        emitter = event.get("_emitter")
        if emitter and emitter in events_by_proxy:
            events_by_proxy[emitter].append(event)

    proxies: dict[str, dict] = {}
    total_upgrades = 0
    all_implementations: list[dict] = []

    for addr, (proxy_type, current_impl) in proxy_meta.items():
        proxy_events = events_by_proxy.get(addr, [])
        implementations = _build_implementation_timeline(proxy_events, current_impl)
        upgrade_events = [e for e in proxy_events if e["event_type"] == "upgraded"]

        proxies[addr] = {
            "proxy_address": addr,
            "proxy_type": proxy_type,
            "current_implementation": current_impl,
            "upgrade_count": len(upgrade_events),
            "first_upgrade_block": upgrade_events[0]["block_number"] if upgrade_events else None,
            "last_upgrade_block": upgrade_events[-1]["block_number"] if upgrade_events else None,
            "implementations": implementations,
            "events": [_strip_internal(e) for e in proxy_events],
        }
        total_upgrades += len(upgrade_events)
        all_implementations.extend(implementations)

    # Resolve names: always apply already-known names from dependencies.json.
    # When enrich=True, also call Etherscan for historical unknowns.
    if enrich:
        _enrich_implementations(all_implementations, known_names, chain_id=chain_id)
    else:
        # Still apply names we already have — zero extra API calls
        for impl in all_implementations:
            if impl["address"] in known_names:
                impl["contract_name"] = known_names[impl["address"]]

    return {
        "schema_version": "0.1",
        "target_address": target_address,
        "proxies": proxies,
        "total_upgrades": total_upgrades,
    }


def project_to_events(
    session,
    *,
    subject_contract_id: int,
    subject_chain: str | None,
    artifact_data: dict,
) -> dict:
    """Project an ``upgrade_history`` artifact into ``UpgradeEvent`` rows.

    Forward direction of the artifact ⇄ rows pair (the inverse is
    ``synthesize_from_events`` below). Idempotent: deletes existing
    ``UpgradeEvent`` rows for each proxy contract (and the subject, as
    legacy cleanup) before re-inserting from the artifact. Caller commits.

    Returns counters useful for logging; ``impl_addrs`` is the set of
    historical impl addresses encountered, suitable for feeding to the
    static worker's historical-impl Contract backfill.
    """
    from datetime import datetime, timezone

    from sqlalchemy import func, select

    from db.models import Contract, UpgradeEvent

    out = {
        "proxies_seen": 0,
        "proxies_projected": 0,
        "proxies_skipped_no_contract": 0,
        "events_written": 0,
        "impl_addrs": set(),
    }
    if not isinstance(artifact_data, dict) or not artifact_data.get("proxies"):
        return out

    # Legacy cleanup: older versions of this projection keyed every event
    # to the subject's id regardless of which proxy the event described.
    # Drop those so re-runs are idempotent for non-proxy subjects.
    session.query(UpgradeEvent).filter(UpgradeEvent.contract_id == subject_contract_id).delete()

    for proxy_info in artifact_data["proxies"].values():
        out["proxies_seen"] += 1
        proxy_addr = proxy_info.get("proxy_address", "")
        if not proxy_addr:
            continue
        # UpgradeEvent.contract_id must point at the PROXY's row, not the
        # subject's — the artifact can describe any proxy in the dependency
        # graph, not just the subject's own.
        chain_filter = Contract.chain == subject_chain if subject_chain is not None else Contract.chain.is_(None)
        proxy_contract = session.execute(
            select(Contract).where(
                func.lower(Contract.address) == proxy_addr.lower(),
                chain_filter,
            )
        ).scalar_one_or_none()
        if proxy_contract is None:
            out["proxies_skipped_no_contract"] += 1
            continue
        session.query(UpgradeEvent).filter(UpgradeEvent.contract_id == proxy_contract.id).delete()
        for evt in proxy_info.get("events", []):
            if evt.get("event_type") != "upgraded":
                continue
            impl = evt.get("implementation")
            # Artifact carries ``timestamp`` as unix seconds (int | None);
            # the DB column is DateTime(timezone=True). Dropping this was
            # the root cause of ImplWindow.from_ts=None downstream, which
            # collapsed every post-upgrade audit to low confidence.
            ts_raw = evt.get("timestamp")
            ts_val = datetime.fromtimestamp(ts_raw, tz=timezone.utc) if ts_raw is not None else None
            session.add(
                UpgradeEvent(
                    contract_id=proxy_contract.id,
                    proxy_address=proxy_addr,
                    old_impl=None,
                    new_impl=impl,
                    block_number=evt.get("block_number"),
                    timestamp=ts_val,
                    tx_hash=evt.get("tx_hash"),
                )
            )
            out["events_written"] += 1
            if impl:
                out["impl_addrs"].add(impl.lower())
        out["proxies_projected"] += 1

    return out


def backfill_historical_impl_contracts(
    session,
    *,
    protocol_id: int,
    chain: str | None,
    impl_addrs: set[str],
    parent_proxy_sources: list[str] | None,
    parent_proxy_current_impl_address: str | None = None,
) -> None:
    """Ensure a Contract row exists for each historical impl address.

    Companion to ``project_to_events`` — every impl referenced by the
    artifact's events should be present as a Contract row so the audit
    coverage matcher can link audits whose scope names a past impl.

    ``parent_proxy_sources`` is the discovery_sources of the proxy whose
    upgrade history produced these impls. If the parent doesn't assert
    ownership (only low-confidence sources, e.g. ``dapp_crawl``), the
    impls are not stamped with ``protocol_id`` — orphan Contract rows
    are created so the coverage matcher still has names to resolve, but
    the protocol's inventory is not polluted. The whole point: a foreign
    proxy (EigenLayer, OP-Stack) that snuck into inventory via a low-
    confidence source must not multiply itself into N "owned" impls. See
    services/discovery/source_confidence.py.

    ``parent_proxy_current_impl_address`` is the proxy's
    ``Contract.implementation`` field — the CURRENT impl address. Pass
    it when the proxy is itself LOW-sourced (e.g. ``structural_adoption``
    after 3a8f4d1c9b07's branch 4 adopted it) so the gate can consult
    the impl's sources too. If the current impl is HIGH-sourced and
    shares the protocol_id, that's the same one-hop-from-HIGH evidence
    that 4d72e9b1f035's branch B uses against the historical orphan
    set. Runtime counterpart to the migration: the LRTSquare* shape
    (LOW UUPSProxy + HIGH LRTSquaredCore impl) gets handled at write
    time instead of only at the next catch-up migration.

    For each address, three cases (when ownership IS asserted):
      1. No Contract row exists → create one tagged
         ``discovery_source='upgrade_history'`` with Etherscan-resolved
         name. Normal path for newly-surfaced impls.
      2. Row exists with ``protocol_id`` NULL or equal to ours → adopt.
         Sets the upgrade_history tag if empty, sets protocol_id. Keeps
         existing name/analysis fields intact.
      3. Row exists in a DIFFERENT protocol → leave alone, log a warning.
         Rare (impl bytecode is usually protocol-specific) but possible;
         silently stomping another protocol's inventory would be worse
         than an unresolved coverage link.

    When ownership is NOT asserted, branch (1) drops ``protocol_id``
    from the new row and branch (2) becomes a no-op (orphan adoption
    is the leak we're closing). Branch (3) is unchanged.

    Etherscan name resolution uses the shared ``get_contract_info`` cache,
    so re-analyzing a protocol re-hits only new impls. Per-address errors
    are swallowed so one flaky lookup doesn't wreck the whole backfill.
    """
    from sqlalchemy import func, select

    from db.models import Contract
    from services.discovery.ranking import CURRENT_IMPLEMENTATION_SOURCE
    from services.discovery.source_confidence import asserts_ownership
    from utils.etherscan import get_contract_info, parallel_get

    if not impl_addrs:
        return

    # The proxy's CURRENT impl appears in its own last ``Upgraded`` event, so it
    # lands in ``impl_addrs`` alongside genuinely-superseded impls. Tag it as the
    # live implementation rather than a superseded anchor so it stays analyzable
    # (see ranking.is_superseded_impl) — the live impl is where the proxy's real
    # functions + principals live.
    current_impl_lc = (parent_proxy_current_impl_address or "").lower()

    # Historical impls are structural same-protocol components of the
    # parent proxy. Route through the unified gate so this path uses
    # the same logic as the resolution / static-worker cascades: direct
    # evidence (parent has a HIGH source) OR structural evidence (the
    # relationship to the parent is ``implementation``). The two
    # branches collapse into a single ``asserts_ownership`` call when
    # the structural relationship is fixed and ``parent_owns`` carries
    # the parent's direct-evidence state.
    parent_owns = asserts_ownership(parent_proxy_sources)

    # Anchor on the proxy's CURRENT impl when the proxy itself is LOW.
    # Mirrors 4d72e9b1f035 branch B: the impl is the authoritative HIGH
    # source in the LRTSquare* shape (LOW-adopted UUPSProxy with
    # HIGH-sourced LRTSquaredCore implementation). Belt-and-suspenders
    # mismatch guard: if the impl belongs to a different protocol, the
    # chain isn't ours — leave the historical impls orphan.
    if not parent_owns and parent_proxy_current_impl_address:
        chain_filter_impl = Contract.chain == chain if chain is not None else Contract.chain.is_(None)
        impl_row = session.execute(
            select(Contract).where(
                func.lower(Contract.address) == parent_proxy_current_impl_address.lower(),
                chain_filter_impl,
            )
        ).scalar_one_or_none()
        if (
            impl_row is not None
            and (impl_row.protocol_id is None or impl_row.protocol_id == protocol_id)
            and asserts_ownership(impl_row.discovery_sources)
        ):
            parent_owns = True

    owns = asserts_ownership(None, parent_owns=parent_owns, parent_relationship="implementation")
    owning_protocol_id = protocol_id if owns else None

    # Match the natural (address, chain) uniqueness grain. Cross-chain
    # protocols (rare but real — CREATE2 / deterministic deployments can
    # put the same impl address on Ethereum and Polygon) would otherwise
    # look like cross-protocol collisions and get skipped incorrectly.
    chain_filter = Contract.chain == chain if chain is not None else Contract.chain.is_(None)
    existing_rows = {
        row.address.lower(): row
        for row in session.execute(select(Contract).where(Contract.address.in_(impl_addrs), chain_filter))
        .scalars()
        .all()
    }

    # Batch Etherscan name lookups for new addresses; sequential calls block
    # for N round-trips when re-analyzing a protocol with many historical impls.
    new_addrs = [addr for addr in impl_addrs if addr not in existing_rows]
    name_results: dict[str, str | None] = {}
    if new_addrs:
        # NULL Contract.chain is legacy-mainnet by convention (same coalesce as
        # routers/jobs.py); a named-but-unknown chain fails loud.
        name_chain_id = require_chain(chain=chain or "ethereum", context="historical impl name fetch").chain_id
        calls = {addr: (lambda a=addr: get_contract_info(a, chain_id=name_chain_id)) for addr in new_addrs}
        fetched = parallel_get(calls)
        for addr in new_addrs:
            value = fetched.get(addr)
            if isinstance(value, tuple) and len(value) == 2:
                name_results[addr] = value[0]
            else:
                if isinstance(value, BaseException):
                    logger.warning("Etherscan name fetch failed for historical impl %s: %s", addr, value)
                name_results[addr] = None

    created = 0
    adopted = 0
    refresh_ids: list[int] = []
    for addr in impl_addrs:
        existing = existing_rows.get(addr)
        is_current = bool(current_impl_lc) and addr == current_impl_lc
        if existing is not None:
            if existing.protocol_id is None or existing.protocol_id == protocol_id:
                was_orphan = existing.protocol_id is None
                existing_sources = list(existing.discovery_sources or [])
                # Without ownership assertion from the parent, don't
                # adopt orphans into this protocol — that's exactly the
                # leak we're closing. The tag append still happens so
                # the source trail is preserved for later corroboration.
                if was_orphan and owns:
                    existing.protocol_id = protocol_id
                if is_current:
                    # Live impl: mark current (keeps it analyzable) instead of
                    # stamping the superseded-anchor ``upgrade_history`` tag.
                    had_no_tag = CURRENT_IMPLEMENTATION_SOURCE not in existing_sources
                    if had_no_tag:
                        existing.discovery_sources = existing_sources + [CURRENT_IMPLEMENTATION_SOURCE]
                else:
                    had_no_tag = "upgrade_history" not in existing_sources
                    if had_no_tag:
                        existing.discovery_sources = existing_sources + ["upgrade_history"]
                adopted += 1
                # Only schedule coverage refresh when the row is actually
                # in our protocol — refresh on an orphan is wasted work
                # since the matcher filters by protocol_id.
                if owns and (was_orphan or had_no_tag):
                    refresh_ids.append(existing.id)
            else:
                logger.warning(
                    "Job protocol %s: historical impl %s already owned by protocol %s — "
                    "coverage link will not be created against this impl",
                    protocol_id,
                    addr,
                    existing.protocol_id,
                )
            continue

        name = name_results.get(addr)

        new_row = Contract(
            protocol_id=owning_protocol_id,
            address=addr,
            chain=chain,
            contract_name=name or "UnknownImpl",
            is_proxy=False,
            job_id=None,
            # Current impl → live marker (stays analyzable); superseded → anchor.
            discovery_sources=[CURRENT_IMPLEMENTATION_SOURCE] if is_current else ["upgrade_history"],
            source_verified=bool(name),
        )
        session.add(new_row)
        created += 1
        session.flush()
        # Same reasoning as above — coverage refresh only fires for rows
        # that actually belong to the protocol.
        if owns:
            refresh_ids.append(new_row.id)

    if created or adopted:
        session.commit()
        logger.info(
            "Protocol %s: backfilled %d historical impl Contract row(s) (%d created, %d adopted)",
            protocol_id,
            created + adopted,
            created,
            adopted,
        )

    if refresh_ids:
        # Lazy import keeps this module importable from contexts that don't
        # have audits-service deps loaded.
        from services.audits.coverage import upsert_coverage_for_contract

        refreshed = 0
        for contract_id in refresh_ids:
            try:
                # Defer source-equivalence to ``CoverageVerifyWorker``: rows
                # land as ``equivalence_status='pending'`` and the worker
                # drains them at a controlled rate. Historical impls still
                # get their coverage links written here; the verdict
                # promotion to ``reviewed_commit`` arrives a few seconds-
                # to-minutes later instead of synchronously. Holding verify
                # inline fanned out 4-way Etherscan + GitHub bursts per
                # backfilled impl, which 429'd the global rate-limit and
                # cascaded into Resolution / Static (#82).
                refreshed += upsert_coverage_for_contract(
                    session,
                    contract_id,
                    verify_source_equivalence=False,
                )
            except Exception as exc:
                # One flaky match shouldn't poison the rest; admin
                # refresh_coverage can fill in what we missed.
                logger.warning(
                    "Coverage refresh failed for backfilled impl contract_id=%s: %s",
                    contract_id,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
        session.commit()
        if refreshed:
            logger.info(
                "Protocol %s: linked %d audit coverage row(s) to %d backfilled impl(s)",
                protocol_id,
                refreshed,
                len(refresh_ids),
            )


def synthesize_from_events(session, contract) -> dict | None:
    """Rebuild the ``upgrade_history`` artifact shape from ``UpgradeEvent`` rows.

    Used as a fallback when the artifact is missing or unreachable in object
    storage. The relational ``UpgradeEvent`` table is the source of truth for
    the count + last-block badges already shown in the company overview, so
    deriving the per-proxy detail view from the same data keeps the two
    consistent. Returns None when there are no events for this contract.
    """
    from sqlalchemy import select

    from db.models import Contract, UpgradeEvent

    rows = (
        session.execute(
            select(UpgradeEvent)
            .where(UpgradeEvent.contract_id == contract.id)
            .order_by(UpgradeEvent.block_number.asc().nullslast(), UpgradeEvent.id.asc())
        )
        .scalars()
        .all()
    )
    if not rows:
        return None

    events: list[dict] = []
    for ev in rows:
        if not ev.new_impl:
            continue
        # The canonical artifact (worker-built) stores ts as unix epoch
        # seconds — see services/discovery/upgrade_history.parse_upgrade_log
        # at the _hex_to_int(ts) call. The frontend formatTimestamp does
        # `new Date(ts * 1000)`, so anything else (ISO string) renders as
        # "Invalid Date". Match the canonical shape.
        events.append(
            {
                "event_type": "upgraded",
                "block_number": ev.block_number,
                "timestamp": int(ev.timestamp.timestamp()) if ev.timestamp else None,
                "tx_hash": ev.tx_hash,
                "implementation": ev.new_impl.lower(),
            }
        )
    if not events:
        return None

    current_impl = (contract.implementation or events[-1]["implementation"]).lower()
    implementations = _build_implementation_timeline(events, current_impl)

    impl_addrs = {impl["address"] for impl in implementations}
    if impl_addrs:
        name_rows = session.execute(
            select(Contract.address, Contract.contract_name).where(Contract.address.in_(list(impl_addrs)))
        ).all()
        names = {addr.lower(): name for addr, name in name_rows if name}
        for impl in implementations:
            n = names.get(impl["address"].lower())
            if n:
                impl["contract_name"] = n

    proxy_addr = (contract.address or "").lower()
    proxy = {
        "proxy_address": proxy_addr,
        "proxy_type": contract.proxy_type or "unknown",
        "current_implementation": current_impl,
        "upgrade_count": len(events),
        "first_upgrade_block": events[0]["block_number"],
        "last_upgrade_block": events[-1]["block_number"],
        "implementations": implementations,
        "events": events,
    }
    return {
        "schema_version": "0.1",
        "target_address": proxy_addr,
        "proxies": {proxy_addr: proxy},
        "total_upgrades": len(events),
        "synthesized": True,
    }
