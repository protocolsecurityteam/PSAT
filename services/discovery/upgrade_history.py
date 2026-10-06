#!/usr/bin/env python3
"""Upgrade history for proxy contracts from Etherscan event logs.

For each proxy, queries upgrade/admin/beacon events over its lifetime to build an implementation timeline. Runs after
dependencies.json is written so proxy metadata is available. Etherscan getLogs is indexed by address+topic, so it's fast
regardless of chain length.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any, cast

from typing_extensions import NotRequired

from schemas.control_tracking import RESOLVED_CONTROLLER_TYPES, ResolvedControllerType
from schemas.upgrade_history import (
    ImplementationRecord,
    ProxyUpgradeHistory,
    UpgradeEventRecord,
    UpgradeEventType,
    UpgradeHistoryOutput,
)
from services.discovery.static_dependencies import normalize_address
from utils.chains import canonical_chain, require_chain
from utils.logging import record_degraded
from utils.scoring_status import NOT_DETERMINED

logger = logging.getLogger(__name__)


def _contract_chain_filter(chain: str | None):
    """Predicate matching a ``Contract`` on the mainnet-coalesced chain key (legacy mainnet rows have
    ``chain=NULL``), as in ``routers/jobs.py`` and ``workers/discovery.py``.
    """
    from sqlalchemy import func

    from db.models import Contract

    return func.lower(func.coalesce(Contract.chain, "ethereum")) == (canonical_chain(chain) or "ethereum")


# EIP-1967 and related topic0 hashes.

UPGRADED_TOPIC0 = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"

ADMIN_CHANGED_TOPIC0 = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"

BEACON_UPGRADED_TOPIC0 = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e"

CHANGED_MASTER_COPY_TOPIC0 = "0x75e41bc35ff1bf14d81d1d2f649c0084a0f974f9289c803ec9898eeec4c8d0b8"

NEW_IMPLEMENTATION_TOPIC0 = "0xd604de94d45953f9138079ec1b82d533cb2160c906d1076d1f7ed54befbca97a"

NEW_PENDING_IMPLEMENTATION_TOPIC0 = "0xe945ccee5d701fc83f9b8aa8ca94ea4219ec1fcbd4f4cab4f0ea57c5c3e1d815"

TARGET_UPDATED_TOPIC0 = "0x814250a3b8c79fcbe2ead2c131c952a278491c8f4322a79fe84b5040a810373e"

UPGRADED_REVISION_TOPIC0 = "0x65a5e70879738a94a00f00947edae8111ae0aed9175ce342db680bf1e0fb87fc"

DIAMOND_CUT_TOPIC0 = "0x8faa70878671ccd212d20771b795c50af8fd3ff6cf27f4bde57e5d4de0aeb673"

EVENT_TOPICS: dict[str, UpgradeEventType] = {
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


def _hex_to_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    if value in ("0x", "0x0", ""):
        return 0
    return int(value, 16) if value.startswith("0x") else int(value)


def _topic_to_address(topic: str) -> str:
    raw = topic.replace("0x", "").zfill(64)
    return normalize_address("0x" + raw[-40:])


def _data_to_addresses(data: str, count: int) -> list[str]:
    raw = data.replace("0x", "").zfill(64 * count)
    addresses = []
    for i in range(count):
        chunk = raw[i * 64 : (i + 1) * 64]
        addresses.append(normalize_address("0x" + chunk[-40:]))
    return addresses


class _ParsedUpgradeLog(UpgradeEventRecord):
    """The parsed record plus its emitter, used for grouping; ``_strip_internal`` removes the emitter before
    persistence.
    """

    _emitter: NotRequired[str]


def parse_upgrade_log(log: dict) -> _ParsedUpgradeLog | None:
    topics = log.get("topics", [])
    if not topics:
        return None

    topic0 = topics[0].lower()
    event_type = EVENT_TOPICS.get(topic0)
    if not event_type:
        return None

    event: _ParsedUpgradeLog = {
        "event_type": event_type,
        "block_number": _hex_to_int(log.get("blockNumber", "0x0")),
        "tx_hash": log.get("transactionHash"),
        "log_index": _hex_to_int(log.get("logIndex", "0x0")),
    }

    # Etherscan returns timeStamp as hex.
    ts = log.get("timeStamp")
    if ts:
        event["timestamp"] = _hex_to_int(ts)

    emitter = log.get("address")
    if emitter:
        event["_emitter"] = normalize_address(emitter)

    if event_type == "upgraded":
        if len(topics) >= 2 and topics[1]:
            event["implementation"] = _topic_to_address(topics[1])
        else:
            # Some proxies (e.g. OZ legacy) put the implementation in data, not a topic.
            data = log.get("data", "0x")
            if data and data != "0x" and len(data.replace("0x", "")) >= 40:
                addrs = _data_to_addresses(data, 1)
                event["implementation"] = addrs[0]

    elif event_type == "admin_changed":
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            addrs = _data_to_addresses(data, 2)
            event["previous_admin"] = addrs[0]
            event["new_admin"] = addrs[1]
        elif len(topics) >= 3 and topics[1] and topics[2]:
            event["previous_admin"] = _topic_to_address(topics[1])
            event["new_admin"] = _topic_to_address(topics[2])

    elif event_type == "beacon_upgraded":
        if len(topics) >= 2 and topics[1]:
            event["beacon"] = _topic_to_address(topics[1])
        else:
            data = log.get("data", "0x")
            if data and data != "0x" and len(data.replace("0x", "")) >= 40:
                addrs = _data_to_addresses(data, 1)
                event["beacon"] = addrs[0]

    elif event_type == "changed_master_copy":
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["implementation"] = addrs[0]

    elif event_type == "new_implementation":
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            addrs = _data_to_addresses(data, 2)
            event["old_implementation"] = addrs[0]
            event["implementation"] = addrs[1]

    elif event_type == "new_pending_implementation":
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            addrs = _data_to_addresses(data, 2)
            event["implementation"] = addrs[1]

    elif event_type == "target_updated":
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["implementation"] = addrs[0]

    elif event_type == "upgraded_revision":
        # Aave V2 carries a revision number, not an implementation address.
        data = log.get("data", "0x")
        if data and data != "0x" and len(data.replace("0x", "")) >= 2:
            event["revision"] = _hex_to_int(data)

    elif event_type == "diamond_cut":
        # EIP-2535 DiamondCut: ABI-encoded FacetCut[] + _init + _calldata; collect facet addresses except Remove
        # actions.
        try:
            data = log.get("data", "0x")
            raw = data.replace("0x", "")
            if len(raw) >= 192:  # minimum: 3 words (offsets) + at least array length
                array_offset = int(raw[0:64], 16) * 2  # convert byte offset to hex-char offset
                count_start = array_offset
                if len(raw) >= count_start + 64:
                    count = int(raw[count_start : count_start + 64], 16)
                    if count > 1000:  # cap to prevent DoS from crafted events
                        count = 0
                    entry_offsets_start = count_start + 64
                    facets: list[str] = []
                    for i in range(count):
                        off_pos = entry_offsets_start + i * 64
                        if len(raw) < off_pos + 64:
                            break
                        entry_offset = int(raw[off_pos : off_pos + 64], 16) * 2
                        entry_start = array_offset + entry_offset
                        if len(raw) < entry_start + 128:
                            break
                        facet_addr = normalize_address("0x" + raw[entry_start + 24 : entry_start + 64])
                        action = int(raw[entry_start + 64 : entry_start + 128], 16)
                        # action: 0=Add, 1=Replace, 2=Remove.
                        if action != 2 and facet_addr != normalize_address("0x" + "0" * 40):
                            facets.append(facet_addr)
                    if facets:
                        event["implementation"] = facets[0]
                        event["facets"] = facets
        except (ValueError, IndexError):
            pass  # malformed data — return event without implementation

    return event


def _fetch_logs_etherscan(proxy_address: str, topic0: str, from_block: int = 0, chain_id: int = 1) -> list[dict]:
    from services.clients.etherscan import get

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


def fetch_upgrade_events(proxy_addresses: list[str], from_block: int = 0, chain_id: int = 1) -> list[_ParsedUpgradeLog]:
    """All upgrade events for the proxies, sorted chronologically.

    Rate-limited by ``services.clients.etherscan``. ``from_block`` limits history; ``chain_id`` routes to the right
    explorer.
    """
    all_events: list[_ParsedUpgradeLog] = []

    # Calls go through the global Etherscan lock, so threading only overlaps RTTs.
    tasks: list[tuple[str, str]] = []
    for addr in proxy_addresses:
        addr = normalize_address(addr)
        for topic0 in EVENT_TOPICS:
            tasks.append((addr, topic0))

    if tasks:
        from services.clients.etherscan import parallel_get

        calls = {
            f"{addr}|{topic0}": (
                lambda a=addr, t=topic0: _fetch_logs_etherscan(a, t, from_block=from_block, chain_id=chain_id)
            )
            for addr, topic0 in tasks
        }
        results = parallel_get(calls)

        # Original order so results are deterministic before sorting.
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


def _build_implementation_timeline(
    events: Sequence[Mapping[str, Any]],
    current_impl: str | None,
) -> list[ImplementationRecord]:
    upgrade_events = [e for e in events if e["event_type"] == "upgraded" and e.get("implementation")]

    if not upgrade_events:
        if current_impl:
            return [{"address": current_impl}]
        return []

    records: list[ImplementationRecord] = []
    for i, event in enumerate(upgrade_events):
        record: ImplementationRecord = {
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


def _enrich_implementations(
    implementations: list[ImplementationRecord], known_names: dict[str, str], *, chain_id: int
) -> None:
    from services.clients.etherscan import get_contract_info, parallel_get

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
    """Proxy metadata for the target only.

    Dependency proxies get their own jobs, and mixing their histories in would conflate contracts.

    Returns ``(target_address, {proxy_addr: (proxy_type, current_impl)}, {addr: name})``, with at most the target in the
    proxy dict.
    """
    target = normalize_address(deps["address"])

    proxy_meta: dict[str, tuple[str, str | None]] = {}
    known_names: dict[str, str] = {}

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

    # Harvest dependency names so enrichment needs fewer Etherscan calls.
    for addr, info in deps.get("dependencies", {}).items():
        if info.get("contract_name"):
            known_names[normalize_address(addr)] = info["contract_name"]
        impl = info.get("implementation")
        if isinstance(impl, dict) and impl.get("contract_name"):
            known_names[normalize_address(impl["address"])] = impl["contract_name"]

    return target, proxy_meta, known_names


def _strip_internal(event: _ParsedUpgradeLog) -> UpgradeEventRecord:
    out = event.copy()
    if "_emitter" in out:
        del out["_emitter"]
    return out


def build_upgrade_history(
    dependencies: dict, *, enrich: bool = True, from_block: int = 0, chain_id: int = 1
) -> UpgradeHistoryOutput:
    """Upgrade history for the target proxy in a unified deps dict (from
    ``services.discovery.unified_dependencies.build_unified_dependencies``).

    ``enrich`` resolves historical impl names via Etherscan. ``from_block`` enables incremental fetches. ``chain_id``
    routes the getLogs query; name enrichment is still mainnet-only (``get_contract_info`` has no chain parameter yet).
    """
    target_address, proxy_meta, known_names = _extract_proxies_from_dependencies(dependencies)

    if not proxy_meta:
        return {
            "schema_version": "0.1",
            "target_address": target_address,
            "proxies": {},
            "total_upgrades": 0,
        }

    all_events = fetch_upgrade_events(list(proxy_meta.keys()), from_block=from_block, chain_id=chain_id)

    events_by_proxy: dict[str, list[_ParsedUpgradeLog]] = {addr: [] for addr in proxy_meta}
    for event in all_events:
        emitter = event.get("_emitter")
        if emitter and emitter in events_by_proxy:
            events_by_proxy[emitter].append(event)

    proxies: dict[str, ProxyUpgradeHistory] = {}
    total_upgrades = 0
    all_implementations: list[ImplementationRecord] = []

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

    # Known names always apply; only ``enrich=True`` calls Etherscan for unknowns.
    if enrich:
        _enrich_implementations(all_implementations, known_names, chain_id=chain_id)
    else:
        for impl in all_implementations:
            known = known_names.get(impl.get("address", ""))
            if known is not None:
                impl["contract_name"] = known

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
    """Project an ``upgrade_history`` artifact into ``UpgradeEvent`` rows (inverse of ``synthesize_from_events``).

    Idempotent: deletes each proxy's rows (and legacy subject-keyed rows) first. Caller commits. Returns counters,
    including historical impl addresses for the static worker's backfill.
    """
    from datetime import datetime, timezone

    from sqlalchemy import func, select

    from db.models import UPGRADE_SOURCE_BACKFILL, Contract, UpgradeEvent

    out = {
        "proxies_seen": 0,
        "proxies_projected": 0,
        "proxies_skipped_no_contract": 0,
        "events_written": 0,
        "impl_addrs": set(),
        # Proxy ids actually written, the receipt fold's scope.
        "proxy_contract_ids": set(),
    }
    if not isinstance(artifact_data, dict) or not artifact_data.get("proxies"):
        return out

    # Legacy cleanup: older versions keyed every event to the subject.
    session.query(UpgradeEvent).filter(UpgradeEvent.contract_id == subject_contract_id).delete()

    for proxy_info in artifact_data["proxies"].values():
        out["proxies_seen"] += 1
        proxy_addr = proxy_info.get("proxy_address", "")
        if not proxy_addr:
            continue
        # Key on the proxy's row; the artifact can describe any proxy in the graph.
        proxy_contract = session.execute(
            select(Contract).where(
                func.lower(Contract.address) == proxy_addr.lower(),
                _contract_chain_filter(subject_chain),
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
            # Artifact timestamps are unix seconds; dropping them once collapsed every post-upgrade audit to low
            # confidence.
            ts_raw = evt.get("timestamp")
            ts_val = datetime.fromtimestamp(ts_raw, tz=timezone.utc) if ts_raw is not None else None
            session.add(
                UpgradeEvent(
                    contract_id=proxy_contract.id,
                    proxy_address=proxy_addr,
                    # Not recorded, as opposed to no predecessor; ``source`` distinguishes them.
                    old_impl=None,
                    new_impl=impl,
                    block_number=evt.get("block_number"),
                    timestamp=ts_val,
                    tx_hash=evt.get("tx_hash"),
                    source=UPGRADE_SOURCE_BACKFILL,
                )
            )
            out["events_written"] += 1
            if impl:
                out["impl_addrs"].add(impl.lower())
        out["proxies_projected"] += 1
        out["proxy_contract_ids"].add(proxy_contract.id)

    return out


def backfill_historical_impl_contracts(
    session,
    *,
    protocol_id: int,
    chain: str | None,
    impl_addrs: set[str],
    current_impl_address: str | None = None,
) -> None:
    """Ensure a Contract row for each historical impl, via the membership gate, so audit coverage can link audits
    naming past impls.

    Rows are nominated, never stamped; the gate admits via W2 ``historical_implementation`` once W1 lands.
    Rows owned by another protocol are left alone with a warning. Coverage refreshes only for members.

    ``current_impl_address`` is tagged as the live implementation so it stays analysable (see
    ranking.is_superseded_impl). Name lookups use the ``get_contract_info`` cache; per-address errors are swallowed.
    """
    from sqlalchemy import select

    from db.models import Contract, ContractCreationWitness
    from services.clients.etherscan import get_contract_info, parallel_get
    from services.clients.rpc import chain_id_for_chain_name
    from services.discovery import membership_gate
    from services.discovery.ranking import CURRENT_IMPLEMENTATION_SOURCE

    if not impl_addrs:
        return

    current_impl_lc = (current_impl_address or "").lower()

    # Match on (address, chain): CREATE2 can place one impl on several chains.
    existing_rows = {
        row.address.lower(): row
        for row in session.execute(
            select(Contract).where(Contract.address.in_(impl_addrs), _contract_chain_filter(chain))
        )
        .scalars()
        .all()
    }

    # Batch name lookups for new addresses.
    new_addrs = [addr for addr in impl_addrs if addr not in existing_rows]
    name_results: dict[str, str | None] = {}
    if new_addrs:
        # NULL chain is legacy mainnet; an unknown named chain fails loud.
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
    rows_by_addr: dict[str, Contract] = {}
    for addr in sorted(impl_addrs):
        is_current = bool(current_impl_lc) and addr == current_impl_lc
        # The live impl stays analysable; superseded ones get the anchor tag (ranking.is_superseded_impl).
        source_tag = CURRENT_IMPLEMENTATION_SOURCE if is_current else "upgrade_history"
        existing = existing_rows.get(addr)
        if existing is not None:
            if existing.protocol_id is not None and existing.protocol_id != protocol_id:
                logger.warning(
                    "Job protocol %s: historical impl %s already owned by protocol %s — "
                    "coverage link will not be created against this impl",
                    protocol_id,
                    addr,
                    existing.protocol_id,
                )
                continue
            membership_gate.nominate(session, contract=existing, protocol_id=protocol_id, source_tag=source_tag)
            adopted += 1
            rows_by_addr[addr] = existing
            continue

        name = name_results.get(addr)
        new_row = Contract(
            address=addr,
            chain=chain,
            contract_name=name or "UnknownImpl",
            is_proxy=False,
            job_id=None,
            source_verified=bool(name),
        )
        session.add(new_row)
        session.flush()
        membership_gate.nominate(session, contract=new_row, protocol_id=protocol_id, source_tag=source_tag)
        created += 1
        rows_by_addr[addr] = new_row

    if created or adopted:
        session.commit()
        logger.info(
            "Protocol %s: backfilled %d historical impl Contract row(s) (%d created, %d adopted)",
            protocol_id,
            created + adopted,
            created,
            adopted,
        )

    if not rows_by_addr:
        return

    # probe for W1, best-effort: a failure leaves an explainable candidate.
    probe_chain_id = chain_id_for_chain_name(chain or "ethereum")
    if probe_chain_id is not None:
        for addr in sorted(rows_by_addr):
            witness = session.get(ContractCreationWitness, (probe_chain_id, addr))
            if witness is not None and witness.code_probe_block is not None:
                continue
            try:
                membership_gate.probe(session, rows_by_addr[addr])
                session.commit()
            except Exception as exc:
                session.rollback()
                record_degraded(phase="historical_impl_probe", exc=exc, context={"address": addr})
                logger.warning("Historical-impl probe failed for %s: %s", addr, exc)

    from services.discovery.deployer_enumeration import session_deployer_enumerator

    membership_gate.evaluate_committed(
        session,
        membership_gate.FactsDelta(recheck_contract_ids=tuple(sorted(row.id for row in rows_by_addr.values()))),
        context=f"upgrade_history_backfill:{protocol_id}",
        deployer_enumerator=session_deployer_enumerator(session),
    )

    # Only members; the matcher filters by protocol_id.
    refresh_ids = sorted(row.id for row in rows_by_addr.values() if row.protocol_id == protocol_id)

    if refresh_ids:
        # Lazy import to avoid pulling audits deps into every context.
        from services.audits.coverage import upsert_coverage_for_contract

        refreshed = 0
        for contract_id in refresh_ids:
            try:
                # Leave equivalence to ``CoverageVerifyWorker`` (rows land ``pending``); verifying inline caused
                # Etherscan/GitHub bursts that hit the global rate limit (#82).
                refreshed += upsert_coverage_for_contract(
                    session,
                    contract_id,
                    verify_source_equivalence=False,
                )
            except Exception as exc:
                # One bad match shouldn't block the rest; admin refresh_coverage can fill gaps.
                record_degraded(
                    phase="backfilled_impl_coverage_refresh",
                    exc=exc,
                    context={"contract_id": contract_id, "protocol_id": protocol_id},
                )
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


def synthesize_from_events(session, contract) -> UpgradeHistoryOutput | None:
    """Rebuild the ``upgrade_history`` artifact shape from ``UpgradeEvent`` rows, when the artifact is missing or
    unreachable. Uses the same table that backs the overview badges, so they stay consistent. None when there are
    no events.
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

    events: list[UpgradeEventRecord] = []
    last_impl: str | None = None
    for ev in rows:
        if not ev.new_impl:
            continue
        # Unix seconds like the canonical artifact; the frontend does ``new Date(ts * 1000)``.
        impl_lc: str = ev.new_impl.lower()
        last_impl = impl_lc
        events.append(
            {
                "event_type": "upgraded",
                "block_number": ev.block_number,
                "timestamp": int(ev.timestamp.timestamp()) if ev.timestamp else None,
                "tx_hash": ev.tx_hash,
                "implementation": impl_lc,
            }
        )
    if not events or last_impl is None:
        return None

    current_impl = (contract.implementation or last_impl).lower()
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
    proxy: ProxyUpgradeHistory = {
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


# Upgrade executor fold (C4).
#
# The executor isn't in a log, so each distinct tx's receipt is fetched and folded into per-transaction facts.
#
# Deliberately not published:
#   * ``authorising_eoa``: ``receipt.from`` on a Safe execution is a relayer (one Safe's executions came from five
# senders), so the literal ``"not_determined"`` is published.
#   * ``timelock_is_decoy``: no observed bypass isn't proof of none; only ``direct_upgrade_witnessed_at_block`` is.
#   * an ``eoa_one_hop`` kind: ``tx.from`` being the top-level caller doesn't make it the caller at the upgrade site.

# Order of record, not strength; disagreeing planes yield not_determined.
_CLASSIFICATION_PLANES = ("function_principals", "control_graph_nodes", "principal_labels")

# Etherscan's ``getcontractcreation`` batch limit.
_CREATION_BATCH = 5


def _bloom_has_topic(logs_bloom: str | None, topic0: str) -> bool | None:
    """Does *logs_bloom* contain *topic0*? ``None`` when unusable.

    Blooms have no false negatives, so ``False`` independently proves absence; ``True`` only means probably present, so
    a ``True`` with no matching log makes the receipt unusable.
    """
    if not isinstance(logs_bloom, str) or not isinstance(topic0, str):
        return None
    raw = logs_bloom.strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 512:
        return None
    try:
        bloom = int(raw, 16)
        topic_bytes = bytes.fromhex(topic0[2:] if topic0.startswith("0x") else topic0)
    except ValueError:
        return None
    if len(topic_bytes) != 32:
        return None

    from eth_utils.crypto import keccak

    digest = keccak(topic_bytes)
    for i in (0, 2, 4):
        bit = ((digest[i] << 8) | digest[i + 1]) & 0x7FF
        if not (bloom >> bit) & 1:
            return False
    return True


def _logs_with_topic(logs: list, topic0: str) -> list[dict]:
    out: list[dict] = []
    for log in logs:
        if not isinstance(log, dict):
            continue
        topics = log.get("topics") or []
        if topics and isinstance(topics[0], str) and topics[0].lower() == topic0.lower():
            out.append(log)
    return out


def _call_executed_targets(call_executed_logs: list[dict]) -> list[str]:
    """``target`` of each ``CallExecuted`` log (the first data word), so a timelock-routed tx isn't attributed to
    every ``Upgraded`` log in it.
    """
    targets: list[str] = []
    for log in call_executed_logs:
        data = log.get("data") or "0x"
        raw = data[2:] if isinstance(data, str) and data.startswith("0x") else data
        if not isinstance(raw, str) or len(raw) < 64:
            continue
        try:
            target = normalize_address("0x" + raw[24:64])
        except Exception:
            continue
        if target not in targets:
            targets.append(target)
    return sorted(targets)


def _row_chain_id(chain_name: Any) -> int | None:
    """The registry chain id for a stored chain name, or ``None`` (NULL, ``"unknown"``, unregistered).

    A row with no determined chain can't classify anything.
    """
    from utils.chains import UnknownChainError, chain_by_name

    if not isinstance(chain_name, str) or not chain_name.strip():
        return None
    try:
        return chain_by_name(chain_name).chain_id
    except UnknownChainError:
        return None


def _classify_emitter(
    session, address: str, *, chain_id: int
) -> tuple[ResolvedControllerType | None, str | None, int | None]:
    """The emitter's type from the persisted classification planes, scoped to the receipt's chain.

    The classification comes from ``services.resolution.tracking``'s negative-controlled probes in another stage, which
    makes it independent of the receipt. Plane rows are joined to ``Contract.chain`` and kept only for the receipt's
    chain (CREATE2 twins are different contracts); unresolvable chains are dropped.

    Returns ``(resolved_type, plane, classification_block)``; no answer or disagreement gives ``(None, None, None)``.
    """
    from sqlalchemy import func, select

    from db.models import Contract, ControlGraphNode, EffectiveFunction, FunctionPrincipal, PrincipalLabel

    lowered = (address or "").lower()
    if not lowered:
        return None, None, None

    statements = {
        "function_principals": (
            select(FunctionPrincipal.resolved_type, FunctionPrincipal.details, Contract.chain)
            .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
            .join(Contract, Contract.id == EffectiveFunction.contract_id)
            .where(
                func.lower(FunctionPrincipal.address) == lowered,
                FunctionPrincipal.resolved_type.isnot(None),
            )
        ),
        "control_graph_nodes": (
            select(ControlGraphNode.resolved_type, ControlGraphNode.details, Contract.chain)
            .join(Contract, Contract.id == ControlGraphNode.contract_id)
            .where(
                func.lower(ControlGraphNode.address) == lowered,
                ControlGraphNode.resolved_type.isnot(None),
            )
        ),
        "principal_labels": (
            select(PrincipalLabel.resolved_type, PrincipalLabel.details, Contract.chain)
            .join(Contract, Contract.id == PrincipalLabel.contract_id)
            .where(
                func.lower(PrincipalLabel.address) == lowered,
                PrincipalLabel.resolved_type.isnot(None),
            )
        ),
    }
    observed: dict[str, list[tuple[str, Any]]] = {}
    for plane in _CLASSIFICATION_PLANES:
        rows = [
            (str(rt), details)
            for rt, details, chain_name in session.execute(statements[plane]).all()
            if _row_chain_id(chain_name) == chain_id
        ]
        if rows:
            observed[plane] = rows

    kinds = {rt for rows in observed.values() for rt, _ in rows}
    if len(kinds) != 1:
        return None, None, None
    resolved_type = kinds.pop()
    if resolved_type not in RESOLVED_CONTROLLER_TYPES:
        # Agreed on a value outside the vocabulary.
        return None, None, None
    typed_resolved = cast(ResolvedControllerType, resolved_type)

    plane = next(p for p in _CLASSIFICATION_PLANES if p in observed)
    block: int | None = None
    for _rt, details in observed[plane]:
        if not isinstance(details, dict):
            continue
        protection = details.get("safe_protection")
        if not isinstance(protection, dict):
            continue
        candidate = protection.get("probe_block")
        # The probe writes ``"not_determined"`` when it has no height.
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            block = candidate
            break
    return typed_resolved, plane, block


def _fetch_receipt(rpc_url: str, tx_hash: str, *, chain_id: int) -> dict | None:
    """One ``eth_getTransactionReceipt``, ``None`` on failure.

    It can't be pinned to a block, so ``blockHash`` is stored to detect reorgs later.
    """
    from services.clients.rpc import rpc_request

    try:
        receipt = rpc_request(rpc_url, "eth_getTransactionReceipt", [tx_hash], chain_id=chain_id)
    except Exception as exc:
        logger.debug("receipt fetch failed for %s: %s", tx_hash, exc)
        return None
    return receipt if isinstance(receipt, dict) else None


def _hex_int_or_none(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


def _decode_receipt(
    receipt: dict,
    *,
    stored_events_by_proxy: dict[str, int],
) -> dict | None:
    """Receipt to column values, or ``None`` if unusable.

    ``receipt_log_set_complete_for_tx`` is computed:

      (i)   every stored ``Upgraded`` event for the tx is in the receipt logs, from its proxy;
      (ii)  the bloom is present, well-formed, and confirms an ``Upgraded`` log the array carries (an all-zero bloom
    would otherwise prove absence of everything);
      (iii) bloom and logs agree about ``CallExecuted`` (bloom-present without the log means the array may be pruned, a
    real risk behind eRPC).

    (ii) and (iii) matter because ``safe_direct`` is an absence verdict.
    """
    block_number = _hex_int_or_none(receipt.get("blockNumber"))
    block_hash = receipt.get("blockHash")
    status = _hex_int_or_none(receipt.get("status"))
    sender = receipt.get("from")
    if block_number is None or not isinstance(block_hash, str) or status is None or not isinstance(sender, str):
        # Pre-Byzantium receipts have no ``status``.
        return None

    logs = receipt.get("logs")
    logs = logs if isinstance(logs, list) else []

    upgraded_logs = _logs_with_topic(logs, UPGRADED_TOPIC0)
    upgraded_by_proxy: dict[str, int] = {}
    for log in upgraded_logs:
        emitter = log.get("address")
        if isinstance(emitter, str):
            key = emitter.lower()
            upgraded_by_proxy[key] = upgraded_by_proxy.get(key, 0) + 1
    self_consistent = all(
        upgraded_by_proxy.get(proxy, 0) >= max(1, stored) for proxy, stored in stored_events_by_proxy.items()
    )

    from services.monitoring.event_topics import CALL_EXECUTED_TOPIC0, EXECUTION_SUCCESS_TOPIC0

    call_executed = _logs_with_topic(logs, CALL_EXECUTED_TOPIC0)
    execution_success = _logs_with_topic(logs, EXECUTION_SUCCESS_TOPIC0)
    logs_bloom = receipt.get("logsBloom")
    bloom_says_call_executed = _bloom_has_topic(logs_bloom, CALL_EXECUTED_TOPIC0)
    # Positive control: a working bloom must confirm the ``Upgraded`` log we know is there.
    bloom_usable = (
        bloom_says_call_executed is not None
        and bool(upgraded_logs)
        and _bloom_has_topic(logs_bloom, UPGRADED_TOPIC0) is True
    )
    bloom_agrees = bloom_usable and not (bloom_says_call_executed is True and not call_executed)

    to_addr = receipt.get("to")
    created = receipt.get("contractAddress")
    return {
        "block_number": block_number,
        "block_hash": block_hash.lower(),
        "tx_status": status,
        "receipt_from": sender.lower(),
        "receipt_to": to_addr.lower() if isinstance(to_addr, str) else None,
        "created_contract_address": created.lower() if isinstance(created, str) else None,
        "is_contract_creation": not isinstance(to_addr, str),
        "receipt_log_set_complete_for_tx": bool(self_consistent and bloom_agrees),
        # The receipt's own per-proxy count; stored rows can't detect under-projection, and two logs for one proxy is
        # never a plain creation.
        "receipt_upgraded_counts": upgraded_by_proxy,
        "_call_executed": call_executed,
        "_execution_success": execution_success,
    }


def _resolve_executor(session, decoded: dict, *, chain_id: int) -> dict:
    """The four-field executor verdict, fail-closed.

    A positive needs a keccak-matched marker log, an emitter typed on this chain by a persisted plane, and a provably
    complete log set.
    """
    blank = {
        "executor_kind": NOT_DETERMINED,
        "executor_address": None,
        "executor_classification_source": None,
        "executor_classified_type": None,
        "executor_classification_block": None,
        "executor_call_targets": None,
    }
    if decoded["tx_status"] != 1 or not decoded["receipt_log_set_complete_for_tx"]:
        return blank

    call_executed = decoded["_call_executed"]
    execution_success = decoded["_execution_success"]

    if call_executed:
        emitters = {log.get("address", "").lower() for log in call_executed if isinstance(log.get("address"), str)}
        if len(emitters) != 1:
            # Two CallExecuted emitters: undecidable.
            return blank
        emitter = emitters.pop()
        resolved_type, plane, block = _classify_emitter(session, emitter, chain_id=chain_id)
        if resolved_type != "timelock":
            return blank
        from db.models import EXECUTOR_KIND_TIMELOCK_ROUTED

        return {
            "executor_kind": EXECUTOR_KIND_TIMELOCK_ROUTED,
            "executor_address": emitter,
            "executor_classification_source": plane,
            "executor_classified_type": resolved_type,
            "executor_classification_block": block,
            "executor_call_targets": _call_executed_targets(call_executed),
        }

    if execution_success:
        emitters = {log.get("address", "").lower() for log in execution_success if isinstance(log.get("address"), str)}
        if len(emitters) != 1:
            return blank
        emitter = emitters.pop()
        resolved_type, plane, block = _classify_emitter(session, emitter, chain_id=chain_id)
        if resolved_type != "safe":
            return blank
        from db.models import EXECUTOR_KIND_SAFE_DIRECT

        return {
            "executor_kind": EXECUTOR_KIND_SAFE_DIRECT,
            "executor_address": emitter,
            "executor_classification_source": plane,
            "executor_classified_type": resolved_type,
            "executor_classification_block": block,
            # ExecutionSuccess carries no target.
            "executor_call_targets": None,
        }

    return blank


def _fetch_creation_witnesses(session, *, chain_id: int, candidates: dict[str, tuple[int, str]], rpc_url: str) -> int:
    """Persist two-witness creation facts for *candidates* (proxy → block and tx of its earliest ``Upgraded``).

    A factory-deployed proxy's deployment ``Upgraded`` looks like an upgrade on the receipt, so require both Etherscan
    naming the creation tx and ``eth_getCode`` showing no code the block before.
    """
    from db.creation_witnesses import upsert_creation_witness
    from services.clients.etherscan import get as etherscan_get
    from services.clients.rpc import rpc_request

    addresses = sorted(candidates)
    written = 0
    creation: dict[str, tuple[str | None, int | None]] = {}
    for start in range(0, len(addresses), _CREATION_BATCH):
        batch = addresses[start : start + _CREATION_BATCH]
        try:
            data = etherscan_get(
                "contract",
                "getcontractcreation",
                chain_id=chain_id,
                contractaddresses=",".join(batch),
            )
        except Exception as exc:
            logger.debug("getcontractcreation failed for %s: %s", batch, exc)
            continue
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list):
            continue
        for item in result:
            if not isinstance(item, dict):
                continue
            addr = item.get("contractAddress")
            tx = item.get("txHash")
            if not isinstance(addr, str) or not isinstance(tx, str):
                continue
            creation[addr.lower()] = (tx.lower(), _coerce_block(item.get("blockNumber")))

    for address in addresses:
        creation_tx, creation_block = creation.get(address, (None, None))
        probe_block: int | None = None
        code_absent: bool | None = None
        # Only probe where the indexer names this proxy's earliest ``Upgraded`` tx; elsewhere it can't change a verdict.
        first_block, first_tx = candidates.get(address, (0, ""))
        if creation_tx is not None and creation_tx == first_tx:
            if first_block > 0:
                probe_block = first_block - 1
                try:
                    code = rpc_request(
                        rpc_url,
                        "eth_getCode",
                        [address, hex(probe_block)],
                        chain_id=chain_id,
                    )
                except Exception as exc:
                    logger.debug("eth_getCode failed for %s@%s: %s", address, probe_block, exc)
                    probe_block = None
                else:
                    if isinstance(code, str):
                        code_absent = code in ("0x", "0x0", "")
                    else:
                        probe_block = None

        # Called only for addresses with no row; a concurrent membership probe's latest-block reading must win.
        upsert_creation_witness(
            session,
            chain_id=chain_id,
            address=address,
            keep_existing=True,
            creation_tx_hash=creation_tx,
            creation_block=creation_block,
            code_probe_block=probe_block,
            code_absent_at_probe=code_absent,
        )
        written += 1
    return written


def _coerce_block(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            return int(raw, 16) if raw.startswith("0x") else int(raw)
        except ValueError:
            return None
    return None


def fold_upgrade_transactions(
    session,
    *,
    chain_id: int,
    contract_ids,
    rpc_url: str | None = None,
) -> dict:
    """Fold each distinct upgrade tx's receipt into per-tx facts, once (receipts are immutable). Caller commits.

    Every failure (no RPC, fetch failure, no ``status``, reverted, unclassified emitter, unprovable log set) lands on
    ``not_determined`` or no row. Nothing defaults or infers from names.
    """
    from sqlalchemy import select

    from db.models import ContractCreationWitness, UpgradeEvent, UpgradeTransaction
    from services.clients.rpc import rpc_url_for_chain_id

    out = {
        "tx_in_scope": 0,
        "tx_folded": 0,
        "tx_receipt_unusable": 0,
        "events_linked": 0,
        "creation_witnesses": 0,
        "kinds": {},
    }
    ids = [int(cid) for cid in (contract_ids or [])]
    if not ids:
        return out

    scoped = session.execute(
        select(UpgradeEvent.tx_hash, UpgradeEvent.proxy_address, UpgradeEvent.block_number).where(
            UpgradeEvent.contract_id.in_(ids), UpgradeEvent.tx_hash.isnot(None)
        )
    ).all()
    tx_hashes = sorted({str(tx).lower() for tx, _addr, _blk in scoped})
    if not tx_hashes:
        return out
    out["tx_in_scope"] = len(tx_hashes)

    resolved_url = rpc_url_for_chain_id(chain_id, rpc_url)
    if not resolved_url:
        # No wire, no witness.
        return out

    # Completeness is a receipt property, so compare against all the tx's stored events.
    all_rows = session.execute(
        select(UpgradeEvent.tx_hash, UpgradeEvent.proxy_address).where(UpgradeEvent.tx_hash.in_(tx_hashes))
    ).all()
    stored_by_tx: dict[str, dict[str, int]] = {}
    for tx, proxy in all_rows:
        by_proxy = stored_by_tx.setdefault(str(tx).lower(), {})
        key = (proxy or "").lower()
        by_proxy[key] = by_proxy.get(key, 0) + 1

    folded: set[str] = set()
    for tx_hash in tx_hashes:
        receipt = _fetch_receipt(resolved_url, tx_hash, chain_id=chain_id)
        if receipt is None:
            out["tx_receipt_unusable"] += 1
            continue
        decoded = _decode_receipt(receipt, stored_events_by_proxy=stored_by_tx.get(tx_hash, {}))
        if decoded is None:
            out["tx_receipt_unusable"] += 1
            continue
        verdict = _resolve_executor(session, decoded, chain_id=chain_id)

        row = session.get(UpgradeTransaction, (chain_id, tx_hash))
        if row is None:
            row = UpgradeTransaction(chain_id=chain_id, tx_hash=tx_hash)
            session.add(row)
        for field in (
            "block_number",
            "block_hash",
            "tx_status",
            "receipt_from",
            "receipt_to",
            "created_contract_address",
            "is_contract_creation",
            "receipt_log_set_complete_for_tx",
            "receipt_upgraded_counts",
        ):
            setattr(row, field, decoded[field])
        for field, value in verdict.items():
            setattr(row, field, value)
        folded.add(tx_hash)
        out["tx_folded"] += 1
        kind = verdict["executor_kind"]
        out["kinds"][kind] = out["kinds"].get(kind, 0) + 1

    # The earliest ``Upgraded`` block is the only place a creation could be.
    earliest: dict[str, tuple[int, str]] = {}
    for tx, proxy, block in scoped:
        tx_lc = str(tx).lower()
        if block is None or tx_lc not in folded:
            continue
        key = (proxy or "").lower()
        if key and (key not in earliest or block < earliest[key][0]):
            earliest[key] = (int(block), tx_lc)
    if earliest:
        missing = {
            addr: pair
            for addr, pair in earliest.items()
            if session.get(ContractCreationWitness, (chain_id, addr)) is None
        }
        if missing:
            out["creation_witnesses"] = _fetch_creation_witnesses(
                session, chain_id=chain_id, candidates=missing, rpc_url=resolved_url
            )

    if folded:
        # Written now that the parent row exists (FK link).
        linked = (
            session.query(UpgradeEvent)
            .filter(UpgradeEvent.contract_id.in_(ids), UpgradeEvent.tx_hash.in_(sorted(folded)))
            .update({UpgradeEvent.chain_id: chain_id}, synchronize_session=False)
        )
        out["events_linked"] = int(linked or 0)
    return out


def event_is_deployment(tx_row, creation_row, *, proxy_address: str, event_block, pair_event_count: int) -> bool:
    """Is this ``Upgraded`` event the proxy's deployment rather than an upgrade? Either the receipt shows ``to IS
    NULL`` and ``contractAddress == proxy``, or the two-witness creation pair holds. ``False`` keeps the event
    counted (over-counting is honest; dropping upgrades isn't).
    """
    if tx_row is None or tx_row.tx_status != 1:
        return False
    proxy = proxy_address.lower()
    # Two Upgraded logs for one proxy isn't a plain deployment. Use the larger of projected and receipt counts, since
    # stored rows can't show their own under-projection.
    observed = tx_row.receipt_upgraded_counts
    observed_for_proxy = int(observed.get(proxy, 0) or 0) if isinstance(observed, dict) else 0
    if max(pair_event_count, observed_for_proxy) != 1:
        return False
    if tx_row.is_contract_creation and (tx_row.created_contract_address or "") == proxy:
        return True
    if creation_row is None:
        return False
    if (creation_row.creation_tx_hash or "") != tx_row.tx_hash:
        return False
    if creation_row.code_absent_at_probe is not True:
        return False
    if event_block is None or creation_row.code_probe_block != int(event_block) - 1:
        return False
    return True


def _chain_id_for_contract(chain_name: str | None) -> int | None:
    """The contract's chain id, mainnet-coalesced like ``_contract_chain_filter``; an unrecognised name is ``None``,
    never 1 (#158).
    """
    from services.clients.rpc import chain_id_for_chain_name

    return chain_id_for_chain_name(canonical_chain(chain_name) or "ethereum")


def _load_action_context(session, contract_ids):
    from sqlalchemy import select, tuple_

    from db.models import Contract, ContractCreationWitness, UpgradeEvent, UpgradeTransaction

    ids = [int(cid) for cid in (contract_ids or [])]
    if not ids:
        return [], {}, {}
    events = session.execute(
        select(
            UpgradeEvent.contract_id,
            UpgradeEvent.proxy_address,
            UpgradeEvent.tx_hash,
            UpgradeEvent.block_number,
            UpgradeEvent.chain_id,
            Contract.chain,
        )
        .join(Contract, Contract.id == UpgradeEvent.contract_id)
        .where(UpgradeEvent.contract_id.in_(ids))
    ).all()

    keys = sorted({(int(cid), str(tx).lower()) for _c, _p, tx, _b, cid, _ch in events if cid is not None and tx})
    tx_rows: dict[tuple[int, str], Any] = {}
    if keys:
        for row in session.execute(
            select(UpgradeTransaction).where(tuple_(UpgradeTransaction.chain_id, UpgradeTransaction.tx_hash).in_(keys))
        ).scalars():
            tx_rows[(row.chain_id, row.tx_hash)] = row

    addr_keys = sorted({(int(cid), (proxy or "").lower()) for _c, proxy, _t, _b, cid, _ch in events if cid is not None})
    creation_rows: dict[tuple[int, str], Any] = {}
    if addr_keys:
        for row in session.execute(
            select(ContractCreationWitness).where(
                tuple_(ContractCreationWitness.chain_id, ContractCreationWitness.address).in_(addr_keys)
            )
        ).scalars():
            creation_rows[(row.chain_id, row.address)] = row
    return events, tx_rows, creation_rows


def _fold_actions(session, contract_ids) -> dict[int, dict]:
    """Fold each contract's events into its action set plus the counters every figure cites."""
    from db.models import EXECUTOR_KIND_SAFE_DIRECT

    events, tx_rows, creation_rows = _load_action_context(session, contract_ids)
    pair_counts: dict[tuple[int, str], int] = {}
    for cid, _proxy, tx, _blk, _chain, _name in events:
        if tx:
            key = (int(cid), str(tx).lower())
            pair_counts[key] = pair_counts.get(key, 0) + 1

    per_contract: dict[int, dict] = {}
    for cid, proxy, tx, block, chain, chain_name in events:
        cid = int(cid)
        state = per_contract.setdefault(
            cid,
            {
                "actions": set(),
                "events_total": 0,
                "events_without_tx_hash": 0,
                "tx_facts_present": 0,
                "events_unlinked": 0,
                "deployments_excluded": 0,
                "kinds": {},
                "direct_blocks": [],
                "chain_id": None,
            },
        )
        state["events_total"] += 1
        # A written ``upgrade_events.chain_id`` wins; else the mainnet-coalesced chain name. Unknown names aren't
        # guessed.
        if state["chain_id"] is None:
            state["chain_id"] = chain if chain is not None else _chain_id_for_contract(chain_name)
        if not tx:
            state["events_without_tx_hash"] += 1
            continue
        tx_lc = str(tx).lower()
        tx_row = tx_rows.get((int(chain), tx_lc)) if chain is not None else None
        if tx_row is None:
            # No receipt fact: stays counted.
            state["events_unlinked"] += 1
            state["actions"].add(tx_lc)
            continue
        state["tx_facts_present"] += 1
        state["kinds"][tx_row.executor_kind] = state["kinds"].get(tx_row.executor_kind, 0) + 1
        if tx_row.executor_kind == EXECUTOR_KIND_SAFE_DIRECT:
            state["direct_blocks"].append(tx_row.block_number)
        creation_row = creation_rows.get((int(chain), (proxy or "").lower()))
        if event_is_deployment(
            tx_row,
            creation_row,
            proxy_address=proxy or "",
            event_block=block,
            pair_event_count=pair_counts.get((cid, tx_lc), 1),
        ):
            state["deployments_excluded"] += 1
            continue
        state["actions"].add(tx_lc)
    return per_contract


def upgrade_action_counts(session, contract_ids) -> dict[int, dict]:
    """Per contract: how many upgrade actions its rows support, plus the basis.

    * The unit is the transaction, not the log (one tx carried 19 ``Upgraded`` logs).
    * Deployments are excluded (a proxy's creation emits ``Upgraded``).
    * A post-exclusion zero publishes ``None``: only ERC-1967 topics are folded and ``old_impl`` is NULL on backfilled
    rows, so "none recorded" isn't "none happened".

    Still an upper bound: events with no receipt fact stay counted.
    """
    out: dict[int, dict] = {}
    for cid, state in _fold_actions(session, contract_ids).items():
        count = len(state["actions"]) + state["events_without_tx_hash"]
        direct = [b for b in state["direct_blocks"] if b is not None]
        out[cid] = {
            "count": count if count > 0 else None,
            "basis": {
                "events_total": state["events_total"],
                "tx_facts_present": state["tx_facts_present"],
                "events_unlinked": state["events_unlinked"],
                "events_without_tx_hash": state["events_without_tx_hash"],
                "deployments_excluded": state["deployments_excluded"],
                "executor_kinds": dict(sorted(state["kinds"].items())),
                # Only ERC-1967 topics are folded, so no event doesn't prove no upgrade.
                "recorded_event_coverage": NOT_DETERMINED,
                # tx.from is the submitter, not the signer set.
                "authorising_eoa": NOT_DETERMINED,
                # No observed bypass isn't proof the bypass is closed.
                "timelock_is_decoy": NOT_DETERMINED,
                # A direct path was exercised at this block; says nothing about now.
                "direct_upgrade_witnessed_at_block": min(direct) if direct else None,
            },
        }
    return out


def governance_actions_for(session, contract_ids) -> set[tuple[int, str]]:
    """The distinct governance actions these contracts' events describe, as ``(chain_id, tx_hash)`` (a bare hash can
    collide across chains, #158).

    A multi-log tx is one action. Proven deployments are excluded; events without receipt facts are kept. Scoped to
    *contract_ids*. Contracts with unresolvable chains contribute nothing here but are still counted by
    ``upgrade_action_counts``.
    """
    actions: set[tuple[int, str]] = set()
    for state in _fold_actions(session, contract_ids).values():
        chain_id = state["chain_id"]
        if chain_id is None:
            continue
        actions |= {(int(chain_id), tx) for tx in state["actions"]}
    return actions
