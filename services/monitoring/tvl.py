"""Protocol-wide TVL tracking — periodic balance refresh and snapshots.

Combines two data sources:
1. DefiLlama protocol TVL (one HTTP call per protocol, gives chain breakdown)
2. On-chain per-contract balances via Etherscan (existing utils)

Stores historical snapshots in the ``tvl_snapshots`` table and refreshes
the ``contract_balances`` table with the latest values.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event

import requests
from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractBalanceLatest,
    Protocol,
    SessionLocal,
    TvlSnapshot,
)
from db.queue import record_heartbeat
from services.clients.rpc import rpc_url_for_chain_id
from services.monitoring import HEARTBEAT_PROTOCOL_TVL, emit_monitor_cycle
from services.monitoring.balance_collection import CollectionReport
from services.monitoring.balance_reads import (
    ObservationSubject,
    contracts_missing_current_rows,
)
from services.monitoring.chain_rpc import chain_id_for
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    BALANCE_WRITER_TVL,
    SWEEP_STATUS_COMPLETED,
)
from utils.logging import log_timed_phase

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)

DEFAULT_TVL_INTERVAL = int(os.getenv("PROTOCOL_TVL_INTERVAL", "3600"))
# Minimum seconds between snapshots for the same protocol.  Prevents
# duplicate rows when the loop is retriggered quickly (restart, signal, etc.).
MIN_SNAPSHOT_INTERVAL = int(os.getenv("PROTOCOL_TVL_MIN_INTERVAL", "300"))
# Protocols refreshed per tick, oldest-snapshot-first — bounds the per-tick
# Etherscan/DefiLlama fan-out (design §2.7).
DEFAULT_TVL_PROTOCOLS_PER_PASS = 10
# The protocol's signers and capability principals use a daily balance cadence.
# The shared collector still deduplicates physical reads across protocols.
DEFAULT_ENTITY_BALANCE_INTERVAL = int(os.getenv("PSAT_ENTITY_BALANCE_INTERVAL", "86400"))
DEFILLAMA_PROTOCOL_URL = "https://api.llama.fi/protocol"


# ---------------------------------------------------------------------------
# DefiLlama TVL
# ---------------------------------------------------------------------------


def fetch_defillama_tvl(protocol_name: str) -> dict | None:
    """Fetch current TVL from DefiLlama for a protocol.

    Uses ``resolve_protocol`` (cached in-memory) to map the protocol name
    to a slug, then calls the DefiLlama protocol endpoint.

    Returns ``{"tvl": float, "chain_breakdown": dict}`` or ``None``.
    """
    from services.discovery.protocol_resolver import resolve_protocol

    resolved = resolve_protocol(protocol_name)
    slug = resolved.get("slug")
    if not slug:
        return None

    try:
        resp = requests.get(f"{DEFILLAMA_PROTOCOL_URL}/{slug}", timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("DefiLlama fetch failed for %s: %s", slug, exc)
        return None

    tvl = data.get("tvl")
    if isinstance(tvl, list):
        # Historical time series — grab the latest entry
        point = tvl[-1] if tvl and isinstance(tvl[-1], dict) else {}
        tvl = point.get("totalLiquidityUSD")
    elif not isinstance(tvl, (int, float)):
        tvl = None

    import math

    if not isinstance(tvl, (int, float)) or not math.isfinite(tvl) or not 0 <= tvl < 1e20:
        tvl = None

    chain_breakdown = data.get("currentChainTvls")
    if not isinstance(chain_breakdown, dict):
        chain_breakdown = {}

    # Filter out borrowed/staking/pool2 keys — keep only chain names
    chain_breakdown = {
        k: v
        for k, v in chain_breakdown.items()
        if not any(k.lower().startswith(p) for p in ("borrowed", "staking", "pool2"))
        and isinstance(v, (int, float))
        and math.isfinite(v)
        and v >= 0
    }

    return {
        "tvl": float(tvl) if tvl is not None else None,
        "chain_breakdown": chain_breakdown,
    }


# ---------------------------------------------------------------------------
# On-chain balance refresh
# ---------------------------------------------------------------------------


def _get_protocol_addresses(session: Session, protocol_id: int) -> list[Contract]:
    """Select current balance subjects, normally excluding proxy implementations.

    Include implementations with a truncated stored page or whose proxy still
    carries a legacy scan observation. Refreshing these accounts avoids leaving
    old evidence permanently attached to the folded entity. These exceptions
    schedule current balance reads only; historical scans are never resumed.
    """
    from services.aggregations.company_overview.entity_keys import _entity_key
    from services.monitoring.balance_reads import winning_asset_fetches

    contracts = session.execute(select(Contract).where(Contract.protocol_id == protocol_id)).scalars().all()
    winning = winning_asset_fetches(session, protocol_id)
    stuck_at_cap = {
        contract_id for contract_id, fetch in winning.items() if fetch.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP
    }
    by_id = {c.id: c for c in contracts}
    legacy_scanned_entities = {
        _entity_key(by_id[contract_id].chain, by_id[contract_id].address)
        for contract_id, fetch in winning.items()
        if contract_id in by_id
        and fetch.asset_set_source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP
        and fetch.sweep_status == SWEEP_STATUS_COMPLETED
        and fetch.swept_through_block is not None
    }
    folded_into_a_legacy_scanned_sheet = {
        c.id
        for c in contracts
        if c.is_proxy and c.implementation and _entity_key(c.chain, c.address) in legacy_scanned_entities
    }
    # The IMPLEMENTATION rows of those proxies, matched the same chain-scoped way
    # the exclusion below is built.
    legacy_scanned_impl_tokens = {
        _entity_key(by_id[cid].chain, by_id[cid].implementation) for cid in folded_into_a_legacy_scanned_sheet
    }

    # Impl-behind-proxy tokens, keyed by the composite "<chain>::<address>": an
    # EIP-1967 impl lives on its proxy's chain, so exclude it only there. A bare
    # address set would also drop a standalone contract that merely shares an
    # address with some other chain's impl (a CREATE2 twin) from balance
    # collection entirely.
    impl_tokens: set[str] = set()
    for c in contracts:
        if c.is_proxy and c.implementation:
            impl_tokens.add(_entity_key(c.chain, c.implementation))

    # Keep proxy contracts (they hold the funds) and non-impl regular contracts
    return [
        c
        for c in contracts
        if c.address
        and (
            _entity_key(c.chain, c.address) not in impl_tokens
            or c.id in stuck_at_cap
            or _entity_key(c.chain, c.address) in legacy_scanned_impl_tokens
        )
    ]


def refresh_contract_balances(
    session: Session,
    protocol_id: int,
    *,
    contract_ids: set[int] | None = None,
    counters: dict[str, int] | None = None,
) -> tuple[dict[str, dict], bool]:
    """Collect current state with short independent publication transactions."""
    from sqlalchemy.orm import sessionmaker

    from services.monitoring.balance_collection import CollectionSubject, collect_balances

    contracts = _get_protocol_addresses(session, protocol_id)
    subjects = [
        CollectionSubject(ObservationSubject.of_contract(c), chain_id_for(c.chain))
        for c in contracts
        if c.address and (contract_ids is None or c.id in contract_ids)
    ]
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    session.commit()
    report = collect_balances(subjects, writer=BALANCE_WRITER_TVL, session_factory=factory)
    if counters is not None:
        for name in ("attempted", "reused", "deferred", "fetched", "committed", "failed", "partial"):
            counters["balances_" + name] = counters.get("balances_" + name, 0) + getattr(report, name)
    session.expire_all()
    breakdown, partial = _read_existing_balances(session, protocol_id)
    return breakdown, partial or bool(report.failed or report.deferred or report.partial)


@dataclass(frozen=True)
class ExcludedHolder:
    """One entity the current observation population did NOT take, and why.

    Published rather than dropped. A population that quietly shrinks is
    indistinguishable from one that was never that size, and every exclusion
    here is a decision a reader is entitled to check.
    """

    entity_key: str
    reason: str


@dataclass(frozen=True)
class EntityHolder:
    """One proven-codeless principal queued for observation at its own address."""

    subject: ObservationSubject
    entity_key: str
    chain: str
    chain_id: int
    address: str


@dataclass
class EntityObservationReport:
    """Durable current-state collection progress for the eligible entity cohort."""

    holders: list[EntityHolder] = field(default_factory=list)
    excluded: list[ExcludedHolder] = field(default_factory=list)
    collection: CollectionReport | None = None
    partial: bool = False


def proven_codeless_holders(
    session: Session,
    protocol_id: int,
    *,
    entity_keys: set[str] | None = None,
) -> tuple[list[EntityHolder], list[ExcludedHolder]]:
    """The protocol's proven-codeless principals, as observation subjects.

    The membership witness is the scorer's own
    :func:`services.scoring.planes.load_proven_eoa_entities` — imported here
    rather than re-expressed, because the producer's population and the plane's
    idea of "proven codeless" must be ONE predicate. ``resolved_type == 'eoa'``
    is only ever written after an empty ``eth_getCode``; a node that was never
    probed carries ``unknown`` and is not in this set, and treating it as an EOA
    would be a name standing in for a witness.

    Returns ``(holders, excluded)``. Nothing is dropped silently: an entity this
    producer cannot read is returned with the reason it cannot.
    """
    # Local import: the scorer reads the monitoring plane, so a module-level
    # import here would close the cycle. Nothing about the predicate is copied.
    from services.scoring.planes import load_proven_eoa_entities
    from services.scoring.schema import coalesce_chain
    from services.scoring.schema import entity_key as make_entity_key

    keys = sorted(load_proven_eoa_entities(session, protocol_id))
    if entity_keys is not None:
        wanted = {k.lower() for k in entity_keys}
        keys = [k for k in keys if k.lower() in wanted]

    # An address this protocol already has a ``contracts`` row for is observed
    # through that row. Two subjects reading one address would fold two accounts
    # onto one entity key, and the sheet's "every account scanned at itself"
    # conjunct would then be asking about an account that is the same account
    # twice.
    contract_keys = {
        make_entity_key(chain, address)
        for address, chain in session.execute(
            select(Contract.address, Contract.chain).where(Contract.protocol_id == protocol_id)
        ).all()
    }

    holders: list[EntityHolder] = []
    excluded: list[ExcludedHolder] = []
    for key in keys:
        chain, _, address = key.partition("::")
        if not address:
            excluded.append(ExcludedHolder(key, "entity key carries no address"))
            continue
        if key in contract_keys:
            excluded.append(ExcludedHolder(key, "already observed through its own contracts row"))
            continue
        try:
            chain_id = chain_id_for(chain)
        except Exception as exc:
            excluded.append(ExcludedHolder(key, f"no chain id for {chain!r}: {type(exc).__name__}"))
            continue
        if rpc_url_for_chain_id(chain_id) is None:
            excluded.append(ExcludedHolder(key, f"no RPC URL configured for chain {chain_id}"))
            continue
        holders.append(
            EntityHolder(
                subject=ObservationSubject.of_entity(coalesce_chain(chain), address),
                entity_key=key,
                chain=coalesce_chain(chain),
                chain_id=chain_id,
                address=address,
            )
        )
    return holders, excluded


def refresh_entity_balances(
    session: Session,
    protocol_id: int,
    *,
    entity_keys: set[str] | None = None,
) -> EntityObservationReport:
    """Same current-state collector; principal wealth never enters protocol TVL."""
    from sqlalchemy.orm import sessionmaker

    from services.monitoring.balance_collection import CollectionSubject, collect_balances
    from services.scoring.dirty import mark_protocol_score_dirty

    holders, excluded = proven_codeless_holders(session, protocol_id, entity_keys=entity_keys)
    report = EntityObservationReport(holders=holders, excluded=excluded)
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    session.commit()
    collected = collect_balances(
        [CollectionSubject(h.subject, h.chain_id) for h in holders],
        writer=BALANCE_WRITER_TVL,
        ttl=DEFAULT_ENTITY_BALANCE_INTERVAL,
        session_factory=factory,
    )
    report.collection = collected
    report.partial = bool(collected.failed or collected.partial or collected.deferred)
    if collected.committed:
        mark_protocol_score_dirty(session, protocol_id, "entity_balance_observation")
        session.commit()
    return report


def refresh_entity_balances_if_due(
    session: Session,
    protocol_id: int,
) -> EntityObservationReport:
    # Due eligibility is per physical holder/read class and last SUCCESS, not a
    # cohort aggregate that hides never-read holders or counts failed attempts.
    return refresh_entity_balances(session, protocol_id)


# ---------------------------------------------------------------------------
# Snapshot orchestration
# ---------------------------------------------------------------------------


def _read_existing_balances(session: Session, protocol_id: int) -> tuple[dict[str, dict], bool]:
    """Observed priced subsets with explicit age, coverage and valuation gaps."""
    from services.aggregations.company_overview.entity_keys import _entity_key
    from services.monitoring.balance_collection import FRESH_SECONDS
    from services.monitoring.balance_reads import latest_partial_asset_fetches, winning_asset_fetches

    contracts = _get_protocol_addresses(session, protocol_id)
    contract_ids = [c.id for c in contracts]
    missing = contracts_missing_current_rows(session, contract_ids)
    winners = winning_asset_fetches(session, protocol_id)
    prefixes = latest_partial_asset_fetches(session, protocol_id)
    rows_by_cid: dict[int, list[ContractBalanceLatest]] = {}
    for row in session.scalars(
        select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id.in_(contract_ids))
    ):
        if row.contract_id is not None:
            rows_by_cid.setdefault(row.contract_id, []).append(row)
    breakdown = {}
    partial = bool(missing)
    now = datetime.now(timezone.utc)
    for contract in contracts:
        rows = rows_by_cid.get(contract.id, [])
        if not rows:
            partial = True
            continue
        priced = [row for row in rows if row.usd_value is not None]
        unpriced = len(rows) - len(priced)
        times = [row.observed_at for row in rows if row.observed_at is not None]
        oldest = min(times) if times else None
        stale = oldest is None or len(times) != len(rows) or (now - oldest).total_seconds() > FRESH_SECONDS
        winner = winners.get(contract.id)
        incomplete = (
            contract.id in missing
            or contract.id in prefixes
            or winner is None
            or winner.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP
        )
        partial |= bool(incomplete or stale or unpriced)
        breakdown[_entity_key(contract.chain, contract.address)] = {
            "name": contract.contract_name,
            "total_usd": round(sum(float(r.usd_value or 0) for r in priced), 2) if priced else None,
            "tokens": [{"symbol": r.token_symbol, "usd_value": float(r.usd_value or 0)} for r in priced],
            "observed_at": oldest.isoformat() if oldest else None,
            "stale": stale,
            "partial": incomplete,
            "unpriced_count": unpriced,
            "coverage": "provider_observed_subset",
        }
    return breakdown, partial


def take_tvl_snapshot(
    session: Session,
    protocol_id: int,
    refresh_balances: bool = True,
    *,
    counters: dict[str, int] | None = None,
) -> tuple[TvlSnapshot | None, bool]:
    """Take a combined TVL snapshot for a protocol.

    1. Collects and commits current balances, or reads existing observations
       when *refresh_balances* is False.
    2. Fetches external DefiLlama TVL with no open database transaction.
       (used by the pipeline where the resolution stage already
       fetched them).
    3. Writes a ``TvlSnapshot`` row.

    Returns ``(snapshot, partial)``. ``snapshot`` is ``None`` (and no work is
    done) when a snapshot for this protocol already exists within the last
    ``MIN_SNAPSHOT_INTERVAL`` seconds. ``partial`` is True when the snapshot
    completed but some contract's value is missing from it — because its chain's
    native coin could not be priced, because a balance read failed
    (see :func:`refresh_contract_balances`), or, on the read-existing branch,
    because a contract has no non-failed fetch for some row class
    (see :func:`_read_existing_balances`). It is never hardcoded: a headline
    money figure that silently omits a contract must say so.
    """
    from datetime import datetime, timezone

    protocol = session.get(Protocol, protocol_id)
    if protocol is None:
        return None, False

    # Dedup guard — skip if a recent snapshot already exists
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=MIN_SNAPSHOT_INTERVAL)
    recent = session.execute(
        select(TvlSnapshot)
        .where(
            TvlSnapshot.protocol_id == protocol_id,
            TvlSnapshot.timestamp >= cutoff,
        )
        .limit(1)
    ).scalar_one_or_none()
    if recent is not None:
        logger.debug(
            "Skipping TVL snapshot for %s — last snapshot at %s is within %ds",
            protocol.name,
            recent.timestamp,
            MIN_SNAPSHOT_INTERVAL,
        )
        return None, False

    protocol_name = protocol.name
    session.commit()
    # Tier 2: on-chain per-contract
    if refresh_balances:
        contract_breakdown, partial = refresh_contract_balances(session, protocol_id, counters=counters)
    else:
        contract_breakdown, partial = _read_existing_balances(session, protocol_id)
    # Acquire external TVL after durable quantities, with no database transaction
    # held over the HTTP request. An external failure cannot undo balance work.
    session.commit()
    dl_result = fetch_defillama_tvl(protocol_name)
    dl_tvl = dl_result["tvl"] if dl_result else None
    chain_breakdown = dl_result["chain_breakdown"] if dl_result else None
    on_chain_total = sum(entry.get("total_usd") or 0 for entry in contract_breakdown.values())

    # Determine source and headline number
    if dl_tvl is not None and contract_breakdown:
        source = "both"
    elif dl_tvl is not None:
        source = "defillama"
    else:
        source = "on_chain"

    # Gross tracked holdings and external protocol TVL have different scopes.
    total_usd = (
        round(on_chain_total, 2) if any(e.get("total_usd") is not None for e in contract_breakdown.values()) else None
    )

    snapshot = TvlSnapshot(
        protocol_id=protocol_id,
        total_usd=total_usd,
        defillama_tvl=round(dl_tvl, 2) if dl_tvl is not None else None,
        chain_breakdown=chain_breakdown,
        contract_breakdown=contract_breakdown or None,
        source=source,
        holdings_observed_at=min(
            (datetime.fromisoformat(e["observed_at"]) for e in contract_breakdown.values() if e.get("observed_at")),
            default=None,
        ),
        holdings_partial=partial,
        valuation_partial=any(e.get("unpriced_count", 0) for e in contract_breakdown.values()),
    )
    session.add(snapshot)
    session.commit()
    session.refresh(snapshot)

    logger.info(
        "TVL snapshot for %s: on_chain=$%s defillama=$%s (%d contracts)",
        protocol_name,
        total_usd,
        dl_tvl,
        len(contract_breakdown),
    )
    return snapshot, partial


def refresh_all_protocols(session: Session) -> int:
    """Refresh a bounded slice in oldest-attempt order, including failed protocols.

    Recording attempts independently of snapshots prevents a persistent failure
    from monopolizing the front of every subsequent rotation.
    """
    started = time.monotonic()
    cap = int(os.getenv("PSAT_TVL_PROTOCOLS_PER_PASS", str(DEFAULT_TVL_PROTOCOLS_PER_PASS)))
    protocols = (
        session.execute(
            select(Protocol).order_by(Protocol.last_balance_attempt_at.asc().nullsfirst(), Protocol.id).limit(cap)
        )
        .scalars()
        .all()
    )
    count = 0
    failures = 0
    partials = 0
    # The cycle's own degradation tally, shared by every protocol in the slice:
    # what failed to be observed, once per cycle rather than once per contract.
    cycle_counts: dict[str, int] = {}
    identities = [(p.id, p.name) for p in protocols]
    session.commit()
    for protocol_id, protocol_name in identities:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            continue
        protocol.last_balance_attempt_at = datetime.now(timezone.utc)
        session.commit()
        try:
            with log_timed_phase(logger, "tvl_snapshot", protocol_id=protocol_id) as phase:
                snapshot, snapshot_partial = take_tvl_snapshot(session, protocol_id, counters=cycle_counts)
                phase["snapshot_written"] = snapshot is not None
                phase["partial"] = snapshot_partial
            if snapshot:
                count += 1
            if snapshot_partial:
                partials += 1
        except Exception as exc:
            failures += 1
            # Discard any partial writes the failed snapshot staged on the shared
            # session so they can't ride the next protocol's commit.
            session.rollback()
            logger.warning(
                "TVL snapshot failed for protocol %s: %s",
                protocol_name,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
        # The daily arm, after the snapshot and in a try of its own. These
        # holders are the protocol's principals, not its deployments: they
        # contribute nothing to the snapshot, so neither pass's failure may be
        # reported as the other's and the snapshot cycle's counters stay a
        # statement about the snapshot.
        try:
            entity_report = refresh_entity_balances_if_due(session, protocol_id)
            if entity_report is not None:
                collected = entity_report.collection
                if collected is not None:
                    for key in ("attempted", "reused", "deferred", "committed", "failed", "partial"):
                        name = f"entity_{key}"
                        cycle_counts[name] = cycle_counts.get(name, 0) + getattr(collected, key)
                logger.info(
                    "entity balance collection complete",
                    extra={
                        "protocol_id": protocol_id,
                        "holders": len(entity_report.holders),
                        "excluded": len(entity_report.excluded),
                        "partial": entity_report.partial,
                    },
                )
        except Exception as exc:
            session.rollback()
            cycle_counts["entity_passes_failed"] = cycle_counts.get("entity_passes_failed", 0) + 1
            logger.warning(
                "entity balance refresh failed for protocol %s: %s",
                protocol_name,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
    from services.effects.balance_dependencies import reconcile_pending_effects

    for protocol_id, _name in identities:
        reconcile_pending_effects(session, protocol_id=protocol_id)
    session.commit()
    # One unconditional per-cycle summary even when nothing snapshotted, so a
    # wedged TVL tracker is detectable. ``contracts_scanned`` carries the
    # protocol count (TVL has no block range -> ``blocks_scanned=0``);
    # ``events_found`` is snapshots written. Cycle is partial if a protocol
    # raised OR a snapshot completed with a contract skipped for want of a
    # native-coin price.
    notes = []
    if failures:
        notes.append(f"{failures}_failed")
    if partials:
        notes.append(f"{partials}_partial")
    emit_monitor_cycle(
        HEARTBEAT_PROTOCOL_TVL,
        started=started,
        contracts_scanned=len(protocols),
        blocks_scanned=0,
        events_found=count,
        partial=failures > 0 or partials > 0,
        note=",".join(notes) if notes else None,
        # Distinguish durable progress, retries and incomplete observations.
        extra_detail={"protocols_failed": failures, "protocols_partial": partials, **cycle_counts},
    )
    return count


# ---------------------------------------------------------------------------
# Loop
# ---------------------------------------------------------------------------


def run_tvl_loop(interval: float = DEFAULT_TVL_INTERVAL, stop_event: Event | None = None) -> None:
    """Run the TVL tracking loop.

    ``stop_event`` (supplied by the thread supervisor) breaks the inter-pass
    wait mid-interval on shutdown; omitting it keeps the original
    blocking-forever behaviour.
    """
    stop_event = stop_event or Event()
    logger.info("Starting TVL tracker (interval=%ss)", interval)
    while not stop_event.is_set():
        try:
            with SessionLocal() as session:
                count = refresh_all_protocols(session)
                if count:
                    logger.info("TVL refresh complete: %d protocol(s) snapshotted", count)
        except Exception as exc:
            logger.warning("TVL refresh cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
            # ``refresh_all_protocols`` raised before it could emit its own
            # cycle summary — still beat so the fleet view sees a degraded cycle.
            record_heartbeat(
                HEARTBEAT_PROTOCOL_TVL,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        stop_event.wait(interval)
