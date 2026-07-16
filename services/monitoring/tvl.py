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
from pathlib import Path
from threading import Event

import requests
from dotenv import load_dotenv
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractBalance,
    Protocol,
    SessionLocal,
    TvlSnapshot,
)
from db.queue import record_heartbeat
from services.monitoring import HEARTBEAT_PROTOCOL_TVL, emit_monitor_cycle
from services.monitoring.chain_rpc import chain_id_for

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)

DEFAULT_TVL_INTERVAL = int(os.getenv("PROTOCOL_TVL_INTERVAL", "3600"))
# Minimum seconds between snapshots for the same protocol.  Prevents
# duplicate rows when the loop is retriggered quickly (restart, signal, etc.).
MIN_SNAPSHOT_INTERVAL = int(os.getenv("PROTOCOL_TVL_MIN_INTERVAL", "300"))
# Protocols refreshed per tick, oldest-snapshot-first — bounds the per-tick
# Etherscan/DefiLlama fan-out (design §2.7).
DEFAULT_TVL_PROTOCOLS_PER_PASS = 10
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
        tvl = tvl[-1].get("totalLiquidityUSD") if tvl else None
    elif not isinstance(tvl, (int, float)):
        tvl = None

    chain_breakdown = data.get("currentChainTvls")
    if not isinstance(chain_breakdown, dict):
        chain_breakdown = {}

    # Filter out borrowed/staking/pool2 keys — keep only chain names
    chain_breakdown = {
        k: v
        for k, v in chain_breakdown.items()
        if not any(k.lower().startswith(p) for p in ("borrowed", "staking", "pool2")) and isinstance(v, (int, float))
    }

    return {
        "tvl": float(tvl) if tvl is not None else None,
        "chain_breakdown": chain_breakdown,
    }


# ---------------------------------------------------------------------------
# On-chain balance refresh
# ---------------------------------------------------------------------------


def _get_protocol_addresses(session: Session, protocol_id: int) -> list[Contract]:
    """Return contracts to fetch balances for, excluding implementation-behind-proxy."""
    contracts = session.execute(select(Contract).where(Contract.protocol_id == protocol_id)).scalars().all()

    # Build set of implementation addresses that sit behind a proxy
    impl_addresses: set[str] = set()
    for c in contracts:
        if c.is_proxy and c.implementation:
            impl_addresses.add(c.implementation.lower())

    # Keep proxy contracts (they hold the funds) and non-impl regular contracts
    return [c for c in contracts if c.address and c.address.lower() not in impl_addresses]


def refresh_contract_balances(
    session: Session,
    protocol_id: int,
) -> dict[str, dict]:
    """Refresh on-chain balances for all contracts in a protocol.

    Updates ``contract_balances`` rows (latest state) and returns a
    per-contract breakdown dict for the snapshot.
    """
    from utils.etherscan import get_eth_balance, get_eth_price, get_token_balances

    contracts = _get_protocol_addresses(session, protocol_id)
    if not contracts:
        return {}

    # Fetch ETH price once for all contracts
    eth_price: float | None = None
    try:
        eth_price = get_eth_price()
    except Exception as exc:
        logger.warning(
            "ETH price fetch failed: %s — ETH balances will not include USD values for %d contract(s)",
            exc,
            len(contracts),
        )

    breakdown: dict[str, dict] = {}

    for contract in contracts:
        address = contract.address
        # Query each contract's balances on its OWN chain (inv. 8). Mainnet
        # contracts resolve to chain_id 1 — unchanged; a legacy NULL chain also
        # maps to 1 until the M1.2 fail-loud flip.
        chain_id = chain_id_for(contract.chain)
        contract_total = 0.0
        tokens: list[dict] = []

        try:
            eth_wei = get_eth_balance(address, chain_id=chain_id)
        except Exception as exc:
            logger.warning("ETH balance failed for %s: %s", address, exc)
            eth_wei = 0

        try:
            token_list = get_token_balances(address, chain_id=chain_id)
        except Exception as exc:
            logger.warning("Token balance failed for %s: %s", address, exc)
            token_list = []

        # Clear old balances for this contract
        session.query(ContractBalance).filter(ContractBalance.contract_id == contract.id).delete()

        # Native ETH
        if eth_wei > 0:
            eth_usd = (eth_wei / 1e18) * eth_price if eth_price else None
            session.add(
                ContractBalance(
                    contract_id=contract.id,
                    token_address=None,
                    token_name="Ether",
                    token_symbol="ETH",
                    decimals=18,
                    raw_balance=str(eth_wei),
                    price_usd=eth_price,
                    usd_value=round(eth_usd, 2) if eth_usd else None,
                )
            )
            if eth_usd:
                contract_total += eth_usd
                tokens.append({"symbol": "ETH", "usd_value": round(eth_usd, 2)})

        # ERC-20 tokens
        for tok in token_list:
            session.add(
                ContractBalance(
                    contract_id=contract.id,
                    token_address=tok["token_address"],
                    token_name=tok["token_name"],
                    token_symbol=tok["token_symbol"],
                    decimals=tok["decimals"],
                    raw_balance=str(tok["balance"]),
                    price_usd=tok.get("price_usd"),
                    usd_value=tok.get("usd_value"),
                )
            )
            usd = tok.get("usd_value")
            if usd:
                contract_total += usd
                tokens.append(
                    {
                        "symbol": tok["token_symbol"],
                        "usd_value": round(usd, 2),
                    }
                )

        breakdown[address.lower()] = {
            "name": contract.contract_name,
            "total_usd": round(contract_total, 2),
            "tokens": tokens,
        }

    session.commit()
    return breakdown


# ---------------------------------------------------------------------------
# Snapshot orchestration
# ---------------------------------------------------------------------------


def _read_existing_balances(session: Session, protocol_id: int) -> dict[str, dict]:
    """Build a contract breakdown from existing ``contract_balances`` rows.

    Used by the pipeline snapshot to avoid re-fetching from Etherscan —
    the resolution stage already wrote these rows minutes earlier.
    """
    contracts = _get_protocol_addresses(session, protocol_id)
    if not contracts:
        return {}
    contract_ids = [c.id for c in contracts]
    rows_by_cid: dict[int, list[ContractBalance]] = {}
    for b in session.execute(select(ContractBalance).where(ContractBalance.contract_id.in_(contract_ids))).scalars():
        rows_by_cid.setdefault(b.contract_id, []).append(b)
    breakdown: dict[str, dict] = {}
    for contract in contracts:
        contract_total = 0.0
        tokens: list[dict] = []
        for b in rows_by_cid.get(contract.id, []):
            usd = float(b.usd_value) if b.usd_value is not None else None
            if usd:
                contract_total += usd
                tokens.append({"symbol": b.token_symbol, "usd_value": round(usd, 2)})
        breakdown[contract.address.lower()] = {
            "name": contract.contract_name,
            "total_usd": round(contract_total, 2),
            "tokens": tokens,
        }
    return breakdown


def take_tvl_snapshot(
    session: Session,
    protocol_id: int,
    refresh_balances: bool = True,
) -> TvlSnapshot | None:
    """Take a combined TVL snapshot for a protocol.

    1. Fetches DefiLlama TVL (non-fatal if unavailable).
    2. Refreshes on-chain balances via Etherscan, or reads existing
       ``contract_balances`` rows when *refresh_balances* is False
       (used by the pipeline where the resolution stage already
       fetched them).
    3. Writes a ``TvlSnapshot`` row.

    Returns ``None`` (and skips work) if a snapshot for this protocol
    already exists within the last ``MIN_SNAPSHOT_INTERVAL`` seconds.
    """
    from datetime import datetime, timedelta, timezone

    protocol = session.get(Protocol, protocol_id)
    if protocol is None:
        return None

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
        return None

    # Tier 1: DefiLlama
    dl_result = fetch_defillama_tvl(protocol.name)
    dl_tvl = dl_result["tvl"] if dl_result else None
    chain_breakdown = dl_result["chain_breakdown"] if dl_result else None

    # Tier 2: on-chain per-contract
    if refresh_balances:
        contract_breakdown = refresh_contract_balances(session, protocol_id)
    else:
        contract_breakdown = _read_existing_balances(session, protocol_id)
    on_chain_total = sum(entry.get("total_usd", 0) for entry in contract_breakdown.values())

    # Determine source and headline number
    if dl_tvl is not None and contract_breakdown:
        source = "both"
    elif dl_tvl is not None:
        source = "defillama"
    else:
        source = "on_chain"

    # Use on-chain total as the primary TVL (it's our ground truth from
    # the actual contracts we track). DefiLlama TVL stored separately for
    # comparison.
    total_usd = round(on_chain_total, 2) if on_chain_total > 0 else None

    snapshot = TvlSnapshot(
        protocol_id=protocol_id,
        total_usd=total_usd,
        defillama_tvl=round(dl_tvl, 2) if dl_tvl else None,
        chain_breakdown=chain_breakdown,
        contract_breakdown=contract_breakdown or None,
        source=source,
    )
    session.add(snapshot)
    session.commit()
    session.refresh(snapshot)

    logger.info(
        "TVL snapshot for %s: on_chain=$%s defillama=$%s (%d contracts)",
        protocol.name,
        total_usd,
        dl_tvl,
        len(contract_breakdown),
    )
    return snapshot


def refresh_all_protocols(session: Session) -> int:
    """Take TVL snapshots for the oldest-snapshot-first rotation slice.

    Each tick refreshes at most ``PSAT_TVL_PROTOCOLS_PER_PASS`` protocols,
    ordered by their most recent snapshot ascending — protocols that have
    never been snapshotted sort first. ``take_tvl_snapshot``'s
    ``MIN_SNAPSHOT_INTERVAL`` dedupe still short-circuits a protocol snapshotted
    too recently, so the slice self-corrects if the rotation revisits one early.
    Returns count of snapshots written.
    """
    started = time.monotonic()
    cap = int(os.getenv("PSAT_TVL_PROTOCOLS_PER_PASS", str(DEFAULT_TVL_PROTOCOLS_PER_PASS)))
    latest_snapshot = (
        select(TvlSnapshot.protocol_id, func.max(TvlSnapshot.timestamp).label("last_ts"))
        .group_by(TvlSnapshot.protocol_id)
        .subquery()
    )
    protocols = (
        session.execute(
            select(Protocol)
            .outerjoin(latest_snapshot, Protocol.id == latest_snapshot.c.protocol_id)
            .order_by(latest_snapshot.c.last_ts.asc().nullsfirst())
            .limit(cap)
        )
        .scalars()
        .all()
    )
    count = 0
    failures = 0
    for protocol in protocols:
        try:
            snapshot = take_tvl_snapshot(session, protocol.id)
            if snapshot:
                count += 1
        except Exception as exc:
            failures += 1
            logger.warning(
                "TVL snapshot failed for protocol %s: %s",
                protocol.name,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
    # One unconditional per-cycle summary even when nothing snapshotted, so a
    # wedged TVL tracker is detectable. ``contracts_scanned`` carries the
    # protocol count (TVL has no block range -> ``blocks_scanned=0``);
    # ``events_found`` is snapshots written; any per-protocol failure -> partial.
    emit_monitor_cycle(
        HEARTBEAT_PROTOCOL_TVL,
        started=started,
        contracts_scanned=len(protocols),
        blocks_scanned=0,
        events_found=count,
        partial=failures > 0,
        note=f"{failures}_failed" if failures else None,
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
