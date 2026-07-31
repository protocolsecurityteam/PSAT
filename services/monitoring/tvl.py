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
    ContractBalanceFetch,
    ContractBalanceLatest,
    Protocol,
    SessionLocal,
    TvlSnapshot,
)
from db.queue import record_heartbeat
from services.monitoring import HEARTBEAT_PROTOCOL_TVL, emit_monitor_cycle
from services.monitoring.balance_reads import (
    contracts_missing_current_rows,
    native_status_for,
    pinned_native_balances,
    prune_balance_fetches,
)
from services.monitoring.chain_rpc import chain_id_for
from utils.balance_status import (
    ASSET_SET_STATUS_FETCH_FAILED,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
)
from utils.chains import chain_by_id
from utils.etherscan import TokenBalancePage

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
    from services.aggregations.company_overview import _entity_key

    contracts = session.execute(select(Contract).where(Contract.protocol_id == protocol_id)).scalars().all()

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
    return [c for c in contracts if c.address and _entity_key(c.chain, c.address) not in impl_tokens]


def refresh_contract_balances(
    session: Session,
    protocol_id: int,
) -> tuple[dict[str, dict], bool]:
    """Refresh on-chain balances for all contracts in a protocol.

    Updates ``contract_balances`` rows (latest state) and returns
    ``(breakdown, partial)`` — the per-contract breakdown dict for the snapshot
    (keyed by the composite ``"<chain>::<address>"`` entity token so a CREATE2
    twin across two chains keeps a distinct entry), and whether pricing was
    degraded this cycle: a non-ETH contract skipped for want of its native-coin
    quote, OR an ETH-native balance written with a NULL price because the upfront
    mainnet ETH/USD quote failed.

    Native-asset USD pricing dispatch (inv. 5): a contract's native gas balance
    is valued in its OWN chain's native coin — a registry fact (``native_asset``)
    — never assumed to be ETH. ETH-native chains (mainnet, the OP-stack L2s, and
    a legacy NULL chain that coalesces to mainnet) reuse a single mainnet ETH/USD
    quote fetched once below. A non-ETH-native chain (POL, BNB, AVAX, ...) is
    priced per-chain via ``get_native_price``; if that quote is unavailable the
    contract is SKIPPED (its prior balances left intact, ``partial`` flagged) —
    we never quote a non-ETH balance at the ETH price, and one unpriceable chain
    no longer aborts the whole protocol's snapshot.
    """
    from services.aggregations.company_overview import _entity_key
    from utils.etherscan import get_eth_balance, get_eth_price, get_native_price, get_token_balances_page

    contracts = _get_protocol_addresses(session, protocol_id)
    if not contracts:
        return {}, False

    # One pinned native read per chain, BEFORE the per-contract loop. This is
    # what makes a zero publishable: ``getEthBalance`` answered 0 AT a named
    # height. Etherscan's ``account/balance`` is ``tag=latest`` and its response
    # carries no height, so a zero from it can only ever be not_determined.
    # Failure here is not fatal — it drops the cycle back to the unpinned path,
    # which is strictly weaker and never wrong.
    pinned_by_chain: dict[int, tuple[int | None, dict[str, int]]] = {}
    for chain_id in sorted({chain_id_for(c.chain) for c in contracts}):
        addresses = [c.address for c in contracts if chain_id_for(c.chain) == chain_id and c.address]
        pinned_by_chain[chain_id] = pinned_native_balances(addresses, chain_id=chain_id)

    # Fetch the mainnet ETH/USD quote once for every ETH-native contract. ETH/USD
    # is an L1-scoped quote reused for the ETH-native L2s too (their ETH balance
    # is L1 ETH); an explicit, documented mainnet read, not a silent default.
    eth_price: float | None = None
    try:
        eth_price = get_eth_price(chain_id=1)
    except Exception as exc:
        logger.warning(
            "ETH price fetch failed: %s — ETH balances will not include USD values for %d contract(s)",
            exc,
            len(contracts),
        )

    # Non-ETH native quotes are fetched at most once per chain and cached; a cached
    # None marks a chain whose native coin could not be priced this cycle.
    native_price_by_chain: dict[int, float | None] = {}
    breakdown: dict[str, dict] = {}
    partial = False

    for contract in contracts:
        address = contract.address
        # Query each contract's balances on its OWN chain (inv. 8). Mainnet
        # contracts resolve to chain_id 1 — unchanged; a legacy NULL chain also
        # maps to 1 until the M1.2 fail-loud flip.
        chain_id = chain_id_for(contract.chain)
        native_asset = chain_by_id(chain_id).native_asset

        # Resolve the native-coin USD quote and the symbol/name to record it under
        # BEFORE touching this contract's stored balances, so an unpriceable chain
        # is skipped with its prior rows intact rather than wiped-and-unwritten.
        if native_asset == "ETH":
            native_price = eth_price
            native_symbol, native_name = "ETH", "Ether"
            if native_price is None:
                # Upfront mainnet ETH/USD quote unavailable this cycle. Unlike the
                # non-ETH branch we do NOT skip — ETH rows are still written with
                # NULL prices (prior behavior) — but we flag the cycle partial so
                # the degraded valuation is operator-visible, symmetric with the
                # non-ETH skip-and-flag path below.
                partial = True
        else:
            if chain_id not in native_price_by_chain:
                try:
                    native_price_by_chain[chain_id] = get_native_price(chain_id)
                except Exception as exc:
                    logger.warning(
                        "Native price fetch failed for chain %s (%s): %s — skipping %s",
                        chain_id,
                        native_asset,
                        exc,
                        address,
                    )
                    native_price_by_chain[chain_id] = None
            native_price = native_price_by_chain[chain_id]
            if native_price is None:
                # No USD quote for this non-ETH native coin this cycle. Refuse to
                # quote its balance at any other asset's price; skip the contract
                # (prior balances untouched) and flag the cycle partial.
                partial = True
                continue
            native_symbol, native_name = native_asset, native_asset

        contract_total = 0.0
        tokens: list[dict] = []

        # This writer reads the contract's OWN address and never a proxy address
        # (unlike the resolution worker, which reads ``request['proxy_address']``);
        # ``_get_protocol_addresses`` has already excluded impls fronted by a
        # proxy. Captured verbatim so the row records which address the quantity
        # actually belongs to instead of leaving it to be re-derived.
        observed_address = address
        pinned_block, pinned_wei = pinned_by_chain.get(chain_id, (None, {}))

        eth_wei: int | None
        if pinned_block is not None and address.lower() in pinned_wei:
            eth_wei = pinned_wei[address.lower()]
            native_block: int | None = pinned_block
            native_failed = False
        else:
            native_block = None
            try:
                eth_wei = get_eth_balance(address, chain_id=chain_id)
                native_failed = False
            except Exception as exc:
                # The swallow this replaces set ``eth_wei = 0`` and left no
                # persisted trace of any kind, so a failed read and a real zero
                # were the same absent row. The quantity stays unknown and the
                # fetch row records why.
                logger.warning("ETH balance failed for %s: %s", address, exc)
                eth_wei = None
                native_failed = True

        try:
            page = get_token_balances_page(address, chain_id=chain_id)
        except Exception as exc:
            # The second swallow: ``token_list = []`` followed by a destructive
            # DELETE published "holds no tokens" from a failed fetch. Note the
            # common Etherscan failure never reaches here at all — it is caught
            # one layer down and returns an empty page carrying ``fetch_failed``.
            logger.warning("Token balance failed for %s: %s", address, exc)
            page = TokenBalancePage(rows=[], page_length=None, status=ASSET_SET_STATUS_FETCH_FAILED)
        token_list = page.rows

        native_status = native_status_for(wei=eth_wei, pinned=native_block is not None, failed=native_failed)
        fetch = ContractBalanceFetch(
            contract_id=contract.id,
            chain_id=chain_id,
            observed_address=observed_address,
            block_number=native_block,
            native_status=native_status,
            asset_set_status=page.status,
            asset_page_length=page.page_length,
            writer=BALANCE_WRITER_TVL,
        )
        session.add(fetch)
        session.flush()

        # No DELETE. The writers are insert-only and ``contract_balances_latest``
        # decides what is current, per row class, so a failed fetch can no longer
        # wipe a holdings set it knows nothing about.

        # Native coin (ETH / POL / BNB / ... — symbol is the chain's native_asset)
        if eth_wei is not None and eth_wei > 0:
            eth_usd = (eth_wei / 1e18) * native_price if native_price else None
            session.add(
                ContractBalance(
                    contract_id=contract.id,
                    token_address=None,
                    token_name=native_name,
                    token_symbol=native_symbol,
                    decimals=18,
                    raw_balance=str(eth_wei),
                    price_usd=native_price,
                    usd_value=round(eth_usd, 2) if eth_usd else None,
                    observed_address=observed_address,
                    block_number=native_block,
                    fetch_id=fetch.id,
                )
            )
            if eth_usd:
                contract_total += eth_usd
                tokens.append({"symbol": native_symbol, "usd_value": round(eth_usd, 2)})

        # ERC-20 tokens. ``block_number`` stays NULL here even when the native
        # read above was pinned: these quantities come from Etherscan's unpinned
        # page, and inheriting the fetch's native height would assert a height
        # they were never read at. DB-enforced by
        # ``ck_contract_balances_token_block_null``.
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
                    observed_address=observed_address,
                    block_number=None,
                    fetch_id=fetch.id,
                )
            )
            usd = tok.get("usd_value")
            if usd is not None:
                contract_total += usd
                tokens.append(
                    {
                        "symbol": tok["token_symbol"],
                        "usd_value": round(usd, 2),
                    }
                )

        # Whether a total over this contract measures anything. Same rule as the
        # sibling read-existing branch (``_read_existing_balances`` via
        # ``contracts_missing_current_rows``): a contract with no publishable
        # figure for some row class is OMITTED and flips ``partial``, rather than
        # emitted as ``total_usd: 0.0``. The zero is indistinguishable from a
        # measured empty contract once it reaches ``TvlSnapshot.total_usd`` and
        # the served breakdown, so publishing it turns a failed read into a
        # lower money figure while the cycle looks complete.
        #
        # Unpriced counts as unpublishable for the same reason a failed read
        # does: holdings we could not value are not holdings worth 0. Only the
        # native class is checked for it here — the ETH branch above keeps
        # writing NULL-priced rows (its non-ETH twin skips the contract
        # outright), so this is where that asymmetry stops being published as a
        # number. Individual unpriced ERC-20s are NOT covered; that would need a
        # per-token witness this loop does not have.
        native_class_failed = native_status == NATIVE_STATUS_FETCH_FAILED
        assets_class_failed = page.status == ASSET_SET_STATUS_FETCH_FAILED
        native_unpriced = native_price is None and eth_wei is not None and eth_wei > 0
        if native_class_failed or assets_class_failed or native_unpriced:
            partial = True
        else:
            # Composite entity token ("<chain>::<address>") so a CREATE2 twin —
            # the same address on two of the protocol's chains — keeps a distinct
            # entry instead of colliding under a bare address (last-wins would
            # drop one chain's balance and under-count on_chain_total).
            breakdown[_entity_key(contract.chain, address)] = {
                "name": contract.contract_name,
                "total_usd": round(contract_total, 2),
                "tokens": tokens,
            }
        # A failed read is a degraded cycle, and this loop has no
        # ``record_degraded`` available (it runs outside ``BaseWorker``, where
        # that call is a no-op). The persisted fetch row is the durable trace;
        # this flag is what carries it into the per-cycle heartbeat, and the log
        # below is unconditional so a failure is visible even without the DB.
        if native_class_failed or assets_class_failed:
            logger.info(
                "balance fetch degraded for %s on chain %s: native=%s assets=%s",
                observed_address,
                chain_id,
                native_status,
                page.status,
            )
        elif native_unpriced:
            logger.info(
                "balance omitted from breakdown for %s on chain %s: native quantity unpriced",
                observed_address,
                chain_id,
            )

        prune_balance_fetches(session, contract.id, observed_address)

    session.commit()
    return breakdown, partial


# ---------------------------------------------------------------------------
# Snapshot orchestration
# ---------------------------------------------------------------------------


def _read_existing_balances(session: Session, protocol_id: int) -> tuple[dict[str, dict], bool]:
    """Build a contract breakdown from the CURRENT ``contract_balances`` rows.

    Used by the pipeline snapshot to avoid re-fetching from Etherscan — the
    resolution stage already wrote these rows minutes earlier.

    Reads ``contract_balances_latest``, not the base table: the writers are
    insert-only now, so the base table carries every past cycle and summing it
    would add the same holding once per hour.

    Returns ``(breakdown, partial)``. A contract whose current holdings the view
    cannot publish — no non-failed fetch for some row class — is OMITTED from
    the breakdown rather than emitted with ``total_usd: 0.0``, and flips
    ``partial``. Emitting the zero would push a failed read into
    ``TvlSnapshot.total_usd`` as a lower money figure while the cycle reported
    itself complete: an absence turned into a number.
    """
    from services.aggregations.company_overview import _entity_key

    contracts = _get_protocol_addresses(session, protocol_id)
    if not contracts:
        return {}, False
    contract_ids = [c.id for c in contracts]
    missing = contracts_missing_current_rows(session, contract_ids)
    rows_by_cid: dict[int, list[ContractBalanceLatest]] = {}
    for b in session.execute(
        select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id.in_(contract_ids))
    ).scalars():
        rows_by_cid.setdefault(b.contract_id, []).append(b)
    breakdown: dict[str, dict] = {}
    for contract in contracts:
        if contract.id in missing:
            continue
        contract_total = 0.0
        tokens: list[dict] = []
        for b in rows_by_cid.get(contract.id, []):
            usd = float(b.usd_value) if b.usd_value is not None else None
            if usd is not None:
                contract_total += usd
                tokens.append({"symbol": b.token_symbol, "usd_value": round(usd, 2)})
        # Composite entity token — see the twin-collapse note in
        # ``refresh_contract_balances``.
        breakdown[_entity_key(contract.chain, contract.address)] = {
            "name": contract.contract_name,
            "total_usd": round(contract_total, 2),
            "tokens": tokens,
        }
    return breakdown, bool(missing)


def take_tvl_snapshot(
    session: Session,
    protocol_id: int,
    refresh_balances: bool = True,
) -> tuple[TvlSnapshot | None, bool]:
    """Take a combined TVL snapshot for a protocol.

    1. Fetches DefiLlama TVL (non-fatal if unavailable).
    2. Refreshes on-chain balances via Etherscan, or reads existing
       ``contract_balances`` rows when *refresh_balances* is False
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
    from datetime import datetime, timedelta, timezone

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

    # Tier 1: DefiLlama
    dl_result = fetch_defillama_tvl(protocol.name)
    dl_tvl = dl_result["tvl"] if dl_result else None
    chain_breakdown = dl_result["chain_breakdown"] if dl_result else None

    # Tier 2: on-chain per-contract
    if refresh_balances:
        contract_breakdown, partial = refresh_contract_balances(session, protocol_id)
    else:
        contract_breakdown, partial = _read_existing_balances(session, protocol_id)
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
    return snapshot, partial


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
    partials = 0
    for protocol in protocols:
        try:
            snapshot, snapshot_partial = take_tvl_snapshot(session, protocol.id)
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
                protocol.name,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
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
