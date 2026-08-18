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
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractBalanceFetch,
    ContractBalanceLatest,
    Protocol,
    SessionLocal,
    TvlSnapshot,
)
from db.queue import record_heartbeat
from services.monitoring import HEARTBEAT_PROTOCOL_TVL, emit_monitor_cycle, warn_degraded_once
from services.monitoring.asset_sweep import SweepCost, SweepOutcome
from services.monitoring.balance_observation import (
    NativeReading,
    RecordedObservation,
    SweepRequest,
    escalation_reason,
    fetch_asset_page,
    known_swept_assets,
    known_typed_assets,
    record_observation,
    run_sweeps,
    scanned_from_block,
    sweep_from_block,
)
from services.monitoring.balance_reads import (
    ObservationSubject,
    contracts_missing_current_rows,
    pinned_native_balances,
)
from services.monitoring.chain_rpc import chain_id_for
from services.monitoring.delivery_shape import (
    discovered_request,
    disposition_requests,
    run_disposition,
)
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
    SWEEP_STATUS_COMPLETED,
)
from utils.chains import chain_by_id
from utils.etherscan import TokenBalancePage
from utils.logging import log_timed_phase
from utils.rpc import rpc_url_for_chain_id

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger(__name__)

DEFAULT_TVL_INTERVAL = int(os.getenv("PROTOCOL_TVL_INTERVAL", "3600"))
# Minimum seconds between snapshots for the same protocol.  Prevents
# duplicate rows when the loop is retriggered quickly (restart, signal, etc.).
MIN_SNAPSHOT_INTERVAL = int(os.getenv("PROTOCOL_TVL_MIN_INTERVAL", "300"))
# Protocols refreshed per tick, oldest-snapshot-first — bounds the per-tick
# Etherscan/DefiLlama fan-out (design §2.7).
DEFAULT_TVL_PROTOCOLS_PER_PASS = 10
# How stale the entity cohort's reading may get before the cycle re-reads it.
# Deliberately a day rather than the TVL tick: these holders are the protocol's
# signers and capability principals, not its deployments, and their scan is
# batched — N holders sharing a cursor cost the same windows as one — so the
# cadence, not the population, is what the spend is bought with.
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
    """Return contracts to fetch balances for, excluding implementation-behind-proxy.

    With TWO exceptions, and both are correctness exceptions rather than
    conveniences. The value plane folds an implementation's rows onto its
    proxy's key, so the two addresses are ONE sheet — and every claim that sheet
    makes about its asset list is a claim about both addresses, which nothing
    could earn while nothing was ever allowed to read the implementation.

    1. **Stuck at the page cap.** An excluded implementation row whose CURRENT
       asset fetch says ``at_page_cap`` is a permanently stuck truncation: that
       stale prefix keeps the proxy's sheet marked incomplete, and refuses it a
       ceiling, no matter how many times the proxy itself is re-observed.
    2. **Folded into a sheet that is proving itself whole.** Where the entity an
       implementation folds onto carries a completed chain-log scan, that sheet
       is trying to publish an asset list as COMPLETE — and it may only do so
       where every account it sums was scanned at its own address. Without this,
       the implementation's address is never read, the sheet can never be shown
       whole, and the honest outcome is a permanent not_determined on entities
       whose proxies swept clean. Re-observed every cycle rather than once: the
       scan is incremental behind ``swept_through_block`` (about one request),
       and a cursor that stops advancing is what makes a completeness claim go
       stale without saying so.
    """
    from services.aggregations.company_overview import _entity_key
    from services.monitoring.balance_reads import winning_asset_fetches

    contracts = session.execute(select(Contract).where(Contract.protocol_id == protocol_id)).scalars().all()
    winning = winning_asset_fetches(session, protocol_id)
    stuck_at_cap = {
        contract_id for contract_id, fetch in winning.items() if fetch.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP
    }
    by_id = {c.id: c for c in contracts}
    scanning_entities = {
        _entity_key(by_id[contract_id].chain, by_id[contract_id].address)
        for contract_id, fetch in winning.items()
        if contract_id in by_id
        and fetch.asset_set_source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP
        and fetch.sweep_status == SWEEP_STATUS_COMPLETED
        and fetch.swept_through_block is not None
    }
    folded_into_a_scanning_sheet = {
        c.id
        for c in contracts
        if c.is_proxy and c.implementation and _entity_key(c.chain, c.address) in scanning_entities
    }
    # The IMPLEMENTATION rows of those proxies, matched the same chain-scoped way
    # the exclusion below is built.
    scanning_impl_tokens = {
        _entity_key(by_id[cid].chain, by_id[cid].implementation) for cid in folded_into_a_scanning_sheet
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
            or _entity_key(c.chain, c.address) in scanning_impl_tokens
        )
    ]


@dataclass(frozen=True)
class _PendingObservation:
    """One contract read but not yet written, held over the escalation pass."""

    contract: Contract
    chain_id: int
    native: NativeReading
    page: TokenBalancePage
    escalation: str | None

    @property
    def subject(self) -> ObservationSubject:
        return ObservationSubject.of_contract(self.contract)


def refresh_contract_balances(
    session: Session,
    protocol_id: int,
    *,
    contract_ids: set[int] | None = None,
    counters: dict[str, int] | None = None,
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

    ``counters`` is the CYCLE's tally, threaded in by ``refresh_all_protocols``
    so the per-cycle heartbeat can carry what this pass degraded (failed sweeps,
    failed balance classes, unpriced natives). This loop runs outside
    ``BaseWorker``, so it is the substitute for the job-scoped accumulator.

    ``contract_ids`` narrows the pass to a named subset. It only ever INTERSECTS
    the population ``_get_protocol_addresses`` returns — it cannot admit a
    contract the unscoped pass would skip — so a targeted re-observation reads
    exactly what the hourly loop would have read for those contracts and nothing
    else. The returned breakdown is then partial by construction and is not a
    protocol total, so a caller that snapshots TVL leaves it ``None``.
    """
    from services.aggregations.company_overview import _entity_key
    from utils.etherscan import get_eth_balance, get_eth_price, get_native_price

    counts = counters if counters is not None else {}
    contracts = _get_protocol_addresses(session, protocol_id)
    if contract_ids is not None:
        contracts = [c for c in contracts if c.id in contract_ids]
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
    # Read first, escalate once, write after: the sweep is batched across the
    # whole cycle, so the per-contract reads cannot also be the per-contract
    # writes.
    pending: list[_PendingObservation] = []

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

        # Every writer reads the contract's OWN address — the one
        # ``observed_address`` policy, which lives in
        # ``balance_observation.record_observation`` so neither producer can
        # drift from it.
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

        page = fetch_asset_page(address, chain_id=chain_id)
        escalation = escalation_reason(session, subject=ObservationSubject.of_contract(contract), page=page)
        pending.append(
            _PendingObservation(
                contract=contract,
                chain_id=chain_id,
                native=NativeReading(
                    wei=eth_wei,
                    block_number=native_block,
                    failed=native_failed,
                    price_usd=native_price,
                    symbol=native_symbol,
                    name=native_name,
                ),
                page=page,
                escalation=escalation,
            )
        )

    # ONE escalation pass for the whole cycle, batched per chain. Per-contract
    # scans would multiply the request count by the number of candidates: the
    # recipient filter is an OR-set in one topic position, so a batch of holders
    # costs the same windows as a single holder.
    sweep_requests = [
        SweepRequest(
            subject=p.subject,
            address=p.contract.address,
            chain_id=p.chain_id,
            from_block=sweep_from_block(session, subject=p.subject),
            reason=p.escalation,
            known_assets=known_swept_assets(session, subject=p.subject),
            known_typed=known_typed_assets(session, subject=p.subject),
            union_from_block=scanned_from_block(session, subject=p.subject),
        )
        for p in pending
        if p.escalation is not None and p.contract.address
    ]
    with log_timed_phase(logger, "run_sweeps", escalated=len(sweep_requests)) as phase:
        sweeps, sweep_cost = run_sweeps(sweep_requests, rpc_url_for=lambda cid: rpc_url_for_chain_id(cid))
        phase["get_logs"] = sweep_cost.get_logs
        phase["multicall"] = sweep_cost.multicall
        phase["head_reads"] = sweep_cost.head_reads
    # A sweep that FAILED publishes no completeness and no cursor, so a cycle
    # where every scan failed and one where every scan succeeded wrote the same
    # number of fetch rows. Counted here, and the counts decide ``partial``:
    # without it a fleet-wide RPC outage during the sweeps is invisible in both
    # the log and the heartbeat.
    sweeps_failed = sum(1 for outcome in sweeps.values() if outcome.status != SWEEP_STATUS_COMPLETED)
    sweeps_completed = len(sweeps) - sweeps_failed
    # An escalated holder with NO outcome was never attempted — today that is an
    # unrouted chain, which produces no failure row to be counted. Tracked apart
    # from the failures rather than folded in: it is a different fact and it is
    # the one a completed-vs-failed count cannot see.
    sweeps_unattempted = max(0, len(sweep_requests) - len(sweeps))
    counts["sweeps_completed"] = counts.get("sweeps_completed", 0) + sweeps_completed
    counts["sweeps_failed"] = counts.get("sweeps_failed", 0) + sweeps_failed
    counts["sweeps_unattempted"] = counts.get("sweeps_unattempted", 0) + sweeps_unattempted
    # Every degraded kind the sweep recorded, so an outage that produced no
    # failed OUTCOME (an unrouted chain) still reaches the cycle heartbeat.
    for kind, seen in sweep_cost.degraded.items():
        counts[f"sweep_{kind}"] = counts.get(f"sweep_{kind}", 0) + seen
    if sweeps_failed or sweeps_unattempted:
        partial = True
    if sweep_requests and not sweeps_completed:
        logger.warning(
            "asset sweep: no escalated contract completed a scan; no asset set gains completeness this cycle",
            extra={
                "protocol_id": protocol_id,
                "escalated": len(sweep_requests),
                "sweeps_failed": sweeps_failed,
                "sweeps_unattempted": sweeps_unattempted,
                "get_logs": sweep_cost.get_logs,
                "multicall": sweep_cost.multicall,
                "head_reads": sweep_cost.head_reads,
                "degraded": dict(sweep_cost.degraded),
            },
        )
    # The cycle's real request count, carried onto every fetch record it wrote.
    # A cost estimate nobody can check against the record is a claim; this is the
    # measurement, stored where a reviewer reads the claim.
    cost_note = (
        f"cycle scan cost {sweep_cost.get_logs} getLogs + {sweep_cost.multicall} multicall + "
        f"{sweep_cost.head_reads} head over {len(sweep_requests)} escalated contract(s)"
        if sweep_requests
        else None
    )
    if sweep_requests:
        logger.info(
            "asset sweep: %d contract(s) escalated, %d completed, %d failed",
            len(sweep_requests),
            sweeps_completed,
            sweeps_failed,
            extra={
                "protocol_id": protocol_id,
                "escalated": len(sweep_requests),
                "sweeps_completed": sweeps_completed,
                "sweeps_failed": sweeps_failed,
                "sweeps_unattempted": sweeps_unattempted,
                "get_logs": sweep_cost.get_logs,
                "multicall": sweep_cost.multicall,
                "head_reads": sweep_cost.head_reads,
                "degraded": dict(sweep_cost.degraded),
            },
        )

    # THIRD PHASE, still before the write: how each unpriced holding ARRIVED.
    # Its own request budget, so a wide disposition run cannot starve the sweep
    # whose proven-empty negative depends on requests of its own. The population
    # is the protocol's whole unpriced set grouped by observed account, plus this
    # cycle's page/sweep readings, whose rows do not exist yet.
    discovered = [
        request
        for request in (
            discovered_request(
                contract_id=p.contract.id,
                chain_id=p.chain_id,
                holder_address=p.contract.address,
                page=p.page,
                sweep=sweeps.get(p.subject),
            )
            for p in pending
            if p.contract.address
        )
        if request is not None
    ]
    disposition_cost = run_disposition(
        session,
        disposition_requests(session, protocol_id=protocol_id, contract_ids=contract_ids, discovered=discovered),
        rpc_url_for=lambda cid: rpc_url_for_chain_id(cid),
        # Also refreshes the protocol-reference verdict for every token in the
        # population, once per cycle: the universe assembly behind it is an
        # object-storage read no presentation path can afford to repeat.
        protocol_id=protocol_id,
    )
    # ``run_disposition`` emits its own timed per-cycle summary; only the counts
    # this cycle must carry onward are folded in here.
    for key, value in disposition_cost.counts.items():
        counts[key] = counts.get(key, 0) + value

    for entry in pending:
        contract = entry.contract
        address = contract.address
        chain_id = entry.chain_id
        observed_address = address
        page = entry.page
        native_price = entry.native.price_usd
        eth_wei = entry.native.wei
        recorded = record_observation(
            session,
            subject=entry.subject,
            chain_id=chain_id,
            native=entry.native,
            page=page,
            writer=BALANCE_WRITER_TVL,
            sweep=sweeps.get(entry.subject),
            escalation=entry.escalation,
            cost_note=cost_note,
        )
        native_status = recorded.native_status

        contract_total = 0.0
        tokens: list[dict] = []
        for row in recorded.rows:
            usd = float(row.usd_value) if row.usd_value is not None else None
            if usd is None:
                continue
            contract_total += usd
            tokens.append({"symbol": row.token_symbol, "usd_value": round(usd, 2)})

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
        # native class is checked for it here — the ETH branch keeps writing
        # NULL-priced rows (its non-ETH twin skips the contract outright), so
        # this is where that asymmetry stops being published as a number.
        # Individual unpriced ERC-20s are NOT covered; that would need a
        # per-token witness this loop does not have.
        native_class_failed = native_status == NATIVE_STATUS_FETCH_FAILED
        assets_class_failed = recorded.asset_set_status == ASSET_SET_STATUS_FETCH_FAILED
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
            warn_degraded_once(
                logger,
                counts,
                "balance_fetch_degraded",
                "balance fetch degraded; the contract is omitted from the protocol's on-chain total",
                observed_address=observed_address,
                chain_id=chain_id,
                native_status=native_status,
                asset_set_status=recorded.asset_set_status,
            )
        elif native_unpriced:
            warn_degraded_once(
                logger,
                counts,
                "native_unpriced",
                "balance omitted from breakdown; the native quantity could not be priced",
                observed_address=observed_address,
                chain_id=chain_id,
            )

    session.commit()
    return breakdown, partial


# ---------------------------------------------------------------------------
# Entity-keyed holders: the perimeter's principals that have no contracts row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExcludedHolder:
    """One entity the sweep population did NOT take, and why.

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
    """What one entity-holder cycle read, per subject and per batch.

    The sweep's batch outcomes are carried, not just the per-address ones: a
    batch that cannot be proven whole fails EVERY holder in it, so a report that
    named only addresses would show forty independent failures where there was
    one.
    """

    holders: list[EntityHolder] = field(default_factory=list)
    excluded: list[ExcludedHolder] = field(default_factory=list)
    observations: dict[str, RecordedObservation] = field(default_factory=dict)
    sweep_outcomes: dict[str, SweepOutcome] = field(default_factory=dict)
    cost: SweepCost = field(default_factory=SweepCost)
    etherscan_pages: int = 0
    native_multicalls: int = 0
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
    probed carries ``unknown`` and is not in this set, and sweeping it as an EOA
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
    """Observe the protocol's entity-keyed holders through the shared ladder.

    Same escalation ladder and the same single write point as
    :func:`refresh_contract_balances` — Etherscan's page first, the chain's own
    transfer history when the page is empty or persistently unobtainable — so a
    guard added on one population holds on the other by construction.

    What it deliberately does NOT share is the TVL side of that function:

    * **No breakdown, no snapshot contribution.** These addresses are the
      protocol's signers and capability principals, not its deployments. Their
      personal holdings are not the protocol's money and must never be summed
      into a published TVL figure.
    * **No disposition pass.** The delivery-evidence plane is keyed on contract
      rows; an entity holder's unpriced token therefore stays ``unpriced``
      rather than being determined as airdrop-delivered. That is the fail-closed
      direction — a weaker claim, never a stronger one.
    """
    from utils.etherscan import get_eth_price, get_native_price

    holders, excluded = proven_codeless_holders(session, protocol_id, entity_keys=entity_keys)
    report = EntityObservationReport(holders=holders, excluded=excluded)
    if not holders:
        return report

    # One pinned native read per chain, before the per-holder loop, for the same
    # reason the contract pass does it: a zero is publishable only when it was
    # read AT a named height.
    pinned_by_chain: dict[int, tuple[int | None, dict[str, int]]] = {}
    for chain_id in sorted({h.chain_id for h in holders}):
        addresses = [h.address for h in holders if h.chain_id == chain_id]
        pinned_by_chain[chain_id] = pinned_native_balances(addresses, chain_id=chain_id)
        report.native_multicalls += 1

    eth_price: float | None = None
    try:
        eth_price = get_eth_price(chain_id=1)
    except Exception as exc:
        logger.warning("entity balances: ETH price fetch failed: %s", exc)
        report.partial = True
    native_price_by_chain: dict[int, float | None] = {}

    pending: list[tuple[EntityHolder, NativeReading, TokenBalancePage, str | None]] = []
    for holder in holders:
        native_asset = chain_by_id(holder.chain_id).native_asset
        if native_asset == "ETH":
            native_price = eth_price
            native_symbol, native_name = "ETH", "Ether"
            if native_price is None:
                report.partial = True
        else:
            if holder.chain_id not in native_price_by_chain:
                try:
                    native_price_by_chain[holder.chain_id] = get_native_price(holder.chain_id)
                except Exception as exc:
                    logger.warning("entity balances: native price failed for chain %s: %s", holder.chain_id, exc)
                    native_price_by_chain[holder.chain_id] = None
            native_price = native_price_by_chain[holder.chain_id]
            if native_price is None:
                report.partial = True
                report.excluded.append(
                    ExcludedHolder(holder.entity_key, f"no USD quote for chain {holder.chain_id} native coin")
                )
                continue
            native_symbol, native_name = native_asset, native_asset

        pinned_block, pinned_wei = pinned_by_chain.get(holder.chain_id, (None, {}))
        if pinned_block is not None and holder.address in pinned_wei:
            wei: int | None = pinned_wei[holder.address]
            native_block: int | None = pinned_block
            native_failed = False
        else:
            # No unpinned fallback here. The contract pass has Etherscan's
            # ``account/balance`` to fall back on; spending one request per
            # holder to obtain a quantity whose zero can never be published as
            # proven would buy nothing this population needs, so the read is
            # recorded as failed and the sheet stays not_determined.
            wei, native_block, native_failed = None, None, True

        page = fetch_asset_page(holder.address, chain_id=holder.chain_id)
        report.etherscan_pages += 1
        escalation = escalation_reason(session, subject=holder.subject, page=page)
        pending.append(
            (
                holder,
                NativeReading(
                    wei=wei,
                    block_number=native_block,
                    failed=native_failed,
                    price_usd=native_price,
                    symbol=native_symbol,
                    name=native_name,
                ),
                page,
                escalation,
            )
        )

    sweep_requests = [
        SweepRequest(
            subject=holder.subject,
            address=holder.address,
            chain_id=holder.chain_id,
            from_block=sweep_from_block(session, subject=holder.subject),
            reason=escalation,
            known_assets=known_swept_assets(session, subject=holder.subject),
            known_typed=known_typed_assets(session, subject=holder.subject),
            union_from_block=scanned_from_block(session, subject=holder.subject),
        )
        for holder, _native, _page, escalation in pending
        if escalation is not None
    ]
    # The entity cohort spends its OWN request counter. ``SWEEP_REQUEST_BUDGET``
    # is a ceiling on whatever counter ``run_sweeps`` carries, so a per-cohort
    # counter is what makes the daily entity pass and the hourly contract sweep
    # two separate allowances rather than one shared one. ``run_sweeps`` already
    # mints a counter per call, so this argument states that invariant at the
    # call site rather than establishing it — pinned here, and by a test,
    # because the isolation is a property this producer depends on and not one
    # a reader should have to infer from a default argument two modules away.
    sweeps, sweep_cost = run_sweeps(
        sweep_requests,
        rpc_url_for=lambda cid: rpc_url_for_chain_id(cid),
        cost=SweepCost(),
    )
    report.cost = sweep_cost
    cost_note = (
        f"cycle scan cost {sweep_cost.get_logs} getLogs + {sweep_cost.multicall} multicall + "
        f"{sweep_cost.head_reads} head over {len(sweep_requests)} escalated entity holder(s)"
        if sweep_requests
        else None
    )
    entity_sweeps_failed = sum(1 for outcome in sweeps.values() if outcome.status != SWEEP_STATUS_COMPLETED)
    if entity_sweeps_failed:
        # Same rule as the contract arm: a failed scan publishes no completeness,
        # so the cohort's reading is partial whatever else succeeded.
        report.partial = True
    if sweep_requests:
        logger.info(
            "entity balances: %d holder(s) escalated, %d completed, %d failed",
            len(sweep_requests),
            len(sweeps) - entity_sweeps_failed,
            entity_sweeps_failed,
            extra={
                "escalated": len(sweep_requests),
                "sweeps_completed": len(sweeps) - entity_sweeps_failed,
                "sweeps_failed": entity_sweeps_failed,
                "get_logs": sweep_cost.get_logs,
                "multicall": sweep_cost.multicall,
                "head_reads": sweep_cost.head_reads,
                "degraded": dict(sweep_cost.degraded),
            },
        )

    for holder, native, page, escalation in pending:
        outcome = sweeps.get(holder.subject)
        if outcome is not None:
            report.sweep_outcomes[holder.entity_key] = outcome
        report.observations[holder.entity_key] = record_observation(
            session,
            subject=holder.subject,
            chain_id=holder.chain_id,
            native=native,
            page=page,
            writer=BALANCE_WRITER_TVL,
            sweep=outcome,
            escalation=escalation,
            cost_note=cost_note,
        )
    session.commit()
    return report


def entity_cohort_oldest_reading(session: Session, holders: list[EntityHolder]) -> datetime | None:
    """The OLDEST current reading in this cohort — the age the cohort really is.

    Per holder its newest fetch, then the minimum across holders, because a
    cohort is only as fresh as its stalest member. The newest-anywhere reading
    would be the wrong anchor for a reason that is structural rather than
    hypothetical: a fetch row's identity is ``(chain, address)`` and carries no
    protocol, while this cohort is protocol-scoped, so one EOA reached from two
    protocols' control graphs is ONE row. Anchoring on the maximum would let
    protocol A's daily pass keep that shared row fresh and starve protocol B's
    exclusive holders for as long as both protocols exist.

    Holders that have never been read are deliberately NOT in the minimum. They
    are not a stale reading, they are no reading, and folding them in as a
    floor would make a cohort the producer keeps declining re-fire every tick.
    Their first reading arrives with the next pass this anchor does open.

    ``None`` = nobody in the cohort has ever been read, so nothing bounds how
    old it is and the caller must read it.
    """
    if not holders:
        return None
    # Scoped by ``ObservationSubject.filters`` — the same predicate the
    # observation modules select a subject's rows with, not a second spelling.
    newest_per_holder = session.execute(
        select(func.max(ContractBalanceFetch.fetched_at))
        .where(or_(*[and_(*holder.subject.filters(ContractBalanceFetch)) for holder in holders]))
        .group_by(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address)
    ).scalars()
    return min((ts for ts in newest_per_holder if ts is not None), default=None)


def refresh_entity_balances_if_due(
    session: Session,
    protocol_id: int,
    *,
    now: datetime | None = None,
    interval_s: int = DEFAULT_ENTITY_BALANCE_INTERVAL,
) -> EntityObservationReport | None:
    """The cycle's daily arm: read the entity cohort, or report it still fresh.

    ``None`` means the pass did not run, and the two reasons are both honest
    ones: the protocol has no proven-codeless holders, or every holder that has
    ever been read was read inside the window.

    The window is measured against the cohort's own fetch rows, the way
    :func:`take_tvl_snapshot` measures ``MIN_SNAPSHOT_INTERVAL`` against its own
    snapshots. The producer's output IS the schedule: a cadence held in
    loop-local state re-spends the day's requests on every restart, and one held
    in a second marker can claim a reading that was never written. What the
    window is measured FROM is :func:`entity_cohort_oldest_reading` — read its
    docstring before changing this to a maximum.
    """
    holders, _excluded = proven_codeless_holders(session, protocol_id)
    if not holders:
        return None
    oldest = entity_cohort_oldest_reading(session, holders)
    if oldest is not None:
        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=timezone.utc)
        if (now or datetime.now(timezone.utc)) - oldest < timedelta(seconds=interval_s):
            return None
    return refresh_entity_balances(session, protocol_id)


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
        # The IN above already excludes entity-keyed rows (their contract_id is
        # NULL); the guard states it rather than leaning on the query's shape.
        if b.contract_id is not None:
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
    *,
    counters: dict[str, int] | None = None,
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
        contract_breakdown, partial = refresh_contract_balances(session, protocol_id, counters=counters)
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
    # The cycle's own degradation tally, shared by every protocol in the slice:
    # what failed to be observed, once per cycle rather than once per contract.
    cycle_counts: dict[str, int] = {}
    for protocol in protocols:
        try:
            with log_timed_phase(logger, "tvl_snapshot", protocol_id=protocol.id) as phase:
                snapshot, snapshot_partial = take_tvl_snapshot(session, protocol.id, counters=cycle_counts)
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
                protocol.name,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
        # The daily arm, after the snapshot and in a try of its own. These
        # holders are the protocol's principals, not its deployments: they
        # contribute nothing to the snapshot, so neither pass's failure may be
        # reported as the other's and the snapshot cycle's counters stay a
        # statement about the snapshot.
        try:
            entity_report = refresh_entity_balances_if_due(session, protocol.id)
            if entity_report is not None:
                # Counted onto the CYCLE under its own keys, never onto the
                # snapshot's: ``EntityObservationReport.partial`` has no reader,
                # so without this the cohort's failed scans reached a log line
                # and nothing else. Distinct keys keep the two passes' figures
                # from being read as each other's.
                entity_failed = sum(
                    1 for outcome in entity_report.sweep_outcomes.values() if outcome.status != SWEEP_STATUS_COMPLETED
                )
                cycle_counts["entity_holders_read"] = cycle_counts.get("entity_holders_read", 0) + len(
                    entity_report.holders
                )
                cycle_counts["entity_sweeps_failed"] = cycle_counts.get("entity_sweeps_failed", 0) + entity_failed
                for kind, seen in entity_report.cost.degraded.items():
                    cycle_counts[f"entity_sweep_{kind}"] = cycle_counts.get(f"entity_sweep_{kind}", 0) + seen
                logger.info(
                    "entity balances for %s: %d holder(s) read, %d excluded, %d sweep(s) failed",
                    protocol.name,
                    len(entity_report.holders),
                    len(entity_report.excluded),
                    entity_failed,
                    extra={
                        "protocol_id": protocol.id,
                        "holders": len(entity_report.holders),
                        "excluded": len(entity_report.excluded),
                        "sweeps_failed": entity_failed,
                        "get_logs": entity_report.cost.get_logs,
                        "multicall": entity_report.cost.multicall,
                        "head_reads": entity_report.cost.head_reads,
                        "degraded": dict(entity_report.cost.degraded),
                    },
                )
        except Exception as exc:
            session.rollback()
            cycle_counts["entity_passes_failed"] = cycle_counts.get("entity_passes_failed", 0) + 1
            logger.warning(
                "entity balance refresh failed for protocol %s: %s",
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
        # What the cycle could not observe, per kind. A pass where every sweep
        # failed and one where every sweep succeeded used to beat identically.
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
