"""The ONE ERC-20 observation path, shared by both balance producers.

``services.monitoring.tvl`` and ``workers.resolution_worker`` used to each call
``get_token_balances_page`` directly and write their own rows, under DIFFERENT
``observed_address`` policies — the TVL loop read ``contracts.address``, the
resolution worker read ``request['proxy_address'] or address`` and filed the
answer against the JOB's contract row. That divergence is not cosmetic: it
attributed a proxy's 19.06 ETH to the implementation's row, where a later TVL
fetch at the implementation's own address won the native class wholesale and
evicted it, leaving the plane publishing a proven zero for an account that was
never the one holding the ETH.

So there is one policy here and it is structural rather than remembered:

    A FETCH ROW'S ``observed_address`` IS ITS OWN CONTRACT'S ``contracts.address``.

:func:`observation_contract` is how a caller that wants some OTHER address read
gets there — it hands back the contract row that owns that address, and the read
is filed against it. A caller cannot express the divergent shape any more.

The escalation ladder (Etherscan first, chain sweep second) and the single write
point both live here for the same reason: an escalation added on one producer
and not the other is the same class of bug as a divergent address policy.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract, ContractBalance, ContractBalanceFetch

# The two wire-reaching functions are called through the MODULE, not bound here:
# one indirection point means a stub (the offline suite's, or a test's) holds no
# matter which producer imported this module's helpers.
from services.monitoring import asset_sweep
from services.monitoring.asset_sweep import (
    SWEEP_COMPLETED,
    CarriedTypedReceipt,
    SweepCost,
    SweepOutcome,
    carried_typed_receipt,
)
from services.monitoring.balance_reads import native_status_for, prune_balance_fetches
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    BALANCE_SOURCE_PINNED_NATIVE_READ,
    BALANCE_SOURCE_UNPINNED_NATIVE_READ,
    NATIVE_STATUS_PROVEN_ZERO,
    SWEEP_STATUS_COMPLETED,
    SWEEP_STATUS_FAILED,
)
from utils.etherscan import TokenBalancePage

logger = logging.getLogger(__name__)

# Consecutive failed asset fetches before Etherscan counts as "persistently
# unobtainable" and the chain is asked instead. One failure is a transport
# hiccup and sweeping on it would spend a full-history scan on noise; a run of
# them is a contract this index will not answer for.
PERSISTENT_FAILURE_RUN = 3

# Consecutive failed scans after which a contract stops being re-escalated. Same
# shape as the trigger above and for the same reason, on the other side: an
# escalation that has failed this many times in a row is not going to be answered
# by asking again next hour, and asking is what costs the budget.
SWEEP_FAILURE_RUN = 3

ESCALATE_RETURNED_EMPTY = "etherscan returned an empty list"
ESCALATE_PERSISTENT_FAILURE = "etherscan persistently unobtainable"
ESCALATE_NO_FETCH_RECORD = "no prior fetch record for this contract"

# A list that came back AT THE CAP is deliberately NOT an escalation trigger.
# Its completeness mechanism is paging the endpoint past entry 100
# (``get_token_balances_page``), which costs one request per additional hundred
# assets and is exactly the asset-list completeness a truncated sheet lacks. The
# chain sweep is the wrong tool for it: a holder rich enough to overflow the page
# is a holder whose incoming-transfer history bisects the scan windows toward the
# floor — measured at up to ~2,350 requests for ONE such address
# (SPAM_CLASSIFIER_FEASIBILITY.md) against ~1 request per 1M-block window for a
# quiet one. A list that is still a prefix after the page budget therefore stays
# ``at_page_cap``, and the plane refuses it a ceiling — the fail-closed answer,
# reached without spending a four-figure request budget to buy it.
AT_CAP_COMPLETENESS_MECHANISM = "etherscan pagination past the first page (not a chain sweep)"

# The measured non-priority, recorded rather than left as an omission: 153
# proven-codeless EOAs in this perimeter are NOT read. They move a non-binding
# confidence term and the published headline by zero, and reading them would
# spend the sweep budget where no number changes.
SWEEP_POPULATION_NOTE = "proven-codeless EOA principals are out of the swept population (measured non-priority)"


@dataclass(frozen=True)
class NativeReading:
    """The native leg, as the calling producer obtained it.

    It stays with the producers because they obtain it differently — the TVL loop
    pins one Multicall3 read per chain ahead of its contract loop, the resolution
    worker fans out per job — and because unifying it was not what diverged.
    """

    wei: int | None
    block_number: int | None
    failed: bool
    price_usd: float | None
    symbol: str
    name: str


@dataclass(frozen=True)
class RecordedObservation:
    """What :func:`record_observation` persisted, for a caller that must report it.

    The caller reads its own cycle summary off these rows rather than off the
    inputs: what was WRITTEN is the observation, and after an escalation the two
    are not the same list.
    """

    fetch: ContractBalanceFetch
    asset_set_status: str
    asset_set_source: str
    native_status: str
    rows: tuple[ContractBalance, ...]


@dataclass(frozen=True)
class SweepRequest:
    """One contract queued for the chain-derived escalation."""

    contract_id: int
    address: str
    chain_id: int
    from_block: int
    reason: str
    # What a previous sweep already found for this holder. An incremental window
    # names only what arrived inside it, so without this the next cycle's row set
    # would omit every earlier asset — and the balance view takes a fetch's rows
    # wholesale, so the omission would read as a sale.
    known_assets: tuple[str, ...] = ()
    # The typed receipts already on record. Carried for the refusal they carry,
    # not for their quantity — and with the token ids a previous scan decoded,
    # which is the only way an incremental window can read an ERC-1155 holding at
    # all: the ids exist only in the delivering logs, long past the cursor.
    known_typed: tuple[CarriedTypedReceipt, ...] = ()
    # First block of the union of the scans behind the current set; None when
    # nothing has been scanned yet.
    union_from_block: int | None = None


def observation_contract(
    session: Session,
    *,
    fallback: Contract,
    chain_id: int,
    requested_address: str | None,
) -> Contract:
    """The contract row an observation of *requested_address* belongs to.

    The single ``observed_address`` policy is enforced by construction: whoever
    owns the address owns the fetch row. Selection is scoped to the PRODUCING
    protocol — a row belonging to another tenant is never adopted, because
    writing a fetch against it (and pruning its history) would let one
    protocol's job mutate another's balance plane. When no row of this
    protocol's owns the address the read falls back to *fallback*'s own address:
    an address nobody here owns is not read at all, which loses an observation
    and is the direction that cannot corrupt a neighbour.
    """
    from services.monitoring.chain_rpc import chain_id_for

    if not requested_address:
        return fallback
    wanted = requested_address.lower()
    if (fallback.address or "").lower() == wanted:
        return fallback
    if fallback.protocol_id is None:
        return fallback
    candidates = (
        session.execute(
            select(Contract)
            .where(func.lower(Contract.address) == wanted, Contract.protocol_id == fallback.protocol_id)
            .order_by(Contract.id)
        )
        .scalars()
        .all()
    )
    same_chain = [c for c in candidates if chain_id_for(c.chain) == chain_id]
    return same_chain[0] if same_chain else fallback


def fetch_asset_page(address: str, *, chain_id: int) -> TokenBalancePage:
    """Etherscan's answer, with a raise turned into the recorded failure state.

    ``get_token_balances_page`` already swallows the common failure into a
    ``fetch_failed`` page; this catches everything else so a producer cycle can
    never end with an asset class that has neither rows nor a status.
    """
    # Imported at call time, not bound at import time: this is the single wire
    # both producers reach Etherscan through, and a module-level binding would
    # make it unstubbable from the outside.
    from utils.etherscan import get_token_balances_page

    try:
        return get_token_balances_page(address, chain_id=chain_id)
    except Exception as exc:
        logger.warning("token balance fetch raised for %s on chain %s: %s", address, chain_id, exc)
        return TokenBalancePage(
            rows=[],
            page_length=None,
            status=ASSET_SET_STATUS_FETCH_FAILED,
            pages_read=0,
            basis=f"etherscan addresstokenbalance raised: {type(exc).__name__}",
        )


def escalation_reason(session: Session, *, contract_id: int, page: TokenBalancePage) -> str | None:
    """Why this contract's asset set must be asked of the chain, or ``None``.

    Uniform: the trigger is the shape of the answer, never what a claim wants to
    be true of the contract.
    """
    if sweep_keeps_failing(session, contract_id=contract_id):
        return None
    if page.status == ASSET_SET_STATUS_RETURNED_EMPTY:
        return ESCALATE_RETURNED_EMPTY
    if page.status == ASSET_SET_STATUS_AT_PAGE_CAP:
        # See AT_CAP_COMPLETENESS_MECHANISM: paging is this state's mechanism and
        # it has already run. Sweeping here would buy the same completeness at a
        # bisection-dominated cost.
        return None
    recent = (
        session.execute(
            select(ContractBalanceFetch.asset_set_status)
            .where(ContractBalanceFetch.contract_id == contract_id)
            .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
            .limit(PERSISTENT_FAILURE_RUN)
        )
        .scalars()
        .all()
    )
    if not recent:
        return ESCALATE_NO_FETCH_RECORD
    if page.status == ASSET_SET_STATUS_FETCH_FAILED and len(recent) >= PERSISTENT_FAILURE_RUN:
        if all(status == ASSET_SET_STATUS_FETCH_FAILED for status in recent):
            return ESCALATE_PERSISTENT_FAILURE
    return None


def sweep_from_block(session: Session, *, contract_id: int) -> int:
    """Where this contract's next scan starts.

    The stored cursor plus one, or 0 for a contract never swept. Without it the
    hourly loop would re-run a full-history scan every cycle — the cursor is what
    makes the one-shot a one-shot.

    THE CURSOR AND THE EVIDENCE COME FROM THE SAME ROW, by construction rather
    than by agreement. A cursor's promise is "those blocks were read and what
    they held is on record", so it may only be taken from a fetch that is also
    the one carrying the record — the current asset fetch. Reading the cursor
    from anywhere wider (a ``max()`` over history, say) lets a row that scanned
    nothing hand back a height a different row earned, and the evidence readers,
    which key on the current fetch, then answer for a scan the cursor did not
    come from. That divergence had three doors: a fetch with a cursor but no
    typed record, an abort that became current, and a plain non-escalating
    ``returned_assets`` cycle. One row closes all three.

    The cost is accepted and stated: a cycle that does not escalate makes the
    next escalation a full re-scan. It converges on that scan, and a re-scan is
    the cheap side of the trade against inheriting a conclusion.

    THE SAME RULE COVERS THE TYPED ID INVENTORY. A cursor promises the blocks
    were read AND what they held is on record; for an ERC-1155 receipt "what it
    held" is a set of token ids, because no address-level call answers for one.
    A record that names typed receipts but no ids is a scan whose evidence cannot
    answer the question the sheet asks, so its cursor is refused and the scan is
    redone — once. After that the ids are stored and the cursor holds forever.
    """
    current = _current_asset_fetch(session, contract_id=contract_id)
    if (
        current is None
        or current.swept_through_block is None
        or not _typed_record_is_readable(current)
        or not _typed_record_is_id_complete(current)
    ):
        return 0
    return int(current.swept_through_block) + 1


def known_swept_assets(session: Session, *, contract_id: int) -> tuple[str, ...]:
    """The assets a previous scan already attributed to this contract.

    Read off the rows of the fetch whose ERC-20 set is CURRENT — the same fetch
    ``contract_balances_latest`` publishes — so the list carried into the next
    incremental window is exactly the one a consumer is reading today.
    """
    fetch = _current_asset_fetch(session, contract_id=contract_id)
    if fetch is None:
        return ()
    winner = fetch.id
    rows = (
        session.execute(
            select(ContractBalance.token_address).where(
                ContractBalance.fetch_id == winner,
                ContractBalance.token_address.is_not(None),
                ContractBalance.source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            )
        )
        .scalars()
        .all()
    )
    return tuple(sorted({str(a).lower() for a in rows if a}))


def known_typed_assets(session: Session, *, contract_id: int) -> tuple[CarriedTypedReceipt, ...]:
    """The ERC-721/1155 receipts the current fetch record already knows about.

    This is the durable half of the completeness refusal. A typed receipt whose
    holding has no readable answer is why a swept set may not be published as
    complete, and an incremental window will not name it again — so it is read
    back from the fetch record and re-carried every cycle. Without it the refusal
    lasted exactly one cycle and the next one published the empty sheet.

    Each receipt carries its standard and its stored token ids, so the next cycle
    can read an ERC-1155 holding without re-scanning the history that named them.
    """
    fetch = _current_asset_fetch(session, contract_id=contract_id)
    if fetch is None or not _typed_record_is_readable(fetch):
        return ()
    receipts = {}
    for entry in fetch.typed_assets or []:
        receipt = carried_typed_receipt(entry)
        if receipt.address:
            receipts[receipt.address] = receipt
    return tuple(receipts[address] for address in sorted(receipts))


def _typed_record_is_readable(fetch: ContractBalanceFetch) -> bool:
    """Whether this fetch's typed-receipt record can be read as one.

    A missing record and an unreadable one are the same thing to every caller
    here: no statement about typed receipts survives from that scan, so the scan
    is redone rather than its conclusions inherited. Silently degrading a
    malformed blob to "no typed receipts" would resurrect exactly the bug this
    column closes — a completeness claim published because the evidence against
    it could not be read.
    """
    entries = fetch.typed_assets
    if entries is None or not isinstance(entries, list):
        return False
    return all(isinstance(entry, dict) and entry.get("address") and _typed_ids_are_readable(entry) for entry in entries)


def _typed_ids_are_readable(entry: dict) -> bool:
    """Whether one entry's id inventory can be read as one.

    An entry from before ids were kept carries neither key, and that absence is a
    fact this reader can act on: it is distinguished from a blob that claims an
    inventory and cannot produce one. The malformed case is distrusted rather
    than degraded to "no ids", for the same reason the record above is: a receipt
    whose ids are unreadable is a receipt whose per-id holding can never be read,
    and reading the blob as absent would let the next cycle inherit a cursor over
    blocks whose evidence is gone.
    """
    if "ids" not in entry and "ids_complete" not in entry:
        return True
    if not isinstance(entry.get("ids_complete"), bool) or not isinstance(entry.get("ids"), list):
        return False
    return all(
        isinstance(item, dict) and isinstance(item.get("id"), str) and str(item["id"]).isdigit()
        for item in entry["ids"]
    )


def _typed_record_is_id_complete(fetch: ContractBalanceFetch) -> bool:
    """Whether every typed receipt on this fetch carries a settled id inventory.

    Settled includes empty — a full-history scan that saw no id for a token has
    established that it has none. What this refuses is the record that never
    asked, which is every record written before the ids were decoded.
    """
    entries = fetch.typed_assets
    if entries is None or not isinstance(entries, list):
        return False
    return all(isinstance(entry, dict) and entry.get("ids_complete") is True for entry in entries)


def scanned_from_block(session: Session, *, contract_id: int) -> int | None:
    """The first block of the union of the scans behind the current asset set."""
    fetch = _current_asset_fetch(session, contract_id=contract_id)
    if (
        fetch is None
        or fetch.swept_through_block is None
        or not _typed_record_is_readable(fetch)
        or not _typed_record_is_id_complete(fetch)
    ):
        # Same row and same rule as :func:`sweep_from_block`: an extent is only
        # readable off the fetch that carries the scan it describes, and a scan
        # being redone has no extent yet. The two conditions must stay identical
        # — a union extent inherited past a refused cursor would name blocks the
        # re-scan is about to read again as if they were already behind the set.
        return None
    return int(fetch.swept_from_block) if fetch.swept_from_block is not None else 0


def _current_asset_fetch(session: Session, *, contract_id: int) -> ContractBalanceFetch | None:
    """The fetch whose ERC-20 row set ``contract_balances_latest`` publishes."""
    return (
        session.execute(
            select(ContractBalanceFetch)
            .where(
                ContractBalanceFetch.contract_id == contract_id,
                ContractBalanceFetch.asset_set_status != ASSET_SET_STATUS_FETCH_FAILED,
            )
            .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


def _has_scan_record(session: Session, *, contract_id: int) -> bool:
    """Whether any fetch for this contract carries a completed scan."""
    return (
        session.execute(
            select(ContractBalanceFetch.id)
            .where(
                ContractBalanceFetch.contract_id == contract_id,
                ContractBalanceFetch.swept_through_block.is_not(None),
            )
            .limit(1)
        )
        .scalars()
        .first()
        is not None
    )


def sweep_keeps_failing(session: Session, *, contract_id: int) -> bool:
    """Whether this contract's last few scans all failed.

    A scan that cannot be proven whole is usually a holder whose transfer history
    bisects the windows toward the floor, and retrying it every cycle spends a
    four-figure request budget to fail the same way. After a run of failures the
    escalation stops asking: the sheet keeps whatever Etherscan says, publishes no
    completeness, and an operator can see the failures in the fetch records.
    """
    recent = (
        session.execute(
            select(ContractBalanceFetch.sweep_status)
            .where(
                ContractBalanceFetch.contract_id == contract_id,
                ContractBalanceFetch.sweep_status.is_not(None),
            )
            .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
            .limit(SWEEP_FAILURE_RUN)
        )
        .scalars()
        .all()
    )
    return len(recent) >= SWEEP_FAILURE_RUN and all(status == SWEEP_STATUS_FAILED for status in recent)


def run_sweeps(
    requests: list[SweepRequest],
    *,
    rpc_url_for: Callable[[int], str | None],
    cost: SweepCost | None = None,
) -> tuple[dict[int, SweepOutcome], SweepCost]:
    """Run the escalation for a whole cycle's candidates, batched per chain.

    Batching is not an optimisation here: the recipient filter is an OR-set in
    one topic position, so N holders sharing a cursor cost the same windows as
    one. Per-contract scans would multiply the cycle's request count by N.
    """
    cost = cost if cost is not None else SweepCost()
    outcomes: dict[int, SweepOutcome] = {}
    by_chain: dict[int, list[SweepRequest]] = {}
    for request in requests:
        by_chain.setdefault(request.chain_id, []).append(request)
    for chain_id, cohort in sorted(by_chain.items()):
        rpc_url = rpc_url_for(chain_id)
        if not rpc_url:
            logger.info("asset sweep: no RPC URL for chain %s; %d contract(s) not swept", chain_id, len(cohort))
            continue
        head = asset_sweep.sweep_head_block(rpc_url, chain_id=chain_id, cost=cost)
        by_address = {r.address.lower(): r for r in cohort}
        results, cost = asset_sweep.sweep_holders(
            list(by_address),
            rpc_url=rpc_url,
            chain_id=chain_id,
            from_block_by_address={a: r.from_block for a, r in by_address.items()},
            known_assets_by_address={a: r.known_assets for a, r in by_address.items()},
            known_typed_by_address={a: r.known_typed for a, r in by_address.items()},
            union_from_by_address={
                a: (r.union_from_block if r.union_from_block is not None else r.from_block)
                for a, r in by_address.items()
            },
            cost=cost,
            head_block=head,
        )
        for address, outcome in results.items():
            request = by_address.get(address)
            if request is not None:
                outcomes[request.contract_id] = outcome
    return outcomes, cost


def record_observation(
    session: Session,
    *,
    contract: Contract,
    chain_id: int,
    native: NativeReading,
    page: TokenBalancePage,
    writer: str,
    sweep: SweepOutcome | None = None,
    escalation: str | None = None,
    cost_note: str | None = None,
) -> RecordedObservation:
    """THE write point for both producers: one fetch row plus its row set.

    The invariant every reader depends on is preserved here rather than at two
    call sites: a non-failed class status is a promise that that class's row set
    was written — possibly empty, when empty is what was observed, never merely
    skipped.
    """
    observed_address = contract.address
    native_status = native_status_for(wei=native.wei, pinned=native.block_number is not None, failed=native.failed)

    assets: dict[str, dict] = {}
    for row in page.rows:
        token = (row.get("token_address") or "").lower()
        if not token:
            continue
        assets[token] = {
            "token_address": token,
            "token_name": row.get("token_name"),
            "token_symbol": row.get("token_symbol"),
            "decimals": row.get("decimals", 18),
            "raw_balance": row["balance"],
            "price_usd": row.get("price_usd"),
            "usd_value": row.get("usd_value"),
            "source": ASSET_SET_SOURCE_ETHERSCAN_PAGES,
        }

    # Two different things, deliberately not one flag. The SCAN either ran to a
    # named block or it did not; the COMPLETENESS of the asset set is a further
    # claim the scan only sometimes supports. A typed (ERC-721/1155) receipt whose
    # current holding could not be read separates them: 1155 has no
    # ``balanceOf(address)`` at all, so the answer is a revert rather than a zero,
    # and the set cannot be shown to be everything — but the scan itself is a
    # fact, and its rows and its cursor are both worth keeping.
    scan_completed = sweep is not None and sweep.status == SWEEP_COMPLETED
    typed_unreadable = [t for t in (sweep.typed_assets if sweep else ()) if t.raw_balance is None]
    swept_ok = scan_completed and not typed_unreadable

    if scan_completed:
        assert sweep is not None
        for asset in sweep.assets:
            # A scan-discovered asset the holder no longer holds writes no row,
            # and the completeness witness is why it does not need to. What
            # ``proven_empty`` turns on is the SET — the fetch record carries
            # ``chain_log_sweep`` + ``swept_through_block``, and the plane reads
            # "this list is everything that ever arrived" off that — so a
            # zero-quantity row would add no evidence while making row existence
            # mean "holds this asset" again, which is the reading
            # ``balance_reads.positive_raw_balance`` exists to stop. It would also
            # flip the recorded asset-set status from ``returned_empty`` to
            # ``returned_assets`` for a holder that holds nothing.
            if asset.raw_balance is None or asset.raw_balance <= 0:
                continue
            existing = assets.get(asset.token_address)
            if existing is not None:
                # The page already carries this asset WITH a price; the sweep adds
                # no money information, only completeness.
                continue
            assets[asset.token_address] = {
                "token_address": asset.token_address,
                "token_name": None,
                "token_symbol": None,
                "decimals": 18 if asset.decimals is None else asset.decimals,
                "raw_balance": asset.raw_balance,
                # No price source reaches a log-derived asset, so the quantity is
                # published unpriced. NOT zero — an unpriced holding is not a
                # holding worth nothing.
                "price_usd": None,
                "usd_value": None,
                "source": ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            }
        for asset in sweep.typed_assets:
            if asset.raw_balance is None or asset.raw_balance <= 0:
                continue
            if asset.token_address in assets:
                continue
            assets[asset.token_address] = {
                "token_address": asset.token_address,
                "token_name": None,
                # The quantity is a COUNT of items, not a scaled amount of
                # anything, so ``decimals`` is 0 — never the conventional 18,
                # which would present a count as a fungible quantity — and there
                # is no USD column to fill. It must never be summed into a sheet
                # total.
                "token_symbol": None,
                "decimals": 0,
                "raw_balance": asset.raw_balance,
                "price_usd": None,
                "usd_value": None,
                "source": ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            }

    # The typed receipts, recorded on the fetch whether or not they are holdings
    # today: they are the evidence for the completeness this scan does or does
    # not claim, and an incremental window will never name them again.
    typed_evidence: list[dict] | None = None
    if scan_completed:
        assert sweep is not None
        # The id inventory is stored beside the quantity, not instead of it. It is
        # what makes the ERC-1155 read a one-off: the ids exist only in the logs
        # that delivered them, nothing else in the pipeline keeps a log, and a
        # record without them sends the next cycle back through the whole
        # full-history scan to learn what it already knew.
        typed_evidence = [
            {
                "address": asset.token_address,
                "kind": asset.kind,
                "standard": asset.standard,
                "quantity_readable": asset.raw_balance is not None,
                "quantity": None if asset.raw_balance is None else str(asset.raw_balance),
                "quantity_basis": asset.quantity_basis,
                "ids_complete": asset.ids_complete,
                "ids": [
                    {"id": item.token_id, "quantity": None if item.quantity is None else str(item.quantity)}
                    for item in asset.items
                ],
            }
            for asset in sweep.typed_assets
        ]

    sweep_status: str | None
    if swept_ok:
        assert sweep is not None
        asset_set_status = ASSET_SET_STATUS_RETURNED_ASSETS if assets else ASSET_SET_STATUS_RETURNED_EMPTY
        asset_set_source = ASSET_SET_SOURCE_CHAIN_LOG_SWEEP
        sweep_status = SWEEP_STATUS_COMPLETED
        swept_through_block = sweep.swept_through_block
        swept_from_block: int | None = sweep.swept_from_block
        basis = f"{sweep.basis}; escalated because {escalation}; {SWEEP_POPULATION_NOTE}"
        if page.status != ASSET_SET_STATUS_FETCH_FAILED and page.rows:
            basis = f"{basis}; priced entries carried from {page.basis}"
    elif scan_completed:
        assert sweep is not None
        # The scan ran and its rows are kept — discarding a holding the chain
        # showed us would be its own fail-open. What is withheld is the
        # COMPLETENESS: the source stays the third-party index's, so no consumer
        # can read this set as chain-proven, and an empty one is Etherscan's
        # empty rather than an earned negative. The cursor still advances,
        # because the blocks WERE read and re-reading them every cycle would buy
        # nothing.
        asset_set_status = ASSET_SET_STATUS_RETURNED_ASSETS if assets else page.status
        asset_set_source = ASSET_SET_SOURCE_ETHERSCAN_PAGES
        sweep_status = SWEEP_STATUS_COMPLETED
        swept_through_block = sweep.swept_through_block
        swept_from_block = sweep.swept_from_block
        basis = (
            f"{page.basis}; chain scan of blocks {sweep.swept_from_block}-{sweep.swept_through_block} ran but "
            f"its asset set is NOT claimed complete: {len(typed_unreadable)} ERC-721/1155 receipt(s) whose "
            f"current holding neither balanceOf(address) nor a per-token-id read could determine "
            f"({', '.join(f'{t.token_address} [{t.standard}, {len(t.items)} id(s)]' for t in typed_unreadable[:8])}); "
            f"{SWEEP_POPULATION_NOTE}"
        )
    else:
        asset_set_status = page.status
        asset_set_source = ASSET_SET_SOURCE_ETHERSCAN_PAGES
        sweep_status = SWEEP_STATUS_FAILED if sweep is not None else None
        swept_through_block = None
        swept_from_block = None
        basis = page.basis
        if sweep is not None:
            basis = (
                f"{basis}; chain sweep ABORTED, asset set NOT proven complete: "
                f"{sweep.failure_reason or 'no reason recorded'}"
            )
            if _has_scan_record(session, contract_id=contract.id):
                # A scan already established this contract's asset set, and this
                # cycle's scan aborted. The Etherscan page is not a replacement
                # for it: it is the answer whose incompleteness triggered the
                # escalation in the first place. Recorded as a FAILED asset class
                # so the earlier, better-evidenced fetch keeps winning the view —
                # otherwise this row becomes current and takes the whole record
                # with it: the sweep-discovered holdings withdraw (a fetch's rows
                # are its set, wholesale), the typed evidence behind a withheld
                # completeness disappears, and the cursor is inherited by a fetch
                # that scanned nothing.
                asset_set_status = ASSET_SET_STATUS_FETCH_FAILED
                basis = (
                    f"{basis}; the asset class is recorded as FAILED because a previous scan "
                    f"had established this set and this cycle could not"
                )

    if cost_note and sweep is not None:
        basis = f"{basis}; {cost_note}"

    fetch = ContractBalanceFetch(
        contract_id=contract.id,
        chain_id=chain_id,
        observed_address=observed_address,
        block_number=native.block_number,
        native_status=native_status,
        asset_set_status=asset_set_status,
        asset_page_length=page.page_length,
        asset_set_source=asset_set_source,
        asset_set_basis=basis or None,
        sweep_status=sweep_status,
        swept_through_block=swept_through_block,
        swept_from_block=swept_from_block,
        typed_assets=typed_evidence,
        writer=writer,
    )
    session.add(fetch)
    session.flush()

    written: list[ContractBalance] = []
    # No DELETE anywhere in here. The writers are insert-only and
    # ``contract_balances_latest`` decides what is current, per row class.
    #
    # A PROVEN zero is persisted as a row of its own. A quantity witnessed zero
    # at a named height is an observation — the earned negative the sheet plane
    # reads as ``proven_empty`` — and dropping it left the plane with an absence
    # where a measurement had been made. The pinned-ness is what admits it and is
    # not assumed: ``native_status_for`` stamps ``proven_zero`` only for a zero
    # read AT a block, and an unpinned zero stays ``not_determined`` and writes
    # nothing, because a zero at an unrecorded moment proves zero at no height.
    if native.wei is not None and (native.wei > 0 or native_status == NATIVE_STATUS_PROVEN_ZERO):
        native_usd = (native.wei / 1e18) * native.price_usd if native.price_usd is not None else None
        written.append(
            ContractBalance(
                contract_id=contract.id,
                token_address=None,
                token_name=native.name,
                token_symbol=native.symbol,
                decimals=18,
                raw_balance=str(native.wei),
                price_usd=native.price_usd,
                usd_value=round(native_usd, 2) if native_usd is not None else None,
                observed_address=observed_address,
                block_number=native.block_number,
                fetch_id=fetch.id,
                source=(
                    BALANCE_SOURCE_PINNED_NATIVE_READ
                    if native.block_number is not None
                    else BALANCE_SOURCE_UNPINNED_NATIVE_READ
                ),
            )
        )

    for token in sorted(assets):
        row = assets[token]
        written.append(
            ContractBalance(
                contract_id=contract.id,
                token_address=row["token_address"],
                token_name=row["token_name"],
                token_symbol=row["token_symbol"],
                decimals=row["decimals"],
                raw_balance=str(row["raw_balance"]),
                price_usd=row["price_usd"],
                usd_value=row["usd_value"],
                observed_address=observed_address,
                # ERC-20 quantities from the page are unpinned ``tag=latest``
                # answers and the schema refuses a height on them, so sweep-read
                # quantities — which DO have one — record it in the fetch's
                # ``swept_through_block`` rather than on the row.
                block_number=None,
                fetch_id=fetch.id,
                source=row["source"],
            )
        )

    for row_obj in written:
        session.add(row_obj)

    prune_balance_fetches(session, contract.id, observed_address)
    return RecordedObservation(
        fetch=fetch,
        asset_set_status=asset_set_status,
        asset_set_source=asset_set_source,
        native_status=native_status,
        rows=tuple(written),
    )


__all__ = [
    "AT_CAP_COMPLETENESS_MECHANISM",
    "ESCALATE_NO_FETCH_RECORD",
    "ESCALATE_PERSISTENT_FAILURE",
    "ESCALATE_RETURNED_EMPTY",
    "PERSISTENT_FAILURE_RUN",
    "SWEEP_POPULATION_NOTE",
    "NativeReading",
    "RecordedObservation",
    "SweepRequest",
    "escalation_reason",
    "fetch_asset_page",
    "known_swept_assets",
    "known_typed_assets",
    "scanned_from_block",
    "observation_contract",
    "record_observation",
    "run_sweeps",
    "sweep_from_block",
    "sweep_keeps_failing",
]
