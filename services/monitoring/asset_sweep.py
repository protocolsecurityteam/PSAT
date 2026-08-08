"""Chain-derived asset discovery — the escalation behind Etherscan's negative.

A third-party index's POSITIVE answer ("here are 24 tokens") is a floor:
under-indexing can only make the truth larger. Its NEGATIVE answer ("no token
found") is a completeness claim about that index, and this pipeline never
outsources a negative. So Etherscan's empty list is a TRIGGER, and what gets
published rests on this module: the chain's own log history, which every
conforming transfer must write to.

What the sweep is, exactly: for a batch of holders, every ``Transfer`` /
``TransferSingle`` / ``TransferBatch`` log that named one of them as recipient,
from genesis (or from a stored cursor) through a named block. The emitters of
those logs are the candidate asset list; a Multicall3 ``balanceOf`` round then
reads what is still held.

What it is NOT: proof of nothing. Four structural blind spots exist and each is
guarded rather than assumed away — see :class:`SweepOutcome`'s ``failure_reason``
(truncation), the 1155 topics in :data:`SWEEP_TOPIC0S` (multi-token standards),
:attr:`SweepOutcome.typed_assets` (721/1155 balances are COUNTS, never money),
and the basis string (assets that move without logs). A caller may publish
"empty" only from ``status == SWEEP_COMPLETED``, and even then only with the
native leg and the NFT gate satisfied.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from eth_utils.crypto import keccak

from services.resolution.repos.event_logs_rpc import (
    MAX_BLOCK_RANGE,
    MIN_BISECT_SPAN,
    FetchedEventLog,
    RpcEventLogFetcher,
)
from utils.balance_status import SWEEP_STATUS_COMPLETED, SWEEP_STATUS_FAILED
from utils.rpc import _MULTICALL3_CHUNK, MULTICALL3_ADDRESS, multicall3_aggregate3, rpc_request, selector

logger = logging.getLogger(__name__)


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


# ERC-20 and ERC-721 share this topic0; they are told apart by topic COUNT (721
# indexes tokenId as a fourth topic), never by a token list.
TRANSFER_TOPIC0 = _topic0("Transfer(address,address,uint256)")
TRANSFER_SINGLE_TOPIC0 = _topic0("TransferSingle(address,address,address,uint256,uint256)")
TRANSFER_BATCH_TOPIC0 = _topic0("TransferBatch(address,address,address,uint256[],uint256[])")

# The full topic0 set. A Transfer-only sweep is blind to ERC-1155 entirely, and
# a blind spot that cheap is not disclosable — it is fixable, at the same window
# count, by asking for the other two topic0s in the same request.
SWEEP_TOPIC0S = (TRANSFER_TOPIC0, TRANSFER_SINGLE_TOPIC0, TRANSFER_BATCH_TOPIC0)
_ERC1155_TOPIC0S = (TRANSFER_SINGLE_TOPIC0, TRANSFER_BATCH_TOPIC0)

# Where the RECIPIENT sits, per standard. ERC-20/721 index ``(from, to)``, so the
# recipient is topic 2. ERC-1155 indexes ``(operator, from, to)``, so it is topic
# 3 — and a sweep that filtered only topic 2 would see 1155 sends and miss 1155
# RECEIPTS, i.e. exactly the direction that refutes "holds nothing". Two passes,
# not one, for that reason.
_RECIPIENT_PASSES = (
    (2, SWEEP_TOPIC0S),
    (3, _ERC1155_TOPIC0S),
)

# The upstream is believed to serve whole pages, but "believed" is not a witness:
# passing an explicit cap turns a page that reaches it into a REJECT the fetcher
# bisects, and a bisect that reaches the floor into a raise. Without a cap the
# silent-truncation branch cannot fire at all and a truncated window reads as
# "few transfers" — the eRPC silent-30k-getLogs-cap shape. Deliberately NOT read
# from ``PSAT_GETLOGS_RESULT_CAP``: that env is the durable indexer's builder
# default, and setting it in-process would change the indexer's behaviour.
SWEEP_RESULT_CAP = 40_000

# Holders per getLogs request. The filter is an OR-set in one topic position, so
# a batch is one request per window rather than one per holder.
SWEEP_ADDRESS_BATCH = 40

# Steps back from head. The sweep's through-block must be a block the upstream
# has certainly seen, since it is published as the extent of the claim.
SWEEP_FINALITY_MARGIN = 12

# Requests one producer cycle's sweep may spend, across every chain and holder.
# A quiet holder costs ~1 request per 1M-block window; a holder with a dense
# incoming-transfer history bisects toward MIN_BISECT_SPAN and can cost four
# figures on its own. Without a ceiling one such address turns an hourly loop
# into a standing bill against a metered API. Exceeding it does NOT shorten
# anyone's asset list: every holder not yet swept is recorded as a typed sweep
# FAILURE, which publishes no completeness and no cursor, so the next cycle
# starts the same scan from the same block.
SWEEP_REQUEST_BUDGET = int(os.getenv("PSAT_SWEEP_REQUEST_BUDGET", "1500"))

# Re-exported from the leaf vocabulary so the producer, the schema and this
# module cannot drift on the literal.
SWEEP_COMPLETED = SWEEP_STATUS_COMPLETED
SWEEP_FAILED = SWEEP_STATUS_FAILED

_BALANCE_OF_SELECTOR = selector("balanceOf(address)")
_DECIMALS_SELECTOR = selector("decimals()")
_WORD_HEX_LEN = 66


@dataclass(frozen=True)
class SweptAsset:
    """One asset a holder was ever sent, with what is still held."""

    token_address: str
    raw_balance: int | None
    decimals: int | None
    # ``erc20`` | ``typed`` — ``typed`` covers every 721/1155 receipt, whose
    # ``balanceOf`` is a COUNT of items and not a quantity of anything priceable.
    kind: str


@dataclass(frozen=True)
class SweepOutcome:
    """What one holder's sweep established.

    ``status == SWEEP_FAILED`` means the claim is ABORTED, not that the holder is
    empty: a partial asset list is a floor with no upper bound, and the whole
    point of the sweep is the upper bound. ``failure_reason`` names which guard
    fired.

    ``typed_assets`` are ERC-721/1155 receipts. Their presence refuses
    proven-empty outright — "holds nothing" is false — while their ``balanceOf``
    is a count that must never be summed into a USD sheet.
    """

    address: str
    status: str
    # The first block of the UNION of the scans behind this asset set, not this
    # cycle's window start: the basis string publishes the extent of the claim,
    # and an incremental window rests on the full-history scan that preceded it.
    swept_from_block: int
    swept_through_block: int | None
    assets: tuple[SweptAsset, ...] = ()
    typed_assets: tuple[SweptAsset, ...] = ()
    failure_reason: str | None = None
    basis: str = ""


@dataclass
class SweepCost:
    """Real request counts, so a cost estimate can be checked rather than quoted."""

    get_logs: int = 0
    multicall: int = 0
    head_reads: int = 0
    windows: list[tuple[int, int, int]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.get_logs + self.multicall + self.head_reads


class SweepBudgetExceeded(RuntimeError):
    """The cycle's request ceiling was reached mid-scan.

    A RuntimeError subclass so the fetcher's bisect-on-reject path treats it like
    any other upstream refusal — except that bisecting spends MORE requests, so
    the budget check fires again immediately at the narrower span and the whole
    scan unwinds instead of grinding down to the floor.
    """


class _CountingFetcher(RpcEventLogFetcher):
    """The sweep's OWN fetcher: explicit ``result_cap``, counted and budgeted."""

    def __init__(self, rpc_url: str, *, chain_id: int, cost: SweepCost, result_cap: int, budget: int) -> None:
        super().__init__(rpc_url, chain_id=chain_id, result_cap=result_cap)
        self._cost = cost
        self._budget = budget

    def _fetch_range(self, event_address, topics, from_block, to_block, window_stats=None):  # type: ignore[no-untyped-def]
        if self._cost.total >= self._budget:
            raise SweepBudgetExceeded(f"sweep request budget of {self._budget} reached")
        self._cost.get_logs += 1
        return super()._fetch_range(event_address, topics, from_block, to_block, window_stats)


def _pad32(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _addr_from_topic(topic: str) -> str:
    return "0x" + topic[-40:].lower()


def sweep_head_block(rpc_url: str, *, chain_id: int, cost: SweepCost) -> int | None:
    """The block the sweep claims through, or ``None`` if the head is unknown."""
    try:
        cost.head_reads += 1
        raw = rpc_request(rpc_url, "eth_blockNumber", [], retries=1, chain_id=chain_id)
        head = int(raw, 16)
    except Exception as exc:
        logger.info("asset sweep: head read failed on chain %s: %s", chain_id, exc)
        return None
    return max(0, head - SWEEP_FINALITY_MARGIN)


def discover_recipient_assets(
    addresses: list[str],
    *,
    rpc_url: str,
    chain_id: int,
    from_block: int,
    to_block: int,
    cost: SweepCost,
    fetcher: RpcEventLogFetcher | None = None,
) -> tuple[dict[str, set[str]], dict[str, set[str]], str | None]:
    """Every asset that ever sent one of *addresses* a transfer in the range.

    Returns ``(erc20_by_holder, typed_by_holder, failure)``. ``failure`` is a
    string on the truncation/exhausted-bisect path and aborts EVERY holder in the
    batch: the logs that did come back cannot be attributed a completeness they
    do not have, and a per-holder rescue would publish a prefix as a whole list.
    """
    scanner = fetcher or _CountingFetcher(
        rpc_url, chain_id=chain_id, cost=cost, result_cap=SWEEP_RESULT_CAP, budget=SWEEP_REQUEST_BUDGET
    )
    wanted = {a.lower() for a in addresses}
    erc20: dict[str, set[str]] = {a: set() for a in wanted}
    typed: dict[str, set[str]] = {a: set() for a in wanted}
    padded = [_pad32(a) for a in sorted(wanted)]

    for position, topic0s in _RECIPIENT_PASSES:
        slots: list[object] = [list(topic0s), None, None, None][: position + 1]
        slots[position] = padded
        try:
            logs = scanner.fetch_logs(
                event_address=None,
                topics=slots,
                from_block=from_block,
                to_block=to_block,
            )
        except SweepBudgetExceeded as exc:
            return erc20, typed, f"scan abandoned at topic position {position}: {exc}"
        except RuntimeError as exc:
            # The fetcher bisects on reject and on a page that reaches the cap;
            # reaching here means it hit MIN_BISECT_SPAN and could not prove the
            # window whole. Fail closed for the batch.
            return (
                erc20,
                typed,
                (
                    f"getLogs window could not be proven whole at topic position {position} "
                    f"(bisect floor {MIN_BISECT_SPAN}, cap {SWEEP_RESULT_CAP}): {exc}"
                ),
            )
        _attribute(logs, position=position, wanted=wanted, erc20=erc20, typed=typed)
    return erc20, typed, None


def _attribute(
    logs: list[FetchedEventLog],
    *,
    position: int,
    wanted: set[str],
    erc20: dict[str, set[str]],
    typed: dict[str, set[str]],
) -> None:
    for log in logs:
        if len(log.topics) <= position or not log.address:
            continue
        holder = _addr_from_topic(log.topics[position])
        if holder not in wanted:
            continue
        topic0 = log.topics[0]
        # A 4-topic Transfer indexes tokenId: ERC-721. A 3-topic one is the
        # ERC-20 shape. The 1155 topic0s are typed by definition.
        if topic0 in _ERC1155_TOPIC0S or (topic0 == TRANSFER_TOPIC0 and len(log.topics) >= 4):
            typed[holder].add(log.address.lower())
        elif topic0 == TRANSFER_TOPIC0:
            erc20[holder].add(log.address.lower())


def read_balances(
    holder: str,
    tokens: list[str],
    *,
    rpc_url: str,
    chain_id: int,
    block: int,
    cost: SweepCost,
) -> tuple[dict[str, tuple[int | None, int | None]], bool]:
    """``({token: (raw_balance, decimals)}, transport_failed)`` at ONE pinned block.

    A token whose ``balanceOf`` did not return a full word is absent from the
    mapping: an undecodable answer is not a zero, and letting it become one would
    mint the exact proven-nothing this module exists to earn honestly. That is a
    per-ASSET outcome (ERC-1155 has no ``balanceOf(address)`` at all, so it is
    the normal answer for one) and the caller downgrades the sheet's completeness
    for it. ``transport_failed`` is the different thing: the batch never
    answered, so nothing at all was read and the whole claim aborts.
    """
    if not tokens:
        return {}, False
    holder_word = holder.lower().removeprefix("0x").rjust(64, "0")
    calls: list[tuple[str, str]] = []
    for token in tokens:
        calls.append((token, _BALANCE_OF_SELECTOR + holder_word))
        calls.append((token, _DECIMALS_SELECTOR))
    cost.multicall += (len(calls) + _MULTICALL3_CHUNK - 1) // _MULTICALL3_CHUNK
    try:
        results = multicall3_aggregate3(rpc_url, calls, hex(block), chain_id=chain_id)
    except Exception as exc:
        logger.info("asset sweep: balanceOf batch failed for %s on chain %s: %s", holder, chain_id, exc)
        return {}, True
    out: dict[str, tuple[int | None, int | None]] = {}
    for index, token in enumerate(tokens):
        ok_balance, balance_data = results[2 * index]
        ok_decimals, decimals_data = results[2 * index + 1]
        balance = None
        if ok_balance and isinstance(balance_data, str) and len(balance_data) == _WORD_HEX_LEN:
            try:
                balance = int(balance_data, 16)
            except ValueError:
                balance = None
        decimals = None
        if ok_decimals and isinstance(decimals_data, str) and len(decimals_data) == _WORD_HEX_LEN:
            try:
                parsed = int(decimals_data, 16)
            except ValueError:
                parsed = -1
            if 0 <= parsed <= 77:
                decimals = parsed
        if balance is not None:
            out[token] = (balance, decimals)
    return out, False


def sweep_holders(
    addresses: list[str],
    *,
    rpc_url: str,
    chain_id: int,
    from_block_by_address: dict[str, int],
    known_assets_by_address: dict[str, tuple[str, ...]] | None = None,
    known_typed_by_address: dict[str, tuple[str, ...]] | None = None,
    union_from_by_address: dict[str, int] | None = None,
    cost: SweepCost | None = None,
    fetcher: RpcEventLogFetcher | None = None,
    head_block: int | None = None,
) -> tuple[dict[str, SweepOutcome], SweepCost]:
    """Sweep a batch of holders on one chain.

    ``from_block_by_address`` carries each holder's cursor: 0 for a holder never
    swept, ``swept_through_block + 1`` for one that has been. Holders sharing a
    cursor share windows, which is what makes the incremental pass one request
    per chain rather than one per contract.

    ``known_assets_by_address`` is what a PREVIOUS sweep already discovered for
    that holder, and passing it is not an optimisation: an incremental window
    only ever names assets that arrived INSIDE it, so a cycle that read only the
    window would publish a row set missing every asset that arrived earlier —
    and the balance view takes a fetch's row set wholesale, so the omission reads
    as a sale. The known list is re-read at the new block alongside whatever the
    window found.

    ``known_typed_by_address`` is the same carry-forward for ERC-721/1155
    receipts, and it is load-bearing rather than symmetric: a typed receipt whose
    holding cannot be read is the EVIDENCE that the asset set may not be
    published as complete, and dropping it after one cycle publishes the earned
    negative the scan refused. A carried typed asset stays typed — its
    ``balanceOf`` is a count of items when it answers at all, and folding it into
    the fungible set would launder a count into an 18-decimal quantity.

    ``union_from_by_address`` is the first block of the union of the scans behind
    each holder's current set; the outcome republishes it so the basis string
    names the extent of the CLAIM rather than of this cycle's window.
    """
    cost = cost if cost is not None else SweepCost()
    outcomes: dict[str, SweepOutcome] = {}
    if not addresses:
        return outcomes, cost
    head = head_block if head_block is not None else sweep_head_block(rpc_url, chain_id=chain_id, cost=cost)
    if head is None:
        for address in addresses:
            outcomes[address.lower()] = SweepOutcome(
                address=address.lower(),
                status=SWEEP_FAILED,
                swept_from_block=from_block_by_address.get(address.lower(), 0),
                swept_through_block=None,
                failure_reason="chain head unknown; a scan with no named end block claims nothing",
            )
        return outcomes, cost

    by_start: dict[int, list[str]] = {}
    for address in addresses:
        lowered = address.lower()
        by_start.setdefault(from_block_by_address.get(lowered, 0), []).append(lowered)

    for start, cohort in sorted(by_start.items()):
        if start > head:
            # Already swept past the current head: no NEW asset can have arrived,
            # which says nothing about the ones already known. Skipping the read
            # here published an empty asset set for a holder whose sheet the last
            # cycle filled — the view takes a fetch's rows wholesale, so an
            # unread set reads as a sale, and an unread typed receipt reads as a
            # completeness this scan never established.
            for address in cohort:
                outcomes[address] = _read_carried_set(
                    address,
                    known_assets=tuple((known_assets_by_address or {}).get(address, ())),
                    known_typed=tuple((known_typed_by_address or {}).get(address, ())),
                    union_from=(union_from_by_address or {}).get(address, start),
                    rpc_url=rpc_url,
                    chain_id=chain_id,
                    head=head,
                    cost=cost,
                )
            continue
        for index in range(0, len(cohort), SWEEP_ADDRESS_BATCH):
            batch = cohort[index : index + SWEEP_ADDRESS_BATCH]
            erc20, typed, failure = discover_recipient_assets(
                batch,
                rpc_url=rpc_url,
                chain_id=chain_id,
                from_block=start,
                to_block=head,
                cost=cost,
                fetcher=fetcher,
            )
            for address in batch:
                if failure is not None:
                    outcomes[address] = SweepOutcome(
                        address=address,
                        status=SWEEP_FAILED,
                        swept_from_block=start,
                        swept_through_block=None,
                        failure_reason=failure,
                    )
                    continue
                known = set((known_assets_by_address or {}).get(address, ()))
                known_typed = set((known_typed_by_address or {}).get(address, ()))
                # A carried typed asset stays typed. It was classified by the log
                # that delivered it — a 4-topic Transfer or an 1155 topic0 — and
                # that classification is a fact about the asset, not about which
                # window happened to see it. Folding it into the fungible set on
                # a later cycle turns an item COUNT into an 18-decimal quantity.
                typed_tokens = sorted(typed.get(address, set()) | known_typed)
                erc20_tokens = sorted((erc20.get(address, set()) | known) - set(typed_tokens))
                balances, balance_transport_failed = read_balances(
                    address,
                    erc20_tokens,
                    rpc_url=rpc_url,
                    chain_id=chain_id,
                    block=head,
                    cost=cost,
                )
                typed_balances, typed_transport_failed = read_balances(
                    address,
                    typed_tokens,
                    rpc_url=rpc_url,
                    chain_id=chain_id,
                    block=head,
                    cost=cost,
                )
                if balance_transport_failed or typed_transport_failed:
                    # Nothing was read at all, so there is no row set and no
                    # completeness — a different thing from an asset that
                    # answered nothing.
                    outcomes[address] = SweepOutcome(
                        address=address,
                        status=SWEEP_FAILED,
                        swept_from_block=start,
                        swept_through_block=None,
                        failure_reason="balanceOf batch did not answer; no holdings were read",
                    )
                    continue
                # An asset that answered no word is not a zero and not a holding:
                # it joins the typed list, whose presence withholds the sheet's
                # completeness claim without discarding the assets that DID answer.
                unreadable = [t for t in erc20_tokens if t not in balances]
                erc20_tokens = [t for t in erc20_tokens if t in balances]
                union_from = (union_from_by_address or {}).get(address, start)
                outcomes[address] = SweepOutcome(
                    address=address,
                    status=SWEEP_COMPLETED,
                    swept_from_block=union_from,
                    swept_through_block=head,
                    assets=tuple(
                        SweptAsset(token_address=t, raw_balance=balances[t][0], decimals=balances[t][1], kind="erc20")
                        for t in erc20_tokens
                    ),
                    typed_assets=tuple(
                        SweptAsset(
                            token_address=t,
                            raw_balance=typed_balances.get(t, (None, None))[0],
                            decimals=None,
                            kind="typed",
                        )
                        for t in typed_tokens
                    )
                    + tuple(
                        SweptAsset(token_address=t, raw_balance=None, decimals=None, kind="typed") for t in unreadable
                    ),
                    basis=_basis(union_from, head),
                )
    return outcomes, cost


def _read_carried_set(
    address: str,
    *,
    known_assets: tuple[str, ...],
    known_typed: tuple[str, ...],
    union_from: int,
    rpc_url: str,
    chain_id: int,
    head: int,
    cost: SweepCost,
) -> SweepOutcome:
    """Re-read a holder's already-discovered set when no window has to be scanned.

    The typed set is subtracted from the fungible one FIRST, exactly as the
    windowed path does. The two carried lists overlap by construction — a typed
    asset with a readable count is stored as a row, and the stored-row reader
    that supplies ``known_assets`` cannot tell a count row from a quantity row —
    so partitioning ``known_assets`` on its own would re-emit an ERC-721 as
    ``erc20``, and its reverting ``decimals()`` would then present a count as an
    18-decimal quantity.
    """
    fungible = tuple(t for t in known_assets if t not in set(known_typed))
    balances, balance_failed = read_balances(
        address, list(fungible), rpc_url=rpc_url, chain_id=chain_id, block=head, cost=cost
    )
    typed_balances, typed_failed = read_balances(
        address, list(known_typed), rpc_url=rpc_url, chain_id=chain_id, block=head, cost=cost
    )
    if balance_failed or typed_failed:
        return SweepOutcome(
            address=address,
            status=SWEEP_FAILED,
            swept_from_block=union_from,
            swept_through_block=None,
            failure_reason="balanceOf batch did not answer; no holdings were read",
        )
    unreadable = [t for t in fungible if t not in balances]
    readable = [t for t in fungible if t in balances]
    return SweepOutcome(
        address=address,
        status=SWEEP_COMPLETED,
        swept_from_block=union_from,
        swept_through_block=head,
        assets=tuple(
            SweptAsset(token_address=t, raw_balance=balances[t][0], decimals=balances[t][1], kind="erc20")
            for t in readable
        ),
        typed_assets=tuple(
            SweptAsset(token_address=t, raw_balance=typed_balances.get(t, (None, None))[0], decimals=None, kind="typed")
            for t in known_typed
        )
        + tuple(SweptAsset(token_address=t, raw_balance=None, decimals=None, kind="typed") for t in unreadable),
        basis=_basis(union_from, head),
    )


def _basis(from_block: int, through_block: int) -> str:
    """The extent of the CLAIM, which is the union of the scans behind the set —
    never the width of the last incremental window."""
    return (
        f"full-history log scan of Transfer/TransferSingle/TransferBatch with the holder as recipient "
        f"(topic 2 for ERC-20/721, topic 3 for ERC-1155), blocks {from_block}-{through_block}, "
        f"window {MAX_BLOCK_RANGE} with an explicit {SWEEP_RESULT_CAP}-log cap; "
        f"balances read by Multicall3 at block {through_block}"
    )


__all__ = [
    "MULTICALL3_ADDRESS",
    "SWEEP_ADDRESS_BATCH",
    "SWEEP_COMPLETED",
    "SWEEP_FAILED",
    "SWEEP_REQUEST_BUDGET",
    "SWEEP_RESULT_CAP",
    "SweepBudgetExceeded",
    "SWEEP_TOPIC0S",
    "SweepCost",
    "SweepOutcome",
    "SweptAsset",
    "discover_recipient_assets",
    "read_balances",
    "sweep_head_block",
    "sweep_holders",
]
