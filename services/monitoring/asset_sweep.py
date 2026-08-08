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
reads what is still held. For an ERC-721/1155 receipt that round answers
nothing — 1155 has no ``balanceOf(address)`` — so the sweep also decodes the
TOKEN IDS out of the delivering logs and reads the holding per id. Those ids are
persisted with the receipt: they exist nowhere else in the pipeline, and a
record without them makes every later cycle re-scan the whole history to learn
what one scan already knew.

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
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

from services.resolution.repos.event_logs_rpc import (
    MAX_BLOCK_RANGE,
    MIN_BISECT_SPAN,
    FetchedEventLog,
    RpcEventLogFetcher,
)
from utils.balance_status import (
    SWEEP_STATUS_COMPLETED,
    SWEEP_STATUS_FAILED,
    TYPED_BASIS_ADDRESS_BALANCE,
    TYPED_BASIS_PER_ID_BALANCE_OF_BATCH,
    TYPED_BASIS_PER_ID_BALANCE_OF_ID,
    TYPED_BASIS_PER_ID_OWNER_OF,
    TYPED_STANDARD_ERC721,
    TYPED_STANDARD_ERC1155,
    TYPED_STANDARD_NOT_DETERMINED,
    TYPED_STANDARD_TRANSFER_NO_ID,
    TYPED_STANDARDS,
)
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
# ERC-1155 has no ``balanceOf(address)`` at all — the address-level call reverts,
# so an 1155 receipt's holding is not_determined for as long as the only thing
# asked is that selector. The call that DOES answer is per token id, and the ids
# exist nowhere but the logs that delivered them. That is why the sweep decodes
# the ids and PERSISTS them: an inventory recovered once is an inventory never
# re-scanned for.
_BALANCE_OF_BATCH_SELECTOR = selector("balanceOfBatch(address[],uint256[])")
_BALANCE_OF_ID_SELECTOR = selector("balanceOf(address,uint256)")
_OWNER_OF_SELECTOR = selector("ownerOf(uint256)")
_WORD_HEX_LEN = 66

# Token ids per ``balanceOfBatch`` sub-call. One aggregate3 carries many
# sub-calls, so this bounds the calldata (and the gas) of a single one rather
# than the request count.
_TYPED_ID_CALL_CHUNK = 100

# The standard and basis vocabularies are re-exported from the leaf module (as
# the sweep statuses are) so the producer, the fetch record and the PLANE that
# reads the record cannot drift on a literal — the plane's resolution rule turns
# on the pair (basis, ids_complete), so it needs the same tokens this writes.
_ID_BEARING_STANDARDS = (TYPED_STANDARD_ERC1155, TYPED_STANDARD_ERC721)


@dataclass(frozen=True)
class TypedItem:
    """One token id a typed receipt delivered, and what is still held of it.

    ``token_id`` is a DECIMAL STRING: ids are uint256 and routinely exceed what a
    JSON number survives, and this value is persisted and read back.
    ``quantity`` is ``None`` when the chain did not answer for that id — never 0,
    which is the answer this module exists to earn rather than assume.
    """

    token_id: str
    quantity: int | None


@dataclass(frozen=True)
class CarriedTypedReceipt:
    """A typed receipt read back off the stored fetch record.

    ``ids_complete`` is the load-bearing field: it says the stored id list is the
    UNION of every id the scans behind this set delivered, which is the only
    footing an "every id reads zero" claim can stand on. False means the
    inventory is a prefix (or absent), and a prefix resolves nothing.
    """

    address: str
    standard: str = TYPED_STANDARD_NOT_DETERMINED
    ids: tuple[str, ...] = ()
    ids_complete: bool = False


@dataclass(frozen=True)
class SweptAsset:
    """One asset a holder was ever sent, with what is still held."""

    token_address: str
    raw_balance: int | None
    decimals: int | None
    # ``erc20`` | ``typed`` — ``typed`` covers every 721/1155 receipt, whose
    # ``balanceOf`` is a COUNT of items and not a quantity of anything priceable.
    kind: str
    # The four fields below describe a TYPED receipt only; an ``erc20`` row
    # carries their defaults. They travel on the same dataclass because they
    # travel on the same list, and the list is what the fetch record persists.
    standard: str = TYPED_STANDARD_NOT_DETERMINED
    # Every id the scans behind this set delivered, with what is still held of
    # each. A per-id quantity of ``None`` is an id the chain did not answer for.
    items: tuple[TypedItem, ...] = ()
    ids_complete: bool = False
    # Which read produced ``raw_balance``; ``None`` when nothing did.
    quantity_basis: str | None = None


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


def _int_word(word: Any) -> int | None:
    """A 32-byte word as an int, or ``None`` if it is not one."""
    if not isinstance(word, str):
        return None
    try:
        return int(word, 16)
    except ValueError:
        return None


def _uint_array(words: list[str]) -> list[int] | None:
    """The ``uint256[]`` an ABI head/tail pair encodes, or ``None``.

    Followed through the head's OFFSET rather than read at a fixed index: the ABI
    puts the tail wherever the head points, and hard-coding word 2 as the length
    happens to work only for the canonical single-array layout. A layout this
    decoder cannot follow is refused outright — a short read here becomes a short
    id inventory, and a short inventory would let "every id reads zero" be
    published over ids nobody looked at.

    Shared by the ``TransferBatch`` id decode and the ``balanceOfBatch`` answer
    decode so the two cannot drift.
    """
    if not words:
        return None
    offset = _int_word(words[0])
    if offset is None or offset % 32:
        return None
    head = offset // 32
    if head >= len(words):
        return None
    length = _int_word(words[head])
    if length is None or length < 0 or head + 1 + length > len(words):
        return None
    values: list[int] = []
    for word in words[head + 1 : head + 1 + length]:
        value = _int_word(word)
        if value is None:
            return None
        values.append(value)
    return values


def _single_ids(words: list[str]) -> list[str] | None:
    """The one id a ``TransferSingle`` carries — ``None`` if the log is malformed.

    Both words are required: a log with the id but not the value is not the event
    this decoder claims to have read.
    """
    if len(words) < 2:
        return None
    token_id = _int_word(words[0])
    return None if token_id is None else [str(token_id)]


def _batch_ids(words: list[str]) -> list[str] | None:
    """The id array a ``TransferBatch`` carries — ``None`` if the log is malformed."""
    values = _uint_array(words)
    return None if values is None else [str(value) for value in values]


@dataclass
class TypedSighting:
    """What the delivering logs said about one (holder, token) typed receipt.

    ``malformed`` is a log this decoder could not read an id out of. The id set is
    then a PREFIX of the truth, and a prefix can never carry the all-quantifier
    behind a resolved receipt — so one malformed log withholds the whole token's
    inventory rather than shortening it.
    """

    standard: str | None = None
    ids: set[str] = field(default_factory=set)
    malformed: bool = False

    def observe(self, standard: str) -> None:
        # Two standards on one token is a contradiction, not a majority vote:
        # neither selector can be trusted, so no per-id read is issued for it.
        if self.standard is None or self.standard == standard:
            self.standard = standard
        else:
            self.standard = TYPED_STANDARD_NOT_DETERMINED


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
) -> tuple[dict[str, set[str]], dict[str, dict[str, TypedSighting]], str | None]:
    """Every asset that ever sent one of *addresses* a transfer in the range.

    Returns ``(erc20_by_holder, typed_by_holder, failure)``. The typed half is
    keyed by token and carries the standard and the token ids its delivering logs
    named — the only place those ids ever exist, since nothing else in the
    pipeline stores a log. ``failure`` is a string on the truncation/
    exhausted-bisect path and aborts EVERY holder in the batch: the logs that did
    come back cannot be attributed a completeness they do not have, and a
    per-holder rescue would publish a prefix as a whole list.
    """
    scanner = fetcher or _CountingFetcher(
        rpc_url, chain_id=chain_id, cost=cost, result_cap=SWEEP_RESULT_CAP, budget=SWEEP_REQUEST_BUDGET
    )
    wanted = {a.lower() for a in addresses}
    erc20: dict[str, set[str]] = {a: set() for a in wanted}
    typed: dict[str, dict[str, TypedSighting]] = {a: {} for a in wanted}
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
    typed: dict[str, dict[str, TypedSighting]],
) -> None:
    for log in logs:
        if len(log.topics) <= position or not log.address:
            continue
        holder = _addr_from_topic(log.topics[position])
        if holder not in wanted:
            continue
        topic0 = log.topics[0]
        token = log.address.lower()
        # A 4-topic Transfer indexes tokenId: ERC-721. A 3-topic one is the
        # ERC-20 shape. The 1155 topic0s are typed by definition. The standard is
        # RECORDED here rather than derived and dropped: it decides which selector
        # can read the holding later, and the logs it comes from are not stored.
        if topic0 in _ERC1155_TOPIC0S:
            sighting = typed[holder].setdefault(token, TypedSighting())
            sighting.observe(TYPED_STANDARD_ERC1155)
            ids = _single_ids(log.data_words) if topic0 == TRANSFER_SINGLE_TOPIC0 else _batch_ids(log.data_words)
            if ids is None:
                sighting.malformed = True
            else:
                sighting.ids.update(ids)
        elif topic0 == TRANSFER_TOPIC0 and len(log.topics) >= 4:
            sighting = typed[holder].setdefault(token, TypedSighting())
            sighting.observe(TYPED_STANDARD_ERC721)
            token_id = _int_word(log.topics[3])
            if token_id is None:
                sighting.malformed = True
            else:
                sighting.ids.add(str(token_id))
        elif topic0 == TRANSFER_TOPIC0:
            erc20[holder].add(token)


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


def _uint_word(value: int) -> str:
    return f"{value:064x}"


def _balance_of_batch_calldata(holder: str, ids: tuple[str, ...]) -> str:
    """``balanceOfBatch([holder]*n, ids)`` — one call for a whole id inventory.

    Hand-encoded rather than routed through an ABI encoder because the two array
    offsets are the only thing to get right and the shape is pinned by a test.
    """
    holder_word = holder.lower().removeprefix("0x").rjust(64, "0")
    count = len(ids)
    words = [
        _uint_word(64),  # accounts[] tail
        _uint_word(64 + 32 + 32 * count),  # ids[] tail, past accounts'
        _uint_word(count),
        *([holder_word] * count),
        _uint_word(count),
        *(_uint_word(int(token_id)) for token_id in ids),
    ]
    return _BALANCE_OF_BATCH_SELECTOR + "".join(words)


def _address_from_word(data: Any) -> str | None:
    if not isinstance(data, str) or len(data) != _WORD_HEX_LEN:
        return None
    return "0x" + data[-40:].lower()


def _data_words(data: Any) -> list[str] | None:
    if not isinstance(data, str) or not data.startswith("0x"):
        return None
    body = data[2:]
    if not body or len(body) % 64:
        return None
    return ["0x" + body[index : index + 64] for index in range(0, len(body), 64)]


def _calls_for(basis: str, holder: str, token: str, ids: tuple[str, ...]) -> list[tuple[str, str]]:
    holder_word = holder.lower().removeprefix("0x").rjust(64, "0")
    if basis == TYPED_BASIS_PER_ID_BALANCE_OF_BATCH:
        return [
            (token, _balance_of_batch_calldata(holder, ids[index : index + _TYPED_ID_CALL_CHUNK]))
            for index in range(0, len(ids), _TYPED_ID_CALL_CHUNK)
        ]
    if basis == TYPED_BASIS_PER_ID_BALANCE_OF_ID:
        return [(token, _BALANCE_OF_ID_SELECTOR + holder_word + _uint_word(int(token_id))) for token_id in ids]
    return [(token, _OWNER_OF_SELECTOR + _uint_word(int(token_id))) for token_id in ids]


def _quantities_for(basis: str, holder: str, chunk: list[tuple[bool, str]]) -> list[int] | None:
    """The per-id quantities one round's answers carry, or ``None`` if any is not one."""
    quantities: list[int] = []
    for ok, data in chunk:
        if not ok:
            return None
        if basis == TYPED_BASIS_PER_ID_BALANCE_OF_BATCH:
            decoded = _uint_array(_data_words(data) or [])
            if decoded is None:
                return None
            quantities.extend(decoded)
        elif basis == TYPED_BASIS_PER_ID_BALANCE_OF_ID:
            value = _int_word(data) if isinstance(data, str) and len(data) == _WORD_HEX_LEN else None
            if value is None:
                return None
            quantities.append(value)
        else:
            owner = _address_from_word(data)
            if owner is None:
                return None
            # ``ownerOf`` names the current owner; anyone else means the item
            # arrived and provably left.
            quantities.append(1 if owner == holder else 0)
    return quantities


# The read shapes, in the order they are tried. ERC-1155 mandates both selectors,
# but a token that emits conforming logs is not thereby a token that implements
# them: four contracts on this corpus revert ``balanceOfBatch`` and answer
# ``balanceOf(address,uint256)``. Trying the batch first keeps the common case at
# one sub-call per receipt; the fallback turns what would be an unreadable
# not_determined into a real reading, which is the whole point of asking.
_TYPED_ID_ROUNDS = (
    (TYPED_STANDARD_ERC1155, TYPED_BASIS_PER_ID_BALANCE_OF_BATCH),
    (TYPED_STANDARD_ERC1155, TYPED_BASIS_PER_ID_BALANCE_OF_ID),
    # ERC-721 has no batch read, and its ``balanceOf(address)`` already answered
    # wherever it was going to; reaching here means it did not.
    (TYPED_STANDARD_ERC721, TYPED_BASIS_PER_ID_OWNER_OF),
)


def read_typed_items(
    requests: list[tuple[str, str, str, tuple[str, ...]]],
    *,
    rpc_url: str,
    chain_id: int,
    block: int,
    cost: SweepCost,
) -> dict[tuple[str, str], tuple[tuple[TypedItem, ...], str]]:
    """Per-id holdings for the typed receipts whose address-level read said nothing.

    *requests* is ``[(holder, token, standard, ids), ...]``; the answer maps
    ``(holder, token)`` to its items and the basis that produced them. A key is
    ABSENT unless EVERY one of its ids answered in the same round: the claim a
    resolved receipt carries is an all-quantifier over the inventory, so one
    unanswered id refuses the whole receipt rather than shrinking it. A transport
    failure is not fatal to the sweep — the scan and its ids are still facts worth
    storing, and the receipts simply stay unresolved for another cycle, which is
    the direction that cannot publish a holding as nothing.

    Batched across every holder on the chain at one pinned block, so the cycle's
    id reads cost a request per round rather than a request per receipt.
    """
    out: dict[tuple[str, str], tuple[tuple[TypedItem, ...], str]] = {}
    for standard, basis in _TYPED_ID_ROUNDS:
        round_requests = [r for r in requests if r[2] == standard and (r[0], r[1]) not in out]
        if round_requests:
            out.update(
                _read_typed_round(
                    round_requests, basis=basis, rpc_url=rpc_url, chain_id=chain_id, block=block, cost=cost
                )
            )
    return out


def _read_typed_round(
    requests: list[tuple[str, str, str, tuple[str, ...]]],
    *,
    basis: str,
    rpc_url: str,
    chain_id: int,
    block: int,
    cost: SweepCost,
) -> dict[tuple[str, str], tuple[tuple[TypedItem, ...], str]]:
    calls: list[tuple[str, str]] = []
    plan: list[tuple[tuple[str, str], tuple[str, ...], int]] = []
    for holder, token, _standard, ids in requests:
        made = _calls_for(basis, holder, token, ids)
        calls.extend(made)
        plan.append(((holder, token), ids, len(made)))
    if not calls:
        return {}
    cost.multicall += (len(calls) + _MULTICALL3_CHUNK - 1) // _MULTICALL3_CHUNK
    try:
        results = multicall3_aggregate3(rpc_url, calls, hex(block), chain_id=chain_id)
    except Exception as exc:
        logger.info("asset sweep: per-id typed read (%s) failed on chain %s: %s", basis, chain_id, exc)
        return {}

    out: dict[tuple[str, str], tuple[tuple[TypedItem, ...], str]] = {}
    cursor = 0
    for key, ids, width in plan:
        chunk = results[cursor : cursor + width]
        cursor += width
        quantities = _quantities_for(basis, key[0], chunk)
        if quantities is None or len(quantities) != len(ids):
            # A short or unreadable answer is not a small holding. Left absent so
            # the receipt keeps refusing — and so the next round may still answer.
            continue
        out[key] = (
            tuple(TypedItem(token_id=token_id, quantity=q) for token_id, q in zip(ids, quantities, strict=True)),
            basis,
        )
    return out


@dataclass
class _PendingTyped:
    """One typed receipt after discovery, before its per-id read."""

    token: str
    standard: str
    ids: tuple[str, ...]
    ids_complete: bool
    # What ``balanceOf(address)`` said, or ``None`` when it said nothing. Not a
    # zero: ERC-1155 answers nothing to that selector by design.
    address_quantity: int | None


@dataclass
class _PendingHolder:
    """A holder whose scan completed, awaiting the batched per-id read."""

    address: str
    union_from: int
    assets: tuple[SweptAsset, ...]
    typed: list[_PendingTyped]


def _pending_typed(
    *,
    token: str,
    sighting: TypedSighting | None,
    carried: CarriedTypedReceipt | None,
    window_is_full_history: bool,
    address_quantity: int | None,
) -> _PendingTyped:
    """Merge what this window saw with what the record carried, for one token.

    ``ids_complete`` is the whole point. A window that started at block 0 IS the
    full history, so whatever it saw is the whole inventory — including seeing
    nothing, which settles the inventory as empty rather than as unknown. A later
    incremental window inherits completeness only from a record that already had
    it. Either way a malformed log takes it away: a prefix inventory resolves
    nothing.
    """
    ids = set(carried.ids if carried else ())
    standard = carried.standard if carried else TYPED_STANDARD_NOT_DETERMINED
    malformed = False
    if sighting is not None:
        ids |= sighting.ids
        malformed = sighting.malformed
        if sighting.standard is not None:
            if standard in (TYPED_STANDARD_NOT_DETERMINED, TYPED_STANDARD_TRANSFER_NO_ID):
                standard = sighting.standard
            elif standard != sighting.standard:
                standard = TYPED_STANDARD_NOT_DETERMINED
    carried_complete = bool(carried and carried.ids_complete)
    return _PendingTyped(
        token=token,
        standard=standard,
        ids=tuple(sorted(ids, key=int)),
        ids_complete=(window_is_full_history or carried_complete) and not malformed,
        address_quantity=address_quantity,
    )


def _typed_swept_asset(item: _PendingTyped, resolved: tuple[tuple[TypedItem, ...], str] | None) -> SweptAsset:
    """One typed receipt as the fetch record will store it.

    Order of evidence: an address-level answer wins, because it was read against
    the holder's whole position rather than an id list. Failing that, an id
    inventory every one of whose ids answered gives the count. Failing THAT the
    quantity stays ``None`` — the ids are still stored, so the next cycle retries
    the read alone instead of the scan.
    """
    unread = tuple(TypedItem(token_id=token_id, quantity=None) for token_id in item.ids)
    if item.address_quantity is not None:
        return SweptAsset(
            token_address=item.token,
            raw_balance=item.address_quantity,
            decimals=None,
            kind="typed",
            standard=item.standard,
            items=unread,
            ids_complete=item.ids_complete,
            quantity_basis=TYPED_BASIS_ADDRESS_BALANCE,
        )
    if resolved is None:
        return SweptAsset(
            token_address=item.token,
            raw_balance=None,
            decimals=None,
            kind="typed",
            standard=item.standard,
            items=unread,
            ids_complete=item.ids_complete,
            quantity_basis=None,
        )
    items, basis = resolved
    return SweptAsset(
        token_address=item.token,
        raw_balance=sum(entry.quantity or 0 for entry in items),
        decimals=None,
        kind="typed",
        standard=item.standard,
        items=items,
        ids_complete=item.ids_complete,
        quantity_basis=basis,
    )


def _resolve_pending(
    pending: list[_PendingHolder],
    *,
    rpc_url: str,
    chain_id: int,
    head: int,
    cost: SweepCost,
) -> dict[str, SweepOutcome]:
    """The per-id read for a whole chain cohort, then the outcomes it completes."""
    requests = [
        (holder.address, item.token, item.standard, item.ids)
        for holder in pending
        for item in holder.typed
        # Only where the cheap read said nothing, only where the inventory is
        # whole, and only for a standard whose selector is known. An empty id list
        # is not an all-quantifier worth publishing — it is a receipt whose
        # delivering logs named no id, which stays unresolved.
        if item.address_quantity is None and item.ids and item.ids_complete and item.standard in _ID_BEARING_STANDARDS
    ]
    resolved = read_typed_items(requests, rpc_url=rpc_url, chain_id=chain_id, block=head, cost=cost)
    return {
        holder.address: SweepOutcome(
            address=holder.address,
            status=SWEEP_COMPLETED,
            swept_from_block=holder.union_from,
            swept_through_block=head,
            assets=holder.assets,
            typed_assets=tuple(
                _typed_swept_asset(item, resolved.get((holder.address, item.token))) for item in holder.typed
            ),
            basis=_basis(holder.union_from, head),
        )
        for holder in pending
    }


def sweep_holders(
    addresses: list[str],
    *,
    rpc_url: str,
    chain_id: int,
    from_block_by_address: dict[str, int],
    known_assets_by_address: dict[str, tuple[str, ...]] | None = None,
    known_typed_by_address: dict[str, tuple[CarriedTypedReceipt, ...]] | None = None,
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
    the fungible set would launder a count into an 18-decimal quantity. It also
    carries the token IDS a previous scan decoded, which is what lets an
    incremental window read an ERC-1155 holding at all: the ids live only in the
    delivering logs, and those are long past the cursor.

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

    def carried_of(address: str) -> dict[str, CarriedTypedReceipt]:
        return {r.address: r for r in (known_typed_by_address or {}).get(address, ())}

    by_start: dict[int, list[str]] = {}
    for address in addresses:
        lowered = address.lower()
        by_start.setdefault(from_block_by_address.get(lowered, 0), []).append(lowered)

    # Holders whose scan completed, held back until the per-id typed read can run
    # once for the whole chain rather than once per holder.
    pending: list[_PendingHolder] = []

    for start, cohort in sorted(by_start.items()):
        if start > head:
            # Already swept past the current head: no NEW asset can have arrived,
            # which says nothing about the ones already known. Skipping the read
            # here published an empty asset set for a holder whose sheet the last
            # cycle filled — the view takes a fetch's rows wholesale, so an
            # unread set reads as a sale, and an unread typed receipt reads as a
            # completeness this scan never established.
            for address in cohort:
                carried_or_failed = _read_carried_set(
                    address,
                    known_assets=tuple((known_assets_by_address or {}).get(address, ())),
                    carried_typed=carried_of(address),
                    union_from=(union_from_by_address or {}).get(address, start),
                    rpc_url=rpc_url,
                    chain_id=chain_id,
                    head=head,
                    cost=cost,
                )
                if isinstance(carried_or_failed, SweepOutcome):
                    outcomes[address] = carried_or_failed
                else:
                    pending.append(carried_or_failed)
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
                carried = carried_of(address)
                sightings = typed.get(address, {})
                # A carried typed asset stays typed. It was classified by the log
                # that delivered it — a 4-topic Transfer or an 1155 topic0 — and
                # that classification is a fact about the asset, not about which
                # window happened to see it. Folding it into the fungible set on
                # a later cycle turns an item COUNT into an 18-decimal quantity.
                typed_tokens = sorted(set(sightings) | set(carried))
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
                pending.append(
                    _PendingHolder(
                        address=address,
                        union_from=union_from,
                        assets=tuple(
                            SweptAsset(
                                token_address=t,
                                raw_balance=balances[t][0],
                                decimals=balances[t][1],
                                kind="erc20",
                            )
                            for t in erc20_tokens
                        ),
                        typed=[
                            _pending_typed(
                                token=t,
                                sighting=sightings.get(t),
                                carried=carried.get(t),
                                window_is_full_history=start == 0,
                                address_quantity=typed_balances.get(t, (None, None))[0],
                            )
                            for t in typed_tokens
                        ]
                        + [_no_id_typed(t) for t in unreadable],
                    )
                )
    outcomes.update(_resolve_pending(pending, rpc_url=rpc_url, chain_id=chain_id, head=head, cost=cost))
    return outcomes, cost


def _no_id_typed(token: str) -> _PendingTyped:
    """A fungible-shaped token whose ``balanceOf(address)`` returned no word.

    Its delivering log carried no id, so its inventory is settled as empty and it
    will never demand another full-history scan — and it stays unresolved, since
    an unreadable balance is not a zero.
    """
    return _PendingTyped(
        token=token,
        standard=TYPED_STANDARD_TRANSFER_NO_ID,
        ids=(),
        ids_complete=True,
        address_quantity=None,
    )


def _read_carried_set(
    address: str,
    *,
    known_assets: tuple[str, ...],
    carried_typed: dict[str, CarriedTypedReceipt],
    union_from: int,
    rpc_url: str,
    chain_id: int,
    head: int,
    cost: SweepCost,
) -> _PendingHolder | SweepOutcome:
    """Re-read a holder's already-discovered set when no window has to be scanned.

    The typed set is subtracted from the fungible one FIRST, exactly as the
    windowed path does. The two carried lists overlap by construction — a typed
    asset with a readable count is stored as a row, and the stored-row reader
    that supplies ``known_assets`` cannot tell a count row from a quantity row —
    so partitioning ``known_assets`` on its own would re-emit an ERC-721 as
    ``erc20``, and its reverting ``decimals()`` would then present a count as an
    18-decimal quantity.

    Returns a ``SweepOutcome`` only for the aborted read; otherwise the holder
    joins the cohort's batched per-id round like any other.
    """
    known_typed = tuple(sorted(carried_typed))
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
    return _PendingHolder(
        address=address,
        union_from=union_from,
        assets=tuple(
            SweptAsset(token_address=t, raw_balance=balances[t][0], decimals=balances[t][1], kind="erc20")
            for t in readable
        ),
        typed=[
            # No window was scanned this cycle, so nothing was sighted and
            # completeness can only be what the record already carried — a
            # full-history UNION behind the set is not itself evidence that the
            # scan which built it kept an id inventory.
            _pending_typed(
                token=t,
                sighting=None,
                carried=carried_typed.get(t),
                window_is_full_history=False,
                address_quantity=typed_balances.get(t, (None, None))[0],
            )
            for t in known_typed
        ]
        + [_no_id_typed(t) for t in unreadable],
    )


def _basis(from_block: int, through_block: int) -> str:
    """The extent of the CLAIM, which is the union of the scans behind the set —
    never the width of the last incremental window."""
    return (
        f"full-history log scan of Transfer/TransferSingle/TransferBatch with the holder as recipient "
        f"(topic 2 for ERC-20/721, topic 3 for ERC-1155), blocks {from_block}-{through_block}, "
        f"window {MAX_BLOCK_RANGE} with an explicit {SWEEP_RESULT_CAP}-log cap; "
        f"balances read by Multicall3 at block {through_block}, and typed (ERC-721/1155) receipts whose "
        f"balanceOf(address) does not answer read per token id over the ids their delivering logs carried "
        f"(balanceOfBatch, then balanceOf(address,uint256) for a token that reverts the batch selector, "
        f"then ownerOf for ERC-721)"
    )


def carried_typed_receipt(entry: Mapping[str, Any]) -> CarriedTypedReceipt:
    """One stored ``typed_assets`` entry, read back for the next scan.

    An id inventory is carried only when the record says it is COMPLETE and every
    id in it parses. A partial or unparseable list is dropped rather than carried
    as if it were most of the truth: the cursor rule sends such a record back for
    a full re-scan, which re-derives the ids from the logs, and carrying a prefix
    in the meantime could only make a later union look whole when it is not.
    """
    ids: tuple[str, ...] = ()
    complete = False
    raw_ids = entry.get("ids")
    if entry.get("ids_complete") is True and isinstance(raw_ids, list):
        parsed = [item.get("id") for item in raw_ids if isinstance(item, dict)]
        if len(parsed) == len(raw_ids) and all(isinstance(value, str) and value.isdigit() for value in parsed):
            ids = tuple(sorted({str(value) for value in parsed}, key=int))
            complete = True
    standard = entry.get("standard")
    return CarriedTypedReceipt(
        address=str(entry.get("address") or "").lower(),
        standard=standard if standard in TYPED_STANDARDS else TYPED_STANDARD_NOT_DETERMINED,
        ids=ids,
        ids_complete=complete,
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
    "TYPED_BASIS_ADDRESS_BALANCE",
    "TYPED_BASIS_PER_ID_BALANCE_OF_BATCH",
    "TYPED_BASIS_PER_ID_BALANCE_OF_ID",
    "TYPED_BASIS_PER_ID_OWNER_OF",
    "TYPED_STANDARDS",
    "TYPED_STANDARD_ERC721",
    "TYPED_STANDARD_ERC1155",
    "TYPED_STANDARD_NOT_DETERMINED",
    "TYPED_STANDARD_TRANSFER_NO_ID",
    "CarriedTypedReceipt",
    "SweepCost",
    "SweepOutcome",
    "SweptAsset",
    "TypedItem",
    "TypedSighting",
    "carried_typed_receipt",
    "discover_recipient_assets",
    "read_balances",
    "read_typed_items",
    "sweep_head_block",
    "sweep_holders",
]
