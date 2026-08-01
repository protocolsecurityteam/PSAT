"""Per-node EigenLayer restaking position: the pinned reads and the record.

This plane publishes ONE quantity — a node's EigenLayer beaconChainETH
withdrawable shares — and it publishes it only where three independent reads
license it. Everything else about the node's money is ``not_determined`` here.

**What a published zero means, and what it does not.** Measured over the 26
enumerated nodes at block 25643300: every one has an EigenPod, and every one
reads 0 shares — while those 26 pods hold **374.148164612 ETH** between them at
that same block, one of them (``0x7474b357106e509918cd1db47c40a7d0d775d4c7``)
holding **exactly 320 ETH**. Summing ``eigenlayer_beacon_shares_wei`` over the
whole enumerated set therefore yields 0 wei against 374+ ETH of pod balances.
The column is named for its scope for that reason: it is not "what this node
holds", it is the EigenLayer beaconChainETH withdrawable-share accounting, and
the execution-layer native balances of the node and its pod are
``not_determined`` on this plane.

**Why every decode here is strict.** Measured at the same block:

* ``eth_call`` to a codeless address returns ``"0x"`` WITH success, and the
  EtherFiNode itself returns ``"0x"`` for any unknown selector. An empty return
  is not a zero, and a two-of-three reading of the identity legs would mint
  "proven no eigenpod, 0 shares" for an address whose own state was never read.
* ``DelegationManager.getWithdrawableShares`` returns ``[0]``/``[0]`` with
  success for a NONEXISTENT staker and for a WRONG strategy, byte-identical to
  the real 26/26 answer. The strategy is therefore witnessed from
  ``EigenPodManager.beaconChainETHStrategy()`` at the same block rather than
  written as a literal — the near-miss
  ``0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`` is eyeball-identical to the true
  ``0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeebeac0`` and answers 0 just as happily.
* ``EigenPodManager.podOwnerDepositShares`` is ``int256``, not ``uint256``
  (verified on implementation ``0xd22dd829779adbf3869fb224f703452f7f95e9db``;
  ``stakerDepositShares`` is the ``uint256`` one). Unsigned decoding of a
  negative would publish ~1.15e77.
* ``EigenPodManager.getPod`` returns a COMPUTED CREATE2 address for any input,
  including ``0x…deadbeef``. It is never used here; ``ownerToPod`` and
  ``hasPod`` are the mapping-backed witnesses.

The constraints in the migration are a backstop. This module decides the basis
FIRST and maps every shape that would violate one to NULL / ``not_determined``
before a row is constructed, so a CHECK firing in production would be a bug
here, not a guard doing its job.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract, RestakingPosition
from utils.restaking_status import (
    CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
    CROSS_READ_AGREE,
    CROSS_READ_DISAGREE_WITHIN_INVARIANT,
    CROSS_READ_INCONSISTENT,
    CROSS_READ_NOT_DETERMINED,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_NOT_DETERMINED,
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    NODE_SET_COMPLETENESS_NOT_DETERMINED,
    OBSERVING_SHARES_BASES,
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
    SHARES_BASIS_NOT_DETERMINED,
    SHARES_BASIS_READ_FAILED,
)
from utils.rpc import MULTICALL3_ADDRESS, multicall3_aggregate3, rpc_request, rpc_url_for_chain_id, selector

logger = logging.getLogger(__name__)

# Steps back from head before pinning, matching the balance plane's margin. The
# reads are ISSUED at this number, which is what lets the height be published as
# a witness of the read rather than an assumption about when a node answered.
PINNED_FINALITY_MARGIN = 12

# A 32-byte word, hex-encoded with the ``0x`` prefix. ``"0x"`` — which
# ``aggregate3`` reports with ``success=True`` for a sub-call that returned no
# data, and which a codeless address returns for ANY selector — is not a word.
WORD_HEX_LEN = 66

ZERO_ADDRESS = "0x" + "0" * 40

# Two's-complement bounds for the signed ``int256`` leg.
_INT256_MODULUS = 1 << 256
_INT256_MAX = (1 << 255) - 1

# Storage widths of the two pod-derived columns. A word above these is not a
# smaller number; it is a fact this schema cannot hold, i.e. a non-observation.
_INT32_MAX = (1 << 31) - 1
_INT64_MAX = (1 << 63) - 1


def _bounded(value: int | None, ceiling: int) -> int | None:
    """``value`` if the column can hold it, else ``None``. Never clamped."""
    if value is None or value > ceiling:
        return None
    return value


@dataclass(frozen=True)
class NodeReads:
    """Raw return data of the seven per-node reads, aligned to their selectors.

    ``None`` means the sub-call FAILED (reverted, ``success=False``, or the
    transport raised). A string is whatever the node returned, ``"0x"``
    included — the difference between those two is not meaningful here because
    both land on the same non-observing states, but keeping the raw value lets
    every decode be strict in one place.
    """

    get_eigen_pod: str | None
    owner_to_pod: str | None
    has_pod: str | None
    pod_owner_deposit_shares: str | None
    withdrawable_shares: str | None
    active_validator_count: str | None
    last_checkpoint_timestamp: str | None


def _hex_word_value(body: str) -> int | None:
    """64 hex NIBBLES as an unsigned int, or ``None``.

    ``bytes.fromhex`` rather than ``int(body, 16)`` because Python's ``int``
    accepts ``_`` separators and strips surrounding whitespace, so a 63-nibble
    return with a trailing newline parses as a perfectly clean value. That is a
    short return decoding to a number — precisely the shape the length check
    above it exists to reject, arriving through the parser instead of past it.
    """
    if len(body) != 64:
        return None
    try:
        data = bytes.fromhex(body)
    except ValueError:
        return None
    # ``bytes.fromhex`` ignores ASCII whitespace too, so a 62-nibble body with
    # two trailing spaces passes the length check above and decodes to 31 bytes.
    if len(data) != 32:
        return None
    return int.from_bytes(data, "big")


def decode_word(raw: object) -> int | None:
    """A full 32-byte word as an unsigned int, or ``None``.

    ``None`` for a failed call, a short return, ``"0x"``, or anything that is not
    64 hex digits. There is deliberately no lenient path: ``int("0x0", 16)`` is 0,
    so a decoder that tolerated short return data would mint a zero out of an
    empty return.
    """
    if not isinstance(raw, str) or len(raw) != WORD_HEX_LEN or not raw.startswith("0x"):
        return None
    return _hex_word_value(raw[2:])


def decode_int256_word(raw: object) -> int | None:
    """A full 32-byte word as a SIGNED int, or ``None``.

    ``podOwnerDepositShares`` is ``int256`` and a pod owner's deposit shares can
    genuinely go negative. The value is stored with its sign and never clamped:
    clamping to zero would be a default standing in for a witness, and unsigned
    decoding would publish a number ~1.15e77 times too large.
    """
    value = decode_word(raw)
    if value is None:
        return None
    return value - _INT256_MODULUS if value > _INT256_MAX else value


def decode_address_word(raw: object) -> str | None:
    """A full 32-byte word as a lower-case address, or ``None``.

    Returns the zero address as a VALUE (it is a real answer from a mapping),
    and ``None`` only where no word was returned at all. Callers must keep those
    apart: the zero address is half of the proven-absent arm, an absent word is
    ``not_determined``.

    **The high-order 12 bytes must be zero.** Truncating them instead would read
    a non-canonical word as a clean address, and this is wire-reachable: an
    upgraded or non-conformant callee can return one. It is load-bearing twice —
    the identity cross-read mints ``proven_pod_cross_read`` on two address legs
    matching, and the witnessed strategy is both published and used to build the
    shares calldata.
    """
    value = decode_word(raw)
    if value is None or value >> 160:
        return None
    return "0x" + f"{value:040x}"


def decode_strict_bool_word(raw: object) -> bool | None:
    """A full 32-byte word that is EXACTLY 0 or EXACTLY 1.

    Any other word is not a bool and yields ``None``. Deliberately NOT
    ``utils.rpc.decode_bool_word``, which answers ``False`` for anything
    unparseable: here "not a bool" must be distinguishable from "false", because
    a false ``hasPod`` is one third of a proven-absent witness.
    """
    value = decode_word(raw)
    if value is None or value not in (0, 1):
        return None
    return value == 1


def decode_withdrawable_shares(raw: object) -> tuple[int | None, int | None]:
    """``(withdrawable, deposited)`` from ``getWithdrawableShares``, or ``(None, None)``.

    The return is ``(uint256[] withdrawable, uint256[] deposited)`` for the ONE
    strategy queried, so exactly six words in a fixed shape: two head offsets
    (0x40, 0x80), then each array's length (1) and its single element. Every
    part of that shape is asserted, because reading the wrong word index here is
    silent — an offset word decodes to 64 and a length word to 1, both of which
    are perfectly plausible share quantities.
    """
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None, None
    body = raw[2:]
    if len(body) != 64 * 6:
        return None, None
    words = [_hex_word_value(body[i * 64 : (i + 1) * 64]) for i in range(6)]
    if any(word is None for word in words):
        return None, None
    if words[0] != 0x40 or words[1] != 0x80 or words[2] != 1 or words[4] != 1:
        return None, None
    return words[3], words[5]


def _eigenpod_basis(reads: NodeReads) -> tuple[str, str | None]:
    """``(eigenpod_basis, eigenpod)`` from the three identity legs.

    All three legs must decode a full word. Two agreeing address legs with a
    ``hasPod`` that returned ``"0x"``, or a word that is neither 0 nor 1, are
    ``not_determined`` — ``proven_pod_cross_read`` is requirement (i) of the
    shares arm and every downstream gate keys off it, so a basis mintable from
    two of three legs would undo the strictness of the absent arm from the other
    side.

    The absent arm needs all three legs zero for a concrete reason: before its
    deployment block a node address is CODELESS, so ``getEigenPod()`` answers
    ``"0x"`` with success while EigenLayer's mappings answer clean zeros. A
    one-leg reading would publish "proven no eigenpod" for an address whose own
    state was never read.
    """
    pod = decode_address_word(reads.get_eigen_pod)
    owner_pod = decode_address_word(reads.owner_to_pod)
    has_pod = decode_strict_bool_word(reads.has_pod)
    if pod is None or owner_pod is None or has_pod is None:
        return EIGENPOD_BASIS_NOT_DETERMINED, None
    if pod == ZERO_ADDRESS and owner_pod == ZERO_ADDRESS and has_pod is False:
        return EIGENPOD_BASIS_NO_EIGENPOD_PROVEN, None
    if pod != ZERO_ADDRESS and pod == owner_pod and has_pod is True:
        return EIGENPOD_BASIS_PROVEN_CROSS_READ, pod
    return EIGENPOD_BASIS_NOT_DETERMINED, None


def _agreement(withdrawable: int, deposits: list[int]) -> str:
    """Consistency of the withdrawable leg against every deposit leg present.

    ``agree`` needs every leg present and equal. ``disagree_within_invariant``
    is the ordinary slashed / queued-withdrawal shape and publishes with a flag.
    ``inconsistent`` — withdrawable above a deposit leg, or a negative deposit
    beside a positive withdrawable — disproves the accounting model that licences
    the number, so the caller suppresses it.

    An ABSENT deposit leg is ``not_determined``, never ``inconsistent``: absence
    is not disagreement, and conflating them would suppress a proven read.
    """
    if any(withdrawable > deposit for deposit in deposits):
        return CROSS_READ_INCONSISTENT
    if any(deposit < 0 for deposit in deposits) and withdrawable > 0:
        return CROSS_READ_INCONSISTENT
    if len(deposits) < 2:
        return CROSS_READ_NOT_DETERMINED
    if all(deposit == withdrawable for deposit in deposits):
        return CROSS_READ_AGREE
    return CROSS_READ_DISAGREE_WITHIN_INVARIANT


def withdrawable_calldata_operands(calldata: object) -> tuple[str, str] | None:
    """``(staker, strategy)`` actually encoded in a ``getWithdrawableShares`` call.

    ``None`` unless the bytes are exactly the one-strategy shape this module
    issues: the right selector, then ``(address staker, address[] strategies)``
    with head offset ``0x40``, length 1, and one element — every operand a
    canonical address word.

    This exists so the strategy is read back out of the BYTES THAT WERE SENT
    rather than taken on the caller's word. A gate that is only a calling
    convention on an exported function is not a gate: the same function, handed a
    strategy the answer was not read against, would publish it beside the answer.
    """
    if not isinstance(calldata, str) or not calldata.startswith("0x"):
        return None
    body = calldata[2:]
    if len(body) != 8 + 64 * 4:
        return None
    if "0x" + body[:8] != selector(_SEL_GET_WITHDRAWABLE_SHARES):
        return None
    words = body[8:]
    staker = decode_address_word("0x" + words[0:64])
    offset = _hex_word_value(words[64:128])
    length = _hex_word_value(words[128:192])
    strategy = decode_address_word("0x" + words[192:256])
    if staker is None or strategy is None or offset != 0x40 or length != 1:
        return None
    return staker, strategy


def position_record(
    *,
    chain_id: int,
    node_address: str,
    block_number: int,
    block_hash: str,
    strategy: str | None,
    reads: NodeReads,
    withdrawable_calldata: str | None = None,
) -> dict[str, object]:
    """The published record for one node at one pinned height.

    ``strategy`` is ``EigenPodManager.beaconChainETHStrategy()`` read at the SAME
    block, or ``None`` if that read failed — in which case no shares read is
    licensed at all, whatever came back on the wire.

    ``withdrawable_calldata`` is the exact calldata the shares answer was read
    with. The witnessed strategy alone does not license the quantity: the answer
    must have been read AGAINST that strategy, and against THIS node. Both are
    checked out of the issued bytes, so the gate holds for any caller rather than
    only for the one that happens to use a single variable for both. Omitted
    (``None``) ⇒ the quantity is ``not_determined``.

    Four bases, disjoint and exhaustive; the two quantity-bearing ones are the
    only ones a consumer may read as an observation.
    """
    eigenpod_basis, eigenpod = _eigenpod_basis(reads)
    record: dict[str, object] = {
        "chain_id": chain_id,
        "node_address": node_address.lower(),
        "block_number": block_number,
        "block_hash": block_hash,
        "eigenpod": eigenpod,
        "eigenpod_basis": eigenpod_basis,
        "eigenlayer_beacon_shares_wei": None,
        "shares_basis": SHARES_BASIS_NOT_DETERMINED,
        "shares_strategy": None,
        "deposit_shares_wei": None,
        "cross_read_agreement": CROSS_READ_NOT_DETERMINED,
        "active_validator_count": None,
        "last_checkpoint_timestamp": None,
        # Always present as a key, always this value. The residual lives on the
        # consensus layer and is unbounded above; it is never a number.
        "consensus_layer_residual": CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
        # The fold proves existence, never absence. One reachable value.
        "node_set_completeness": NODE_SET_COMPLETENESS_NOT_DETERMINED,
    }

    if eigenpod_basis == EIGENPOD_BASIS_NO_EIGENPOD_PROVEN:
        # A distinct PROVEN ZERO: no pod exists, so there is no EigenLayer
        # beaconChainETH position to have. This is the beacon-implementation
        # shape; it was not observed on any enumerated node.
        record["eigenlayer_beacon_shares_wei"] = 0
        record["shares_basis"] = SHARES_BASIS_NO_EIGENPOD_PROVEN
        return record

    if eigenpod_basis != EIGENPOD_BASIS_PROVEN_CROSS_READ:
        return record

    # Pod-derived facts require the proven pod. Without this gate a
    # ``lastCheckpointTimestamp`` of 0 — "never checkpointed" — could be minted
    # against an address never proven to have a pod at all.
    #
    # Range-guarded to the storage column's own width. An out-of-range word is a
    # non-observation of that fact and nothing more; letting it reach the insert
    # raises NumericValueOutOfRange and aborts the whole batch, so ONE malformed
    # pod would cost every other node in the cycle its observation.
    record["active_validator_count"] = _bounded(decode_word(reads.active_validator_count), _INT32_MAX)
    record["last_checkpoint_timestamp"] = _bounded(decode_word(reads.last_checkpoint_timestamp), _INT64_MAX)

    if strategy is None:
        # The strategy is a witness, not a literal. Without it the shares read
        # is against an unproven input, and a wrong input answers 0 with success.
        return record

    operands = withdrawable_calldata_operands(withdrawable_calldata)
    if operands is None or operands != (node_address.lower(), strategy.lower()):
        # Either the calldata was not supplied, or the answer was read against a
        # different strategy or a different staker than the ones being published.
        return record

    withdrawable, dm_deposit = decode_withdrawable_shares(reads.withdrawable_shares)
    if withdrawable is None:
        record["shares_basis"] = SHARES_BASIS_READ_FAILED
        return record

    epm_deposit = decode_int256_word(reads.pod_owner_deposit_shares)
    deposits = [d for d in (dm_deposit, epm_deposit) if d is not None]
    agreement = _agreement(withdrawable, deposits)

    if agreement == CROSS_READ_INCONSISTENT:
        return record

    if withdrawable == 0 and agreement != CROSS_READ_AGREE:
        # A zero is exactly the answer a wrong strategy and a nonexistent staker
        # produce, so it is admitted only under full three-way agreement. This
        # deliberately under-claims the fully-slashed case (withdrawable 0 with
        # a positive deposit leg), and deliberately refuses to publish a 0 when
        # the deposit leg failed and (iii) is therefore unevaluable.
        return record

    record["eigenlayer_beacon_shares_wei"] = withdrawable
    record["shares_basis"] = SHARES_BASIS_EIGENLAYER_BEACON_SHARES
    record["shares_strategy"] = strategy.lower()
    record["deposit_shares_wei"] = epm_deposit
    record["cross_read_agreement"] = agreement
    return record


# --- production read path --------------------------------------------------

_SEL_GET_EIGEN_POD = "getEigenPod()"
_SEL_OWNER_TO_POD = "ownerToPod(address)"
_SEL_HAS_POD = "hasPod(address)"
_SEL_POD_OWNER_DEPOSIT_SHARES = "podOwnerDepositShares(address)"
_SEL_GET_WITHDRAWABLE_SHARES = "getWithdrawableShares(address,address[])"
_SEL_ACTIVE_VALIDATOR_COUNT = "activeValidatorCount()"
_SEL_LAST_CHECKPOINT_TIMESTAMP = "lastCheckpointTimestamp()"
_SEL_BEACON_CHAIN_ETH_STRATEGY = "beaconChainETHStrategy()"

# Reads per node per cycle. Batched through one ``aggregate3`` per chunk, so the
# wire cost is ~1 request per 100 nodes rather than 7 per node.
READS_PER_NODE = 7


def _word(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def _withdrawable_calldata(node: str, strategy: str) -> str:
    # (address staker, address[] strategies) with a one-element tail.
    return selector(_SEL_GET_WITHDRAWABLE_SHARES) + _word(node) + f"{64:064x}" + f"{1:064x}" + _word(strategy)


def pinned_head(chain_id: int, rpc_url: str) -> tuple[int, str] | None:
    """``(block_number, block_hash)`` to pin every read of one cycle at.

    ``None`` when either cannot be established. There is no unpinned fallback on
    this plane: without a height nothing read here may be published at all, and
    without the hash a replay cannot tell it is on the same chain history
    (inv.11/12, the reason the event indexer stamps ``last_indexed_block_hash``).
    """
    try:
        head = int(rpc_request(rpc_url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception as exc:
        logger.info("restaking position: head read failed on chain %s: %s", chain_id, exc)
        return None
    block = max(1, head - PINNED_FINALITY_MARGIN)
    try:
        header = rpc_request(rpc_url, "eth_getBlockByNumber", [hex(block), False], retries=1, chain_id=chain_id)
    except Exception as exc:
        logger.info("restaking position: block header read failed at %d: %s", block, exc)
        return None
    if not isinstance(header, dict):
        return None
    block_hash = header.get("hash")
    if not isinstance(block_hash, str) or len(block_hash) != WORD_HEX_LEN:
        return None
    # The header must be the one that was asked for. A racing or load-balanced
    # upstream can answer a different height, and pairing that hash with this
    # number would make the stored reorg witness name a block the reads were not
    # issued at — which is the replay claim (inv.11/12), not a detail.
    number = header.get("number")
    if not isinstance(number, str) or not number.startswith("0x"):
        return None
    if _hex_word_value(number[2:].rjust(64, "0")) != block:
        return None
    return block, block_hash


def read_positions(
    node_addresses: list[str],
    *,
    chain_id: int,
    eigen_pod_manager: str,
    delegation_manager: str,
    rpc_url: str | None = None,
) -> list[dict[str, object]]:
    """Read every enumerated node's position at ONE pinned height.

    Returns the published records. An empty list means the cycle established no
    height (or had no nodes) and wrote nothing — never that the nodes hold
    nothing.

    The pod address is not known before the first read, so this runs in two
    aggregate3 rounds against the same pinned block: the identity legs and the
    EigenLayer legs first, then the pod-local legs for the nodes whose pod was
    proven. Both rounds are issued at the same explicit block, so the record
    remains a single-height observation.
    """
    if not node_addresses:
        return []
    url = rpc_url or rpc_url_for_chain_id(chain_id)
    if not url:
        return []
    pinned = pinned_head(chain_id, url)
    if pinned is None:
        return []
    block, block_hash = pinned
    block_tag = hex(block)

    strategy_results = _aggregate(
        url,
        [(eigen_pod_manager, selector(_SEL_BEACON_CHAIN_ETH_STRATEGY))],
        block_tag,
        chain_id,
    )
    strategy = None
    if strategy_results:
        ok, data = strategy_results[0]
        strategy = decode_address_word(data) if ok else None
    if strategy == ZERO_ADDRESS:
        # A zero strategy is not a strategy; treat it as unwitnessed rather than
        # querying shares against the zero address.
        strategy = None

    nodes = [a.lower() for a in node_addresses]
    # Without a witnessed strategy the shares call is not issued at all: its
    # answer could not license anything, and an unissued call is cheaper than a
    # discarded one. The stride follows so the windows stay aligned.
    stride = 5 if strategy else 4
    issued: dict[str, str] = {}
    first_calls: list[tuple[str, str]] = []
    for node in nodes:
        first_calls.append((node, selector(_SEL_GET_EIGEN_POD)))
        first_calls.append((eigen_pod_manager, selector(_SEL_OWNER_TO_POD) + _word(node)))
        first_calls.append((eigen_pod_manager, selector(_SEL_HAS_POD) + _word(node)))
        first_calls.append((eigen_pod_manager, selector(_SEL_POD_OWNER_DEPOSIT_SHARES) + _word(node)))
        if strategy:
            issued[node] = _withdrawable_calldata(node, strategy)
            first_calls.append((delegation_manager, issued[node]))
    first = _aggregate(url, first_calls, block_tag, chain_id)
    if len(first) != len(first_calls):
        return []

    partial: dict[str, list[str | None]] = {}
    for index, node in enumerate(nodes):
        window = first[index * stride : index * stride + stride]
        values = [data if ok else None for ok, data in window]
        partial[node] = values + [None] * (5 - stride)

    # Second round: the pod-local legs, for the nodes whose pod cross-read holds.
    pod_by_node: dict[str, str] = {}
    for node, values in partial.items():
        basis, pod = _eigenpod_basis(
            NodeReads(
                get_eigen_pod=values[0],
                owner_to_pod=values[1],
                has_pod=values[2],
                pod_owner_deposit_shares=values[3],
                withdrawable_shares=values[4],
                active_validator_count=None,
                last_checkpoint_timestamp=None,
            )
        )
        if basis == EIGENPOD_BASIS_PROVEN_CROSS_READ and pod is not None:
            pod_by_node[node] = pod

    pod_nodes = list(pod_by_node)
    second_calls: list[tuple[str, str]] = []
    for node in pod_nodes:
        second_calls.append((pod_by_node[node], selector(_SEL_ACTIVE_VALIDATOR_COUNT)))
        second_calls.append((pod_by_node[node], selector(_SEL_LAST_CHECKPOINT_TIMESTAMP)))
    second = _aggregate(url, second_calls, block_tag, chain_id)
    pod_reads: dict[str, tuple[str | None, str | None]] = {}
    if len(second) == len(second_calls):
        for index, node in enumerate(pod_nodes):
            ok_count, count = second[index * 2]
            ok_ts, timestamp = second[index * 2 + 1]
            pod_reads[node] = (count if ok_count else None, timestamp if ok_ts else None)

    records: list[dict[str, object]] = []
    for node, values in partial.items():
        count, timestamp = pod_reads.get(node, (None, None))
        records.append(
            position_record(
                chain_id=chain_id,
                node_address=node,
                block_number=block,
                block_hash=block_hash,
                strategy=strategy,
                reads=NodeReads(
                    get_eigen_pod=values[0],
                    owner_to_pod=values[1],
                    has_pod=values[2],
                    pod_owner_deposit_shares=values[3],
                    withdrawable_shares=values[4],
                    active_validator_count=count,
                    last_checkpoint_timestamp=timestamp,
                ),
                withdrawable_calldata=issued.get(node),
            )
        )
    return records


def restaking_history_depth() -> int:
    """How many reads per ``(chain, node)`` retention keeps.

    Raises below 1. Depth 0 would prune every read, and because the ``latest``
    view publishes only observing rows, that would make every node vanish — an
    absence manufactured by a retention policy.
    """
    raw = os.getenv("PSAT_RESTAKING_HISTORY_DEPTH", "10")
    try:
        depth = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"PSAT_RESTAKING_HISTORY_DEPTH must be an integer >= 1, got {raw!r}") from exc
    if depth < 1:
        raise ValueError(f"PSAT_RESTAKING_HISTORY_DEPTH must be >= 1, got {depth}")
    return depth


def prune_positions(session: Session, *, chain_id: int, node_address: str) -> int:
    """Bound insert-only growth without ever deleting the current observation.

    Keeps the ``depth`` most recent reads AND, unconditionally, the most recent
    OBSERVING read. Without the second rule ``depth`` consecutive failures would
    evict exactly the row the view is publishing.
    """
    depth = restaking_history_depth()
    rows = session.execute(
        select(RestakingPosition.id, RestakingPosition.shares_basis)
        .where(
            RestakingPosition.chain_id == chain_id,
            RestakingPosition.node_address == node_address.lower(),
        )
        .order_by(RestakingPosition.block_number.desc(), RestakingPosition.id.desc())
    ).all()
    if len(rows) <= depth:
        return 0
    keep = {row.id for row in rows[:depth]}
    for row in rows:
        if row.shares_basis in OBSERVING_SHARES_BASES:
            keep.add(row.id)
            break
    doomed = [row.id for row in rows if row.id not in keep]
    if not doomed:
        return 0
    session.query(RestakingPosition).filter(RestakingPosition.id.in_(doomed)).delete(synchronize_session=False)
    return len(doomed)


def persist_positions(
    session: Session,
    records: list[dict[str, object]],
    *,
    manager_contract_id: int | None,
    protocol_id: int | None,
) -> int:
    """Insert one row per record. Insert-only; nothing is ever overwritten.

    ``manager_contract_id`` is provenance: the ``contracts`` row whose ADDRESS
    equals the address the enumerating log was emitted at. It never means that
    contract holds the position.
    """
    if not records:
        return 0
    for record in records:
        block_hash = record["block_hash"]
        session.add(
            RestakingPosition(
                chain_id=record["chain_id"],
                node_address=record["node_address"],
                manager_contract_id=manager_contract_id,
                protocol_id=protocol_id,
                block_number=record["block_number"],
                block_hash=bytes.fromhex(str(block_hash).removeprefix("0x")),
                eigenpod=record["eigenpod"],
                eigenpod_basis=record["eigenpod_basis"],
                eigenlayer_beacon_shares_wei=record["eigenlayer_beacon_shares_wei"],
                shares_basis=record["shares_basis"],
                shares_strategy=record["shares_strategy"],
                deposit_shares_wei=record["deposit_shares_wei"],
                cross_read_agreement=record["cross_read_agreement"],
                active_validator_count=record["active_validator_count"],
                last_checkpoint_timestamp=record["last_checkpoint_timestamp"],
                consensus_layer_residual=record["consensus_layer_residual"],
                node_set_completeness=record["node_set_completeness"],
            )
        )
    session.flush()
    # One cycle reads one chain, so every record here shares a ``chain_id`` and
    # the first row's is the batch's. A future multi-chain caller must prune per
    # (chain, node) instead — pruning node X on the wrong chain would delete
    # observations that were never in this batch.
    chain_ids = {int(str(record["chain_id"])) for record in records}
    for chain_id in chain_ids:
        for node in {str(record["node_address"]) for record in records if int(str(record["chain_id"])) == chain_id}:
            prune_positions(session, chain_id=chain_id, node_address=node)
    return len(records)


def manager_contract_id_for(session: Session, *, emitter: str, protocol_id: int) -> int | None:
    """The ``contracts`` row whose ADDRESS EQUALS the emitting address.

    Never the implementation row that shares the manager's name: the manager's
    ``contracts`` row is keyed at ``0xcf5928ea…`` while the logs are emitted at
    the proxy ``0x8b71140a…``, and pinning provenance to the implementation
    would repeat the keying defect this plane exists to avoid.
    """
    return session.execute(
        select(Contract.id)
        .where(Contract.protocol_id == protocol_id, func.lower(Contract.address) == emitter.lower())
        .order_by(Contract.id.asc())
    ).scalar()


def _aggregate(url: str, calls: list[tuple[str, str]], block_tag: str, chain_id: int) -> list[tuple[bool, str]]:
    """``aggregate3`` with a transport failure reported as "nothing read".

    A raised transport error yields an empty list, which every caller maps to
    the non-observing states — never to a quantity.
    """
    if not calls:
        return []
    try:
        return multicall3_aggregate3(url, calls, block_tag, chain_id=chain_id)
    except Exception as exc:
        logger.info("restaking position: aggregate3 failed on chain %s at %s: %s", chain_id, block_tag, exc)
        return []


__all__ = [
    "MULTICALL3_ADDRESS",
    "PINNED_FINALITY_MARGIN",
    "READS_PER_NODE",
    "WORD_HEX_LEN",
    "ZERO_ADDRESS",
    "NodeReads",
    "decode_address_word",
    "decode_int256_word",
    "decode_strict_bool_word",
    "decode_withdrawable_shares",
    "decode_word",
    "manager_contract_id_for",
    "persist_positions",
    "pinned_head",
    "position_record",
    "prune_positions",
    "read_positions",
    "restaking_history_depth",
    "withdrawable_calldata_operands",
]
