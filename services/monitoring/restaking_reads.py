"""Per-node EigenLayer restaking position: the pinned reads and the record.

Publishes one quantity, a node's EigenLayer beaconChainETH withdrawable shares, and only
where three independent reads license it; everything else is ``not_determined``. It is not
"what the node holds": measured nodes read 0 shares while their pods held 374 ETH.

Every decode is strict because the wire lies in measured ways:

* ``eth_call`` to a codeless address (and EtherFiNode for unknown selectors) returns ``"0x"``
  with success. Empty is not zero.
* ``getWithdrawableShares`` answers 0 for a nonexistent staker or a wrong strategy, so the
  strategy is read from ``beaconChainETHStrategy()`` at the same block, never a literal
  (``0xbeac0eee...eeee`` is a near-miss of the real ``...ebeac0``).
* ``podOwnerDepositShares`` is ``int256``; unsigned decoding would publish ~1.15e77.
* ``getPod`` returns a computed CREATE2 address for any input; ``ownerToPod`` and ``hasPod``
  are the witnesses.

Migration CHECKs are a backstop; a CHECK firing in production means a bug here.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract, RestakingPosition
from services.clients.rpc import MULTICALL3_ADDRESS, multicall3_aggregate3, rpc_request, rpc_url_for_chain_id, selector
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

logger = logging.getLogger(__name__)

# Reads are issued at this height, so it is a witness of the read, not an assumption.
PINNED_FINALITY_MARGIN = 12

# A 32-byte hex word. ``"0x"`` (empty success) is not a word.
WORD_HEX_LEN = 66

ZERO_ADDRESS = "0x" + "0" * 40

_INT256_MODULUS = 1 << 256
_INT256_MAX = (1 << 255) - 1

# Column widths; a larger word is a non-observation, not a smaller number.
_INT32_MAX = (1 << 31) - 1
_INT64_MAX = (1 << 63) - 1


def _bounded(value: int | None, ceiling: int) -> int | None:
    if value is None or value > ceiling:
        return None
    return value


@dataclass(frozen=True)
class NodeReads:
    """Raw return data of the seven per-node reads.

    ``None`` means the sub-call failed; ``"0x"`` is kept raw so decoding is strict in one place.
    """

    get_eigen_pod: str | None
    owner_to_pod: str | None
    has_pod: str | None
    pod_owner_deposit_shares: str | None
    withdrawable_shares: str | None
    active_validator_count: str | None
    last_checkpoint_timestamp: str | None


def _hex_word_value(body: str) -> int | None:
    """64 hex nibbles as an unsigned int, or ``None``.

    ``bytes.fromhex``, because ``int(body, 16)`` accepts ``_`` and whitespace, letting a short return parse.
    """
    if len(body) != 64:
        return None
    try:
        data = bytes.fromhex(body)
    except ValueError:
        return None
    # ``bytes.fromhex`` also skips whitespace, so re-check the decoded length.
    if len(data) != 32:
        return None
    return int.from_bytes(data, "big")


def decode_word(raw: object) -> int | None:
    """A full 32-byte word as an unsigned int, or ``None``.

    No lenient path: ``int("0x0", 16)`` would mint a zero from an empty return.
    """
    if not isinstance(raw, str) or len(raw) != WORD_HEX_LEN or not raw.startswith("0x"):
        return None
    return _hex_word_value(raw[2:])


def decode_int256_word(raw: object) -> int | None:
    """A full 32-byte word as a signed int, or ``None``. Deposit shares can go negative; never clamped."""
    value = decode_word(raw)
    if value is None:
        return None
    return value - _INT256_MODULUS if value > _INT256_MAX else value


def decode_address_word(raw: object) -> str | None:
    """A full word as a lower-case address, or ``None``.

    The zero address is a real value (half the proven-absent arm); ``None`` is no word. The high 12 bytes must be zero:
    a non-canonical word must not read as an address, since the cross-read and the shares calldata both depend on it.
    """
    value = decode_word(raw)
    if value is None or value >> 160:
        return None
    return "0x" + f"{value:040x}"


def decode_strict_bool_word(raw: object) -> bool | None:
    """A word that is exactly 0 or 1, else ``None``.

    Unlike ``rpc.decode_bool_word``, "not a bool" must differ from false: a false ``hasPod`` is a third of the absent
    witness.
    """
    value = decode_word(raw)
    if value is None or value not in (0, 1):
        return None
    return value == 1


def decode_withdrawable_shares(raw: object) -> tuple[int | None, int | None]:
    """``(withdrawable, deposited)`` for the one queried strategy, or ``(None, None)``.

    The whole six-word shape is asserted: a misread offset (64) or length (1) would decode as a plausible share count.
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
    """``(eigenpod_basis, eigenpod)`` from the three identity legs, all of which must decode.

    Two of three never suffices. The absent arm needs all three zero because a not-yet-deployed node is codeless:
    ``getEigenPod()`` answers ``"0x"`` while the mappings answer clean zeros.
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
    """Withdrawable vs every present deposit leg.

    ``agree``: all present and equal. ``disagree_within_invariant``: slashing or queued withdrawals, published with a
    flag. ``inconsistent``: disproves the model, suppressed. A missing leg is ``not_determined``, not a disagreement.
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
    """``(staker, strategy)`` decoded from issued ``getWithdrawableShares`` calldata, or ``None`` unless it is
    exactly the one-strategy shape.

    Reading them back from the bytes sent makes the gate hold for any caller, not just by convention.
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

    ``strategy`` is the same-block ``beaconChainETHStrategy()`` read, or ``None`` (no shares licensed). The shares
    answer only counts if ``withdrawable_calldata`` shows it was read against that strategy and this node. Four disjoint
    bases; only the two quantity-bearing ones are observations.
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
        # Consensus-layer residual is unbounded above; never a number.
        "consensus_layer_residual": CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
        # The fold proves existence, never absence.
        "node_set_completeness": NODE_SET_COMPLETENESS_NOT_DETERMINED,
    }

    if eigenpod_basis == EIGENPOD_BASIS_NO_EIGENPOD_PROVEN:
        # A proven zero: no pod, so no position. Not observed on any enumerated node.
        record["eigenlayer_beacon_shares_wei"] = 0
        record["shares_basis"] = SHARES_BASIS_NO_EIGENPOD_PROVEN
        return record

    if eigenpod_basis != EIGENPOD_BASIS_PROVEN_CROSS_READ:
        return record

    # Pod-derived facts require the proven pod (else a 0 checkpoint could be minted for a podless address).
    # Range-guarded because one overflowing word would abort the whole batch insert.
    record["active_validator_count"] = _bounded(decode_word(reads.active_validator_count), _INT32_MAX)
    record["last_checkpoint_timestamp"] = _bounded(decode_word(reads.last_checkpoint_timestamp), _INT64_MAX)

    if strategy is None:
        # No witnessed strategy: a wrong strategy answers 0 with success.
        return record

    operands = withdrawable_calldata_operands(withdrawable_calldata)
    if operands is None or operands != (node_address.lower(), strategy.lower()):
        # Calldata missing, or read against a different strategy or staker.
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
        # Zero is what a wrong strategy or missing staker returns, so it needs full three-way agreement. Deliberately
        # under-claims fully-slashed nodes.
        return record

    record["eigenlayer_beacon_shares_wei"] = withdrawable
    record["shares_basis"] = SHARES_BASIS_EIGENLAYER_BEACON_SHARES
    record["shares_strategy"] = strategy.lower()
    record["deposit_shares_wei"] = epm_deposit
    record["cross_read_agreement"] = agreement
    return record


_SEL_GET_EIGEN_POD = "getEigenPod()"
_SEL_OWNER_TO_POD = "ownerToPod(address)"
_SEL_HAS_POD = "hasPod(address)"
_SEL_POD_OWNER_DEPOSIT_SHARES = "podOwnerDepositShares(address)"
_SEL_GET_WITHDRAWABLE_SHARES = "getWithdrawableShares(address,address[])"
_SEL_ACTIVE_VALIDATOR_COUNT = "activeValidatorCount()"
_SEL_LAST_CHECKPOINT_TIMESTAMP = "lastCheckpointTimestamp()"
_SEL_BEACON_CHAIN_ETH_STRATEGY = "beaconChainETHStrategy()"

# Batched through ``aggregate3``: about one request per 100 nodes.
READS_PER_NODE = 7


def _word(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def _withdrawable_calldata(node: str, strategy: str) -> str:
    return selector(_SEL_GET_WITHDRAWABLE_SHARES) + _word(node) + f"{64:064x}" + f"{1:064x}" + _word(strategy)


def pinned_head(chain_id: int, rpc_url: str) -> tuple[int, str] | None:
    """``(block_number, block_hash)`` to pin a cycle's reads at, or ``None``.

    No unpinned fallback: without a height nothing may be published, and without the hash a replay can't confirm chain
    history.
    """
    try:
        head = int(rpc_request(rpc_url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception as exc:
        # Once per chain per cycle; a head that won't read withholds the chain's positions.
        logger.warning(
            "restaking position: head read failed; no position on this chain is read this cycle",
            extra={"chain_id": chain_id, "exc_type": type(exc).__name__, "error": str(exc)},
        )
        return None
    block = max(1, head - PINNED_FINALITY_MARGIN)
    try:
        header = rpc_request(rpc_url, "eth_getBlockByNumber", [hex(block), False], retries=1, chain_id=chain_id)
    except Exception as exc:
        logger.warning(
            "restaking position: block header read failed; no position on this chain is read this cycle",
            extra={
                "chain_id": chain_id,
                "block_number": block,
                "exc_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return None
    if not isinstance(header, dict):
        return None
    block_hash = header.get("hash")
    if not isinstance(block_hash, str) or len(block_hash) != WORD_HEX_LEN:
        return None
    # A racing upstream can answer a different height; pairing that hash with this number would mis-witness the reads.
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
    """Every enumerated node's position at one pinned height; empty means nothing was established, never zero
    holdings.

    Two aggregate3 rounds at the same block: identity and EigenLayer legs, then pod-local legs for nodes with a proven
    pod.
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
        # A zero strategy is unwitnessed.
        strategy = None

    nodes = [a.lower() for a in node_addresses]
    # No witnessed strategy, so the shares call isn't issued; the stride keeps windows aligned.
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
    """Reads kept per ``(chain, node)``.

    Must be at least 1: 0 would prune every row and make nodes vanish from ``latest``.
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
    """Keep the ``depth`` newest reads and always the newest observing one, so failures can't evict what the view
    publishes.
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
    """Insert one row per record, never overwriting.

    ``manager_contract_id`` is provenance (the emitting contract), not the holder.
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
    # One cycle reads one chain; a multi-chain caller must prune per (chain, node).
    chain_ids = {int(str(record["chain_id"])) for record in records}
    for chain_id in chain_ids:
        for node in {str(record["node_address"]) for record in records if int(str(record["chain_id"])) == chain_id}:
            prune_positions(session, chain_id=chain_id, node_address=node)
    return len(records)


def manager_contract_id_for(session: Session, *, emitter: str, protocol_id: int) -> int | None:
    """The ``contracts`` row whose address equals the emitter: the proxy, never the same-named implementation row."""
    return session.execute(
        select(Contract.id)
        .where(Contract.protocol_id == protocol_id, func.lower(Contract.address) == emitter.lower())
        .order_by(Contract.id.asc())
    ).scalar()


def _aggregate(url: str, calls: list[tuple[str, str]], block_tag: str, chain_id: int) -> list[tuple[bool, str]]:
    """``aggregate3`` with transport failure returned as an empty list, which maps to non-observing states."""
    if not calls:
        return []
    try:
        return multicall3_aggregate3(url, calls, block_tag, chain_id=chain_id)
    except Exception as exc:
        # Per chunk, so this can't storm per node.
        logger.warning(
            "restaking position: aggregate3 did not answer; the chunk's reads are not determined",
            extra={
                "chain_id": chain_id,
                "block_tag": block_tag,
                "calls": len(calls),
                "exc_type": type(exc).__name__,
                "error": str(exc),
            },
        )
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
