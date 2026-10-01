"""A simulated JSON-RPC upstream for the event indexer: stands in for ``rpc_request`` only.

Serves ``eth_getLogs`` / ``eth_blockNumber`` / ``eth_getBlockByNumber`` from an in-memory log set, with the upstream
behaviours the indexer must survive: a log-count rejection (``-32005``), ranges an aggregator serves whole regardless of
size, one-shot client timeouts, a moving head, and fringe reorgs that change block hashes and the logs under them.
"""

from __future__ import annotations

import bisect
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from services.clients.rpc import RpcClientTimeout


@dataclass(frozen=True)
class SimLog:
    address: str
    topics: tuple[str, ...]
    data: str
    block: int
    tx_index: int
    log_index: int
    tag: int = 0  # distinguishes a reorged replacement from the log it replaced

    def sort_key(self) -> tuple[int, int, int]:
        return (self.block, self.tx_index, self.log_index)


@dataclass
class _Lane:
    keys: list[tuple[int, int, int]] = field(default_factory=list)
    logs: list[SimLog] = field(default_factory=list)

    def add(self, log: SimLog) -> None:
        key = log.sort_key()
        at = bisect.bisect_right(self.keys, key)
        self.keys.insert(at, key)
        self.logs.insert(at, log)

    def extend_sorted(self, logs: list[SimLog]) -> None:
        for log in logs:
            self.add(log)

    def between(self, lo: int, hi: int) -> list[SimLog]:
        start = bisect.bisect_left(self.keys, (lo, -1, -1))
        end = bisect.bisect_right(self.keys, (hi, 1 << 62, 1 << 62))
        return self.logs[start:end]


@dataclass
class MergeRange:
    """Requests for ``address`` overlapping ``[lo, hi]`` are served whole up to ``limit`` logs (an aggregator merging
    its split sub-requests)."""

    chain_id: int
    address: str
    lo: int
    hi: int
    limit: int


def topic(n: int) -> str:
    return "0x" + f"{n:064x}"


def address(n: int) -> str:
    return "0x" + f"{n:040x}"


def word(n: int) -> str:
    return f"{n:064x}"


class SimChain:
    def __init__(self, *, heads: dict[int, int], reject_over: int = 50_000, max_addresses: int | None = None) -> None:
        self.heads = dict(heads)
        self.reject_over = reject_over
        # An upstream address-array limit; larger filters are refused.
        self.max_addresses = max_addresses
        self.merges: list[MergeRange] = []
        self.lanes: dict[tuple[int, str], _Lane] = {}
        # Per chain: (from_block, epoch) entries; a block's hash changes with the latest entry at or below it.
        self.epochs: dict[int, list[tuple[int, int]]] = {}
        # One-shot client timeouts: (chain_id, address or None) consumed by the first matching eth_getLogs.
        self.pending_timeouts: list[tuple[int, str | None]] = []
        self.calls: list[tuple[str, int | None, Any]] = []
        self.getlogs: list[dict[str, Any]] = []
        # Called before serving each request (e.g. to assert no DB transaction is open, or to deliver SIGTERM).
        self.before_request: Callable[[str, list[Any]], None] | None = None
        # A moving head: when set, it answers the chain's head instead of ``heads``.
        self.head_fn: Callable[[int], int] | None = None
        # Rewrites a log's wire form (e.g. drop a field) before it is served.
        self.mutate_raw: Callable[[SimLog, dict[str, Any]], dict[str, Any]] | None = None

    def head(self, chain_id: int) -> int:
        return self.head_fn(chain_id) if self.head_fn is not None else self.heads[chain_id]

    # -- fixture building --

    def add(self, chain_id: int, log: SimLog) -> None:
        self.lanes.setdefault((chain_id, log.address.lower()), _Lane()).add(log)

    def add_many(self, chain_id: int, logs: list[SimLog]) -> None:
        for log in sorted(logs, key=SimLog.sort_key):
            self.add(chain_id, log)

    def remove(self, chain_id: int, predicate: Callable[[SimLog], bool]) -> int:
        removed = 0
        for (lane_chain, _address), lane in self.lanes.items():
            if lane_chain != chain_id:
                continue
            keep = [(k, log) for k, log in zip(lane.keys, lane.logs) if not predicate(log)]
            removed += len(lane.logs) - len(keep)
            lane.keys = [k for k, _ in keep]
            lane.logs = [log for _, log in keep]
        return removed

    def reorg(self, chain_id: int, from_block: int) -> None:
        """Every block at or above ``from_block`` gets a new hash (logs there carry it)."""
        entries = self.epochs.setdefault(chain_id, [])
        entries.append((from_block, len(entries) + 1))

    def block_hash(self, chain_id: int, block: int) -> str:
        epoch = 0
        for start, value in self.epochs.get(chain_id, []):
            if block >= start:
                epoch = value
        digest = hashlib.sha256(f"{chain_id}:{block}:{epoch}".encode()).hexdigest()
        return "0x" + digest

    # -- the wire --

    def rpc_request(
        self,
        url: str,
        method: str,
        params: list[Any],
        *,
        chain_id: int | None = None,
        timeout: float | None = None,
        before_retry: Callable[[], None] | None = None,
    ) -> Any:
        self.calls.append((method, chain_id, params))
        if self.before_request is not None:
            self.before_request(method, params)
        assert chain_id is not None, "the indexer always routes by chain"
        if method == "eth_blockNumber":
            return hex(self.head(chain_id))
        if method == "eth_getBlockByNumber":
            block = int(params[0], 16)
            if block > self.head(chain_id):
                return None
            return {"number": params[0], "hash": self.block_hash(chain_id, block)}
        if method == "eth_getLogs":
            return self._get_logs(chain_id, params[0])
        raise AssertionError(f"unexpected RPC method {method}")

    def _get_logs(self, chain_id: int, query: dict[str, Any]) -> list[dict[str, Any]]:
        lo = int(query["fromBlock"], 16)
        hi = int(query["toBlock"], 16)
        raw_address = query.get("address")
        addresses = [raw_address] if isinstance(raw_address, str) else list(raw_address or [])
        addresses = [a.lower() for a in addresses]
        topic_slots = query.get("topics") or []
        first = topic_slots[0] if topic_slots else None
        wanted = None if first is None else {t.lower() for t in first}
        record: dict[str, Any] = {
            "chain_id": chain_id,
            "addresses": addresses,
            "from": lo,
            "to": hi,
            "topics": wanted,
            "served": None,
        }
        self.getlogs.append(record)
        if self.max_addresses is not None and len(addresses) > self.max_addresses:
            raise RuntimeError("{'code': -32602, 'message': 'too many addresses in filter'}")
        for index, (timeout_chain, timeout_address) in enumerate(self.pending_timeouts):
            if timeout_chain == chain_id and (timeout_address is None or timeout_address in addresses):
                del self.pending_timeouts[index]
                raise RpcClientTimeout("RPC request failed for <redacted>: read timed out")
        out: list[SimLog] = []
        for addr in addresses:
            lane = self.lanes.get((chain_id, addr))
            if lane is None:
                continue
            for log in lane.between(lo, hi):
                if wanted is None or log.topics[0] in wanted:
                    out.append(log)
        limit = self.reject_over
        for merge in self.merges:
            if merge.chain_id == chain_id and merge.address in addresses and lo <= merge.hi and hi >= merge.lo:
                limit = max(limit, merge.limit)
        if len(out) > limit and hi > lo:
            raise RuntimeError(f"{{'code': -32005, 'message': 'Limit exceeded: More than {limit} logs returned'}}")
        out.sort(key=SimLog.sort_key)
        record["served"] = len(out)
        raws = [self.raw(chain_id, log) for log in out]
        if self.mutate_raw is not None:
            raws = [self.mutate_raw(log, raw) for log, raw in zip(out, raws)]
        return raws

    def raw(self, chain_id: int, log: SimLog) -> dict[str, Any]:
        tx = hashlib.sha256(f"{chain_id}:{log.block}:{log.tx_index}:{log.tag}".encode()).hexdigest()
        return {
            "address": log.address,
            "topics": list(log.topics),
            "data": log.data,
            "blockNumber": hex(log.block),
            "blockHash": self.block_hash(chain_id, log.block),
            "transactionHash": "0x" + tx,
            "transactionIndex": hex(log.tx_index),
            "logIndex": hex(log.log_index),
            "removed": False,
        }

    def getlogs_count(self) -> int:
        return len(self.getlogs)
