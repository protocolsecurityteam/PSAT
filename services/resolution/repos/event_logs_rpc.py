"""RPC-backed fetchers for the generic event indexer."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Sequence

from utils.rpc import rpc_request

logger = logging.getLogger(__name__)

# One eth_getLogs per window up to this span. The eRPC fast lane for getLogs
# (Envio HyperRPC) bills a flat 1000 credits per REQUEST regardless of block
# range — 60 requests/min total — and serves million-block ranges fine, so
# paging a window into small chunks burns the entire budget for no data
# (measured: 10k-page scanning cost ~140 credits per 1k blocks vs ~1 with
# single-request windows). Upstreams that can't take a wide range fail loudly
# (HyperRPC: -32005 "Limit exceeded: More than 50000 logs returned" / -32603
# "Query timed out"; regular nodes: explicit range caps) — never truncate — so
# ``_fetch_range`` bisects on error down to MIN_BISECT_SPAN before giving up.
MAX_BLOCK_RANGE = 1_000_000
MIN_BISECT_SPAN = 10_000


@dataclass(frozen=True)
class FetchedEventLog:
    tx_hash: bytes
    log_index: int
    block_number: int
    block_hash: bytes
    transaction_index: int
    topics: list[str]
    data_words: list[str]
    # Emitting contract, lowercased — how a multi-address caller attributes a
    # log to the cohort member that emitted it. Empty for logs a caller
    # constructed without one (single-address callers already know the address).
    address: str = ""
    # The untouched RPC log dict, so a caller that runs the raw-dict decode
    # pipeline (services/monitoring/event_topics.parse_any_log) gets its input
    # from the same bisecting fetch — excluded from equality (dicts are unhashable
    # and the decoded fields above already carry identity).
    raw: dict[str, Any] | None = field(default=None, compare=False)


class RpcEventLogFetcher:
    def __init__(
        self,
        rpc_url: str,
        *,
        max_block_range: int = MAX_BLOCK_RANGE,
        min_bisect_span: int = MIN_BISECT_SPAN,
        chain_id: int | None = None,
    ) -> None:
        self.rpc_url = rpc_url
        self.max_block_range = max(1, max_block_range)
        self.min_bisect_span = max(1, min_bisect_span)
        # Declared so ``rpc_request`` can assert the eRPC URL routes this chain
        # (inv. 7). None keeps the guard a no-op for callers that lack a chain.
        self.chain_id = chain_id

    def fetch_logs(
        self,
        *,
        event_address: str | Sequence[str],
        topics: Sequence[str],
        from_block: int,
        to_block: int,
    ) -> list[FetchedEventLog]:
        """Fetch logs matching ANY of ``topics`` in topic position 0.

        Multiple topic0 values fold into one request (`"topics": [[t1, t2]]`
        is OR semantics) so same-address cursors don't each rescan the same
        range — the request, not the range, is what the upstream budget meters.

        ``event_address`` may be a single address (existing per-cursor callers)
        or a list — a multi-address filter serves a whole cohort of monitored
        contracts in one request. Per-emitter attribution is on each result's
        ``.address``. Both shapes share this one bisect-on-reject implementation.
        """
        if isinstance(event_address, str):
            address_filter: str | list[str] = event_address
        else:
            address_filter = list(event_address)
        topic_list = [str(t).lower() for t in topics]
        out: list[FetchedEventLog] = []
        start = from_block
        while start <= to_block:
            end = min(to_block, start + self.max_block_range - 1)
            out.extend(self._fetch_range(address_filter, topic_list, start, end))
            start = end + 1
        return out

    def _fetch_range(
        self,
        event_address: str | list[str],
        topics: list[str],
        from_block: int,
        to_block: int,
    ) -> list[FetchedEventLog]:
        params = [
            {
                "address": event_address,
                "topics": [topics],
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block),
            }
        ]
        try:
            raw_logs = rpc_request(self.rpc_url, "eth_getLogs", params, chain_id=self.chain_id)
        except RuntimeError as exc:
            # Result-cap / range-cap / query-timeout from the upstream. Halve and
            # recurse; a span at the floor is a real error, not a sizing problem.
            span = to_block - from_block + 1
            if span <= self.min_bisect_span:
                raise
            # Per-window detail (the parent scan logs the aggregate) — DEBUG.
            logger.debug(
                "eth_getLogs window rejected; bisecting",
                extra={
                    "event_address": event_address,
                    "from_block": from_block,
                    "to_block": to_block,
                    "span": span,
                    "exc_type": type(exc).__name__,
                },
            )
            mid = from_block + span // 2 - 1
            return self._fetch_range(event_address, topics, from_block, mid) + self._fetch_range(
                event_address, topics, mid + 1, to_block
            )
        out: list[FetchedEventLog] = []
        if isinstance(raw_logs, list):
            for raw in raw_logs:
                decoded = _decode_log(raw)
                if decoded is not None:
                    out.append(decoded)
        return out


class RpcHeadBlockFetcher:
    def __init__(self, rpc_url: str, *, chain_id: int | None = None) -> None:
        self.rpc_url = rpc_url
        self.chain_id = chain_id

    def head_block(self) -> int:
        raw = rpc_request(self.rpc_url, "eth_blockNumber", [], chain_id=self.chain_id)
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise RuntimeError(f"Unexpected eth_blockNumber result: {raw!r}")
        return int(raw, 16)


class RpcBlockHashFetcher:
    def __init__(self, rpc_url: str, *, chain_id: int | None = None) -> None:
        self.rpc_url = rpc_url
        self.chain_id = chain_id

    def block_hash(self, block_number: int) -> bytes | None:
        raw = rpc_request(self.rpc_url, "eth_getBlockByNumber", [hex(block_number), False], chain_id=self.chain_id)
        if not isinstance(raw, dict):
            return None
        return _hex_to_bytes(raw.get("hash"), 32)


def _decode_log(raw: Any) -> FetchedEventLog | None:
    if not isinstance(raw, dict):
        return None
    topics = raw.get("topics")
    if not isinstance(topics, list) or not topics:
        return None
    tx_hash = _hex_to_bytes(raw.get("transactionHash"), 32)
    block_hash = _hex_to_bytes(raw.get("blockHash"), 32)
    if tx_hash is None or block_hash is None:
        return None
    try:
        log_index = _hex_int(raw.get("logIndex"))
        block_number = _hex_int(raw.get("blockNumber"))
        transaction_index = _hex_int(raw.get("transactionIndex"))
    except (TypeError, ValueError):
        return None
    emitter = raw.get("address")
    return FetchedEventLog(
        tx_hash=tx_hash,
        log_index=log_index,
        block_number=block_number,
        block_hash=block_hash,
        transaction_index=transaction_index,
        topics=[str(t).lower() for t in topics],
        data_words=_split_data_words(raw.get("data")),
        address=emitter.lower() if isinstance(emitter, str) else "",
        raw=raw,
    )


def _hex_int(raw: Any) -> int:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise TypeError(raw)
    return int(raw, 16)


def _hex_to_bytes(raw: Any, size: int) -> bytes | None:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:]
    if len(body) != size * 2:
        return None
    try:
        return bytes.fromhex(body)
    except ValueError:
        return None


def _split_data_words(raw: Any) -> list[str]:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return []
    body = raw[2:]
    if len(body) % 64 != 0:
        return []
    return ["0x" + body[i : i + 64].lower() for i in range(0, len(body), 64)]
