"""RPC-backed fetchers for the generic event indexer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from utils.rpc import rpc_request

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


class RpcEventLogFetcher:
    def __init__(
        self,
        rpc_url: str,
        *,
        max_block_range: int = MAX_BLOCK_RANGE,
        min_bisect_span: int = MIN_BISECT_SPAN,
    ) -> None:
        self.rpc_url = rpc_url
        self.max_block_range = max(1, max_block_range)
        self.min_bisect_span = max(1, min_bisect_span)

    def fetch_logs(
        self,
        *,
        event_address: str,
        topics: Sequence[str],
        from_block: int,
        to_block: int,
    ) -> list[FetchedEventLog]:
        """Fetch logs matching ANY of ``topics`` in topic position 0.

        Multiple topic0 values fold into one request (`"topics": [[t1, t2]]`
        is OR semantics) so same-address cursors don't each rescan the same
        range — the request, not the range, is what the upstream budget meters.
        """
        topic_list = [str(t).lower() for t in topics]
        out: list[FetchedEventLog] = []
        start = from_block
        while start <= to_block:
            end = min(to_block, start + self.max_block_range - 1)
            out.extend(self._fetch_range(event_address, topic_list, start, end))
            start = end + 1
        return out

    def _fetch_range(
        self, event_address: str, topics: list[str], from_block: int, to_block: int
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
            raw_logs = rpc_request(self.rpc_url, "eth_getLogs", params)
        except RuntimeError:
            # Result-cap / range-cap / query-timeout from the upstream. Halve and
            # recurse; a span at the floor is a real error, not a sizing problem.
            span = to_block - from_block + 1
            if span <= self.min_bisect_span:
                raise
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
    def __init__(self, rpc_url: str) -> None:
        self.rpc_url = rpc_url

    def head_block(self) -> int:
        raw = rpc_request(self.rpc_url, "eth_blockNumber", [])
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise RuntimeError(f"Unexpected eth_blockNumber result: {raw!r}")
        return int(raw, 16)


class RpcBlockHashFetcher:
    def __init__(self, rpc_url: str) -> None:
        self.rpc_url = rpc_url

    def block_hash(self, block_number: int) -> bytes | None:
        raw = rpc_request(self.rpc_url, "eth_getBlockByNumber", [hex(block_number), False])
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
    return FetchedEventLog(
        tx_hash=tx_hash,
        log_index=log_index,
        block_number=block_number,
        block_hash=block_hash,
        transaction_index=transaction_index,
        topics=[str(t).lower() for t in topics],
        data_words=_split_data_words(raw.get("data")),
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
