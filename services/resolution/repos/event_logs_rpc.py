"""RPC-backed fetchers for the generic event indexer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from utils.rpc import rpc_request

MAX_BLOCK_RANGE = 10_000


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
    def __init__(self, rpc_url: str, *, max_block_range: int = MAX_BLOCK_RANGE) -> None:
        self.rpc_url = rpc_url
        self.max_block_range = max_block_range

    def fetch_logs(
        self,
        *,
        event_address: str,
        topic0: str,
        from_block: int,
        to_block: int,
    ) -> list[FetchedEventLog]:
        out: list[FetchedEventLog] = []
        start = from_block
        while start <= to_block:
            end = min(to_block, start + self.max_block_range - 1)
            params = [
                {
                    "address": event_address,
                    "topics": [topic0],
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                }
            ]
            raw_logs = rpc_request(self.rpc_url, "eth_getLogs", params)
            if isinstance(raw_logs, list):
                for raw in raw_logs:
                    decoded = _decode_log(raw)
                    if decoded is not None:
                        out.append(decoded)
            start = end + 1
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
