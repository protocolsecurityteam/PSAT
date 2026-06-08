"""RPC-backed fetchers for the generic event indexer."""

from __future__ import annotations

import logging
from typing import Any

from services.resolution.types import FetchedEventLog
from utils.rpc import require_configured_erpc_url, require_supported_chain_id, rpc_request

MAX_BLOCK_RANGE = 10_000
logger = logging.getLogger(__name__)


class RpcEventLogFetcher:
    def __init__(self, rpc_url: str, *, chain_id: int, max_block_range: int = MAX_BLOCK_RANGE) -> None:
        self.chain_id = require_supported_chain_id(chain_id=chain_id, context="event log fetcher")
        self.rpc_url = require_configured_erpc_url(
            rpc_url,
            context="event log fetcher",
            chain_id=self.chain_id,
        )
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
            raw_logs = rpc_request(self.rpc_url, "eth_getLogs", params, chain_id=self.chain_id)
            if not isinstance(raw_logs, list):
                logger.error(
                    "eth_getLogs returned invalid payload address=%s topic0=%s blocks=%d-%d: %r",
                    event_address,
                    topic0,
                    start,
                    end,
                    raw_logs,
                )
                raise RuntimeError(f"eth_getLogs returned invalid payload for {event_address} topic0={topic0}")
            for raw in raw_logs:
                decoded = _decode_log(raw)
                if decoded is None:
                    logger.error(
                        "eth_getLogs returned malformed log address=%s topic0=%s blocks=%d-%d: %r",
                        event_address,
                        topic0,
                        start,
                        end,
                        raw,
                    )
                    raise RuntimeError(f"eth_getLogs returned malformed log for {event_address} topic0={topic0}")
                out.append(decoded)
            start = end + 1
        return out


class RpcHeadBlockFetcher:
    def __init__(self, rpc_url: str, *, chain_id: int) -> None:
        self.chain_id = require_supported_chain_id(chain_id=chain_id, context="event head block fetcher")
        self.rpc_url = require_configured_erpc_url(
            rpc_url,
            context="event head block fetcher",
            chain_id=self.chain_id,
        )

    def head_block(self) -> int:
        raw = rpc_request(self.rpc_url, "eth_blockNumber", [], chain_id=self.chain_id)
        if not isinstance(raw, str) or not raw.startswith("0x"):
            logger.error("eth_blockNumber returned invalid payload: %r", raw)
            raise RuntimeError(f"Unexpected eth_blockNumber result: {raw!r}")
        try:
            return int(raw, 16)
        except ValueError as exc:
            logger.error("eth_blockNumber returned malformed hex: %r", raw)
            raise RuntimeError(f"Unexpected malformed eth_blockNumber result: {raw!r}") from exc


class RpcBlockHashFetcher:
    def __init__(self, rpc_url: str, *, chain_id: int) -> None:
        self.chain_id = require_supported_chain_id(chain_id=chain_id, context="event block hash fetcher")
        self.rpc_url = require_configured_erpc_url(
            rpc_url,
            context="event block hash fetcher",
            chain_id=self.chain_id,
        )

    def block_hash(self, block_number: int) -> bytes | None:
        raw = rpc_request(self.rpc_url, "eth_getBlockByNumber", [hex(block_number), False], chain_id=self.chain_id)
        if not isinstance(raw, dict):
            logger.error("eth_getBlockByNumber returned invalid payload for block=%d: %r", block_number, raw)
            raise RuntimeError(f"eth_getBlockByNumber returned invalid payload for block={block_number}")
        block_hash = _hex_to_bytes(raw.get("hash"), 32)
        if block_hash is None:
            logger.error(
                "eth_getBlockByNumber returned malformed hash for block=%d: %r",
                block_number,
                raw.get("hash"),
            )
            raise RuntimeError(f"eth_getBlockByNumber returned malformed hash for block={block_number}")
        return block_hash


def _decode_log(raw: Any) -> FetchedEventLog | None:
    if not isinstance(raw, dict):
        return None
    topics = raw.get("topics")
    if not isinstance(topics, list) or not topics:
        return None
    if any(not isinstance(topic, str) or not topic.startswith("0x") or len(topic) != 66 for topic in topics):
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
    data_words = _split_data_words(raw.get("data"))
    if data_words is None:
        return None
    return FetchedEventLog(
        tx_hash=tx_hash,
        log_index=log_index,
        block_number=block_number,
        block_hash=block_hash,
        transaction_index=transaction_index,
        topics=[str(t).lower() for t in topics],
        data_words=data_words,
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


def _split_data_words(raw: Any) -> list[str] | None:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:]
    if len(body) % 64 != 0:
        return None
    try:
        bytes.fromhex(body)
    except ValueError:
        return None
    return ["0x" + body[i : i + 64].lower() for i in range(0, len(body), 64)]
