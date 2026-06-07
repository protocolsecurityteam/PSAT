"""HyperSync-backed generic event-log repo.

This is the live fallback for semantic predicate resolution when the
durable ``indexed_event_logs`` table has not caught up or has no cursor
for a descriptor yet.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from services.resolution.adapters import Confidence, EnumerationResult

from .event_logs_pg import (
    _caller_key_index,
    _constant_key_filters,
    _event_hints_by_topic,
    _event_keys,
    _word_to_address,
)

DEFAULT_HYPERSYNC_URL = "https://eth.hypersync.xyz"
DEFAULT_TIMEOUT_S = float(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_TIMEOUT_S", "45"))
DEFAULT_MAX_PAGES = int(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_MAX_PAGES", "50"))


class HyperSyncEventLogRepo:
    """Fold event writes directly from HyperSync log history."""

    def __init__(
        self,
        *,
        url: str = DEFAULT_HYPERSYNC_URL,
        bearer_token: str | None = None,
        from_block: int = 0,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> None:
        self.url = url
        self.bearer_token = bearer_token or os.getenv("ENVIO_API_TOKEN")
        self.from_block = from_block
        self.timeout_s = timeout_s
        self.max_pages = max_pages

    def fold_event_writes(
        self,
        *,
        chain_id: int,
        event_address: str,
        topic0: str,
        topics_to_keys: dict[int, int],
        data_to_keys: dict[int, int],
        key_sources: list[dict[str, Any]],
        direction: str,
        block: int | None = None,
    ) -> EnumerationResult:
        del chain_id
        if not self.bearer_token:
            return EnumerationResult(members=[], confidence=Confidence.PARTIAL, partial_reason="no_hypersync_token")
        return asyncio.run(
            self._fold_event_writes_async(
                event_address=event_address,
                topic0=topic0,
                topics_to_keys=topics_to_keys,
                data_to_keys=data_to_keys,
                key_sources=key_sources,
                direction=direction,
                to_block=block,
            )
        )

    def fold_event_history(
        self,
        *,
        chain_id: int,
        event_address: str,
        event_hints: list[dict[str, Any]],
        key_sources: list[dict[str, Any]],
        block: int | None = None,
    ) -> EnumerationResult:
        del chain_id
        if not self.bearer_token:
            return EnumerationResult(members=[], confidence=Confidence.PARTIAL, partial_reason="no_hypersync_token")
        return asyncio.run(
            self._fold_event_history_async(
                event_address=event_address,
                event_hints=event_hints,
                key_sources=key_sources,
                to_block=block,
            )
        )

    async def _fold_event_writes_async(
        self,
        *,
        event_address: str,
        topic0: str,
        topics_to_keys: dict[int, int],
        data_to_keys: dict[int, int],
        key_sources: list[dict[str, Any]],
        direction: str,
        to_block: int | None,
    ) -> EnumerationResult:
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence=Confidence.PARTIAL, partial_reason="unresolved_event_key")
        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence=Confidence.PARTIAL, partial_reason="unresolved_event_key")

        try:
            import hypersync  # type: ignore

            client = hypersync.HypersyncClient(hypersync.ClientConfig(url=self.url, bearer_token=self.bearer_token))
        except Exception as exc:
            return EnumerationResult(
                members=[],
                confidence=Confidence.PARTIAL,
                partial_reason=f"hypersync_error:{type(exc).__name__}",
            )
        current_from = self.from_block
        page_count = 0
        started = time.monotonic()
        state: dict[str, bool] = {}
        last_block = current_from
        partial_reason: str | None = None

        while True:
            if time.monotonic() - started > self.timeout_s:
                partial_reason = "hypersync_timeout"
                break
            if page_count >= self.max_pages:
                partial_reason = "hypersync_max_pages"
                break

            query = hypersync.Query(
                from_block=current_from,
                to_block=to_block,
                logs=[
                    hypersync.LogSelection(
                        address=[event_address.lower()],
                        topics=[[topic0.lower()]],
                    )
                ],
                field_selection=hypersync.FieldSelection(
                    log=[field.value for field in hypersync.LogField],
                ),
            )
            try:
                response = await client.get(query)
            except Exception as exc:
                return EnumerationResult(
                    members=sorted(addr for addr, present in state.items() if present),
                    confidence=Confidence.PARTIAL,
                    partial_reason=f"hypersync_error:{type(exc).__name__}",
                    last_indexed_block=last_block or None,
                )

            page_count += 1
            logs = _logs_from_response(response)
            for log in logs:
                topics = _topics_from_log(log)
                if not topics or topics[0].lower() != topic0.lower():
                    continue
                event_keys = _event_keys(topics, _data_words_from_log(log), topics_to_keys, data_to_keys)
                if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                    continue
                member = _word_to_address(event_keys.get(member_key))
                if member is None:
                    continue
                state[member] = True
                block_number = getattr(log, "block_number", None)
                if isinstance(block_number, int):
                    last_block = max(last_block, block_number)

            next_block = getattr(response, "next_block", None)
            if next_block is None or next_block <= current_from:
                break
            if to_block is not None and next_block >= to_block:
                break
            current_from = next_block

        return EnumerationResult(
            members=sorted(addr for addr, present in state.items() if present),
            confidence=Confidence.PARTIAL if partial_reason else Confidence.ENUMERABLE,
            partial_reason=partial_reason,
            last_indexed_block=last_block or None,
        )

    async def _fold_event_history_async(
        self,
        *,
        event_address: str,
        event_hints: list[dict[str, Any]],
        key_sources: list[dict[str, Any]],
        to_block: int | None,
    ) -> EnumerationResult:
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence=Confidence.PARTIAL, partial_reason="unresolved_event_key")
        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence=Confidence.PARTIAL, partial_reason="unresolved_event_key")

        hints_by_topic = _event_hints_by_topic(event_hints)
        if not hints_by_topic:
            return EnumerationResult(members=[], confidence=Confidence.PARTIAL, partial_reason="unresolved_event_key")

        try:
            import hypersync  # type: ignore

            client = hypersync.HypersyncClient(hypersync.ClientConfig(url=self.url, bearer_token=self.bearer_token))
        except Exception as exc:
            return EnumerationResult(
                members=[],
                confidence=Confidence.PARTIAL,
                partial_reason=f"hypersync_error:{type(exc).__name__}",
            )

        topic0s = sorted(hints_by_topic)
        current_from = self.from_block
        page_count = 0
        started = time.monotonic()
        state: dict[str, bool] = {}
        last_block = current_from
        partial_reason: str | None = None

        while True:
            if time.monotonic() - started > self.timeout_s:
                partial_reason = "hypersync_timeout"
                break
            if page_count >= self.max_pages:
                partial_reason = "hypersync_max_pages"
                break

            query = hypersync.Query(
                from_block=current_from,
                to_block=to_block,
                logs=[
                    hypersync.LogSelection(
                        address=[event_address.lower()],
                        topics=[topic0s],
                    )
                ],
                field_selection=hypersync.FieldSelection(
                    log=[field.value for field in hypersync.LogField],
                ),
            )
            try:
                response = await client.get(query)
            except Exception as exc:
                return EnumerationResult(
                    members=sorted(addr for addr, present in state.items() if present),
                    confidence=Confidence.PARTIAL,
                    partial_reason=f"hypersync_error:{type(exc).__name__}",
                    last_indexed_block=last_block or None,
                )

            page_count += 1
            logs = _logs_from_response(response)
            for log in logs:
                topics = _topics_from_log(log)
                if not topics:
                    continue
                topic0 = topics[0].lower()
                for hint in hints_by_topic.get(topic0, []):
                    event_keys = _event_keys(
                        topics,
                        _data_words_from_log(log),
                        hint.get("topics_to_keys") or {},
                        hint.get("data_to_keys") or {},
                    )
                    if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                        continue
                    member = _word_to_address(event_keys.get(member_key))
                    if member is None:
                        continue
                    state[member] = hint["direction"] == "add"
                    block_number = getattr(log, "block_number", None)
                    if isinstance(block_number, int):
                        last_block = max(last_block, block_number)

            next_block = getattr(response, "next_block", None)
            if next_block is None or next_block <= current_from:
                break
            if to_block is not None and next_block >= to_block:
                break
            current_from = next_block

        return EnumerationResult(
            members=sorted(addr for addr, present in state.items() if present),
            confidence=Confidence.PARTIAL if partial_reason else Confidence.ENUMERABLE,
            partial_reason=partial_reason,
            last_indexed_block=last_block or None,
        )


def _logs_from_response(response: Any) -> list[Any]:
    data = getattr(response, "data", None)
    if data is not None and hasattr(data, "logs"):
        return list(getattr(data, "logs", None) or [])
    if isinstance(data, list):
        return data
    return list(getattr(response, "logs", None) or [])


def _topics_from_log(log: Any) -> list[str]:
    topics = getattr(log, "topics", None)
    if isinstance(topics, (list, tuple)):
        return [str(topic).lower() for topic in topics if isinstance(topic, str) and topic.startswith("0x")]
    out: list[str] = []
    for attr in ("topic0", "topic1", "topic2", "topic3"):
        value = getattr(log, attr, None)
        if isinstance(value, str) and value.startswith("0x") and value not in {"0x", "0x0"}:
            out.append(value.lower())
    return out


def _data_words_from_log(log: Any) -> list[str]:
    raw = getattr(log, "data", "0x") or "0x"
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return []
    body = raw[2:]
    if len(body) % 64 != 0:
        return []
    return ["0x" + body[i : i + 64].lower() for i in range(0, len(body), 64)]
