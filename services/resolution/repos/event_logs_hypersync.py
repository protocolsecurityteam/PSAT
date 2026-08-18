"""HyperSync-backed generic event-log repo.

This is the live fallback for semantic predicate resolution when the
durable ``indexed_event_logs`` table has not caught up or has no cursor
for a descriptor yet.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from services.resolution.adapters import EnumerationResult

from .event_logs_pg import (
    _caller_key_index,
    _constant_key_filters,
    _event_hints_by_topic,
    _event_keys,
    _note_partial_reason,
    _payload_membership,
    _topic_fold_modes,
    _word_to_address,
)

logger = logging.getLogger(__name__)


def _hypersync_url_for_chain(chain_id: int) -> str | None:
    """Per-chain HyperSync endpoint from the registry.

    ``None`` means the chain has no proven HyperSync coverage — the repo is
    unavailable there (the same class as a missing token: a partial result, never
    a silent mainnet fallback). Unknown chain ids resolve to ``None`` too;
    failing loud on an unregistered chain is a caller's job, not this lookup's.
    """
    from utils.chains import UnknownChainError, chain_by_id

    try:
        return chain_by_id(chain_id).hypersync_url
    except UnknownChainError:
        return None


# Mainnet endpoint, sourced from the registry rather than a hardcoded literal.
# Mainnet always has HyperSync coverage, so this is never ``None``.
_MAINNET_HYPERSYNC_URL = _hypersync_url_for_chain(1)
assert _MAINNET_HYPERSYNC_URL is not None
DEFAULT_HYPERSYNC_URL: str = _MAINNET_HYPERSYNC_URL
DEFAULT_TIMEOUT_S = float(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_TIMEOUT_S", "45"))
DEFAULT_MAX_PAGES = int(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_MAX_PAGES", "50"))


class HyperSyncEventLogRepo:
    """Fold event writes directly from HyperSync log history."""

    def __init__(
        self,
        *,
        from_block: int,
        url: str = DEFAULT_HYPERSYNC_URL,
        bearer_token: str | None = None,
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
        url = _hypersync_url_for_chain(chain_id)
        if url is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="hypersync_unavailable_for_chain")
        if not self.bearer_token:
            return EnumerationResult(members=[], confidence="partial", partial_reason="no_hypersync_token")
        return asyncio.run(
            self._fold_event_writes_async(
                url=url,
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
        url = _hypersync_url_for_chain(chain_id)
        if url is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="hypersync_unavailable_for_chain")
        if not self.bearer_token:
            return EnumerationResult(members=[], confidence="partial", partial_reason="no_hypersync_token")
        return asyncio.run(
            self._fold_event_history_async(
                url=url,
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
        url: str | None = None,
    ) -> EnumerationResult:
        scan_url = url or self.url
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")
        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        try:
            import hypersync

            from services.resolution.hypersync_bound import build_hypersync_client

            client = build_hypersync_client(hypersync, url=scan_url, bearer_token=self.bearer_token)
        except Exception as exc:
            reason = f"hypersync_error:{type(exc).__name__}"
            _note_partial_reason(reason, event_address=event_address, repo="hypersync")
            return EnumerationResult(
                members=[],
                confidence="partial",
                partial_reason=reason,
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
                from services.resolution.hypersync_bound import hypersync_slot

                with hypersync_slot(self.bearer_token):
                    response = await client.get(query)
            except Exception as exc:
                reason = f"hypersync_error:{type(exc).__name__}"
                _note_partial_reason(reason, event_address=event_address, repo="hypersync")
                return EnumerationResult(
                    members=sorted(addr for addr, present in state.items() if present),
                    confidence="partial",
                    partial_reason=reason,
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

        # An unpinned ``to_block`` scans to HyperSync's live archive tip, which
        # lags the true chain head (#119, same class as the durable-cursor fold).
        # Only a pinned ``to_block`` the scan reached completely is exact.
        if partial_reason is None and to_block is None:
            partial_reason = "cursor_behind_block"
        _note_partial_reason(partial_reason, event_address=event_address, repo="hypersync")
        return EnumerationResult(
            members=sorted(addr for addr, present in state.items() if present),
            confidence="partial" if partial_reason else "enumerable",
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
        url: str | None = None,
    ) -> EnumerationResult:
        scan_url = url or self.url
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")
        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        hints_by_topic = _event_hints_by_topic(event_hints)
        if not hints_by_topic:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        # Same rule as the durable repo (``event_logs_pg.fold_event_history``):
        # a same-topic0 add/remove conflict folds from the event payload, and a
        # conflict with no payload position fails the whole fold closed.
        fold_modes, ambiguous = _topic_fold_modes(hints_by_topic)
        if ambiguous:
            _note_partial_reason("ambiguous_event_direction", event_address=event_address, repo="hypersync")
            return EnumerationResult(members=[], confidence="partial", partial_reason="ambiguous_event_direction")

        try:
            import hypersync

            from services.resolution.hypersync_bound import build_hypersync_client

            client = build_hypersync_client(hypersync, url=scan_url, bearer_token=self.bearer_token)
        except Exception as exc:
            reason = f"hypersync_error:{type(exc).__name__}"
            _note_partial_reason(reason, event_address=event_address, repo="hypersync")
            return EnumerationResult(
                members=[],
                confidence="partial",
                partial_reason=reason,
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
                from services.resolution.hypersync_bound import hypersync_slot

                with hypersync_slot(self.bearer_token):
                    response = await client.get(query)
            except Exception as exc:
                reason = f"hypersync_error:{type(exc).__name__}"
                _note_partial_reason(reason, event_address=event_address, repo="hypersync")
                return EnumerationResult(
                    members=sorted(addr for addr, present in state.items() if present),
                    confidence="partial",
                    partial_reason=reason,
                    last_indexed_block=last_block or None,
                )

            page_count += 1
            logs = _logs_from_response(response)
            undecidable_row = False
            for log in logs:
                topics = _topics_from_log(log)
                if not topics:
                    continue
                topic0 = topics[0].lower()
                mode = fold_modes.get(topic0)
                if mode is None:
                    continue
                mode_kind, value_hint = mode
                data_words = _data_words_from_log(log)
                row_hints = [value_hint] if mode_kind == "payload" else hints_by_topic.get(topic0, [])
                for hint in row_hints:
                    event_keys = _event_keys(
                        topics,
                        data_words,
                        hint.get("topics_to_keys") or {},
                        hint.get("data_to_keys") or {},
                    )
                    if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                        continue
                    member = _word_to_address(event_keys.get(member_key))
                    if member is None:
                        continue
                    if mode_kind == "payload":
                        present = _payload_membership(topics, data_words, hint)
                        if present is None:
                            undecidable_row = True
                            break
                    else:
                        present = hint["direction"] == "add"
                    state[member] = present
                    block_number = getattr(log, "block_number", None)
                    if isinstance(block_number, int):
                        last_block = max(last_block, block_number)
                if undecidable_row:
                    break
            if undecidable_row:
                _note_partial_reason("ambiguous_event_direction", event_address=event_address, repo="hypersync")
                return EnumerationResult(members=[], confidence="partial", partial_reason="ambiguous_event_direction")

            next_block = getattr(response, "next_block", None)
            if next_block is None or next_block <= current_from:
                break
            if to_block is not None and next_block >= to_block:
                break
            current_from = next_block

        # An unpinned ``to_block`` scans to HyperSync's live archive tip, which
        # lags the true chain head (#119, same class as the durable-cursor fold).
        # Only a pinned ``to_block`` the scan reached completely is exact.
        if partial_reason is None and to_block is None:
            partial_reason = "cursor_behind_block"
        _note_partial_reason(partial_reason, event_address=event_address, repo="hypersync")
        return EnumerationResult(
            members=sorted(addr for addr, present in state.items() if present),
            confidence="partial" if partial_reason else "enumerable",
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
