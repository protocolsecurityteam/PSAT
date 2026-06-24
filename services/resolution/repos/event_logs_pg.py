"""Postgres-backed generic event-log repo."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import IndexedEventCursor, IndexedEventLog
from services.resolution.adapters import EnumerationResult

_CALLER_SOURCES = {"msg_sender", "tx_origin", "signature_recovery", "root_caller"}


@dataclass(frozen=True)
class ValueFoldResult:
    """Latest-value-per-caller fold output for ``fold_event_values``.

    ``entries`` maps each caller (``key``) to the 32-byte hex word it was
    most recently assigned (``value_hex``). ``complete`` is True only when
    every participating topic's durable backfill has reached head.
    """

    entries: list[dict[str, Any]] = field(default_factory=list)
    complete: bool = False
    partial_reason: str | None = None


class PostgresEventLogRepo:
    """Fold generic indexed logs according to a descriptor's event hint."""

    def __init__(self, session: Session) -> None:
        self.session = session

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
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        q = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
            .where(func.lower(IndexedEventLog.topic0) == topic0.lower())
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        if block is not None:
            q = q.where(IndexedEventLog.block_number <= block)

        state: dict[str, bool] = {}
        for row in self.session.execute(q).scalars():
            event_keys = _event_keys(row.topics or [], row.data_words or [], topics_to_keys, data_to_keys)
            if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                continue
            member = _word_to_address(event_keys.get(member_key))
            if member is None:
                continue
            state[member] = True

        cursor_block, complete = self._cursor_state(chain_id, event_address, topic0)
        # Trust the durable index only once its historical backfill has reached
        # head. Cursors are seeded at the event address's deploy block, so a
        # positive ``last_indexed_block`` no longer implies "fully indexed" — gate
        # on ``backfill_complete`` so a cold/mid-backfill cursor defers to the
        # adapter's inline fallback instead of folding a partial history.
        if cursor_block is None or not complete:
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason="no_index_cursor",
                last_indexed_block=None,
            )
        return EnumerationResult(
            members=sorted(addr for addr, present in state.items() if present),
            confidence="enumerable",
            last_indexed_block=cursor_block,
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
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        hints_by_topic = _event_hints_by_topic(event_hints)
        if not hints_by_topic:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        topic0s = sorted(hints_by_topic)
        q = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
            .where(func.lower(IndexedEventLog.topic0).in_(topic0s))
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        if block is not None:
            q = q.where(IndexedEventLog.block_number <= block)

        state: dict[str, bool] = {}
        for row in self.session.execute(q).scalars():
            topic0 = str(row.topic0).lower()
            for hint in hints_by_topic.get(topic0, []):
                event_keys = _event_keys(
                    row.topics or [],
                    row.data_words or [],
                    hint.get("topics_to_keys") or {},
                    hint.get("data_to_keys") or {},
                )
                if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                    continue
                member = _word_to_address(event_keys.get(member_key))
                if member is None:
                    continue
                state[member] = hint["direction"] == "add"

        cursor_states = {topic0: self._cursor_state(chain_id, event_address, topic0) for topic0 in topic0s}
        # As in fold_event_writes: a topic counts as indexed only when its
        # backfill is complete, not merely because its cursor advanced past 0.
        complete_blocks = [block for block, complete in cursor_states.values() if block is not None and complete]
        last_indexed_block = min(complete_blocks) if complete_blocks else None
        if len(complete_blocks) != len(topic0s):
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason="no_index_cursor",
                last_indexed_block=last_indexed_block,
            )

        return EnumerationResult(
            members=sorted(addr for addr, present in state.items() if present),
            confidence="enumerable",
            last_indexed_block=last_indexed_block,
        )

    def fold_event_values(
        self,
        *,
        chain_id: int,
        event_address: str,
        value_hints: list[dict[str, Any]],
        key_sources: list[dict[str, Any]],
        fold_key_position: int | None,
        block: int | None = None,
    ) -> "ValueFoldResult":
        """Latest-value-per-caller fold over the durable index.

        Mirrors ``fold_event_history`` (same caller-key resolution and
        constant-key filtering) but, instead of folding an add/remove
        present-set, remembers the most recent value word each caller was
        assigned. ``value_hints`` carry the writer-event topic, the
        value's event-arg position, the indexed-arg positions, and the
        topic/data → key-source maps. ``fold_key_position``, when given,
        re-keys the fold onto the caller's event-arg position (a
        caller-keyed membership ACL keys on the caller, not the hint's
        innermost mapping key); ``None`` keeps the hint's own key map.

        Returns the per-caller latest value plus an ``enumerable`` flag
        that is True only when every participating topic's backfill is
        complete. Reads no live endpoint.

        With ``fold_key_position`` set (a caller-keyed membership ACL) the
        member is read directly at the caller's event-arg position and the
        other event args (free per-call parameters such as the selector or
        target) are not constrained. Otherwise the hint's own caller-key
        resolution + constant-key filtering applies, mirroring
        ``fold_event_history``.
        """
        member_key: int | None = None
        key_filters: dict[int, str] = {}
        if fold_key_position is None:
            member_key = _caller_key_index(key_sources)
            if member_key is None:
                return ValueFoldResult(entries=[], complete=False, partial_reason="unresolved_event_key")
            resolved_filters = _constant_key_filters(key_sources, member_key)
            if resolved_filters is None:
                return ValueFoldResult(entries=[], complete=False, partial_reason="unresolved_event_key")
            key_filters = resolved_filters

        hints_by_topic = _value_hints_by_topic(value_hints)
        if not hints_by_topic:
            return ValueFoldResult(entries=[], complete=False, partial_reason="unresolved_event_key")

        topic0s = sorted(hints_by_topic)
        rows = self.iter_event_rows(chain_id=chain_id, event_address=event_address, topic0s=topic0s, block=block)

        # (member) -> (value_hex, block, tx_index, log_index) — keep the latest.
        state: dict[str, tuple[str, int, int, int]] = {}
        for row in rows:
            topic0 = str(row.topic0).lower()
            topics = list(row.topics or [])
            data_words = list(row.data_words or [])
            for hint in hints_by_topic.get(topic0, []):
                if fold_key_position is not None:
                    member = _word_to_address(_word_at_event_arg(topics, data_words, fold_key_position, hint))
                else:
                    topics_to_keys = hint.get("topics_to_keys") or {}
                    data_to_keys = hint.get("data_to_keys") or {}
                    event_keys = _event_keys(topics, data_words, topics_to_keys, data_to_keys)
                    if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                        continue
                    member = _word_to_address(event_keys.get(member_key)) if member_key is not None else None
                if member is None:
                    continue
                value_position = hint.get("value_position")
                if value_position is None:
                    continue
                value_hex = _word_at_event_arg(topics, data_words, int(value_position), hint)
                if value_hex is None:
                    continue
                position = (
                    int(row.block_number),
                    int(row.transaction_index),
                    int(row.log_index),
                )
                prior = state.get(member)
                if prior is None or position > (prior[1], prior[2], prior[3]):
                    state[member] = (value_hex, position[0], position[1], position[2])

        cursor_states = {topic0: self._cursor_state(chain_id, event_address, topic0) for topic0 in topic0s}
        complete = all(c_block is not None and done for c_block, done in cursor_states.values())
        entries = [
            {"key": member, "value_hex": value_hex, "last_block": last_block}
            for member, (value_hex, last_block, _tx, _log) in state.items()
        ]
        return ValueFoldResult(
            entries=entries,
            complete=complete,
            partial_reason=None if complete else "no_index_cursor",
        )

    def iter_event_rows(
        self,
        *,
        chain_id: int,
        event_address: str,
        topic0s: list[str],
        block: int | None = None,
    ) -> list[IndexedEventLog]:
        """Raw indexed logs for ``event_address`` matching any of ``topic0s``,
        in canonical log order (block, tx_index, log_index).

        Named adapters that need a multi-event join (e.g. Solmate
        ``RolesAuthority``'s capability ⋈ user-role reconstruction) read
        rows directly rather than going through the single-event fold.
        """
        lowered = [t.lower() for t in topic0s if isinstance(t, str)]
        if not lowered:
            return []
        q = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
            .where(func.lower(IndexedEventLog.topic0).in_(lowered))
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        if block is not None:
            q = q.where(IndexedEventLog.block_number <= block)
        return list(self.session.execute(q).scalars())

    def min_indexed_block(self, *, chain_id: int, event_address: str, topic0s: list[str]) -> int | None:
        """Lowest indexed-cursor block across ``topic0s``, or ``None`` when any
        topic's backfill isn't complete (i.e. not yet durably indexed to head).
        Callers use ``None`` to demote an empty result from exact to an inline
        fetch / probe. A cursor seeded at the deploy block reads a positive
        block immediately, so completeness — not the block number — is the
        trust signal."""
        topics = [t for t in topic0s if isinstance(t, str)]
        if not topics:
            return None
        states = [self._cursor_state(chain_id, event_address, t) for t in topics]
        if any(block is None or not complete for block, complete in states):
            return None
        return min(block for block, _ in states if block is not None)

    def _cursor_block(self, chain_id: int, event_address: str, topic0: str) -> int | None:
        return self._cursor_state(chain_id, event_address, topic0)[0]

    def _cursor_state(self, chain_id: int, event_address: str, topic0: str) -> tuple[int | None, bool]:
        """``(last_indexed_block, backfill_complete)`` for one cursor, or
        ``(None, False)`` when no cursor exists."""
        row = self.session.execute(
            select(IndexedEventCursor.last_indexed_block, IndexedEventCursor.backfill_complete)
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
            .where(func.lower(IndexedEventCursor.topic0) == topic0.lower())
        ).first()
        if row is None:
            return None, False
        return row[0], bool(row[1])


def _caller_key_index(key_sources: list[dict[str, Any]]) -> int | None:
    for idx, source in enumerate(key_sources):
        if source.get("source") in _CALLER_SOURCES:
            return idx
    return None


def _constant_key_filters(key_sources: list[dict[str, Any]], member_key: int) -> dict[int, str] | None:
    filters: dict[int, str] = {}
    for idx, source in enumerate(key_sources):
        if idx == member_key:
            continue
        value = _constant_word(source)
        if value is None:
            return None
        filters[idx] = value
    return filters


def _constant_word(source: dict[str, Any]) -> str | None:
    raw_const = source.get("constant_value")
    word = _normalize_word(raw_const)
    if word is not None:
        return word
    if source.get("source") == "constant":
        for key in ("constant_value", "value"):
            raw = source.get(key)
            word = _normalize_word(raw)
            if word is not None:
                return word
    domain = source.get("role_domain")
    if isinstance(domain, dict) and domain.get("kind") == "constant_set":
        values = domain.get("values") or []
        if len(values) == 1:
            return _normalize_word(values[0])
    return None


def _event_hints_by_topic(event_hints: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for hint in event_hints:
        topic0 = _normalize_topic(hint.get("topic0"))
        direction = hint.get("direction")
        if topic0 is None or direction not in {"add", "remove"}:
            continue
        out.setdefault(topic0, []).append(hint)
    return out


def _value_hints_by_topic(value_hints: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for hint in value_hints:
        topic0 = _normalize_topic(hint.get("topic0"))
        if topic0 is None or hint.get("value_position") is None:
            continue
        out.setdefault(topic0, []).append(hint)
    return out


def _word_at_event_arg(
    topics: list[str],
    data_words: list[str],
    event_arg_position: int,
    hint: dict[str, Any],
) -> str | None:
    """The 32-byte word at an event-arg position over a durable row.

    Event-arg positions count every event argument in declaration order;
    ``indexed_positions`` lists which of those are indexed (carried in
    ``topics`` after ``topic0``), the rest live in ``data_words`` in order.
    """
    indexed_positions = sorted({int(p) for p in (hint.get("indexed_positions") or [])})
    if event_arg_position in indexed_positions:
        topic_index = 1 + indexed_positions.index(event_arg_position)
        if 0 <= topic_index < len(topics):
            return _normalize_word(topics[topic_index])
        return None
    data_rank = len([p for p in range(event_arg_position) if p not in indexed_positions])
    if 0 <= data_rank < len(data_words):
        return _normalize_word(data_words[data_rank])
    return None


def _event_keys(
    topics: list[str],
    data_words: list[str],
    topics_to_keys: dict[int, int],
    data_to_keys: dict[int, int],
) -> dict[int, str]:
    out: dict[int, str] = {}
    for topic_pos, key_pos in _int_items(topics_to_keys):
        if 0 <= topic_pos < len(topics):
            word = _normalize_word(topics[topic_pos])
            if word is not None:
                out[key_pos] = word
    for data_pos, key_pos in _int_items(data_to_keys):
        if 0 <= data_pos < len(data_words):
            word = _normalize_word(data_words[data_pos])
            if word is not None:
                out[key_pos] = word
    return out


def _int_items(mapping: dict[int, int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for k, v in mapping.items():
        try:
            out.append((int(k), int(v)))
        except (TypeError, ValueError):
            continue
    return out


def _normalize_word(raw: Any) -> str | None:
    if isinstance(raw, bytes):
        return "0x" + raw.rjust(32, b"\x00").hex()
    if not isinstance(raw, str):
        return None
    value = raw.lower()
    if not value.startswith("0x"):
        return None
    body = value[2:]
    if len(body) == 8:
        return "0x" + body.ljust(64, "0")
    if len(body) == 40:
        return "0x" + body.rjust(64, "0")
    if len(body) == 64:
        return value
    return None


def _normalize_topic(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.lower()
    if not value.startswith("0x"):
        return None
    return value


def _word_to_address(word: str | None) -> str | None:
    if word is None:
        return None
    normalized = _normalize_word(word)
    if normalized is None:
        return None
    return "0x" + normalized[-40:]
