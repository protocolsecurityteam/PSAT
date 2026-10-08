"""Postgres-backed generic event-log repo."""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import IndexedEventCursor, IndexedEventLog, cursor_permits_exactness
from services.resolution.adapters import EnumerationResult
from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from utils.logging import record_stage_metric

if TYPE_CHECKING:
    from services.resolution.event_tail import TailScan, TailScanner

logger = logging.getLogger(__name__)


# Partial fold outcomes by reason (bounded set), also folded into the stage timing artifact so spikes are chartable.
_PARTIAL_REASON_COUNTS: "Counter[str]" = Counter()
# Real upstream degradation (WARNING), including an indexed log no ABI can decode; others log at DEBUG.
_DEGRADED_PARTIAL_REASONS = {"hypersync_timeout", "hypersync_max_pages", "undecodable_event_data"}


def _note_partial_reason(partial_reason: str | None, *, event_address: str, repo: str) -> int:
    """Count and log one partial fold outcome; returns the running count. No-op for ``None``."""
    if not partial_reason:
        return 0
    _PARTIAL_REASON_COUNTS[partial_reason] += 1
    count = _PARTIAL_REASON_COUNTS[partial_reason]
    record_stage_metric(f"event_fold_partial_{partial_reason}", count)
    level = logging.WARNING if partial_reason in _DEGRADED_PARTIAL_REASONS else logging.DEBUG
    logger.log(
        level,
        "event fold returned partial result: %s",
        partial_reason,
        extra={
            "partial_reason": partial_reason,
            "partial_reason_count": count,
            "event_address": event_address,
            "repo": repo,
        },
    )
    return count


@dataclass(frozen=True)
class ValueFoldResult:
    """Latest value per caller: ``entries`` maps each key to its last ``value_hex``; ``complete`` only when every
    topic's rows are proven through the evaluated block.
    """

    entries: list[dict[str, Any]] = field(default_factory=list)
    complete: bool = False
    partial_reason: str | None = None
    last_indexed_block: int | None = None
    scan_window: dict[str, Any] | None = None


# A warm fold behind the evaluated block: ``cursor_behind_block`` without a tail scanner, ``tail_scan_failed`` when the
# tail could not prove ``(frontier, block]``. Either way the durable rows are proven only through the frontier.
BEHIND_PARTIAL_REASONS = frozenset({"cursor_behind_block", "tail_scan_failed"})


# A row whose ``data`` isn't word-aligned (stored only in ``data_hex``) can't be decoded against any ABI, so no fold
# that reads it is complete: the result is partial with this reason, never missing the row silently.
UNDECODABLE_EVENT_DATA = "undecodable_event_data"

# A writer event a value fold can't replay (its value is neither in the event nor a known zero).
UNFOLDABLE_WRITER_EVENT = "unfoldable_writer_event"

NO_INDEX_CURSOR = "no_index_cursor"
UNPINNED_BLOCK = "unpinned_block"
CURSOR_BEHIND_BLOCK = "cursor_behind_block"


@dataclass(frozen=True)
class IndexedLogs:
    """Stored rows then tail logs in log order; ``complete`` only when they are every log through ``block``."""

    logs: tuple[Any, ...]
    complete: bool
    reason: str | None = None
    last_indexed_block: int | None = None


_ZERO_WORD = "0x" + "0" * 64


class UndecodableEventRow(RuntimeError):
    """An indexed row the reader would need carries undecodable data."""


def row_is_undecodable(row: Any) -> bool:
    return getattr(row, "data_hex", None) is not None


def _row_topic0(row: Any) -> str:
    topic0 = getattr(row, "topic0", None)
    if isinstance(topic0, str):
        return topic0.lower()
    topics = getattr(row, "topics", None) or []
    return str(topics[0]).lower() if topics else ""


def _complete_with_tail(
    tail: "TailScanner | None",
    *,
    event_address: str,
    topic0s: list[str],
    frontier: int,
    block: int | None,
) -> "TailScan | None":
    """The tail over ``(frontier, block]``, or ``None`` when there is no scanner or no pinned block."""
    if tail is None or not isinstance(block, int):
        return None
    return tail(event_address, topic0s, frontier, block)


def _cursor_covers_block(cursor_block: int | None, block: int | None) -> bool:
    """Whether a warm cursor covers the evaluated ``block``, licensing ``enumerable``/``exact``.

    ``block is None`` means live head, which the cursor always lags, so never covered (the resolver pins a finalized
    height to avoid this). Otherwise covered iff the cursor reached it. Uncovered folds return
    ``partial``/``cursor_behind_block`` and demote to ``lower_bound``.
    """
    if cursor_block is None:
        return False
    if block is None:
        return False
    return cursor_block >= block


def _row_ceiling(frontier_block: int | None, block: int | None) -> int | None:
    """Upper bound for the row scan: the index frontier (cursor), not the finality pin.

    The pin only gates exactness. Truncating rows at it would drop indexed writes in ``(block, frontier]``: a real
    controller from an allowlist, or (fail-open) a recent entry from a negated denylist. The cursor is already
    reorg-safe. Cold path falls back to ``block``.
    """
    if frontier_block is None:
        return block
    return frontier_block


class PostgresEventLogRepo:
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
        tail: "TailScanner | None" = None,
    ) -> EnumerationResult:
        """Members written by one topic. A warm cursor behind ``block`` is completed by ``tail`` over
        ``(cursor, block]``; without a complete tail the result stays partial.
        """
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        cursor_block, complete = self.cursor_state(chain_id, event_address, topic0)

        q = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(IndexedEventLog.event_address == event_address.lower())
            .where(IndexedEventLog.topic0 == topic0.lower())
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        # See _row_ceiling.
        row_ceiling = _row_ceiling(cursor_block, block)
        if row_ceiling is not None:
            q = q.where(IndexedEventLog.block_number <= row_ceiling)

        state: dict[str, bool] = {}

        def _apply(rows: Iterable[Any]) -> bool:
            """Fold rows into ``state``; False when a row can't be decoded."""
            for row in rows:
                if row_is_undecodable(row):
                    return False
                event_keys = _event_keys(row.topics or [], row.data_words or [], topics_to_keys, data_to_keys)
                if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                    continue
                member = _word_to_address(event_keys.get(member_key))
                if member is None:
                    continue
                state[member] = True
            return True

        def _undecodable() -> EnumerationResult:
            _note_partial_reason(UNDECODABLE_EVENT_DATA, event_address=event_address, repo="postgres")
            return EnumerationResult(members=[], confidence="partial", partial_reason=UNDECODABLE_EVENT_DATA)

        if not _apply(self.session.execute(q).scalars()):
            return _undecodable()

        # Cursors are seeded at deploy, so trust only ``backfill_complete``, not a positive block.
        if cursor_block is None or not complete:
            _note_partial_reason("no_index_cursor", event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason="no_index_cursor",
                last_indexed_block=None,
            )
        if not _cursor_covers_block(cursor_block, block):
            scan = _complete_with_tail(
                tail, event_address=event_address, topic0s=[topic0.lower()], frontier=cursor_block, block=block
            )
            if scan is not None and scan.complete:
                if not _apply(scan.logs):
                    return _undecodable()
                return EnumerationResult(
                    members=sorted(addr for addr, present in state.items() if present),
                    confidence="enumerable",
                    last_indexed_block=block,
                    scan_window=scan.trace_fields(),
                )
            reason = "cursor_behind_block" if scan is None else "tail_scan_failed"
            _note_partial_reason(reason, event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason=reason,
                last_indexed_block=cursor_block,
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
        tail: "TailScanner | None" = None,
    ) -> EnumerationResult:
        """Add/remove fold into the current member set.

        When every cursor is warm but the least advanced (``warm_block``) is behind ``block``, rows are cut at exactly
        ``warm_block`` and ``tail`` completes ``(warm_block, block]`` in log order; a removal in that range is never
        left out of a published set.
        """
        member_key = _caller_key_index(key_sources)
        if member_key is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        key_filters = _constant_key_filters(key_sources, member_key)
        if key_filters is None:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        hints_by_topic = _event_hints_by_topic(event_hints)
        if not hints_by_topic:
            return EnumerationResult(members=[], confidence="partial", partial_reason="unresolved_event_key")

        # An undecidable same-topic add/remove conflict poisons the whole var's fold.
        fold_modes, ambiguous = _topic_fold_modes(hints_by_topic)
        if ambiguous:
            _note_partial_reason("ambiguous_event_direction", event_address=event_address, repo="postgres")
            return EnumerationResult(members=[], confidence="partial", partial_reason="ambiguous_event_direction")

        topic0s = sorted(hints_by_topic)
        cursor_states = {topic0: self.cursor_state(chain_id, event_address, topic0) for topic0 in topic0s}
        # Indexed means backfill complete, not just an advanced cursor.
        complete_blocks = [block for block, complete in cursor_states.values() if block is not None and complete]
        warm_block = min(complete_blocks) if len(complete_blocks) == len(topic0s) else None
        behind = warm_block is not None and not _cursor_covers_block(warm_block, block)
        if behind:
            # Rows past the least advanced cursor would be applied again, out of order, by the tail.
            row_ceiling = warm_block
        else:
            # The max per-topic frontier admits every indexed row and no phantom ones.
            frontier = max((b for b, _ in cursor_states.values() if b is not None), default=None)
            row_ceiling = _row_ceiling(frontier, block)

        q = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(IndexedEventLog.event_address == event_address.lower())
            .where(IndexedEventLog.topic0.in_(topic0s))
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        if row_ceiling is not None:
            q = q.where(IndexedEventLog.block_number <= row_ceiling)

        state: dict[str, bool] = {}

        undecodable = False

        def _apply(rows: Iterable[Any]) -> bool:
            """Fold rows into ``state``; False when a row is undecidable."""
            nonlocal undecodable
            for row in rows:
                topic0 = _row_topic0(row)
                mode = fold_modes.get(topic0)
                if mode is None:
                    continue
                if row_is_undecodable(row):
                    undecodable = True
                    return False
                mode_kind, value_hint = mode
                topics = list(row.topics or [])
                data_words = list(row.data_words or [])
                # Payload mode reads one hint (the value word decides); uniform mode unions every hint's keys.
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
                            # An unreadable payload word leaves the var's member set undetermined.
                            return False
                    else:
                        present = hint["direction"] == "add"
                    state[member] = present
            return True

        def _ambiguous() -> EnumerationResult:
            reason = UNDECODABLE_EVENT_DATA if undecodable else "ambiguous_event_direction"
            _note_partial_reason(reason, event_address=event_address, repo="postgres")
            return EnumerationResult(members=[], confidence="partial", partial_reason=reason)

        if not _apply(self.session.execute(q).scalars()):
            return _ambiguous()

        def _members() -> list[str]:
            return sorted(addr for addr, present in state.items() if present)

        if warm_block is None:
            _note_partial_reason("no_index_cursor", event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=_members(),
                confidence="partial",
                partial_reason="no_index_cursor",
                last_indexed_block=min(complete_blocks) if complete_blocks else None,
            )

        if behind:
            scan = _complete_with_tail(
                tail, event_address=event_address, topic0s=topic0s, frontier=warm_block, block=block
            )
            if scan is not None and scan.complete:
                if not _apply(scan.logs):
                    return _ambiguous()
                return EnumerationResult(
                    members=_members(),
                    confidence="enumerable",
                    last_indexed_block=block,
                    scan_window=scan.trace_fields(),
                )
            reason = "cursor_behind_block" if scan is None else "tail_scan_failed"
            _note_partial_reason(reason, event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=_members(),
                confidence="partial",
                partial_reason=reason,
                last_indexed_block=warm_block,
            )
        return EnumerationResult(
            members=_members(),
            confidence="enumerable",
            last_indexed_block=warm_block,
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
        tail: "TailScanner | None" = None,
    ) -> "ValueFoldResult":
        """Latest value per caller over the durable index.

        Like ``fold_event_history`` but keeps each caller's most recent value word. ``fold_key_position`` re-keys onto
        the caller's arg position (then other args are unconstrained); ``None`` uses the hint's key map with
        constant-key filtering.

        If any topic is cold, returns an empty ``no_index_cursor`` result without scanning. When every topic is warm
        but the least advanced cursor (``warm_block``) is behind ``block``, rows are cut at exactly ``warm_block`` and
        ``tail`` completes ``(warm_block, block]``; without a complete tail the durable entries come back partial with
        ``last_indexed_block=warm_block``.
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

        from services.resolution.mapping_enumerator import value_writer_spec_foldable

        if not all(value_writer_spec_foldable(hint) for hint in value_hints):
            return ValueFoldResult(entries=[], complete=False, partial_reason=UNFOLDABLE_WRITER_EVENT)
        hints_by_topic = _value_hints_by_topic(value_hints)
        if not hints_by_topic:
            return ValueFoldResult(entries=[], complete=False, partial_reason="unresolved_event_key")
        if any(len({_value_reading(h) for h in hints}) > 1 for hints in hints_by_topic.values()):
            return ValueFoldResult(entries=[], complete=False, partial_reason="ambiguous_event_direction")

        topic0s = sorted(hints_by_topic)

        # Any cold topic means the fold can't be complete, so read cursors first and skip the scan.
        cursor_states = {topic0: self.cursor_state(chain_id, event_address, topic0) for topic0 in topic0s}
        complete = all(c_block is not None and done for c_block, done in cursor_states.values())
        if not complete:
            _note_partial_reason("no_index_cursor", event_address=event_address, repo="postgres")
            return ValueFoldResult(entries=[], complete=False, partial_reason="no_index_cursor")
        # Warm cursors prove completeness only up to their height.
        warm_block = min(c_block for c_block, _done in cursor_states.values() if c_block is not None)
        behind = not _cursor_covers_block(warm_block, block)
        # Covered: scan to the frontier (max cursor), exactness is gated on the min. Behind: cut at the min so the tail
        # never applies a row twice.
        row_ceiling = (
            warm_block if behind else max(c_block for c_block, _done in cursor_states.values() if c_block is not None)
        )

        # member -> (value_hex, block, tx_index, log_index)
        state: dict[str, tuple[str, int, int, int]] = {}

        def _apply(rows: Iterable[Any]) -> None:
            for row in rows:
                topic0 = _row_topic0(row)
                if topic0 in hints_by_topic and row_is_undecodable(row):
                    raise UndecodableEventRow(topic0)
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
                    value_position = hint.get("value_position")
                    if value_position is None:
                        value_hex = _ZERO_WORD
                    else:
                        value_hex = _word_at_event_arg(topics, data_words, int(value_position), hint)
                    if member is None or value_hex is None:
                        raise UndecodableEventRow(topic0)
                    position = (
                        int(row.block_number),
                        int(row.transaction_index),
                        int(row.log_index),
                    )
                    prior = state.get(member)
                    if prior is None or position > (prior[1], prior[2], prior[3]):
                        state[member] = (value_hex, position[0], position[1], position[2])

        def _entries() -> list[dict[str, Any]]:
            return [
                {"key": member, "value_hex": value_hex, "last_block": last_block}
                for member, (value_hex, last_block, _tx, _log) in state.items()
            ]

        def _undecodable() -> ValueFoldResult:
            _note_partial_reason(UNDECODABLE_EVENT_DATA, event_address=event_address, repo="postgres")
            return ValueFoldResult(entries=[], complete=False, partial_reason=UNDECODABLE_EVENT_DATA)

        try:
            _apply(
                self.iter_event_rows(chain_id=chain_id, event_address=event_address, topic0s=topic0s, block=row_ceiling)
            )
        except UndecodableEventRow:
            return _undecodable()

        if behind:
            scan = _complete_with_tail(
                tail, event_address=event_address, topic0s=topic0s, frontier=warm_block, block=block
            )
            if scan is not None and scan.complete:
                try:
                    _apply(scan.logs)
                except UndecodableEventRow:
                    return _undecodable()
                return ValueFoldResult(
                    entries=_entries(), complete=True, last_indexed_block=block, scan_window=scan.trace_fields()
                )
            reason = "cursor_behind_block" if scan is None else "tail_scan_failed"
            _note_partial_reason(reason, event_address=event_address, repo="postgres")
            return ValueFoldResult(
                entries=_entries(), complete=False, partial_reason=reason, last_indexed_block=warm_block
            )
        return ValueFoldResult(entries=_entries(), complete=True, partial_reason=None, last_indexed_block=warm_block)

    def iter_event_rows(
        self,
        *,
        chain_id: int,
        event_address: str,
        topic0s: list[str],
        block: int | None = None,
    ) -> list[IndexedEventLog]:
        """Raw indexed logs for ``event_address`` matching ``topic0s``, in log order, for adapters that join several
        events (e.g. Solmate RolesAuthority).

        Raises :class:`UndecodableEventRow` rather than hand back a row whose data can't be decoded.
        """
        lowered = [t.lower() for t in topic0s if isinstance(t, str)]
        if not lowered:
            return []
        q = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(IndexedEventLog.event_address == event_address.lower())
            .where(IndexedEventLog.topic0.in_(lowered))
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        if block is not None:
            q = q.where(IndexedEventLog.block_number <= block)
        rows = list(self.session.execute(q).scalars())
        if any(row_is_undecodable(row) for row in rows):
            raise UndecodableEventRow(event_address)
        return rows

    def logs_through_block(
        self,
        *,
        chain_id: int,
        event_address: str,
        topic0s: list[str],
        block: int | None,
        tail: "TailScanner | None",
    ) -> IndexedLogs:
        """Every log for ``topic0s`` through ``block`` under ``fold_event_history``'s completeness rules.

        Every cursor must be exactness-eligible and ``backfill_complete``. Covered cursors read rows to the max
        frontier; behind ones cut rows at the least advanced cursor and need a complete ``tail`` over
        ``(warm, block]``. Raises :class:`UndecodableEventRow` for a row or tail log no fold may skip.
        """
        topics = sorted({t.lower() for t in topic0s if isinstance(t, str)})
        states = [self.cursor_state(chain_id, event_address, topic0) for topic0 in topics]
        if not topics or any(cursor_block is None or not done for cursor_block, done in states):
            return IndexedLogs(logs=(), complete=False, reason=NO_INDEX_CURSOR)
        if not isinstance(block, int):
            return IndexedLogs(logs=(), complete=False, reason=UNPINNED_BLOCK)
        frontiers = [cursor_block for cursor_block, _done in states if cursor_block is not None]
        warm_block = min(frontiers)
        behind = warm_block < block
        # Behind: cut at the least advanced cursor so the tail never applies a row twice. Covered: the max frontier
        # admits every indexed row.
        rows = self.iter_event_rows(
            chain_id=chain_id,
            event_address=event_address,
            topic0s=topics,
            block=warm_block if behind else max(frontiers),
        )
        if not behind:
            return IndexedLogs(logs=tuple(rows), complete=True, last_indexed_block=warm_block)
        scan = tail(event_address.lower(), topics, warm_block, block) if tail is not None else None
        if scan is None or not scan.complete:
            reason = CURSOR_BEHIND_BLOCK if scan is None else (scan.reason or CURSOR_BEHIND_BLOCK)
            return IndexedLogs(logs=(), complete=False, reason=reason, last_indexed_block=warm_block)
        if any(row_is_undecodable(log) for log in scan.logs):
            raise UndecodableEventRow(event_address)
        return IndexedLogs(logs=(*rows, *scan.logs), complete=True, last_indexed_block=block)

    def min_indexed_block(self, *, chain_id: int, event_address: str, topic0s: list[str]) -> int | None:
        """Lowest cursor block across ``topic0s``, or ``None`` when any backfill is incomplete.

        Completeness, not the number, is the trust signal.
        """
        topics = [t for t in topic0s if isinstance(t, str)]
        if not topics:
            return None
        states = [self.cursor_state(chain_id, event_address, t) for t in topics]
        if any(block is None or not complete for block, complete in states):
            return None
        return min(block for block, _ in states if block is not None)

    def cursor_state(self, chain_id: int, event_address: str, topic0: str) -> tuple[int | None, bool]:
        """``(last_indexed_block, backfill_complete)`` for one cursor, or ``(None, False)``.

        Every exactness gate goes through here, and a complete zero-row fold is published as exact-empty. Eligibility is
        an allow-list (``cursor_permits_exactness``): an attributed ``enrollment_basis`` and a witnessed
        ``first_indexed_block_basis``, so unknown bases, ``not_determined``, NULL and ``explicit_seed`` lower bounds are
        ineligible by default.

        E.g. a cursor enrolled from a monitoring plan only proves that topic never fired, not that the variable was
        never written. Ineligible cursors report ``complete=False`` and route to the inline fallback.
        """
        row = self.session.execute(
            select(
                IndexedEventCursor.last_indexed_block,
                IndexedEventCursor.backfill_complete,
                IndexedEventCursor.enrollment_basis,
                IndexedEventCursor.first_indexed_block_basis,
            )
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(IndexedEventCursor.event_address == event_address.lower())
            .where(IndexedEventCursor.topic0 == topic0.lower())
        ).first()
        if row is None:
            return None, False
        if not cursor_permits_exactness(row[2], row[3]):
            return row[0], False
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


def _topic_fold_modes(
    hints_by_topic: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, tuple[str, dict[str, Any]]], bool]:
    """Per-topic fold mode for an add/remove fold.

    Agreeing hints fold from the hint (``("hint", first_hint)``). A topic with both directions is one event emitted by
    both writers, so direction comes from the payload word at ``value_position`` (``("payload", value_hint)``). Without
    a usable position the whole var is undetermined: returns ``ambiguous=True`` so the caller fails closed.
    """
    modes: dict[str, tuple[str, dict[str, Any]]] = {}
    ambiguous = False
    for topic0, hints in hints_by_topic.items():
        directions = {h.get("direction") for h in hints}
        if len(directions) <= 1:
            modes[topic0] = ("hint", hints[0])
            continue
        value_hint = next((h for h in hints if h.get("value_position") is not None), None)
        if value_hint is None:
            ambiguous = True
            continue
        modes[topic0] = ("payload", value_hint)
    return modes, ambiguous


def _payload_membership(
    topics: list[str],
    data_words: list[str],
    value_hint: dict[str, Any],
) -> bool | None:
    """Membership from the payload's value word (nonzero == present), or ``None`` when unreadable (the row is
    undecidable).
    """
    try:
        position = int(value_hint["value_position"])
    except (KeyError, TypeError, ValueError):
        return None
    word = _word_at_event_arg(topics, data_words, position, value_hint)
    if word is None:
        return None
    try:
        return int(word, 16) != 0
    except ValueError:
        return None


def _value_hints_by_topic(value_hints: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for hint in value_hints:
        topic0 = _normalize_topic(hint.get("topic0"))
        if topic0 is None:
            continue
        out.setdefault(topic0, []).append(hint)
    return out


def _value_reading(hint: dict[str, Any]) -> tuple[Any, ...]:
    """How a hint reads its event: the value word (or zero for a removal) and the key map. Two readings of one event
    conflict.
    """
    return (
        hint.get("value_position"),
        json.dumps(hint.get("topics_to_keys") or {}, sort_keys=True, default=str),
        json.dumps(hint.get("data_to_keys") or {}, sort_keys=True, default=str),
    )


def _word_at_event_arg(
    topics: list[str],
    data_words: list[str],
    event_arg_position: int,
    hint: dict[str, Any],
) -> str | None:
    """The 32-byte word at an event-arg position.

    Positions count all args; ``indexed_positions`` says which are in ``topics``, the rest are ``data_words`` in order.
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
