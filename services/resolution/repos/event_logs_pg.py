"""Postgres-backed generic event-log repo."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import IndexedEventCursor, IndexedEventLog, enrollment_basis_permits_exactness
from services.resolution.adapters import EnumerationResult
from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from utils.logging import record_stage_metric

logger = logging.getLogger(__name__)


# Tally of partial fold outcomes broken out by ``partial_reason`` — bounded
# because the reason set is finite (cold index, unresolved key, HyperSync
# timeout / page-cap / typed transport error). A module-scoped counter gives an
# inspectable running total; ``_note_partial_reason`` also folds it into the
# resolution stage's timing artifact (when called under a worker job) so a spike
# in cold-index defers or HyperSync timeouts is chartable rather than silent.
_PARTIAL_REASON_COUNTS: "Counter[str]" = Counter()
# Reasons that signal a genuine upstream degradation (vs. an expected cold-index
# defer or a descriptor-shape miss) — these log at WARNING, the rest at DEBUG.
_DEGRADED_PARTIAL_REASONS = {"hypersync_timeout", "hypersync_max_pages"}


def _note_partial_reason(partial_reason: str | None, *, event_address: str, repo: str) -> int:
    """Count + log one partial fold outcome, keyed by ``partial_reason``.

    Returns the running count for that reason. A no-op for ``None`` (a complete
    fold). The ``record_stage_metric`` write is a no-op outside a worker job
    context, so repos can call this unconditionally.
    """
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
    """Latest-value-per-caller fold output for ``fold_event_values``.

    ``entries`` maps each caller (``key``) to the 32-byte hex word it was
    most recently assigned (``value_hex``). ``complete`` is True only when
    every participating topic's durable backfill has reached head.
    """

    entries: list[dict[str, Any]] = field(default_factory=list)
    complete: bool = False
    partial_reason: str | None = None


def _cursor_covers_block(cursor_block: int | None, block: int | None) -> bool:
    """A warm (``backfill_complete``) cursor proves the member set is complete
    only up to ``cursor_block``. ``enumerable``/``exact`` may be claimed only when
    that cursor demonstrably COVERS the evaluated point ``block``:

      * ``block is None`` == evaluate at the live head. The durable cursor lags
        live head by at least ``confirmation_depth`` + the poll interval (more if
        the indexer is stopped), so head-coverage can never be asserted -> not
        covered. The resolver pins a finalized head into ``block`` so a
        keeping-up cursor stays exact; an unpinned ``None`` here cannot.
      * ``block is not None`` -> covered iff the cursor reached it.

    Not covered -> the fold returns ``partial``/``cursor_behind_block``, which the
    adapter demotes to ``lower_bound`` (NOT a forever-defer like the cold
    ``no_index_cursor`` path: steady-state lag never "warms to head")."""
    if cursor_block is None:
        return False
    if block is None:
        return False
    return cursor_block >= block


def _row_ceiling(frontier_block: int | None, block: int | None) -> int | None:
    """Upper block bound for a fold's ROW scan — DECOUPLED from the finality pin.

    Rows are included up to the durable index frontier (``frontier_block``, the
    cursor), NEVER truncated at the resolver's lower finality pin (``block``).
    The pin (``RESOLVER_FINALITY_MARGIN`` behind head) governs only the
    exact-vs-lower_bound gate (``_cursor_covers_block``); using it as the row
    ceiling would drop an already-indexed write in ``(block, frontier_block]``.
    For a positive allowlist that silently drops a real (indexed) controller; for
    a ``falsy``/denylist leaf that is negated into a cofinite blacklist it is
    FAIL-OPEN — a recently-blocked but indexed address would fall out of the
    blacklist and read PUBLIC while the set is still labelled exact. The cursor
    is the indexer's confirmed (``confirmation_depth``-deep) frontier, so folding
    up to it is itself reorg-safe. With no cursor (cold path) fall back to the
    requested ``block``."""
    if frontier_block is None:
        return block
    return frontier_block


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

        cursor_block, complete = self._cursor_state(chain_id, event_address, topic0)

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
        # Fold rows up to the index frontier (cursor), not the finality pin: the
        # pin only gates exactness below (``_cursor_covers_block``). See _row_ceiling.
        row_ceiling = _row_ceiling(cursor_block, block)
        if row_ceiling is not None:
            q = q.where(IndexedEventLog.block_number <= row_ceiling)

        state: dict[str, bool] = {}
        for row in self.session.execute(q).scalars():
            event_keys = _event_keys(row.topics or [], row.data_words or [], topics_to_keys, data_to_keys)
            if any(event_keys.get(idx) != expected for idx, expected in key_filters.items()):
                continue
            member = _word_to_address(event_keys.get(member_key))
            if member is None:
                continue
            state[member] = True

        # Trust the durable index only once its historical backfill has reached
        # head. Cursors are seeded at the event address's deploy block, so a
        # positive ``last_indexed_block`` no longer implies "fully indexed" — gate
        # on ``backfill_complete`` so a cold/mid-backfill cursor defers to the
        # adapter's inline fallback instead of folding a partial history.
        if cursor_block is None or not complete:
            _note_partial_reason("no_index_cursor", event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason="no_index_cursor",
                last_indexed_block=None,
            )
        if not _cursor_covers_block(cursor_block, block):
            _note_partial_reason("cursor_behind_block", event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason="cursor_behind_block",
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

        # Same-topic0 add/remove conflicts fold from the event payload; a
        # conflict with no payload position poisons the whole var's fold (any
        # such event may have removed a member another topic added), so it
        # fails closed rather than folding a hint-order artifact.
        fold_modes, ambiguous = _topic_fold_modes(hints_by_topic)
        if ambiguous:
            _note_partial_reason("ambiguous_event_direction", event_address=event_address, repo="postgres")
            return EnumerationResult(members=[], confidence="partial", partial_reason="ambiguous_event_direction")

        topic0s = sorted(hints_by_topic)
        cursor_states = {topic0: self._cursor_state(chain_id, event_address, topic0) for topic0 in topic0s}
        # Fold rows up to the HIGHEST per-topic index frontier (every topic's rows
        # only exist up to its own cursor, so the max admits all indexed rows and no
        # phantom ones), not the finality pin — the pin only gates exactness below.
        frontier = max((b for b, _ in cursor_states.values() if b is not None), default=None)

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
        row_ceiling = _row_ceiling(frontier, block)
        if row_ceiling is not None:
            q = q.where(IndexedEventLog.block_number <= row_ceiling)

        state: dict[str, bool] = {}
        undecidable_row = False
        for row in self.session.execute(q).scalars():
            topic0 = str(row.topic0).lower()
            mode = fold_modes.get(topic0)
            if mode is None:
                continue
            mode_kind, value_hint = mode
            topics = row.topics or []
            data_words = row.data_words or []
            # Payload mode reads ONE hint (the conflicted hints describe the
            # same event; the value word decides). Uniform mode keeps the
            # historical union over every hint's key extraction.
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
                        # A conflicted event whose payload word cannot be read
                        # on this row leaves that member's state — and
                        # therefore the var's member set — undetermined.
                        undecidable_row = True
                        break
                else:
                    present = hint["direction"] == "add"
                state[member] = present
            if undecidable_row:
                break
        if undecidable_row:
            _note_partial_reason("ambiguous_event_direction", event_address=event_address, repo="postgres")
            return EnumerationResult(members=[], confidence="partial", partial_reason="ambiguous_event_direction")

        # As in fold_event_writes: a topic counts as indexed only when its
        # backfill is complete, not merely because its cursor advanced past 0.
        complete_blocks = [block for block, complete in cursor_states.values() if block is not None and complete]
        last_indexed_block = min(complete_blocks) if complete_blocks else None
        if len(complete_blocks) != len(topic0s):
            _note_partial_reason("no_index_cursor", event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason="no_index_cursor",
                last_indexed_block=last_indexed_block,
            )

        if not _cursor_covers_block(last_indexed_block, block):
            _note_partial_reason("cursor_behind_block", event_address=event_address, repo="postgres")
            return EnumerationResult(
                members=sorted(addr for addr, present in state.items() if present),
                confidence="partial",
                partial_reason="cursor_behind_block",
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

        Returns the per-caller latest value with ``complete`` True only when
        every participating topic's backfill has reached head. When any required
        topic's cursor is cold the fold is incomplete by definition, so it returns
        an empty ``no_index_cursor`` result without scanning rows (the caller
        defers to the reconciler); the row scan + fold runs only on a warm head.
        Reads no live endpoint.

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

        # A topic is trustworthy only when its backfill has reached head. If any
        # required topic is cold (no ``backfill_complete`` cursor) the fold cannot
        # be complete, so it defers (``no_index_cursor``) regardless of what a scan
        # would return — read the cursors first and skip the row scan entirely.
        # The adapter re-resolves the deferral once the indexer warms the address.
        cursor_states = {topic0: self._cursor_state(chain_id, event_address, topic0) for topic0 in topic0s}
        complete = all(c_block is not None and done for c_block, done in cursor_states.values())
        if not complete:
            _note_partial_reason("no_index_cursor", event_address=event_address, repo="postgres")
            return ValueFoldResult(entries=[], complete=False, partial_reason="no_index_cursor")
        # Warm cursors only prove completeness up to their height; a fold that
        # evaluates past the cursor (or at an unpinned live head) is a lower_bound.
        warm_block = min(c_block for c_block, _done in cursor_states.values() if c_block is not None)
        if not _cursor_covers_block(warm_block, block):
            _note_partial_reason("cursor_behind_block", event_address=event_address, repo="postgres")
            return ValueFoldResult(entries=[], complete=False, partial_reason="cursor_behind_block")

        # Scan up to the index frontier (max cursor), not the lower finality pin —
        # the pin already gated completeness above via ``warm_block`` (min cursor).
        frontier = max(c_block for c_block, _done in cursor_states.values() if c_block is not None)
        rows = self.iter_event_rows(chain_id=chain_id, event_address=event_address, topic0s=topic0s, block=frontier)

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

        entries = [
            {"key": member, "value_hex": value_hex, "last_block": last_block}
            for member, (value_hex, last_block, _tx, _log) in state.items()
        ]
        return ValueFoldResult(entries=entries, complete=True, partial_reason=None)

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

    def _cursor_state(self, chain_id: int, event_address: str, topic0: str) -> tuple[int | None, bool]:
        """``(last_indexed_block, backfill_complete)`` for one cursor, or
        ``(None, False)`` when no cursor exists.

        Every exactness gate in this repo funnels through here, and a zero-row
        fold under a complete state is published as an EXACT EMPTY — an earned
        negative asserting the event never fired. Whether a cursor may support
        that is decided by an ALLOW-LIST over ``enrollment_basis``
        (``enrollment_basis_permits_exactness``), never by excluding the tokens we
        happened to think of: an unrecognised basis, a future enrolment source, or
        the literal ``not_determined`` that ``enroll_event_cursor`` stores when a
        caller omits the argument all answer "not eligible" without anyone having
        to remember to add them.

        A cursor enrolled from a monitoring tracking plan is the concrete case:
        the plan names topics an emitter can emit and attributes them to no state
        variable, so a warm cursor over one proves that THAT TOPIC never fired,
        never that the variable behind it was never written by some other topic
        nobody enrolled. An ineligible cursor is held at ``complete=False``, which
        routes callers to the inline fallback exactly as a cold cursor does — it
        still indexes, it just never licenses the negative.

        Rows predating ``enrollment_basis`` are NULL and stay eligible, so the 80
        pre-existing cursors keep folding exactly as before.
        """
        row = self.session.execute(
            select(
                IndexedEventCursor.last_indexed_block,
                IndexedEventCursor.backfill_complete,
                IndexedEventCursor.enrollment_basis,
            )
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(IndexedEventCursor.event_address == event_address.lower())
            .where(IndexedEventCursor.topic0 == topic0.lower())
        ).first()
        if row is None:
            return None, False
        if not enrollment_basis_permits_exactness(row[2]):
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
    """Per-topic membership-fold decision for an add/remove event fold.

    A topic0 whose hints all agree on ``direction`` folds from the hint
    (``("hint", first_hint)``). A topic0 carrying BOTH directions is one event
    emitted by both the grant and the revoke writer — direction is then a
    property of the EVENT PAYLOAD, not of whichever hint a list ordered last:
    fold from the assigned-value word at the hint's own ``value_position``
    (``("payload", value_hint)``).

    A conflicted topic0 with no usable ``value_position`` is undecidable: no
    row of that event supports any membership conclusion, and because every
    hint here writes the same storage var, membership of the WHOLE var is
    undetermined. Returns ``ambiguous=True`` so the caller fails the fold
    closed (``partial`` / ``ambiguous_event_direction``) instead of publishing
    a hint-order artifact as a member set.
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
    """Membership boolean carried in the event's own payload: the assigned
    value word at ``value_position`` (nonzero == present). ``None`` when the
    word cannot be read from this row — the caller must treat that row as
    undecidable, never default a direction."""
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
