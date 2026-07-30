"""What a set of event cursors does and does not prove about absence.

An earned negative of the form "this state variable has never been written"
rests on three separate things being true at once:

1. **Recording surface** — every topic that CAN write the variable has a warm
   cursor. Enumerating that surface requires a proven inverse index from
   variables to writing topics. No such index exists in this system: the static
   pass that discovers writer events attaches its findings only to mappings keyed
   on the CALLER, and the one persisted forward map
   (``tracked_topics[].effect_tags.writes[]``) is a union over every emitter of a
   signature, so reading it backwards attributes a write to the wrong event.
2. **Range** — the covered range's LOWER bound. ``backfill_complete`` is an
   upper-bound flag; a cursor can be warm to head having started above the first
   write.
3. **Pages** — every ``eth_getLogs`` page in that range came back whole. A page
   returned at an upstream's result cap is indistinguishable from a truncated
   one, and nothing recorded the counts until now.

This module reports on (2) and (3) from persisted rows, and reports honestly that
(1) is unavailable. It therefore publishes a CEILING — a necessary condition that
can fail — and never a licence. ``earned_negative_admissible`` is hard-wired
False: making it reachable requires a proven inverse index, which does not exist,
and a new adversarial panel. It is not "unreachable by construction" in some
permanent sense — it is unreachable because the evidence is missing.

A caller may pass ``write_surface_topics`` to say which topics IT believes write
the variable. That populates ``enrolled`` / ``missing`` / ``blocking_reasons``
FOR REPORTING ONLY; it NEVER changes ``write_surface_basis``, which remains
``not_determined``, and therefore never changes ``enrollment_complete`` (false)
or ``earned_negative_admissible`` (false). A caller's belief about a third
party's write surface is a code-invariant claim, not a witness — a role registry
written directly by ``_roles[role].members[x] = true``, or an implementation
swapped behind a proxy after the plan was built, breaks it silently.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    FIRST_INDEXED_BASIS_CREATION,
    WINDOW_STATS_CONTINUOUS,
    IndexedEventCursor,
)
from services.resolution.repos.event_logs_rpc import default_result_cap

NOT_DETERMINED = "not_determined"

# ``page_completeness`` domain.
PAGES_COMPLETE = "complete"
PAGES_INCOMPLETE = "incomplete"

# ``blocking_reasons`` vocabulary — why the earned negative is not admissible.
REASON_NO_INVERSE_INDEX = "write_surface_not_enumerable"
REASON_MISSING_CURSORS = "write_surface_topics_missing_cursors"
REASON_COLD_CURSORS = "enrolled_cursors_not_warm"
REASON_LOWER_BOUND_UNKNOWN = "range_lower_bound_not_determined"
REASON_PAGE_RESIDUAL = "page_completeness_not_determined"


def page_completeness(cursor: IndexedEventCursor, *, configured_cap: int | None) -> str:
    """Whether every page this cursor folded is proven whole.

    ``complete`` requires all four of: a continuous window record, a recorded
    maximum, a cap persisted alongside those counts, and that persisted cap
    still being the one in force. The last condition is what stops a cap change
    from silently re-grading history: pages accepted under one guard say nothing
    about a different guard, in either direction, so a disagreement is
    ``not_determined`` rather than a re-computation.
    """
    if cursor.window_stats_basis != WINDOW_STATS_CONTINUOUS:
        return NOT_DETERMINED
    if cursor.max_window_log_count is None or cursor.window_stats_cap is None:
        return NOT_DETERMINED
    if configured_cap is None or int(configured_cap) != int(cursor.window_stats_cap):
        return NOT_DETERMINED
    return PAGES_COMPLETE if int(cursor.max_window_log_count) < int(cursor.window_stats_cap) else PAGES_INCOMPLETE


def _range_lower_bound(cursors: Sequence[IndexedEventCursor]) -> tuple[int | None, str]:
    """The highest witnessed lower bound across ``cursors``, or not_determined.

    Highest, not lowest: the claim is "no write below this height", and it holds
    only where EVERY cursor was covered, so the weakest link governs. One cursor
    without a witnessed bound makes the whole set's bound unknown — a NULL is
    never read as 0, which would assert coverage from genesis.
    """
    if not cursors:
        return None, NOT_DETERMINED
    bounds: list[int] = []
    for cursor in cursors:
        if cursor.first_indexed_block_basis != FIRST_INDEXED_BASIS_CREATION or cursor.first_indexed_block is None:
            return None, NOT_DETERMINED
        bounds.append(int(cursor.first_indexed_block))
    return max(bounds), FIRST_INDEXED_BASIS_CREATION


def _normalize_topics(topics: Iterable[str] | None) -> list[str] | None:
    if topics is None:
        return None
    return sorted({str(t).lower() for t in topics if isinstance(t, str) and t.startswith("0x")})


def absence_coverage(
    session: Session,
    *,
    chain_id: int,
    address: str,
    write_surface_topics: Iterable[str] | None = None,
    configured_cap: int | None = None,
) -> dict[str, Any]:
    """Report what the cursors on ``(chain_id, address)`` can support.

    The gate travels inside the same object as the numbers that produced it, so a
    consumer cannot read the payload without the verdict that qualifies it.
    """
    cap = default_result_cap() if configured_cap is None else configured_cap
    rows = list(
        session.execute(
            select(IndexedEventCursor)
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(IndexedEventCursor.event_address == address.lower())
        ).scalars()
    )
    enrolled = sorted(str(row.topic0).lower() for row in rows)
    warm = sorted(str(row.topic0).lower() for row in rows if bool(row.backfill_complete))
    asserted = _normalize_topics(write_surface_topics)

    reasons: list[str] = [REASON_NO_INVERSE_INDEX]
    missing: list[str] | None = None
    if asserted is not None:
        missing = [topic for topic in asserted if topic not in set(enrolled)]
        if missing:
            reasons.append(REASON_MISSING_CURSORS)
        cold = [topic for topic in asserted if topic in set(enrolled) and topic not in set(warm)]
        if cold:
            reasons.append(REASON_COLD_CURSORS)

    graded = rows if asserted is None else [row for row in rows if str(row.topic0).lower() in set(asserted)]
    lower_bound, lower_bound_basis = _range_lower_bound(graded)
    if lower_bound_basis != FIRST_INDEXED_BASIS_CREATION:
        reasons.append(REASON_LOWER_BOUND_UNKNOWN)

    verdicts = {page_completeness(row, configured_cap=cap) for row in graded}
    if not graded or verdicts != {PAGES_COMPLETE}:
        pages = NOT_DETERMINED if (not graded or NOT_DETERMINED in verdicts) else PAGES_INCOMPLETE
    else:
        pages = PAGES_COMPLETE
    if pages != PAGES_COMPLETE:
        reasons.append(REASON_PAGE_RESIDUAL)

    return {
        "chain_id": chain_id,
        "address": address.lower(),
        # The PROVEN write surface. Always null: no inverse index exists.
        "write_surface": None,
        "write_surface_basis": NOT_DETERMINED,
        # A caller's assertion, echoed under its own key so it can never be
        # mistaken for the proven surface above.
        "write_surface_asserted": asserted,
        "enrolled": enrolled,
        "warm": warm,
        "missing": missing,
        "range_lower_bound": lower_bound,
        "range_lower_bound_basis": lower_bound_basis,
        "page_completeness": pages,
        # Ceiling, not licence. False here does not mean the variable HAS been
        # written; it means this system cannot yet see whether it was.
        "enrollment_complete": False,
        "earned_negative_admissible": False,
        "blocking_reasons": sorted(set(reasons)),
    }
