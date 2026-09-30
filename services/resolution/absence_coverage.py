"""What a set of event cursors does and does not prove about absence.

"This variable was never written" needs three things:

1. Recording surface: every topic that can write the variable has a warm cursor. That needs a proven variable-to-topic
inverse index, which doesn't exist (writer events are only attached to caller-keyed mappings, and
``tracked_topics[].effect_tags.writes[]`` is a union over emitters).
2. Range: a witnessed lower bound; ``backfill_complete`` only bounds from above.
3. Pages: every ``eth_getLogs`` page came back whole.

This reports (2) and (3) and says (1) is unavailable, so it publishes a ceiling, never a licence:
``earned_negative_admissible`` is hard-wired False until an inverse index exists.

``write_surface_topics`` lets a caller say which topics it believes write the variable. That fills ``enrolled`` /
``missing`` / ``blocking_reasons`` for reporting only; ``write_surface_basis`` stays ``not_determined``, since such a
belief is a claim, not a witness.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    FIRST_INDEXED_BASIS_CREATION,
    WINDOW_STATS_CONTINUOUS,
    IndexedEventCursor,
    enrollment_basis_permits_exactness,
)
from services.resolution.repos.event_logs_rpc import default_result_cap
from utils.scoring_status import NOT_DETERMINED

PAGES_COMPLETE = "complete"
PAGES_INCOMPLETE = "incomplete"

# Why the earned negative isn't admissible.
REASON_NO_INVERSE_INDEX = "write_surface_not_enumerable"
REASON_MISSING_CURSORS = "write_surface_topics_missing_cursors"
REASON_COLD_CURSORS = "enrolled_cursors_not_warm"
REASON_LOWER_BOUND_UNKNOWN = "range_lower_bound_not_determined"
REASON_PAGE_RESIDUAL = "page_completeness_not_determined"


def page_completeness(cursor: IndexedEventCursor, *, configured_cap: int | None) -> str:
    """Whether every page this cursor folded is proven whole: a continuous window record, a recorded maximum, a
    persisted cap, and that cap still in force. A cap change gives ``not_determined`` rather than re-grading
    history.
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

    Highest because every cursor must be covered; a NULL is never read as 0 (coverage from genesis).
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
    """Lowercase before testing the prefix, or an uppercase ``0X`` topic is dropped and shortens ``missing``."""
    if topics is None:
        return None
    lowered = (str(t).lower() for t in topics if isinstance(t, str))
    return sorted({t for t in lowered if t.startswith("0x")})


def absence_coverage(
    session: Session,
    *,
    chain_id: int,
    address: str,
    write_surface_topics: Iterable[str] | None = None,
    configured_cap: int | None = None,
) -> dict[str, Any]:
    """Report what the cursors on ``(chain_id, address)`` can support.

    The verdict travels with the numbers so they can't be read without it.
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
    # ``warm`` must match the resolution gate; refused cursors are reported under their own key.
    warm = sorted(
        str(row.topic0).lower()
        for row in rows
        if bool(row.backfill_complete) and enrollment_basis_permits_exactness(row.enrollment_basis)
    )
    exactness_ineligible = sorted(
        str(row.topic0).lower() for row in rows if not enrollment_basis_permits_exactness(row.enrollment_basis)
    )
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
        # The proven write surface: always null (no inverse index).
        "write_surface": None,
        "write_surface_basis": NOT_DETERMINED,
        # The caller's assertion, under its own key so it can't be mistaken for the proven surface.
        "write_surface_asserted": asserted,
        "enrolled": enrolled,
        "warm": warm,
        # Enrolled but refused by the resolution gate: indexes history, licenses nothing.
        "exactness_ineligible": exactness_ineligible,
        "missing": missing,
        "range_lower_bound": lower_bound,
        "range_lower_bound_basis": lower_bound_basis,
        "page_completeness": pages,
        # Ceiling, not licence: False means we can't see, not that it was written.
        "enrollment_complete": False,
        "earned_negative_admissible": False,
        "blocking_reasons": sorted(set(reasons)),
    }
