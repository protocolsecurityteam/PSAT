"""Unified confidence + ranking logic for discovered contracts.

Every discovery source — inventory, DApp crawl, DefiLlama scan — eventually
produces rows in the ``contracts`` table and competes for the
``analyze_limit`` budget in the ``selection`` stage. The scoring used to
live in two places: ``_score_inventory_item`` in ``inventory.py`` for
evidence-rich entries, and a parallel default-confidence map in the
selection worker for sources that don't carry evidence. This module is
the single place those decisions live now.

Layers:

1. **Initial confidence** — assigned at discovery time.
   - Inventory entries: ``score_inventory_evidence`` reads Tavily-derived
     evidence (table/link/text/deployer/explorer) and produces 0.35-0.99.
   - DApp / DefiLlama rows: no evidence to score, so they store
     ``confidence=NULL`` and the selector applies a source-specific
     default (see ``default_confidence_for_source``).

2. **Ranking** — performed once in the selection stage.
   ``rank_contract_rows`` shims ``Contract`` rows into the dict shape
   ``enrich_with_activity`` expects and returns them sorted by the
   same blended ``rank_score = confidence * 0.35 + activity * 0.65``
   the inventory path already uses. Sharing this function across
   sources is the whole point of the selection stage: on-chain
   evidence (DApp, DefiLlama) and documented evidence (inventory)
   compete on equal footing.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from db.models import Contract

from .activity import enrich_with_activity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum confidence for a contract to be queued for analysis. Applied
# by the selection stage to every discovery source uniformly — the
# threshold exists to cut rows that exist only as weak rumors (a one-off
# Tavily mention with no corroboration). DApp/DefiLlama rows default
# above this floor via ``default_confidence_for_source``, so they all
# clear it unless a test explicitly overrides confidence.
MIN_CONFIDENCE_THRESHOLD = 0.3

# Backfilled ``upgrade_history`` rows only exist to anchor audit-coverage
# matches against superseded implementations; analyzing them would waste
# pipeline cycles on bytecode nobody's using anymore.
EXCLUDED_DISCOVERY_SOURCES: tuple[str, ...] = ("upgrade_history",)

# Tag stamped on the CURRENT implementation of a live proxy when the upgrade-
# history backfill encounters it. The current impl appears in the proxy's own
# last ``Upgraded`` event, so the backfill would otherwise tag it
# ``upgrade_history`` and the anchor predicate would wrongly exclude the live
# impl — where the proxy's real functions + principals live — from analysis,
# requeue, and coverage metrics. See services/discovery/upgrade_history.py.
CURRENT_IMPLEMENTATION_SOURCE = "current_implementation"


def is_superseded_impl(discovery_sources: Iterable[str] | None) -> bool:
    """True for a row that exists ONLY to anchor audit coverage against a
    *superseded* implementation — the rows that should be excluded from
    analysis, requeue, and resolution-coverage metrics.

    A proxy's current live impl carries :data:`CURRENT_IMPLEMENTATION_SOURCE`
    (stamped by the backfill) so it is never mistaken for a superseded anchor.
    This is the single source of truth for the anchor predicate; the SQL form
    is :func:`not_superseded_impl_clause`.
    """
    srcs = set(discovery_sources or [])
    return "upgrade_history" in srcs and CURRENT_IMPLEMENTATION_SOURCE not in srcs


def not_superseded_impl_clause(discovery_sources_column: Any) -> Any:
    """SQLAlchemy *keep* predicate mirroring :func:`is_superseded_impl`.

    Keep a row unless it is a superseded-only anchor: ``upgrade_history`` is
    present AND it is not flagged as a live current implementation. NULL
    discovery_sources (legacy rows) are always kept.
    """
    from sqlalchemy import not_

    return (
        discovery_sources_column.is_(None)
        | not_(discovery_sources_column.contains(["upgrade_history"]))
        | discovery_sources_column.contains([CURRENT_IMPLEMENTATION_SOURCE])
    )


# Default confidence applied when a ``contracts`` row has ``confidence=NULL``.
# DApp-crawl and DefiLlama discoveries represent confirmed on-chain usage
# (the protocol's frontend actually calls them, the adapter actually
# reports TVL against them), so they start above the average inventory
# score rather than at the inventory floor.
DEFAULT_CONFIDENCE_BY_SOURCE: dict[str, float] = {
    "dapp_crawl": 0.7,
    "defillama": 0.7,
    "inventory": 0.5,
    "ai_inventory": 0.5,
    "tavily_ai_inventory": 0.5,
    "deployer_expansion": 0.4,
}
DEFAULT_CONFIDENCE_FALLBACK = 0.5

# Per-extra-source confidence boost for contracts corroborated by more
# than one discovery pipeline. Two independent sources naming the same
# address is meaningfully stronger than one — the docs page plus the
# live DApp crawl, for example, is hard to fake. The boost is linear
# per additional source and clamped at ``_MAX_CORROBORATION_BOOST`` so
# an unusual "everyone says X" row can't saturate to 0.99 from a weak
# base on corroboration alone.
CORROBORATION_BOOST_PER_SOURCE = 0.10
_MAX_CORROBORATION_BOOST = 0.25
_MAX_CONFIDENCE = 0.99


# ---------------------------------------------------------------------------
# Initial confidence
# ---------------------------------------------------------------------------


def default_confidence_for_source(sources: list[str] | tuple[str, ...] | None) -> float:
    """Baseline confidence for a contract that was written without one.

    Takes the full set of sources that corroborated the contract and
    returns the highest per-source default. Corroboration stacking
    happens in :func:`effective_confidence`, not here — this function
    answers "what's the best single-source baseline?" only.
    """
    if not sources:
        return DEFAULT_CONFIDENCE_FALLBACK
    return max(DEFAULT_CONFIDENCE_BY_SOURCE.get(s, DEFAULT_CONFIDENCE_FALLBACK) for s in sources)


def effective_confidence(
    raw_confidence: float | None,
    sources: list[str] | tuple[str, ...] | None,
) -> float:
    """Confidence for ranking purposes: stored value + corroboration boost.

    The stored ``Contract.confidence`` is the "raw" score one discovery
    pipeline assigned (inventory evidence scoring, or NULL for sources
    that don't score). The effective value is what the selection stage
    ranks on — raw, plus a boost per extra corroborating source, capped
    so a thin-evidence row can't rocket past well-evidenced ones on
    corroboration alone.

    Consumers that read confidence for UI / filtering should call this
    with the row's ``discovery_sources`` list so they see the same
    number the selector used.
    """
    unique_sources = list(dict.fromkeys(sources or []))  # dedupe, preserve order
    if raw_confidence is None:
        base = default_confidence_for_source(unique_sources)
    else:
        base = float(raw_confidence)
    extra = max(0, len(unique_sources) - 1)
    boost = min(CORROBORATION_BOOST_PER_SOURCE * extra, _MAX_CORROBORATION_BOOST)
    return min(_MAX_CONFIDENCE, max(0.0, base + boost))


def score_inventory_evidence(
    chain: str,
    evidence: list[dict[str, Any]],
) -> tuple[float, dict[str, Any]]:
    """Score an inventory entry from its supporting evidence.

    ``evidence`` is the list of page-level observations the inventory
    extractor gathered for a single address. Each observation carries a
    ``kind`` label (``official_inventory_table``, ``deployer_expansion``,
    etc.) and optional metadata (``name``, ``url``, ``explorer_url``).
    Confidence rises with:

        - distinct pages the address appears on
        - the presence of a human-readable name
        - strong evidence kinds (tables > links > free-form text)
        - deployer / explorer corroboration
        - a known chain (vs ``unknown``)

    Cap at 0.99 so a perfect-score inventory row still leaves room
    for on-chain activity in the ranking blend.
    """
    page_count = len({str(item.get("url", "")) for item in evidence if item.get("url")})
    named_count = sum(1 for item in evidence if item.get("name"))
    table_count = sum(1 for item in evidence if item.get("kind") == "official_inventory_table")
    link_count = sum(1 for item in evidence if item.get("kind") == "official_inventory_link")
    text_count = sum(1 for item in evidence if item.get("kind") == "official_inventory_text")
    deployer_count = sum(1 for item in evidence if item.get("kind") == "deployer_expansion")
    explorer_count = sum(1 for item in evidence if item.get("explorer_url"))

    confidence = 0.35
    if named_count:
        confidence += 0.20
    if table_count:
        confidence += 0.18
    if link_count:
        confidence += 0.12
    if text_count and not table_count and not link_count:
        confidence += 0.05
    if deployer_count:
        confidence += 0.15
    confidence += min(0.12, max(0, page_count - 1) * 0.06)
    if explorer_count:
        confidence += 0.06
    if chain != "unknown":
        confidence += 0.05
    confidence = min(confidence, 0.99)

    evidence_counts: dict[str, Any] = {"official": page_count, "named": named_count}
    if table_count:
        evidence_counts["table"] = table_count
    if link_count:
        evidence_counts["link"] = link_count
    if text_count and not table_count:
        evidence_counts["text"] = text_count
    if deployer_count:
        evidence_counts["deployer"] = deployer_count
    if explorer_count:
        evidence_counts["explorer"] = explorer_count

    return round(confidence, 4), evidence_counts


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def rank_contract_rows(rows: Iterable[Contract]) -> list[dict[str, Any]]:
    """Rank Contract rows by the shared activity + confidence blend.

    The canonical ranking lives in ``enrich_with_activity``, which
    operates on dicts. This shim bridges the ORM boundary so the
    selection stage can rank rows that came from any discovery
    source without enrich_with_activity needing to know about the
    database.

    Confidence fed to the blend is the *effective* confidence — the
    row's raw stored value plus the corroboration boost from
    ``discovery_sources``. That means a contract found by inventory
    AND DApp crawl AND DefiLlama outranks a contract found by only one
    pipeline, even when the stored raw confidence is identical.

    Returns a list of dicts sorted by ``rank_score`` descending, each
    carrying:

        - ``address``, ``chains``, ``confidence``, ``name``,
          ``discovery_sources`` (input fields; confidence is the
          effective value fed to the ranker)
        - ``activity`` (set by ``enrich_with_activity``)
        - ``rank_score`` (set by ``enrich_with_activity``)
        - ``__row_address`` / ``__row_chain`` (back-refs to identify
          the originating Contract row; the name + underscore prefix
          avoids any collision with real keys)
    """
    shimmed: list[dict[str, Any]] = []
    for row in rows:
        chains = _resolve_chains(row)
        sources = list(row.discovery_sources or [])
        # Cast Decimal → float here so ``effective_confidence`` always
        # sees a float; ``Contract.confidence`` is ``NUMERIC(10,4)`` and
        # SQLAlchemy returns ``Decimal`` objects.
        raw = float(row.confidence) if row.confidence is not None else None
        confidence = effective_confidence(raw, sources)
        shimmed.append(
            {
                "__row_address": row.address,
                "__row_chain": row.chain,
                "address": row.address,
                "chains": chains,
                "confidence": confidence,
                "name": row.contract_name,
                "discovery_sources": sources,
            }
        )
    return enrich_with_activity(shimmed)


def _resolve_chains(row: Contract) -> list[str]:
    """Pick the chains list ``enrich_with_activity`` expects.

    A Contract row may carry ``chains`` (multi-chain inventory
    deployments) or just the scalar ``chain``. Activity ranking only
    reads the first element, but we pass the full list when available
    so the shim stays lossless for downstream consumers.
    """
    if row.chains:
        return list(row.chains)
    if row.chain:
        return [row.chain]
    return ["unknown"]


__all__ = [
    "CORROBORATION_BOOST_PER_SOURCE",
    "CURRENT_IMPLEMENTATION_SOURCE",
    "DEFAULT_CONFIDENCE_BY_SOURCE",
    "DEFAULT_CONFIDENCE_FALLBACK",
    "EXCLUDED_DISCOVERY_SOURCES",
    "MIN_CONFIDENCE_THRESHOLD",
    "default_confidence_for_source",
    "effective_confidence",
    "is_superseded_impl",
    "not_superseded_impl_clause",
    "rank_contract_rows",
    "score_inventory_evidence",
]
