"""Unified confidence and ranking for discovered contracts.

Every source writes ``contracts`` rows that compete for ``analyze_limit`` in selection; this is the single place scoring
lives.

1. Initial confidence at discovery: ``score_inventory_evidence`` for inventory entries (0.35-0.99); DApp/DefiLlama rows
store NULL and get ``default_confidence_for_source``.
2. Ranking once in selection: ``rank_contract_rows`` adapts rows for ``enrich_with_activity`` and sorts by ``confidence
* 0.35 + activity * 0.65``, so all sources compete equally.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from db.models import Contract

from .activity import enrich_with_activity

# Cuts rows that are only weak rumours (a single uncorroborated mention). DApp/DefiLlama defaults sit above it.
MIN_CONFIDENCE_THRESHOLD = 0.3

# Backfilled rows exist only to anchor audit coverage for superseded implementations; analysing them is wasted work.
EXCLUDED_DISCOVERY_SOURCES: tuple[str, ...] = ("upgrade_history",)

# Tag for a live proxy's current implementation, which also appears in the proxy's last ``Upgraded`` event; without it
# the backfill would tag it ``upgrade_history`` and exclude the live impl. See services/discovery/upgrade_history.py.
CURRENT_IMPLEMENTATION_SOURCE = "current_implementation"


def is_superseded_impl(discovery_sources: Iterable[str] | None) -> bool:
    """True for rows that exist only to anchor audit coverage for a superseded implementation (excluded from
    analysis, requeue and coverage metrics). The live impl carries :data:`CURRENT_IMPLEMENTATION_SOURCE`. SQL
    form: :func:`not_superseded_impl_clause`.
    """
    srcs = set(discovery_sources or [])
    return "upgrade_history" in srcs and CURRENT_IMPLEMENTATION_SOURCE not in srcs


def not_superseded_impl_clause(discovery_sources_column: Any) -> Any:
    """SQLAlchemy keep-predicate mirroring :func:`is_superseded_impl`; NULL sources are always kept."""
    from sqlalchemy import not_

    return (
        discovery_sources_column.is_(None)
        | not_(discovery_sources_column.contains(["upgrade_history"]))
        | discovery_sources_column.contains([CURRENT_IMPLEMENTATION_SOURCE])
    )


# Defaults for NULL confidence. DApp-crawl and DefiLlama rows reflect confirmed on-chain use, so they start above the
# average inventory score.
DEFAULT_CONFIDENCE_BY_SOURCE: dict[str, float] = {
    "dapp_crawl": 0.7,
    "defillama": 0.7,
    "inventory": 0.5,
    "ai_inventory": 0.5,
    "tavily_ai_inventory": 0.5,
    "deployer_expansion": 0.4,
}
DEFAULT_CONFIDENCE_FALLBACK = 0.5

# Boost per extra corroborating source (independent sources are hard to fake), capped at ``_MAX_CORROBORATION_BOOST`` so
# weak rows can't saturate on corroboration alone.
CORROBORATION_BOOST_PER_SOURCE = 0.10
_MAX_CORROBORATION_BOOST = 0.25
_MAX_CONFIDENCE = 0.99


def default_confidence_for_source(sources: list[str] | tuple[str, ...] | None) -> float:
    """The best single-source baseline confidence; stacking happens in :func:`effective_confidence`."""
    if not sources:
        return DEFAULT_CONFIDENCE_FALLBACK
    return max(DEFAULT_CONFIDENCE_BY_SOURCE.get(s, DEFAULT_CONFIDENCE_FALLBACK) for s in sources)


def effective_confidence(
    raw_confidence: float | None,
    sources: list[str] | tuple[str, ...] | None,
) -> float:
    """Ranking confidence: the stored value plus a capped boost per extra source.

    UI/filter consumers should use this with ``discovery_sources`` to match the selector.
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
    """Score an inventory entry from its evidence observations (each with a ``kind`` and optional ``name``, ``url``,
    ``explorer_url``, ``chain_from_hint``). Rises with distinct pages, a name, strong kinds (tables > links >
    text), deployer/explorer corroboration, and a known chain. Capped at 0.99 to leave room for activity.
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
    if any(item.get("chain_from_hint") for item in evidence):
        evidence_counts["chain_hinted"] = True

    return round(confidence, 4), evidence_counts


def rank_contract_rows(rows: Iterable[Contract]) -> list[dict[str, Any]]:
    """Rank Contract rows by the shared activity + confidence blend, adapting ORM rows to ``enrich_with_activity``'s
    dicts. Uses effective confidence, so multiply-corroborated contracts outrank single-source ones.

    Returns dicts sorted by ``rank_score``, with ``address``, ``chains``, ``confidence`` (effective), ``name``,
    ``discovery_sources``, ``activity``, ``rank_score``, and ``__row_address`` / ``__row_chain`` back-references.
    """
    shimmed: list[dict[str, Any]] = []
    for row in rows:
        chains = _resolve_chains(row)
        sources = list(row.discovery_sources or [])
        # ``NUMERIC(10,4)`` comes back as Decimal.
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
    """The chains list for ``enrich_with_activity``: ``chains`` when present, else the scalar ``chain``."""
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
