"""Resolve a company/protocol name to DefiLlama slug and DApp URL."""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher

import requests

from utils.logging import record_degraded

logger = logging.getLogger(__name__)

DEFILLAMA_PROTOCOLS_URL = "https://api.llama.fi/protocols"
_protocols_cache: list[dict] | None = None

_SIMILARITY_THRESHOLD = 0.90


def _fetch_protocols() -> list[dict]:
    global _protocols_cache
    if _protocols_cache is not None:
        return _protocols_cache
    resp = requests.get(DEFILLAMA_PROTOCOLS_URL, timeout=15)
    resp.raise_for_status()
    # Sort by TVL descending so the most important protocol wins on ties
    data = resp.json()
    data.sort(key=lambda p: p.get("tvl") or 0, reverse=True)
    _protocols_cache = data
    return data


def _normalize(s: str) -> str:
    """Strip punctuation, spaces, and lowercase for comparison."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _make_result(primary: dict, siblings: list[dict]) -> dict:
    return {
        "slug": primary.get("slug"),
        "url": primary.get("url"),
        "name": primary.get("name"),
        "chains": primary.get("chains", []),
        "all_slugs": [s.get("slug") for s in siblings if s.get("slug")],
        # Display names for every sibling — used by ``get_or_create_protocol``
        # to find pre-resolver duplicate rows that share a family. Keep the
        # primary name first so callers can still treat ``[0]`` as the
        # canonical display string.
        "all_names": [primary.get("name")]
        + [s.get("name") for s in siblings if s.get("name") and s.get("slug") != primary.get("slug")],
    }


def _find_siblings(match: dict, protocols: list[dict]) -> list[dict]:
    """Return all protocols sharing the same parentProtocol, sorted by TVL desc.

    If the match has no parent, returns just the match itself.
    """
    parent = match.get("parentProtocol")
    if not parent:
        return [match]
    return [p for p in protocols if p.get("parentProtocol") == parent]


def _match_protocol(name: str, protocols: list[dict]) -> dict | None:
    """Find the best matching protocol entry. Returns None if no match."""
    name_lower = name.lower().strip()
    name_norm = _normalize(name)

    if not name_norm:
        return None

    # 1. Exact slug match
    for p in protocols:
        if p.get("slug", "").lower() == name_lower:
            return p

    # 2. Exact name match
    for p in protocols:
        if p.get("name", "").lower() == name_lower:
            return p

    # 3. Normalized match (etherfi == ether.fi == ether-fi)
    for p in protocols:
        if _normalize(p.get("slug", "")) == name_norm or _normalize(p.get("name", "")) == name_norm:
            return p

    # 4. Normalized substring — bidirectional. The forward direction
    # ("name in slug/name") catches partial inputs like "ether" → "etherfi".
    # The reverse ("slug/name in name") catches the bare-hostname case:
    # ``_normalize("etherfi.org") = "etherfiorg"`` contains slug "etherfi".
    # Both gate on ≥50% length overlap to keep the match-space tight.
    for p in protocols:
        slug_norm = _normalize(p.get("slug", ""))
        p_name_norm = _normalize(p.get("name", ""))
        if slug_norm and name_norm in slug_norm and len(name_norm) / len(slug_norm) >= 0.5:
            return p
        if p_name_norm and name_norm in p_name_norm and len(name_norm) / len(p_name_norm) >= 0.5:
            return p
        if slug_norm and slug_norm in name_norm and len(slug_norm) / len(name_norm) >= 0.5:
            return p
        if p_name_norm and p_name_norm in name_norm and len(p_name_norm) / len(name_norm) >= 0.5:
            return p

    # 5. Similarity search — compare normalized strings, pick best above threshold
    best_score = 0.0
    best_protocol = None
    for p in protocols:
        slug_score = SequenceMatcher(None, name_norm, _normalize(p.get("slug", ""))).ratio()
        name_score = SequenceMatcher(None, name_norm, _normalize(p.get("name", ""))).ratio()
        score = max(slug_score, name_score)
        if score > best_score:
            best_score = score
            best_protocol = p

    if best_protocol and best_score >= _SIMILARITY_THRESHOLD:
        logger.info(
            "Fuzzy matched '%s' → '%s' (slug=%s, score=%.2f)",
            name,
            best_protocol.get("name"),
            best_protocol.get("slug"),
            best_score,
        )
        return best_protocol

    return None


def pick_family_slug(resolved: dict) -> str | None:
    """Return a stable slug shared by every sibling under one parentProtocol.

    DefiLlama splits some protocols into siblings (ether.fi has 4:
    ether.fi-stake, ether.fi-cash, ...). The resolver's ``slug`` is the
    primary match — picked by TVL — and can shift across runs. Picking
    the alphabetically-first slug across ``all_slugs`` gives every input
    in the family the same canonical key regardless of which sibling
    happened to top the TVL ranking.

    Falls back to ``slug`` if ``all_slugs`` is empty (legacy stub data).
    Returns None when the resolver had no match at all.
    """
    all_slugs = resolved.get("all_slugs") or []
    if all_slugs:
        return min(all_slugs)
    return resolved.get("slug")


def resolve_protocol(name: str) -> dict:
    """Resolve a company name to DefiLlama slug and DApp URL.

    Finds the best matching protocol, then returns it along with all sibling
    protocols sharing the same ``parentProtocol`` (e.g. "etherfi" returns
    ether.fi-stake, ether.fi-liquid, etherfi-cash-liquid, etc.).

    Returns {"slug", "url", "name", "chains", "all_slugs"}.
    """
    try:
        protocols = _fetch_protocols()
    except Exception as exc:
        record_degraded(phase="defillama_protocols_fetch", exc=exc, context={"name": name})
        logger.warning("Failed to fetch DefiLlama protocols: %s", exc)
        return {"slug": None, "url": None, "name": None, "chains": [], "all_slugs": [], "all_names": []}

    match = _match_protocol(name, protocols)
    if not match:
        return {"slug": None, "url": None, "name": None, "chains": [], "all_slugs": [], "all_names": []}

    siblings = _find_siblings(match, protocols)
    result = _make_result(match, siblings)
    if len(siblings) > 1:
        logger.info(
            "Resolved '%s' → %s (%d sibling protocols)",
            name,
            match.get("slug"),
            len(siblings),
        )
    return result
