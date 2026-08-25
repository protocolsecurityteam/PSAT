"""Resolve a company/protocol name to DefiLlama slug and DApp URL."""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher

import requests

from utils.chains import canonical_chain
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


_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

#: DefiLlama listing ``address`` values that name no address. ``"-"`` is the
#: listing's own placeholder for a chainless/tokenless entry.
_NON_ADDRESS_LISTING_VALUES = frozenset({"", "-", "null", "none"})


def parse_listing_address(raw: object) -> tuple[str, str | None] | None:
    """Parse one DefiLlama listing ``address`` field into
    ``(address, chain_name)``.

    The field is either chain-prefixed (``"base:0x60…"``), bare (``"0xfe0c…"``
    — ethereum by the listing's own convention), or a non-address placeholder.
    Returns None for every shape that names no address; a prefix this parser
    cannot read is a refusal, never a silent fall back to ethereum.
    """
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if value.lower() in _NON_ADDRESS_LISTING_VALUES:
        return None
    chain: str | None = None
    if ":" in value:
        prefix, _, rest = value.partition(":")
        prefix = prefix.strip().lower()
        if not prefix:
            return None
        chain = prefix
        value = rest.strip()
    if not _ADDRESS_RE.match(value):
        return None
    return value.lower(), chain


def listing_addresses(protocols: list[dict]) -> list[dict]:
    """The parsed ``address`` field of every listing in a protocol family, in
    deterministic order, as ``{"address", "chain", "slug"}``. Chainless (bare)
    entries carry ``chain=None`` — the caller resolves that to ethereum."""
    seen: dict[tuple[str, str | None], dict] = {}
    for entry in protocols:
        parsed = parse_listing_address(entry.get("address"))
        if parsed is None:
            continue
        address, chain = parsed
        key = (address, chain)
        if key in seen:
            continue
        seen[key] = {"address": address, "chain": chain, "slug": entry.get("slug")}
    return [seen[key] for key in sorted(seen, key=lambda k: (k[0], k[1] or ""))]


def listing_nominations(resolved: dict) -> list[dict]:
    """``resolve_protocol`` output → nomination entries ``{"address", "chain"}``.

    A bare listing address is ethereum by the listing's own convention; a
    prefixed one keeps its chain under PSAT's canonical key. An unrecognized
    prefix is preserved verbatim rather than coerced — the row is then a
    candidate whose chain never resolves, which is the honest state, not a
    member on a chain nobody named.
    """
    out: list[dict] = []
    for entry in resolved.get("listing_addresses") or []:
        raw_chain = entry.get("chain")
        out.append(
            {
                "address": entry["address"],
                "chain": "ethereum" if raw_chain is None else (canonical_chain(raw_chain) or raw_chain),
            }
        )
    return out


def _make_result(primary: dict, siblings: list[dict]) -> dict:
    return {
        "slug": primary.get("slug"),
        "url": primary.get("url"),
        "name": primary.get("name"),
        "chains": primary.get("chains", []),
        # The listing's own governance/token address, per sibling — a
        # DefiLlama-curated fact of the same provenance the W6 seed rests on
        # (spec §3.2), and the only address the listing itself publishes.
        "listing_addresses": listing_addresses(siblings),
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
        return {
            "slug": None,
            "url": None,
            "name": None,
            "chains": [],
            "listing_addresses": [],
            "all_slugs": [],
            "all_names": [],
        }

    match = _match_protocol(name, protocols)
    if not match:
        return {
            "slug": None,
            "url": None,
            "name": None,
            "chains": [],
            "listing_addresses": [],
            "all_slugs": [],
            "all_names": [],
        }

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
