"""Canonical chain-label helpers shared by discovery writers."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_CHAIN_ALIASES = {
    "mainnet": "ethereum",
    "eth": "ethereum",
    "ethereum": "ethereum",
    "ethereum mainnet": "ethereum",
    "eth mainnet": "ethereum",
    "base": "base",
    "base mainnet": "base",
    "arbitrum": "arbitrum",
    "arbitrum one": "arbitrum",
    "optimism": "optimism",
    "optimistic ethereum": "optimism",
    "polygon": "polygon",
    "polygon pos": "polygon",
    "matic": "polygon",
    "avalanche": "avalanche",
    "avalanche c-chain": "avalanche",
    "avax": "avalanche",
    "bsc": "bsc",
    "bnb": "bsc",
    "bnb chain": "bsc",
    "binance smart chain": "bsc",
    "linea": "linea",
    "scroll": "scroll",
    "zksync": "zksync",
    "zk sync": "zksync",
    "blast": "blast",
    "unknown": "unknown",
}


def canonical_chain(value: Any) -> str | None:
    """Return PSAT's stable lower-case chain key for a loose label."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalized = re.sub(r"[\s_-]+", " ", text).strip().lower()
    return _CHAIN_ALIASES.get(normalized, normalized)


def canonical_chain_list(values: Iterable[Any] | None) -> list[str] | None:
    """Canonicalize, dedupe, and preserve first-seen order for chain arrays."""
    if values is None:
        return None
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        chain = canonical_chain(value)
        if not chain or chain in seen:
            continue
        seen.add(chain)
        out.append(chain)
    return out


DEFAULT_CHAIN = "ethereum"


def normalize_chain_fields(request_dict: dict[str, Any], *, default_chain: str = DEFAULT_CHAIN) -> dict[str, Any]:
    """Stamp canonical ``chain`` and derived ``chain_id`` onto a job request dict, in place.

    The single chokepoint reused by ``create_job`` and every child-job spawn so
    no job — root or child — ever carries ``chain=None``. ``chain`` is the
    canonical string (default ``"ethereum"`` when omitted); when the caller
    supplied only a numeric ``chain_id`` the name is back-filled from it. An
    explicit positive ``chain_id`` wins; otherwise it's derived from the chain
    name and may stay ``None`` for chains outside ``COMMON_CHAIN_IDS`` —
    ``default_rpc_url`` routes those by the chain string instead.
    """
    from utils.rpc import chain_id_for_chain_name, chain_name_for_chain_id

    chain = canonical_chain(request_dict.get("chain"))
    explicit_id = request_dict.get("chain_id")
    try:
        explicit_id = int(explicit_id) if explicit_id is not None else None
    except (TypeError, ValueError):
        explicit_id = None

    if not chain:
        chain = chain_name_for_chain_id(explicit_id) or default_chain
    request_dict["chain"] = chain

    if explicit_id is not None and explicit_id > 0:
        request_dict["chain_id"] = explicit_id
    else:
        request_dict["chain_id"] = chain_id_for_chain_name(chain)
    return request_dict
