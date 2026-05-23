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
    "mode": "mode",
    "mode network": "mode",
    "bera": "berachain",
    "berachain": "berachain",
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
