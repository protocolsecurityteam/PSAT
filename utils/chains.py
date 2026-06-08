"""Canonical chain-label helpers shared by discovery writers."""

from __future__ import annotations

import re
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
