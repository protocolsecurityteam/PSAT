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
    "ethereum l1": "ethereum",
    "l1": "ethereum",
    "base": "base",
    "base mainnet": "base",
    "base chain": "base",
    "arbitrum": "arbitrum",
    "arbitrum one": "arbitrum",
    "arbitrum one chain": "arbitrum",
    "arbitrum mainnet": "arbitrum",
    "arb": "arbitrum",
    "optimism": "optimism",
    "optimistic ethereum": "optimism",
    "optimism mainnet": "optimism",
    "op": "optimism",
    "op mainnet": "optimism",
    "polygon": "polygon",
    "polygon pos": "polygon",
    "polygon pos network": "polygon",
    "polygon mainnet": "polygon",
    "matic": "polygon",
    "matic mainnet": "polygon",
    "avalanche": "avalanche",
    "avalanche c-chain": "avalanche",
    "avalanche c chain": "avalanche",
    "avalanche mainnet": "avalanche",
    "avax": "avalanche",
    "avax c-chain": "avalanche",
    "bsc": "bsc",
    "bnb": "bsc",
    "bnb chain": "bsc",
    "bnb smart chain": "bsc",
    "binance smart chain": "bsc",
    "binance chain": "bsc",
    "bsc mainnet": "bsc",
    "linea": "linea",
    "linea mainnet": "linea",
    "scroll": "scroll",
    "scroll chain": "scroll",
    "scroll mainnet": "scroll",
    "zksync": "zksync",
    "zk sync": "zksync",
    "zksync era": "zksync",
    "zksync mainnet": "zksync",
    "zk-sync": "zksync",
    "blast": "blast",
    "blast mainnet": "blast",
    "blast l2": "blast",
    "mode": "mode",
    "mode network": "mode",
    "mode mainnet": "mode",
    "mantle": "mantle",
    "mantle network": "mantle",
    "mantle mainnet": "mantle",
    "celo": "celo",
    "celo mainnet": "celo",
    "bera": "berachain",
    "berachain": "berachain",
    "berachain mainnet": "berachain",
    "bera chain": "berachain",
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
