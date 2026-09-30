"""Canonical chain registry: every per-chain constant lives in :class:`ChainInfo`.

:func:`canonical_chain` is the loose-label front door.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
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
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalized = re.sub(r"[\s_-]+", " ", text).strip().lower()
    return _CHAIN_ALIASES.get(normalized, normalized)


def canonical_chain_list(values: Iterable[Any] | None) -> list[str] | None:
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


# Per-chain tuning happens at enablement.
DEFAULT_CONFIRMATION_DEPTH = 12
MAX_GETLOGS_RANGE = 2000

# Unset means mainnet-only: never silently enable an unproven chain.
SUPPORTED_CHAIN_IDS_ENV = "PSAT_SUPPORTED_CHAIN_IDS"
_DEFAULT_SUPPORTED_CHAIN_IDS = frozenset({1})


class UnknownChainError(ValueError):
    """A ``ValueError`` so existing handlers keep catching it."""


class UnsupportedChainError(ValueError):
    """Fail-loud signal where a chain used to default to mainnet.

    A ``ValueError`` so existing handlers still catch it.
    """


@dataclass(frozen=True)
class ChainInfo:
    """The eRPC route is derived from ``chain_id`` by :func:`services.clients.rpc.erpc_url_for_chain_id`, not stored."""

    chain_id: int
    name: str
    aliases: tuple[str, ...]
    # Native USD pricing keys on this and refuses to quote a non-ETH native at the ETH price.
    native_asset: str
    # Explicit per chain, never pattern-derived. Non-None means proven Envio coverage: the indexer-enabled signal (inv.
    # 10) and the native HyperSync endpoint the inline resolution scans POST to. The durable indexer uses the eRPC route
    # instead.
    hypersync_url: str | None
    explorer_base_url: str
    confirmation_depth: int
    max_getlogs_range: int
    # Nominal seconds per block, so wall-clock budgets can be expressed in blocks. Required: a borrowed 12s would
    # misjudge every L2. Never a claim about a real block timestamp.
    block_time_s: float
    # Populated at Phase 2 enablement.
    bridge_executors: tuple[str, ...]
    cross_domain_messengers: tuple[str, ...]
    # Etherscan v2 stats action for the native USD price. ``ethprice`` serves most chains (including non-ETH L1s); BSC
    # needs ``bnbprice``. ``native_asset`` is what was priced.
    native_price_action: str = "ethprice"

    @property
    def supported(self) -> bool:
        """Computed so env changes (including in tests) apply immediately."""
        return self.chain_id in supported_chain_ids()


# HyperSync is set only where coverage is proven; others are indexer-disabled until proven.
_CHAINS: tuple[ChainInfo, ...] = (
    ChainInfo(
        chain_id=1,
        name="ethereum",
        aliases=("mainnet",),
        native_asset="ETH",
        hypersync_url="https://eth.hypersync.xyz",
        explorer_base_url="https://etherscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=12,  # Ethereum: 12s slot
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=42161,
        name="arbitrum",
        aliases=(),
        native_asset="ETH",
        hypersync_url=None,
        explorer_base_url="https://arbiscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=0.25,  # Arbitrum One: ~0.25s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=10,
        name="optimism",
        aliases=(),
        native_asset="ETH",
        hypersync_url=None,
        explorer_base_url="https://optimistic.etherscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2,  # OP-stack: 2s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=137,
        name="polygon",
        aliases=(),
        native_asset="POL",
        hypersync_url=None,
        explorer_base_url="https://polygonscan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2.1,  # Polygon PoS: ~2.1s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=8453,
        name="base",
        aliases=(),
        native_asset="ETH",
        # Preview-validated: HyperSync is unreachable from the dev network.
        hypersync_url="https://base.hypersync.xyz",
        explorer_base_url="https://basescan.org",
        # 75 × ~2s ≈ mainnet's 12 × ~12s; OP-stack unsafe-head reorgs are possible until the L1 batch posts.
        confirmation_depth=75,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2,  # OP-stack: 2s
        # OP-stack predeploys: L2StandardBridge executes bridged transfers; L2CrossDomainMessenger's
        # xDomainMessageSender surfaces an aliased L1 owner.
        bridge_executors=("0x4200000000000000000000000000000000000010",),
        cross_domain_messengers=("0x4200000000000000000000000000000000000007",),
    ),
    ChainInfo(
        chain_id=43114,
        name="avalanche",
        aliases=(),
        native_asset="AVAX",
        hypersync_url=None,
        explorer_base_url="https://snowtrace.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2,  # Avalanche C-chain: ~2s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=56,
        name="bsc",
        aliases=(),
        native_asset="BNB",
        hypersync_url=None,
        explorer_base_url="https://bscscan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=3,  # BNB Smart Chain: 3s
        bridge_executors=(),
        cross_domain_messengers=(),
        native_price_action="bnbprice",
    ),
    ChainInfo(
        chain_id=59144,
        name="linea",
        aliases=(),
        native_asset="ETH",
        hypersync_url=None,
        explorer_base_url="https://lineascan.build",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2,  # Linea: 2s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=534352,
        name="scroll",
        aliases=(),
        native_asset="ETH",
        hypersync_url=None,
        explorer_base_url="https://scrollscan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=3,  # Scroll: ~3s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=324,
        name="zksync",
        aliases=(),
        native_asset="ETH",
        hypersync_url=None,
        explorer_base_url="https://era.zksync.network",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=1,  # zkSync Era: ~1s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=81457,
        name="blast",
        aliases=(),
        native_asset="ETH",
        hypersync_url=None,
        explorer_base_url="https://blastscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2,  # OP-stack: 2s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=34443,
        name="mode",
        aliases=(),
        native_asset="ETH",
        hypersync_url=None,
        explorer_base_url="https://explorer.mode.network",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2,  # OP-stack: 2s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=80094,
        name="berachain",
        aliases=("bera",),
        native_asset="BERA",
        hypersync_url=None,
        explorer_base_url="https://berascan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        block_time_s=2,  # Berachain: ~2s
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
)


def _build_indexes() -> tuple[dict[int, ChainInfo], dict[str, ChainInfo]]:
    by_id: dict[int, ChainInfo] = {}
    by_name: dict[str, ChainInfo] = {}
    for info in _CHAINS:
        if info.chain_id in by_id:
            raise ValueError(f"duplicate chain_id in registry: {info.chain_id}")
        by_id[info.chain_id] = info
        for key in (info.name, *info.aliases):
            if key in by_name:
                raise ValueError(f"duplicate chain name/alias in registry: {key!r}")
            by_name[key] = info
    return by_id, by_name


_BY_ID, _BY_NAME = _build_indexes()


def chain_by_id(chain_id: int) -> ChainInfo:
    info = _BY_ID.get(chain_id)
    if info is None:
        raise UnknownChainError(f"unknown chain_id: {chain_id!r}")
    return info


def chain_by_name(name: str) -> ChainInfo:
    """Resolve a canonical name or alias, falling back to :func:`canonical_chain`. The ``"unknown"`` sentinel raises."""
    if not isinstance(name, str) or not name.strip():
        raise UnknownChainError(f"unknown chain name: {name!r}")
    normalized = re.sub(r"[\s_-]+", " ", name.strip()).strip().lower()
    info = _BY_NAME.get(normalized)
    if info is not None:
        return info
    canonical = canonical_chain(name)
    if canonical and canonical != "unknown":
        info = _BY_NAME.get(canonical)
        if info is not None:
            return info
    raise UnknownChainError(f"unknown chain name: {name!r}")


def require_chain(
    chain_id: int | str | None = None,
    *,
    chain: str | None = None,
    context: str,
) -> ChainInfo:
    """Resolve by ``chain_id`` then name, or raise :class:`UnsupportedChainError`.

    Never falls back to mainnet.
    """
    if chain_id is not None:
        try:
            parsed = int(chain_id)
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None:
            try:
                return chain_by_id(parsed)
            except UnknownChainError:
                raise UnsupportedChainError(f"{context}: unsupported chain_id {chain_id!r}") from None
    if isinstance(chain, str) and chain.strip() and chain.strip().lower() != "unknown":
        try:
            return chain_by_name(chain)
        except UnknownChainError:
            raise UnsupportedChainError(f"{context}: unsupported chain name {chain!r}") from None
    raise UnsupportedChainError(
        f"{context}: no chain supplied (chain_id={chain_id!r}, chain={chain!r}); "
        "chain is required and can no longer default to mainnet"
    )


def require_supported_chain(
    chain_id: int | str | None = None,
    *,
    chain: str | None = None,
    context: str,
) -> ChainInfo:
    """Resolve a chain and require it in ``PSAT_SUPPORTED_CHAIN_IDS``.

    For state-writing edges; read-only listings skip it so a since-disabled chain's rows stay reachable.
    """
    info = require_chain(chain_id, chain=chain, context=context)
    if info.chain_id not in supported_chain_ids():
        raise UnsupportedChainError(
            f"{context}: chain {info.name!r} (chain_id={info.chain_id}) is not enabled for this "
            f"deployment; add it to {SUPPORTED_CHAIN_IDS_ENV} to enable it"
        )
    return info


def chain_enabled(chain: str | int | None) -> bool:
    """Allowlist check for internal work origination; never raises.

    ``None``/empty coalesces to mainnet (NULL ≡ ``ethereum``); an unresolvable name is ``False``, not mainnet.
    """
    allow = supported_chain_ids()
    if chain is None:
        return 1 in allow
    if isinstance(chain, int):
        return chain in allow
    text = chain.strip()
    if not text:
        return 1 in allow
    if text.isdigit():
        return int(text) in allow
    try:
        return chain_by_name(text).chain_id in allow
    except UnknownChainError:
        return False


def chain_cache_token(chain: str | int | None) -> str:
    """Cache-key token for a chain: the decimal chain id, collapsing name and id keys onto one row.

    ``None`` is mainnet. An unregistered name is its own lowercased bucket rather than mainnet, so a lookup misses
    instead of colliding across chains.
    """
    if chain is None:
        return "1"
    if isinstance(chain, int):
        return str(chain)
    text = chain.strip()
    if not text:
        return "1"
    if text.isdigit():
        return text
    try:
        return str(chain_by_name(text).chain_id)
    except UnknownChainError:
        return text.lower()


def supported_chain_ids() -> frozenset[int]:
    """Unset or empty defaults to ``{1}``; non-integers are ignored."""
    raw = os.getenv(SUPPORTED_CHAIN_IDS_ENV)
    if raw is None or not raw.strip():
        return _DEFAULT_SUPPORTED_CHAIN_IDS
    ids: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            ids.add(int(token))
        except ValueError:
            continue
    return frozenset(ids) if ids else _DEFAULT_SUPPORTED_CHAIN_IDS


def all_chains() -> tuple[ChainInfo, ...]:
    return _CHAINS


def chain_name_to_id_map() -> dict[str, int]:
    out: dict[str, int] = {}
    for info in _CHAINS:
        for key in (info.name, *info.aliases):
            out[key] = info.chain_id
    return out
