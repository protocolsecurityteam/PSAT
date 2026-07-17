"""Canonical chain registry — the single source of chain truth for PSAT.

Historically this module only held the loose-label normalizer
:func:`canonical_chain` used by discovery writers. It now also carries the
:class:`ChainInfo` registry (invariant 5 of ``MULTICHAIN_INVARIANTS.md``): every
per-chain constant (ids, aliases, HyperSync/explorer URLs, finality depth,
getLogs range, bridge constants) lives here, and the four former ad-hoc chain
maps derive from it. :func:`canonical_chain` stays as the loose-label front door
that feeds canonical names into :func:`chain_by_name`.
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


# ---------------------------------------------------------------------------
# Chain registry (invariant 5)
# ---------------------------------------------------------------------------

# Fleet-wide defaults. Per-chain tuning happens at chain-enablement (inv. 14);
# for now every chain carries the values the codebase already used on mainnet.
DEFAULT_CONFIRMATION_DEPTH = 12
MAX_GETLOGS_RANGE = 2000

# Env allowlist of chains PSAT is allowed to operate on. Conservative default is
# mainnet-only: an unset allowlist must not silently enable an unproven chain.
SUPPORTED_CHAIN_IDS_ENV = "PSAT_SUPPORTED_CHAIN_IDS"
_DEFAULT_SUPPORTED_CHAIN_IDS = frozenset({1})


class UnknownChainError(ValueError):
    """Raised when a chain id / name cannot be resolved in the registry.

    A subclass of :class:`ValueError` so call sites that already tolerate an
    unknown chain by catching ``ValueError`` keep working.
    """


class UnsupportedChainError(ValueError):
    """Raised by :func:`require_chain` when a chain can no longer be defaulted.

    The single fail-loud signal for the M1.2 default-kill sites (invariant 6):
    a missing / empty / ``"unknown"`` / unregistered chain at a site where the
    old code silently resolved to mainnet. Carries the offending value AND the
    call context so a raise names both what was wrong and where. A subclass of
    :class:`ValueError` (like :class:`UnknownChainError`) so existing
    ``ValueError`` handlers still catch it, and never a bare ``TypeError`` from
    a removed signature default.
    """


@dataclass(frozen=True)
class ChainInfo:
    """Immutable per-chain facts. The eRPC route is NOT stored — it is derived
    from ``chain_id`` (``{ERPC_BASE_URL}/main/evm/{chain_id}``) by
    :func:`utils.rpc.erpc_url_for_chain_id`."""

    chain_id: int
    name: str
    aliases: tuple[str, ...]
    # Explicit per chain — never pattern-derived. Non-None marks a chain with
    # proven Envio coverage and serves two roles:
    #   * it is the "event indexer enabled for this chain" signal (inv. 10); and
    #   * it is the NATIVE HyperSync query endpoint (``<chain>.hypersync.xyz``) that
    #     the inline resolution repos (``event_logs_hypersync.py``,
    #     ``mapping_enumerator.py``) POST to directly with an ENVIO_API_TOKEN bearer.
    # The durable event indexer does NOT read this URL: it goes through the chain's
    # eRPC route, which fronts a HyperRPC (JSON-RPC) upstream carrying the Envio
    # token server-side plus provider failover. ``None`` = no proven coverage =
    # indexer disabled for this chain.
    hypersync_url: str | None
    explorer_base_url: str
    confirmation_depth: int
    max_getlogs_range: int
    # Populated at Phase 2 chain enablement (inv. 15); empty until then.
    bridge_executors: tuple[str, ...]
    cross_domain_messengers: tuple[str, ...]

    @property
    def supported(self) -> bool:
        """Whether this chain is in the env allowlist. Computed (not stored) so a
        change to ``PSAT_SUPPORTED_CHAIN_IDS`` — including in tests — is reflected
        immediately rather than frozen at import time."""
        return self.chain_id in supported_chain_ids()


# Initial chain set (inv. 5): the 11 inventory chains
# (``services/discovery/inventory_domain.py``) plus ``mode``/``berachain`` from
# the ``utils/rpc.py`` alias map. HyperSync URL is set only where the codebase
# already demonstrates one in use (mainnet); every other chain is None =
# indexer-disabled until coverage is proven per inv. 14. Explorer URLs are the
# well-known canonical bases. Finality depth / getLogs range use the current
# fleet-wide values pending per-chain tuning.
_CHAINS: tuple[ChainInfo, ...] = (
    ChainInfo(
        chain_id=1,
        name="ethereum",
        aliases=("mainnet",),
        hypersync_url="https://eth.hypersync.xyz",
        explorer_base_url="https://etherscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=42161,
        name="arbitrum",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://arbiscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=10,
        name="optimism",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://optimistic.etherscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=137,
        name="polygon",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://polygonscan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=8453,
        name="base",
        aliases=(),
        # Coverage is preview-validated (inv. 14): HyperSync is unreachable from
        # the dev network, so the $0-cost indexer path for this URL is proven in
        # the PR preview environment, not here.
        hypersync_url="https://base.hypersync.xyz",
        explorer_base_url="https://basescan.org",
        # 75 × ~2s ≈ 150s wall-clock, matching/exceeding mainnet finality
        # (12 × ~12s ≈ 144s). OP-stack unsafe-head reorgs are shallow but
        # possible until the L1 batch is posted, so we track the L1 window.
        confirmation_depth=75,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        # OP-stack L2 predeploys for authority recognition (inv. 15). The
        # L2StandardBridge *executes* bridged deposits/withdrawals → bridge
        # executor; the L2CrossDomainMessenger *relays* L1↔L2 messages and is
        # the contract whose xDomainMessageSender surfaces an aliased L1 owner
        # → cross-domain messenger.
        bridge_executors=("0x4200000000000000000000000000000000000010",),
        cross_domain_messengers=("0x4200000000000000000000000000000000000007",),
    ),
    ChainInfo(
        chain_id=43114,
        name="avalanche",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://snowtrace.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=56,
        name="bsc",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://bscscan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=59144,
        name="linea",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://lineascan.build",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=534352,
        name="scroll",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://scrollscan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=324,
        name="zksync",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://era.zksync.network",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=81457,
        name="blast",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://blastscan.io",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=34443,
        name="mode",
        aliases=(),
        hypersync_url=None,
        explorer_base_url="https://explorer.mode.network",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
        bridge_executors=(),
        cross_domain_messengers=(),
    ),
    ChainInfo(
        chain_id=80094,
        name="berachain",
        aliases=("bera",),
        hypersync_url=None,
        explorer_base_url="https://berascan.com",
        confirmation_depth=DEFAULT_CONFIRMATION_DEPTH,
        max_getlogs_range=MAX_GETLOGS_RANGE,
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
    """Return the :class:`ChainInfo` for *chain_id*; raise on unknown."""
    info = _BY_ID.get(chain_id)
    if info is None:
        raise UnknownChainError(f"unknown chain_id: {chain_id!r}")
    return info


def chain_by_name(name: str) -> ChainInfo:
    """Resolve a chain name (canonical or alias) to its :class:`ChainInfo`.

    The single home of canonical-name normalization: it first checks the
    registry's own names/aliases, then falls back to the loose-label normalizer
    (:func:`canonical_chain`) so labels like ``"avax"`` / ``"arbitrum one"``
    resolve too. The ``"unknown"`` discovery sentinel is NOT resolvable — it
    raises, as does any genuinely-unknown chain.
    """
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
    """Resolve a chain to its :class:`ChainInfo`, or raise :class:`UnsupportedChainError`.

    The single fail-loud mechanism for the M1.2 kill sites (invariant 6): call
    it wherever a chain used to silently default to mainnet. Resolution order is
    ``chain_id`` first (int or decimal string), then the ``chain`` name/alias.
    Anything that cannot be resolved — ``None``, empty, the ``"unknown"``
    sentinel, an unparseable id, or a name/id absent from the registry — raises
    with *context* and the offending value, never a bare ``TypeError`` from a
    removed default and never a silent mainnet fallback.
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
    """Resolve a chain AND require it be enabled for this deployment (invariant 14).

    The single enforcement point for the user-facing chain-accepting edges: it
    first resolves the chain through :func:`require_chain` (registry lookup +
    fail-loud on an unknown/missing chain), then rejects a chain that exists in
    the registry but is absent from the ``PSAT_SUPPORTED_CHAIN_IDS`` allowlist —
    so an edge cannot enroll / analyze / monitor a chain the deployment has not
    proven and enabled. Both failure modes raise :class:`UnsupportedChainError`
    (naming the chain and the allowlist env var); routers translate it to HTTP
    400. State-writing edges call this; read-only listings and historical-row
    cleanup do not, so a since-disabled chain's rows stay reachable.
    """
    info = require_chain(chain_id, chain=chain, context=context)
    if info.chain_id not in supported_chain_ids():
        raise UnsupportedChainError(
            f"{context}: chain {info.name!r} (chain_id={info.chain_id}) is not enabled for this "
            f"deployment; add it to {SUPPORTED_CHAIN_IDS_ENV} to enable it"
        )
    return info


def chain_enabled(chain: str | int | None) -> bool:
    """Whether *chain* is in the ``PSAT_SUPPORTED_CHAIN_IDS`` allowlist (invariant 14).

    The gate for internal work-origination sites — analysis-job spawns and
    monitoring enrollment — where an off-allowlist chain is expected input, not
    an error. Unlike :func:`require_supported_chain` (the fail-loud user-edge
    guard) this NEVER raises: a chain outside the allowlist, or one that cannot
    be resolved at all, returns ``False`` so the caller skips-and-logs the one
    discovery rather than aborting the whole run.

    Accepts a chain id (``int`` or decimal string) or a name/alias. ``None`` /
    empty coalesces to mainnet (the NULL≡``ethereum`` convention), so a
    mainnet-only deployment enrolls/spawns legacy chainless rows exactly as
    before. A non-empty but unresolvable name returns ``False`` — an unknown
    chain can never be "enabled" — rather than silently coalescing to mainnet.
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
    """Canonical cache-key token for a chain (invariant 11): the decimal-string
    chain id (``"1"``, ``"8453"``).

    Accepts a chain id (``int`` or decimal string), a chain name/alias
    (``"ethereum"``, ``"base"``, ``"mainnet"``), or ``None`` (the historical
    mainnet default). This is the single normalizer that collapses the two key
    formats the mapping-enumeration cache used to mix — a chain *name* from one
    code path and ``str(chain_id)`` from another — onto one token, so both hit
    the same row.

    ``None``/empty resolves to the mainnet token, mirroring the Phase-0
    dual-write default. An *unregistered* non-numeric name is not silently
    aliased to mainnet (that would let an unknown chain's scan serve mainnet
    resolution and vice versa); it is returned lowercased as its own isolated
    bucket, so a lookup degrades to a miss rather than a cross-chain collision.
    Fail-loud on unknown chains is the M1.2 kill-the-defaults step, not this one.
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
    """Chain ids in the ``PSAT_SUPPORTED_CHAIN_IDS`` allowlist.

    Comma-separated decimal ids; blanks and non-integers are ignored. When the
    env var is unset or empty, defaults to mainnet-only (``{1}``) so an
    unconfigured deployment never silently operates on an unproven chain.
    """
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
    """All registered chains, in registry declaration order."""
    return _CHAINS


def chain_name_to_id_map() -> dict[str, int]:
    """``{name_or_alias: chain_id}`` for every registered name and alias.

    This is the registry-backed replacement for the hand-maintained
    ``COMMON_CHAIN_IDS`` map in ``utils/rpc.py``.
    """
    out: dict[str, int] = {}
    for info in _CHAINS:
        for key in (info.name, *info.aliases):
            out[key] = info.chain_id
    return out
