"""Multi-chain resolution for discovered contracts.

After the inventory pipeline builds contracts, some entries have an unknown or
merely *claimed* chain. This module probes ``eth_getCode`` across the supported
chains to determine where each contract is actually deployed.

Probing is **provider-agnostic**: it routes through the shared chain-aware RPC
layer (``utils.rpc``), which prefers the configured eRPC endpoint
(``…/evm/<chain_id>``, valid for any chain) and falls back to a legacy Alchemy
``ETH_RPC`` or the public mainnet endpoint. Calls go through the cache-aware
batched ``eth_getCode`` so repeated probes hit the ``(chain_id, address)``
bytecode cache instead of the wire.

Strategy
--------
1. **Phase 1** -- probe every target address on the protocol's known chains in
   parallel.
2. **Phase 2** -- for addresses that matched nothing, probe the remaining
   supported chains (also in parallel).

When no RPC endpoint can be derived for a chain it is skipped, and resolution
degrades cleanly (unknowns stay unknown) rather than raising.
"""

from __future__ import annotations

import contextvars
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from utils.chains import canonical_chain, canonical_chain_list

from .inventory_domain import CHAIN_IDS, _debug_log
from .static_dependencies import has_deployed_code

# Legacy Alchemy network slugs — used only when ETH_RPC is an Alchemy URL and
# no eRPC endpoint is configured for the chain.
_ALCHEMY_CHAIN_SLUGS: dict[str, str] = {
    "ethereum": "eth-mainnet",
    "arbitrum": "arb-mainnet",
    "optimism": "opt-mainnet",
    "polygon": "polygon-mainnet",
    "base": "base-mainnet",
    "avalanche": "avax-mainnet",
    "bsc": "bnb-mainnet",
    "linea": "linea-mainnet",
    "scroll": "scroll-mainnet",
    "zksync": "zksync-mainnet",
    "blast": "blast-mainnet",
}


def _alchemy_key_or_none() -> str | None:
    """Return the Alchemy API key embedded in ETH_RPC, or None when it isn't an Alchemy URL."""
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    rpc = os.getenv("ETH_RPC", "")
    return rpc.rstrip("/").rsplit("/", 1)[-1] if "/v2/" in rpc else None


def _alchemy_rpc(chain_name: str, api_key: str) -> str | None:
    """Build a legacy Alchemy RPC URL for a chain, or None if unsupported."""
    slug = _ALCHEMY_CHAIN_SLUGS.get(chain_name)
    if not slug:
        return None
    return f"https://{slug}.g.alchemy.com/v2/{api_key}"


def _chain_probe_rpc_url(chain_name: str) -> str | None:
    """Per-chain RPC URL for probing, provider-agnostic.

    eRPC first (serves any chain via ``…/evm/<chain_id>``), then a legacy
    Alchemy ``ETH_RPC``, then the public mainnet fallback for ethereum. ``None``
    means "no endpoint for this chain" and the caller skips it cleanly.
    """
    from utils.rpc import chain_id_for_chain_name, default_rpc_url, erpc_url_for_chain_id

    erpc = erpc_url_for_chain_id(chain_id_for_chain_name(chain_name))
    if erpc:
        return erpc
    key = _alchemy_key_or_none()
    if key:
        alchemy = _alchemy_rpc(chain_name, key)
        if alchemy:
            return alchemy
    if chain_name == "ethereum":
        return default_rpc_url(chain="ethereum", chain_id=1)
    return None


def _probe_chain_batch(addresses: list[str], chain_name: str, debug: bool = False) -> set[str]:
    """Return the subset of *addresses* with deployed code on *chain_name*.

    Routes through ``utils.rpc.get_code_batch`` (eRPC auth headers + the
    ``(chain_id, address)`` bytecode cache), so repeated probes are cheap.
    """
    rpc_url = _chain_probe_rpc_url(chain_name)
    if not rpc_url:
        _debug_log(debug, f"  {chain_name}: no RPC endpoint configured, skipping")
        return set()
    from utils.rpc import chain_id_for_chain_name, get_code_batch, normalize_address

    try:
        code_map = get_code_batch(rpc_url, addresses, chain_id=chain_id_for_chain_name(chain_name))
    except Exception as exc:
        _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
        return set()
    hits = {addr for addr, code in code_map.items() if has_deployed_code(code)}
    # get_code_batch normalizes its keys; map back to the caller's address forms.
    return {a for a in addresses if normalize_address(a) in hits}


def _probe_chains(
    addresses: list[str],
    chains: list[str],
    matched: dict[str, list[str]],
    debug: bool = False,
) -> None:
    """Probe multiple chains in parallel; append every chain where an address has code to ``matched``."""
    if not chains:
        return
    with ThreadPoolExecutor(max_workers=min(len(chains), 10)) as executor:
        # Per-chain context copy preserves the caller's trace context inside
        # each per-chain batch RPC call.
        future_to_chain = {}
        for chain_name in chains:
            ctx = contextvars.copy_context()
            future_to_chain[executor.submit(ctx.run, _probe_chain_batch, addresses, chain_name, debug)] = chain_name
        for future in as_completed(future_to_chain):
            chain_name = future_to_chain[future]
            try:
                hits = future.result()
                for addr in hits:
                    matched[addr].append(chain_name)
                _debug_log(debug, f"  {chain_name}: {len(hits)} hit(s)")
            except Exception as exc:
                _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")


def _primary_chain(contract: dict[str, Any]) -> str:
    """Return the first chain from a contract's chains list, or 'unknown'."""
    chains = contract.get("chains", [])
    return (canonical_chain(chains[0]) if chains else None) or "unknown"


def resolve_unknown_chains(
    contracts: list[dict[str, Any]],
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Resolve ``chains=["unknown"]`` entries by probing ``eth_getCode`` across chains.

    Mutates the contract dicts in-place (updates ``chains``) and returns the
    same list. Degrades cleanly (unknowns stay unknown) when no RPC endpoint is
    configured for a chain.
    """
    if not contracts:
        return contracts

    unknowns = [c for c in contracts if _primary_chain(c) == "unknown"]
    if not unknowns:
        _debug_log(debug, "Chain resolution: no unknown-chain contracts to resolve")
        return contracts

    # Probe the protocol's already-known chains first, then the rest.
    known_chains: list[str] = []
    seen: set[str] = set()
    for c in contracts:
        for ch in canonical_chain_list(c.get("chains", [])) or []:
            if ch not in seen and ch != "unknown" and ch in CHAIN_IDS:
                known_chains.append(ch)
                seen.add(ch)
    if not known_chains:
        known_chains = list(CHAIN_IDS.keys())
    remaining_chains = [ch for ch in CHAIN_IDS if ch not in seen]

    _debug_log(
        debug,
        f"Chain resolution: {len(unknowns)} unknown contract(s), "
        f"probing {len(known_chains)} known chain(s): {known_chains}",
    )

    # address -> list of chains where it has code
    matched: dict[str, list[str]] = {c["address"]: [] for c in unknowns}
    all_addrs = list(matched.keys())

    # Phase 1: probe ALL unknowns on the known chains in parallel.
    _probe_chains(all_addrs, known_chains, matched, debug)

    # Phase 2: for addresses that matched nothing, probe the remaining chains.
    unresolved = [addr for addr, chains in matched.items() if not chains]
    if unresolved and remaining_chains:
        _debug_log(debug, f"Probing {len(remaining_chains)} remaining chain(s) for {len(unresolved)} address(es)")
        _probe_chains(unresolved, remaining_chains, matched, debug)

    resolved_count = 0
    for contract in unknowns:
        chains = matched.get(contract["address"], [])
        if chains:
            contract["chains"] = canonical_chain_list(chains)
            resolved_count += 1
            _debug_log(debug, f"  {contract['address']}: resolved to {chains}")

    _debug_log(debug, f"Chain resolution: resolved {resolved_count}/{len(unknowns)} contract(s)")
    return contracts


def validate_claimed_chains(
    contracts: list[dict[str, Any]],
    *,
    source_names: tuple[str, ...] = ("exa_deep_research",),
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Verify AI-supplied chain claims with ``eth_getCode``.

    If a claimed chain has no code, probe the remaining supported chains and
    either correct to the detected chain(s) or mark the entry unknown.
    """
    targets: list[tuple[dict[str, Any], str, list[str]]] = []
    for contract in contracts:
        sources = set(contract.get("source") or [])
        if sources.isdisjoint(source_names):
            continue
        address = str(contract.get("address") or "").lower()
        chains = canonical_chain_list(contract.get("chains")) or []
        claimed = [chain for chain in chains if chain and chain != "unknown" and chain in CHAIN_IDS]
        if address and claimed:
            targets.append((contract, address, claimed))

    if not targets:
        return contracts

    for contract, address, claimed in targets:
        matched: dict[str, list[str]] = {address: []}
        _probe_chains([address], claimed, matched, debug)
        if matched[address]:
            contract["chains"] = canonical_chain_list(matched[address])
            continue

        remaining = [chain for chain in CHAIN_IDS if chain not in set(claimed)]
        if remaining:
            _probe_chains([address], remaining, matched, debug)
        if matched[address]:
            corrected = canonical_chain_list(matched[address]) or ["unknown"]
            contract["chains"] = corrected
            _debug_log(debug, f"  {address}: corrected claimed chain {claimed} -> {corrected}")
        else:
            contract["chains"] = ["unknown"]
            contract["chain_sanity"] = {
                "status": "unresolved_no_code_on_claimed_or_supported_chains",
                "claimed_chains": claimed,
            }
            _debug_log(debug, f"  {address}: no code on claimed chain(s) {claimed}; marked unknown")

    return contracts
