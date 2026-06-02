"""Terminal multi-chain resolution for discovered contracts.

Discovery sources emit addresses; this is the single place that decides which
chains they actually live on. It probes ``eth_getCode`` for every address
across the supported chains and sets ``chains`` to where the **same** contract
lives — grouping by the runtime-bytecode keccak so a CREATE2 / deterministic
collision (a *different* contract sharing the address on another chain) is
excluded rather than merged into the sibling set. A source's prior chain claim
is only an anchor (which contract we actually found) + an unprobeable fallback,
never overridden ground truth.

Probing routes through the shared chain-aware RPC layer (``utils.rpc``): eRPC
serves any chain at ``…/evm/<chain_id>``, and calls go through the cache-aware
batched ``eth_getCode`` so repeated probes hit the ``(chain_id, address)``
bytecode cache instead of the wire — re-probing is effectively free.

Residual: bytecode equality treats an identical proxy *shell* on two chains as
one contract even when it fronts different implementations per chain. Splitting
those would need an implementation-slot read; not done here.
"""

from __future__ import annotations

import contextvars
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from eth_utils.crypto import keccak

from utils.chains import canonical_chain_list

from .inventory_domain import CHAIN_IDS, _debug_log
from .static_dependencies import has_deployed_code


def _chain_probe_rpc_url(chain_name: str) -> str | None:
    """eRPC URL for probing *chain_name*, or ``None`` when eRPC isn't configured.

    Probing is eRPC-only: without a multi-chain provider we can't confirm
    non-mainnet chains, so we return ``None`` (the caller keeps the prior)
    rather than fall back to a mainnet-only endpoint — which also keeps CLI and
    offline test runs off the wire.
    """
    from utils.rpc import chain_id_for_chain_name, erpc_url_for_chain_id

    return erpc_url_for_chain_id(chain_id_for_chain_name(chain_name))


def _probe_chain_codes(addresses: list[str], chain_name: str, debug: bool = False) -> dict[str, str]:
    """Return ``{address: code_keccak}`` for *addresses* with deployed code on *chain_name*.

    Routes through ``utils.rpc.get_code_batch`` (eRPC auth + the
    ``(chain_id, address)`` bytecode cache); addresses without code are omitted.
    """
    rpc_url = _chain_probe_rpc_url(chain_name)
    if not rpc_url:
        _debug_log(debug, f"  {chain_name}: no RPC endpoint configured, skipping")
        return {}
    from utils.rpc import chain_id_for_chain_name, get_code_batch, normalize_address

    try:
        code_map = get_code_batch(rpc_url, addresses, chain_id=chain_id_for_chain_name(chain_name))
    except Exception as exc:
        _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
        return {}
    by_input = {normalize_address(a): a for a in addresses}
    out: dict[str, str] = {}
    for addr, code in code_map.items():
        if has_deployed_code(code):
            out[by_input.get(addr, addr)] = "0x" + keccak(bytes.fromhex(code[2:])).hex()
    return out


def _probe_footprint(addresses: list[str], chains: list[str], debug: bool = False) -> dict[str, dict[str, str]]:
    """Probe every chain in parallel; return ``{address: {chain: code_keccak}}``."""
    result: dict[str, dict[str, str]] = {a: {} for a in addresses}
    if not chains:
        return result
    with ThreadPoolExecutor(max_workers=min(len(chains), 10)) as executor:
        # Per-chain context copy preserves the caller's trace context inside
        # each per-chain batch RPC call.
        future_to_chain = {}
        for chain_name in chains:
            ctx = contextvars.copy_context()
            future_to_chain[executor.submit(ctx.run, _probe_chain_codes, addresses, chain_name, debug)] = chain_name
        for future in as_completed(future_to_chain):
            chain_name = future_to_chain[future]
            try:
                for addr, code_keccak in future.result().items():
                    result[addr][chain_name] = code_keccak
            except Exception as exc:
                _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
    return result


def resolve_chains(contracts: list[dict[str, Any]], debug: bool = False) -> list[dict[str, Any]]:
    """Set each contract's ``chains`` to where the *same* contract is deployed.

    Probes ``eth_getCode`` for every address across all chains, groups the hits
    by code keccak, and keeps only the group matching the contract's anchor
    chain — so siblings (identical bytecode) fold together while collisions
    (different bytecode at the same address) are excluded. The anchor is the
    source-claimed chain when it has code, else ethereum, else the first chain
    with code; within the sibling set the order is ethereum-first then the
    supported-chain order, so the analyzed primary (``chains[0]``) is stable.
    When the address can't be confirmed anywhere (unprobeable), the prior is
    kept. Mutates the contract dicts in place and returns the same list.
    """
    if not contracts:
        return contracts

    addrs = sorted({c["address"] for c in contracts if c.get("address")})
    if not addrs:
        return contracts

    footprint = _probe_footprint(addrs, list(CHAIN_IDS.keys()), debug)
    order = {ch: i for i, ch in enumerate(CHAIN_IDS)}

    def _key(ch: str) -> tuple[bool, int]:
        return (ch != "ethereum", order.get(ch, len(order)))

    resolved = 0
    for contract in contracts:
        codes = footprint.get(contract.get("address", ""), {})  # {chain: code_keccak}
        if not codes:
            # Unprobeable (no endpoint / no code reachable): keep the prior.
            continue
        prior = [ch for ch in (canonical_chain_list(contract.get("chains")) or []) if ch in codes]
        anchor = prior[0] if prior else ("ethereum" if "ethereum" in codes else sorted(codes, key=_key)[0])
        anchor_keccak = codes[anchor]
        siblings = sorted((ch for ch, k in codes.items() if k == anchor_keccak), key=_key)
        contract["chains"] = siblings
        resolved += 1

    _debug_log(debug, f"Chain resolution: probed {len(addrs)} address(es), set chains for {resolved}")
    return contracts
