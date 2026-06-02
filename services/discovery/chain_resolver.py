"""Terminal multi-chain resolution for discovered contracts.

Discovery sources emit addresses; this is the single place that decides which
chains they actually live on. It probes ``eth_getCode`` for every address
across the supported chains and sets ``chains`` to where code really exists — a
source's prior chain claim is only an ordering hint / unprobeable fallback,
never ground truth, so a wrong LLM-claimed chain is just overwritten by the
probe (no separate "verify and correct" path).

Probing routes through the shared chain-aware RPC layer (``utils.rpc``): eRPC
serves any chain at ``…/evm/<chain_id>``, and calls go through the cache-aware
batched ``eth_getCode`` so repeated probes hit the ``(chain_id, address)``
bytecode cache instead of the wire — re-probing is effectively free.

When no endpoint can be derived for a chain it's skipped; an address that can't
be confirmed anywhere keeps whatever prior it had rather than being downgraded.
"""

from __future__ import annotations

import contextvars
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

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


def resolve_chains(
    contracts: list[dict[str, Any]],
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Probe every contract across all chains and set ``chains`` from the result.

    The probe is the authority: ``chains`` becomes the chains where the address
    actually has code, ordered with any confirmed prior first. A prior claim is
    kept only when the address can't be confirmed anywhere (unprobeable), so the
    pipeline never downgrades on a failed probe and a wrong claim is simply
    overwritten. Mutates the contract dicts in place and returns the same list.
    """
    if not contracts:
        return contracts

    addrs = sorted({c["address"] for c in contracts if c.get("address")})
    if not addrs:
        return contracts

    matched: dict[str, list[str]] = {a: [] for a in addrs}
    _probe_chains(addrs, list(CHAIN_IDS.keys()), matched, debug)

    # Deterministic chain order — ethereum first (the canonical deployment when
    # present), then the supported-chain order — so the primary chain a contract
    # is analyzed on (chains[0]) is stable across runs. Probe completion order
    # (as_completed) is not.
    order = {ch: i for i, ch in enumerate(CHAIN_IDS)}
    resolved = 0
    for contract in contracts:
        found = canonical_chain_list(matched.get(contract.get("address", ""), [])) or []
        if not found:
            # Unprobeable (no endpoint / no code reachable): keep the prior.
            continue
        contract["chains"] = sorted(found, key=lambda ch: (ch != "ethereum", order.get(ch, len(order))))
        resolved += 1

    _debug_log(debug, f"Chain resolution: probed {len(addrs)} address(es), set chains for {resolved}")
    return contracts
