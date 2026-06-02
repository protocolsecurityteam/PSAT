"""Terminal multi-chain resolution for discovered contracts.

Discovery sources emit addresses; this is the single place that decides which
chains they actually live on. It probes ``eth_getCode`` for every address
across the supported chains and sets ``chains`` to every chain hosting the
**same** contract, grouped by runtime-bytecode keccak:

  * Same-bytecode siblings are kept. The discovery DB-write fans them out to one
    analyzable row per chain, because governance (owner/admin/roles, proxy
    implementation slots) lives in per-chain *storage* — identical bytecode does
    not imply identical governance, so each chain needs its own analysis.
  * Different bytecode at the same address is a CREATE2 / deterministic
    collision and is excluded from ``chains`` — *unless* a discovery source
    independently claimed that chain, which marks a legitimate per-chain variant
    (immutables with baked-in constructor args, linked libraries, L2 builds).
    Source-backed variants are kept; probe-only collisions are recorded under
    ``chain_collisions`` rather than silently dropped from evidence.

A source's prior chain claim is an anchor (which contract we found) and, for a
chain that can't be probed at all — no eRPC endpoint or an RPC error, as opposed
to a definitive "no code" — an unconfirmed fallback that is kept rather than
overridden by a successful probe elsewhere.

Probing routes through the shared chain-aware RPC layer (``utils.rpc``): eRPC
serves any chain at ``…/evm/<chain_id>``, and calls go through the cache-aware
batched ``eth_getCode`` so repeated probes hit the ``(chain_id, address)``
bytecode cache instead of the wire — re-probing is effectively free.
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


def _probe_chain_codes(addresses: list[str], chain_name: str, debug: bool = False) -> dict[str, str] | None:
    """Return ``{address: code_keccak}`` for *addresses* with deployed code on *chain_name*.

    Routes through ``utils.rpc.get_code_batch`` (eRPC auth + the
    ``(chain_id, address)`` bytecode cache); addresses without code are omitted.

    The ``None`` vs ``{}`` distinction is load-bearing: ``None`` means the chain
    could not be probed at all (no eRPC endpoint, or the batch RPC failed) — a
    prior claim on it survives as an unconfirmed fallback. ``{}`` means we
    probed successfully and found no code, which is authority to drop a wrong
    source claim.
    """
    rpc_url = _chain_probe_rpc_url(chain_name)
    if not rpc_url:
        _debug_log(debug, f"  {chain_name}: no RPC endpoint configured, skipping")
        return None
    from utils.rpc import chain_id_for_chain_name, get_code_batch, normalize_address

    try:
        code_map = get_code_batch(rpc_url, addresses, chain_id=chain_id_for_chain_name(chain_name))
    except Exception as exc:
        _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
        return None
    by_input = {normalize_address(a): a for a in addresses}
    out: dict[str, str] = {}
    for addr, code in code_map.items():
        if has_deployed_code(code):
            out[by_input.get(addr, addr)] = "0x" + keccak(bytes.fromhex(code[2:])).hex()
    return out


def _probe_footprint(
    addresses: list[str], chains: list[str], debug: bool = False
) -> tuple[dict[str, dict[str, str]], set[str]]:
    """Probe every chain in parallel.

    Returns ``({address: {chain: code_keccak}}, unprobeable_chains)`` where
    *unprobeable_chains* are the chains that couldn't be checked at all (no
    endpoint / RPC error) — kept distinct from chains that answered with "no
    code" so a source claim on an unprobeable chain isn't silently dropped.
    """
    result: dict[str, dict[str, str]] = {a: {} for a in addresses}
    unprobeable: set[str] = set()
    if not chains:
        return result, unprobeable
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
                codes = future.result()
            except Exception as exc:
                _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
                unprobeable.add(chain_name)
                continue
            if codes is None:
                unprobeable.add(chain_name)
                continue
            for addr, code_keccak in codes.items():
                result[addr][chain_name] = code_keccak
    return result, unprobeable


def resolve_chains(contracts: list[dict[str, Any]], debug: bool = False) -> list[dict[str, Any]]:
    """Set each contract's ``chains`` to every chain hosting the *same* contract.

    Probes ``eth_getCode`` for every address across all chains, groups the hits
    by code keccak, and sets ``chains`` to the anchor's same-bytecode siblings
    plus any source-claimed different-bytecode variants (legit per-chain
    builds); unclaimed different-bytecode chains are recorded under
    ``chain_collisions`` instead of folded in. The anchor is the source-claimed
    chain when it has code, else ethereum, else the first chain with code;
    ``chains`` is ordered ethereum-first then the supported-chain order, so the
    primary (``chains[0]``) is stable. A claimed chain that couldn't be probed
    at all is kept as an unconfirmed fallback; when nothing probes successfully
    the prior is kept untouched. The discovery DB-write fans ``chains`` out to
    one analyzable row per chain. Mutates the contract dicts in place and
    returns the same list.
    """
    if not contracts:
        return contracts

    addrs = sorted({c["address"] for c in contracts if c.get("address")})
    if not addrs:
        return contracts

    footprint, unprobeable = _probe_footprint(addrs, list(CHAIN_IDS.keys()), debug)
    order = {ch: i for i, ch in enumerate(CHAIN_IDS)}

    def _key(ch: str) -> tuple[bool, int]:
        return (ch != "ethereum", order.get(ch, len(order)))

    resolved = 0
    for contract in contracts:
        codes = footprint.get(contract.get("address", ""), {})  # {chain: code_keccak}
        prior = canonical_chain_list(contract.get("chains")) or []
        if not codes:
            # Probed nowhere successfully (no endpoint / all errored): keep prior.
            continue
        prior_confirmed = [ch for ch in prior if ch in codes]
        anchor = (
            prior_confirmed[0]
            if prior_confirmed
            else ("ethereum" if "ethereum" in codes else sorted(codes, key=_key)[0])
        )
        anchor_keccak = codes[anchor]

        siblings = {ch for ch, k in codes.items() if k == anchor_keccak}
        # Different bytecode at the same address is a collision UNLESS a source
        # independently claimed that chain — then it's a legit per-chain variant
        # (immutables, linked libs, L2 builds), kept and analyzed. Probe-only
        # collisions are recorded for evidence, not attributed.
        variants = {ch for ch, k in codes.items() if k != anchor_keccak}
        source_backed = variants & set(prior)
        collisions = variants - source_backed
        # A claimed chain we couldn't probe at all stays as an unconfirmed
        # fallback rather than being dropped by a successful probe elsewhere.
        unconfirmed = {ch for ch in prior if ch in unprobeable and ch not in codes}

        contract["chains"] = sorted(siblings | source_backed | unconfirmed, key=_key)
        if collisions:
            contract["chain_collisions"] = sorted(collisions, key=_key)
        resolved += 1

    _debug_log(debug, f"Chain resolution: probed {len(addrs)} address(es), set chains for {resolved}")
    return contracts
