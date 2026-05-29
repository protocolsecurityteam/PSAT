"""Multi-chain resolution for discovered contracts.

After the inventory pipeline builds contracts, some entries have
``chains=["unknown"]``.  This module probes ``eth_getCode`` via JSON-RPC
batch requests to determine where each contract is actually deployed.

Per-chain RPC URLs come from eRPC (``ERPC_BASE_URL``), which proxies to
the configured upstream providers and is auth'd via the
``X-ERPC-Secret-Token`` header. Each probe runs in parallel so hundreds
of addresses across 15+ chains finish in a few seconds.
"""

from __future__ import annotations

import contextvars
import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from utils.chains import canonical_chain, canonical_chain_list
from utils.rpc import erpc_url_for_chain_id, rpc_headers

from .inventory_domain import CHAIN_IDS, RateLimiter, _debug_log
from .static_dependencies import RPC_TIMEOUT_SECONDS, has_deployed_code

# Legacy direct-Alchemy fallback used only when ``ERPC_BASE_URL`` isn't
# configured (e.g. local dev with raw Alchemy keys).
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
    "mode": "mode-mainnet",
    "mantle": "mantle-mainnet",
    "celo": "celo-mainnet",
    "berachain": "berachain-mainnet",
}

# Max addresses per JSON-RPC batch request.
_BATCH_RPC_SIZE = 100

# Fallback: rate-limited individual calls if batch is rejected.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")
_RPC_RATE_LIMIT = int(os.getenv("RPC_RATE_LIMIT", "15"))
_FALLBACK_WORKERS = 4


def _get_alchemy_key() -> str | None:
    """Legacy Alchemy key lookup, used only when eRPC isn't configured.

    Returns ``None`` if no key is available. ``rpc_url_for_chain`` callers
    handle the None case so eRPC remains the preferred path.
    """
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    key = (os.getenv("ALCHEMY_API_KEY") or "").strip()
    if key:
        return key
    rpc = os.getenv("ETH_RPC", "")
    if "/v2/" in rpc:
        return rpc.rstrip("/").rsplit("/", 1)[-1] or None
    return None


def _alchemy_rpc(chain_name: str, api_key: str) -> str | None:
    """Build an Alchemy RPC URL for a given chain (legacy fallback)."""
    slug = _ALCHEMY_CHAIN_SLUGS.get(chain_name)
    if not slug:
        return None
    return f"https://{slug}.g.alchemy.com/v2/{api_key}"


def rpc_url_for_chain(chain_name: str) -> str | None:
    """Return the RPC URL for a chain, preferring eRPC over direct Alchemy.

    With ``ERPC_BASE_URL`` set, builds ``{base}/{project}/evm/{chain_id}``
    and the eRPC secret header is attached automatically by ``rpc_headers``.
    Falls back to a direct Alchemy URL only when eRPC isn't configured —
    keeps local dev with raw Alchemy keys working.
    """
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    chain_id = CHAIN_IDS.get(chain_name)
    if chain_id is not None:
        erpc_url = erpc_url_for_chain_id(chain_id)
        if erpc_url:
            return erpc_url
    api_key = _get_alchemy_key()
    if not api_key:
        return None
    return _alchemy_rpc(chain_name, api_key)


def _individual_get_code(rpc_url: str, addr: str, limiter: RateLimiter) -> tuple[str, str]:
    """Fetch code for a single address with rate limiting -- returns (addr, bytecode_hex)."""
    from .static_dependencies import get_code

    limiter.wait()
    try:
        return addr, get_code(rpc_url, addr)
    except RuntimeError:
        return addr, "0x"


def _batch_get_code(rpc_url: str, addresses: list[str]) -> dict[str, str]:
    """Batch-fetch eth_getCode for many addresses in a single HTTP request.

    Returns ``{address: bytecode_hex}`` for each address.  Splits into
    sub-batches of ``_BATCH_RPC_SIZE`` to stay within RPC limits.
    Falls back to rate-limited concurrent individual calls if the RPC
    rejects batching.
    """
    if not addresses:
        return {}

    results: dict[str, str] = {}
    for i in range(0, len(addresses), _BATCH_RPC_SIZE):
        batch = addresses[i : i + _BATCH_RPC_SIZE]
        payload = json.dumps(
            [
                {"jsonrpc": "2.0", "id": idx, "method": "eth_getCode", "params": [addr, "latest"]}
                for idx, addr in enumerate(batch)
            ]
        ).encode("utf-8")
        headers = rpc_headers(
            rpc_url,
            {"Accept": "application/json", "User-Agent": "getContractAddresses/1.0"},
        )
        request = urllib.request.Request(rpc_url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=max(RPC_TIMEOUT_SECONDS, 30)) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            body = None

        # A successful batch returns a JSON list.  If we got a dict instead
        # (e.g. RPC error like "too many calls in batch") or an HTTP error,
        # fall back to rate-limited concurrent individual calls.
        if not isinstance(body, list):
            limiter = RateLimiter(_RPC_RATE_LIMIT)
            with ThreadPoolExecutor(max_workers=_FALLBACK_WORKERS) as executor:
                # Per-submission context copy so trace_id/job_id contextvars
                # bound by the calling worker survive into the fallback fan-out.
                futures = []
                for addr in batch:
                    ctx = contextvars.copy_context()
                    futures.append(executor.submit(ctx.run, _individual_get_code, rpc_url, addr, limiter))
                for future in futures:
                    addr, code = future.result()
                    results[addr] = code
            continue

        for item in body:
            idx = item.get("id")
            if idx is not None and 0 <= idx < len(batch):
                code = item.get("result") or "0x"
                results[batch[idx]] = code if isinstance(code, str) and code.startswith("0x") else "0x"
        # Fill in any missing addresses (e.g. from errors in individual items).
        for addr in batch:
            if addr not in results:
                results[addr] = "0x"

    return results


def _probe_chain_batch(
    addresses: list[str],
    chain_name: str,
    debug: bool = False,
) -> set[str]:
    """Probe all *addresses* on a single chain via JSON-RPC batch (eRPC preferred)."""
    rpc_url = rpc_url_for_chain(chain_name)
    if not rpc_url:
        _debug_log(debug, f"  {chain_name}: no RPC URL available, skipping")
        return set()

    try:
        code_map = _batch_get_code(rpc_url, addresses)
        return {addr for addr, code in code_map.items() if has_deployed_code(code)}
    except Exception as exc:
        _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
        return set()


def _probe_chains(
    addresses: list[str],
    chains: list[str],
    matched: dict[str, list[str]],
    debug: bool = False,
) -> None:
    """Probe multiple chains in parallel via per-chain eRPC endpoints."""
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

    Mutates the contract dicts in-place (updates ``chains`` field) and
    returns the same list.
    """
    if not contracts:
        return contracts

    unknowns = [c for c in contracts if _primary_chain(c) == "unknown"]
    if not unknowns:
        _debug_log(debug, "Chain resolution: no unknown-chain contracts to resolve")
        return contracts

    # Determine which chains this protocol is known to use -- probe these first.
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

    # Phase 1: probe ALL unknowns on ALL known chains in parallel.
    _probe_chains(all_addrs, known_chains, matched, debug)

    # Phase 2: for addresses that matched NOTHING on known chains, probe the
    # remaining chains in parallel.
    unresolved = [addr for addr, chains in matched.items() if not chains]
    if unresolved and remaining_chains:
        _debug_log(debug, f"Probing {len(remaining_chains)} remaining chain(s) for {len(unresolved)} address(es)")
        _probe_chains(unresolved, remaining_chains, matched, debug)

    # Apply results.
    resolved_count = 0
    for contract in unknowns:
        chains = matched.get(contract["address"], [])
        if chains:
            contract["chains"] = canonical_chain_list(chains)
            resolved_count += 1
            _debug_log(debug, f"  {contract['address']}: resolved to {chains}")

    _debug_log(debug, f"Chain resolution: resolved {resolved_count}/{len(unknowns)} contract(s)")
    return contracts


def probe_sibling_chains(
    contracts: list[dict[str, Any]],
    *,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Find sibling deployments by probing the same address on every supported chain.

    Many protocols (LayerZero OFTs, deterministic CREATE2 deploys, governance
    factories) live at the same address on multiple chains. The web-search and
    Deep Research stages typically surface only one chain per address — usually
    Ethereum. This sweep batches ``eth_getCode`` for every (discovered address,
    supported chain) pair we haven't already recorded, and returns inventory
    entries for any chain where bytecode is found.
    """
    if not contracts:
        return []

    known: dict[str, set[str]] = {}
    name_by_address: dict[str, str] = {}

    def _record(address: str, chain: str | None, name: str | None) -> None:
        addr = address.lower()
        if not addr.startswith("0x") or len(addr) != 42:
            return
        canonical = canonical_chain(chain) if chain else None
        if canonical and canonical != "unknown":
            known.setdefault(addr, set()).add(canonical)
        else:
            known.setdefault(addr, set())
        if name and addr not in name_by_address:
            name_by_address[addr] = name

    for contract in contracts:
        address = str(contract.get("address") or "")
        chains = canonical_chain_list(contract.get("chains")) or []
        for chain in chains or [None]:
            _record(address, chain, contract.get("name"))
        for deployment in contract.get("deployments") or []:
            if not isinstance(deployment, dict):
                continue
            dep_chains = canonical_chain_list(deployment.get("chains")) or []
            for chain in dep_chains or [None]:
                _record(str(deployment.get("address") or ""), chain, deployment.get("name") or contract.get("name"))

    if not known:
        return []

    # Limit to chains the resolver can actually reach: eRPC-routable chain_ids,
    # or chains with a legacy Alchemy slug as fallback when eRPC is absent.
    probe_chains = [ch for ch in CHAIN_IDS if erpc_url_for_chain_id(CHAIN_IDS[ch]) or ch in _ALCHEMY_CHAIN_SLUGS]
    all_addrs = sorted(known.keys())

    _debug_log(
        debug,
        f"Sibling-chain probe: {len(all_addrs)} address(es) × {len(probe_chains)} chain(s)",
    )

    matched: dict[str, list[str]] = {addr: [] for addr in all_addrs}
    _probe_chains(all_addrs, probe_chains, matched, debug)

    new_entries: list[dict[str, Any]] = []
    for address, chains_found in matched.items():
        existing = known.get(address, set())
        for chain in chains_found:
            canonical = canonical_chain(chain)
            if not canonical or canonical == "unknown" or canonical in existing:
                continue
            entry: dict[str, Any] = {
                "address": address,
                "chains": [canonical],
                "chain": canonical,
                "confidence": 0.9,
                "source": ["sibling_chain_probe"],
                "evidence": {"sibling_chain_probe": 1},
            }
            if name_by_address.get(address):
                entry["name"] = name_by_address[address]
            new_entries.append(entry)
            existing.add(canonical)

    _debug_log(debug, f"Sibling-chain probe: added {len(new_entries)} new deployment(s)")
    return new_entries


def validate_claimed_chains(
    contracts: list[dict[str, Any]],
    *,
    source_names: tuple[str, ...] = ("exa_deep_research",),
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Verify high-risk AI-supplied chain claims with ``eth_getCode``.

    If a claimed chain has no code, probe the remaining supported chains and
    either correct to the detected chain(s) or mark it unknown.
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
