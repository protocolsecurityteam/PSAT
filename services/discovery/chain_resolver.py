"""Multi-chain resolution for discovered contracts.

Discovery sources surface candidate addresses. This module probes
``eth_getCode`` via JSON-RPC batch requests to the configured eRPC
endpoint and materializes one database row per chain where deployed code
exists.

Requires ``ERPC_BASE_URL`` to be configured. Each chain is resolved by
its explicit chain id into ``{ERPC_BASE_URL}/main/evm/{chain_id}`` so all
chains can be probed **in parallel** (~1-2 seconds for hundreds of
addresses across 10+ chains).

Strategy
--------
1. Resolve each supported chain to its configured eRPC URL.
2. Probe every candidate address on every supported chain in parallel.
3. Return only positive deployed-code matches. RPC failures are hard
   failures; callers should not write guessed or unknown-chain rows.
"""

from __future__ import annotations

import contextvars
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from utils.chains import canonical_chain_list
from utils.rpc import erpc_url_for_chain_id, rpc_batch_request_with_status

from .inventory_domain import CHAIN_IDS, _debug_log
from .static_dependencies import has_deployed_code, normalize_address

# Max addresses per JSON-RPC batch request.
_BATCH_RPC_SIZE = 100

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def _chain_id_for_probe(chain_name: str) -> int | None:
    chain_id = CHAIN_IDS.get(chain_name)
    return chain_id if isinstance(chain_id, int) and chain_id > 0 else None


def _erpc_url_for_chain(chain_name: str) -> str:
    """Build the configured eRPC URL for a known discovery chain."""
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    chain_id = _chain_id_for_probe(chain_name)
    if chain_id is None:
        raise RuntimeError(f"No chain id configured for chain {chain_name}")
    rpc_url = erpc_url_for_chain_id(chain_id)
    if not rpc_url:
        raise RuntimeError(f"Chain resolution requires ERPC_BASE_URL; no eRPC URL for {chain_name} ({chain_id})")
    return rpc_url


def _batch_get_code(rpc_url: str, addresses: list[str]) -> dict[str, str]:
    """Batch-fetch eth_getCode for many addresses in a single HTTP request.

    Returns ``{address: bytecode_hex}`` for each address.  Splits into
    sub-batches of ``_BATCH_RPC_SIZE`` to stay within RPC limits. Any
    transport error, batch-level error, item-level error, or omitted result
    raises instead of guessing.
    """
    if not addresses:
        return {}

    results: dict[str, str] = {}
    for i in range(0, len(addresses), _BATCH_RPC_SIZE):
        batch = addresses[i : i + _BATCH_RPC_SIZE]
        calls = [("eth_getCode", [addr, "latest"]) for addr in batch]
        raw_results = rpc_batch_request_with_status(rpc_url, calls)
        if len(raw_results) != len(batch):
            raise RuntimeError(f"RPC batch returned {len(raw_results)} result(s) for {len(batch)} call(s) on {rpc_url}")

        for addr, (code, had_error) in zip(batch, raw_results):
            if had_error:
                raise RuntimeError(f"RPC batch item error for {addr} on {rpc_url}")
            if not isinstance(code, str) or not code.startswith("0x"):
                raise RuntimeError(f"RPC batch returned invalid eth_getCode result for {rpc_url}: {code!r}")
            results[addr] = "0x" if code == "0x0" else code

    return results


def _probe_chain_batch(
    addresses: list[str],
    chain_name: str,
    debug: bool = False,
) -> set[str]:
    """Probe all *addresses* on a single chain via eRPC JSON-RPC batch."""
    rpc_url = _erpc_url_for_chain(chain_name)
    code_map = _batch_get_code(rpc_url, addresses)
    return {addr for addr, code in code_map.items() if has_deployed_code(code)}


def _probe_chains(
    addresses: list[str],
    chains: list[str],
    matched: dict[str, list[str]],
    debug: bool = False,
) -> None:
    """Probe multiple chains in parallel using eRPC batch endpoints."""
    with ThreadPoolExecutor(max_workers=min(len(chains), 10)) as executor:
        # Per-chain context copy preserves the caller's trace context inside
        # each per-chain batch RPC call.
        future_to_chain = {}
        for chain_name in chains:
            ctx = contextvars.copy_context()
            future_to_chain[executor.submit(ctx.run, _probe_chain_batch, addresses, chain_name, debug)] = chain_name
        for future in as_completed(future_to_chain):
            chain_name = future_to_chain[future]
            hits = future.result()
            for addr in hits:
                matched[addr].append(chain_name)
            _debug_log(debug, f"  {chain_name}: {len(hits)} hit(s)")


def _normalize_probe_address(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"Expected address string, got {type(raw).__name__}")
    address = normalize_address(raw)
    if not address.startswith("0x") or len(address) != 42:
        raise ValueError(f"Invalid address for chain probe: {raw!r}")
    try:
        int(address[2:], 16)
    except ValueError as exc:
        raise ValueError(f"Invalid address for chain probe: {raw!r}") from exc
    return address


def resolve_address_chains(
    addresses: list[str],
    *,
    debug: bool = False,
) -> dict[str, list[str]]:
    """Probe every supported chain and return deployed-code matches per address.

    Returns ``{address: [chain, ...]}``. Addresses with no deployed code on any
    supported chain are present with an empty list so callers can intentionally
    avoid writing unknown-chain rows.
    """
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in addresses:
        address = _normalize_probe_address(raw)
        if address not in seen:
            seen.add(address)
            normalized.append(address)

    if not normalized:
        return {}

    chains = list(CHAIN_IDS.keys())
    uncovered = sorted(ch for ch in chains if _chain_id_for_probe(ch) is None)
    if uncovered:
        raise RuntimeError(f"No chain id configured for chain(s): {uncovered}")

    matched: dict[str, list[str]] = {address: [] for address in normalized}
    _debug_log(debug, f"Chain materialization: probing {len(normalized)} address(es) across {len(chains)} chain(s)")
    _probe_chains(normalized, chains, matched, debug)

    return {
        address: sorted(canonical_chain_list(chains) or [], key=lambda chain: list(CHAIN_IDS).index(chain))
        for address, chains in matched.items()
    }


def expand_entries_by_resolved_chains(
    entries: list[dict[str, Any]],
    *,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Expand discovery write entries into one DB row per resolved chain."""
    addresses = [str(entry.get("address") or "") for entry in entries]
    chain_map = resolve_address_chains(addresses, debug=debug)
    expanded: list[dict[str, Any]] = []

    for entry in entries:
        address = _normalize_probe_address(entry.get("address"))
        for chain in chain_map.get(address, []):
            materialized = dict(entry)
            materialized["address"] = address
            materialized["chain"] = chain
            materialized["chains"] = [chain]
            expanded.append(materialized)

    _debug_log(debug, f"Chain materialization: expanded {len(entries)} entry/entries to {len(expanded)} chain row(s)")
    return expanded
