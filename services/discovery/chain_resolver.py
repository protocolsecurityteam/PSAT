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
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from utils.rpc import default_rpc_url, get_code_batch, require_supported_chain_id, supported_chain_ids

from .inventory_domain import _debug_log
from .static_dependencies import has_deployed_code, normalize_address

logger = logging.getLogger(__name__)

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def _probe_chain_ids() -> list[int]:
    try:
        return sorted(supported_chain_ids())
    except RuntimeError as exc:
        logger.error("Chain materialization failed to load supported chain ids: %s", exc)
        raise


def _erpc_url_for_chain_id(chain_id: int) -> str:
    """Build the configured eRPC URL for a known discovery chain id."""
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    return default_rpc_url(chain_id=chain_id)


def _batch_get_code(rpc_url: str, addresses: list[str], *, chain_id: int) -> dict[str, str]:
    """Batch-fetch eth_getCode for many addresses through the shared strict RPC path.

    Returns ``{address: bytecode_hex}`` for each address. Any transport error,
    batch-level error, item-level error, omitted result, or malformed bytecode
    raises instead of guessing.
    """
    return get_code_batch(rpc_url, addresses, chain_id=chain_id)


def _probe_chain_batch(
    addresses: list[str],
    chain_id: int,
    debug: bool = False,
) -> set[str]:
    """Probe all *addresses* on a single chain via eRPC JSON-RPC batch."""
    rpc_url = _erpc_url_for_chain_id(chain_id)
    code_map = _batch_get_code(rpc_url, addresses, chain_id=chain_id)
    return {addr for addr, code in code_map.items() if has_deployed_code(code)}


def _probe_chains(
    addresses: list[str],
    chain_ids: list[int],
    matched: dict[str, list[int]],
    debug: bool = False,
) -> None:
    """Probe multiple chains in parallel using eRPC batch endpoints."""
    with ThreadPoolExecutor(max_workers=min(len(chain_ids), 10)) as executor:
        # Per-chain context copy preserves the caller's trace context inside
        # each per-chain batch RPC call.
        future_to_chain = {}
        for chain_id in chain_ids:
            ctx = contextvars.copy_context()
            future_to_chain[executor.submit(ctx.run, _probe_chain_batch, addresses, chain_id, debug)] = chain_id
        for future in as_completed(future_to_chain):
            chain_id = future_to_chain[future]
            try:
                hits = future.result()
            except Exception as exc:
                logger.exception("Chain materialization probe failed for chain_id=%s", chain_id)
                raise RuntimeError(f"Chain materialization probe failed for chain_id={chain_id}") from exc
            for addr in hits:
                matched[addr].append(chain_id)
            _debug_log(debug, f"  chain_id={chain_id}: {len(hits)} hit(s)")


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


def resolve_address_chain_ids(
    addresses: list[str],
    *,
    debug: bool = False,
) -> dict[str, list[int]]:
    """Probe every supported chain id and return deployed-code matches per address.

    Returns ``{address: [chain_id, ...]}``. Addresses with no deployed code on any
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

    chain_ids = _probe_chain_ids()
    if not chain_ids:
        raise RuntimeError("No supported chain ids configured for chain resolution")

    matched: dict[str, list[int]] = {address: [] for address in normalized}
    _debug_log(debug, f"Chain materialization: probing {len(normalized)} address(es) across {len(chain_ids)} chain(s)")
    _probe_chains(normalized, chain_ids, matched, debug)

    chain_order = {chain_id: idx for idx, chain_id in enumerate(chain_ids)}
    return {address: sorted(ids, key=lambda chain_id: chain_order[chain_id]) for address, ids in matched.items()}


def expand_entries_by_resolved_chains(
    entries: list[dict[str, Any]],
    *,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Expand discovery write entries into one DB row per verified chain.

    Entries with explicit ``chain_id`` evidence are verified only on that chain.
    Entries without chain evidence are probed across all supported chains.
    """
    unknown_chain_addresses: list[str] = []
    explicit_by_chain: dict[int, list[str]] = {}
    explicit_entry_chains: dict[int, int] = {}
    normalized_by_entry: dict[int, str] = {}
    seen_unknown: set[str] = set()
    seen_explicit_by_chain: dict[int, set[str]] = {}

    for idx, entry in enumerate(entries):
        address = _normalize_probe_address(entry.get("address"))
        normalized_by_entry[idx] = address
        raw_chain_id = entry.get("chain_id")
        if raw_chain_id is None:
            if address not in seen_unknown:
                seen_unknown.add(address)
                unknown_chain_addresses.append(address)
            continue

        chain_id = require_supported_chain_id(
            chain_id=raw_chain_id,
            context=f"chain materialization for {address}",
        )
        explicit_entry_chains[idx] = chain_id
        seen_for_chain = seen_explicit_by_chain.setdefault(chain_id, set())
        if address not in seen_for_chain:
            seen_for_chain.add(address)
            explicit_by_chain.setdefault(chain_id, []).append(address)

    chain_map = resolve_address_chain_ids(unknown_chain_addresses, debug=debug) if unknown_chain_addresses else {}
    explicit_hits_by_chain: dict[int, set[str]] = {}
    for chain_id, addresses in explicit_by_chain.items():
        try:
            explicit_hits_by_chain[chain_id] = _probe_chain_batch(addresses, chain_id, debug=debug)
        except Exception as exc:
            logger.exception("Explicit chain materialization probe failed for chain_id=%s", chain_id)
            raise RuntimeError(f"Explicit chain materialization probe failed for chain_id={chain_id}") from exc

    expanded: list[dict[str, Any]] = []

    for idx, entry in enumerate(entries):
        address = normalized_by_entry[idx]
        explicit_chain_id = explicit_entry_chains.get(idx)
        if explicit_chain_id is not None:
            if address not in explicit_hits_by_chain.get(explicit_chain_id, set()):
                logger.error(
                    "Chain materialization found no deployed code for explicit address=%s chain_id=%s",
                    address,
                    explicit_chain_id,
                )
                raise RuntimeError(
                    f"Chain materialization found no deployed code for explicit address={address} "
                    f"chain_id={explicit_chain_id}"
                )
            chain_ids = [explicit_chain_id]
        else:
            chain_ids = chain_map.get(address, [])
            if not chain_ids:
                logger.error(
                    "Chain materialization found no deployed code on supported chains for address=%s",
                    address,
                )
                raise RuntimeError(
                    "Chain materialization found no deployed code on supported chains "
                    f"for address={address}"
                )

        for chain_id in chain_ids:
            materialized = dict(entry)
            materialized["address"] = address
            materialized["chain_id"] = chain_id
            materialized.pop("chain", None)
            materialized.pop("chains", None)
            materialized.pop("chain_ids", None)
            expanded.append(materialized)

    _debug_log(debug, f"Chain materialization: expanded {len(entries)} entry/entries to {len(expanded)} chain row(s)")
    return expanded
