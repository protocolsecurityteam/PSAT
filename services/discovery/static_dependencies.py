#!/usr/bin/env python3
"""Discover statically embedded dependent contract addresses from EVM bytecode."""

import argparse
import json
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from utils.rpc import JSON_RPC_TIMEOUT_SECONDS as RPC_TIMEOUT_SECONDS  # noqa: F401 — re-export
from utils.rpc import (
    get_code,  # noqa: F401 — re-export for backward compat
    normalize_address,  # noqa: F401 — re-export for backward compat
    rpc_request,
)

EMPTY_CODE_VALUES = {"0x", "0x0"}


def has_deployed_code(bytecode_hex: str) -> bool:
    """Return True if an eth_getCode response represents deployed contract bytecode."""
    return bytecode_hex not in EMPTY_CODE_VALUES


def rpc_call(rpc_url: str, method: str, params: list, retries: int = 1, *, chain_id: int | None = None) -> Any:
    """Backward-compatible wrapper. Prefer utils.rpc.rpc_request for new code."""
    return rpc_request(rpc_url, method, params, retries=retries, chain_id=chain_id) or "0x"


def extract_push20_addresses(bytecode_hex: str) -> set[str]:
    """Parse EVM bytecode and extract 20-byte constants from PUSH20 (0x73) opcodes."""
    raw = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    if len(raw) % 2 != 0:
        return set()
    code = bytes.fromhex(raw) if raw else b""

    out = set()
    i = 0
    while i < len(code):
        op = code[i]
        if op == 0x73 and i + 20 < len(code):
            out.add("0x" + code[i + 1 : i + 21].hex())
            i += 21
            continue
        if 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
            continue
        i += 1

    out.discard("0x" + ("0" * 40))
    return out


def discover_dependencies(
    rpc_url: str,
    root: str,
    code_cache: dict[str, str] | None = None,
    *,
    chain_id: int | None = None,
) -> list[str]:
    """BFS-traverse embedded PUSH20 addresses and return deployed contract dependencies.

    Uses ``utils.rpc.get_code_batch`` to probe all candidates extracted
    from one contract's bytecode in a single JSON-RPC roundtrip — saves
    N-1 sequential RTTs per BFS layer when the contract embeds many
    PUSH20 addresses (Solidity hardcoded library refs, factory deploys,
    etc.). Falls back transparently to single-address ``get_code`` for
    addresses not returned by the batch (per-call error handling lives
    inside get_code_batch).
    """
    from utils.rpc import get_code_batch

    root = normalize_address(root)
    if code_cache is None:
        code_cache = {}

    def cached_get_code(address: str) -> str:
        normalized = normalize_address(address)
        if normalized not in code_cache:
            code_cache[normalized] = get_code(rpc_url, normalized, chain_id=chain_id)
        return code_cache[normalized]

    def batch_fill_cache(addrs: list[str]) -> None:
        """Populate code_cache for every address in addrs in one batch."""
        to_fetch = [a for a in addrs if a not in code_cache]
        if not to_fetch:
            return
        results = get_code_batch(rpc_url, to_fetch, chain_id=chain_id)
        for addr in to_fetch:
            # get_code_batch omits errored slots; backfill with single-call
            # so the per-cascade contract still gets evaluated (will raise
            # if the RPC is genuinely down — same surface as before).
            if addr in results:
                code_cache[addr] = results[addr]
            else:
                code_cache[addr] = get_code(rpc_url, addr, chain_id=chain_id)

    if not has_deployed_code(cached_get_code(root)):
        raise RuntimeError(f"Address {root} has no deployed bytecode.")

    stack = [root]
    seen = {root}
    deps = set()

    while stack:
        current = stack.pop()
        # Collect candidates from this contract's bytecode, dedupe against
        # the BFS-wide `seen` set, then batch-probe them all at once.
        candidates: list[str] = []
        for raw in extract_push20_addresses(cached_get_code(current)):
            cand = normalize_address(raw)
            if cand in seen:
                continue
            seen.add(cand)
            candidates.append(cand)

        if candidates:
            batch_fill_cache(candidates)
            for cand in candidates:
                if has_deployed_code(code_cache.get(cand, "0x")):
                    deps.add(cand)
                    stack.append(cand)

    return sorted(deps)


def find_dependencies(
    address: str,
    rpc_url: str | None = None,
    code_cache: dict[str, str] | None = None,
    *,
    chain_id: int | None = None,
) -> dict:
    """Resolve an RPC endpoint and return discovered static contract dependencies.

    *chain_id* (the job's chain, threaded from the static worker) arms the inv-7
    URL↔chain_id guard on every ``eth_getCode`` read; None keeps it a no-op for
    the CLI ``main`` path below (which has no chain in scope)."""
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    from utils.rpc import default_rpc_url

    # The pipeline (static_worker) always passes a chain-resolved rpc_url; this
    # explicit-mainnet base is only reached from the CLI ``main`` below when no
    # --rpc is given — a documented dev-tool default (inv. 6), not a silent one.
    effective_rpc = rpc_url or default_rpc_url(chain_id=1)
    if not effective_rpc:
        raise RuntimeError("No RPC URL provided and eRPC not configured (set ERPC_BASE_URL)")

    address = normalize_address(address)
    deps = discover_dependencies(effective_rpc, address, code_cache=code_cache, chain_id=chain_id)
    return {"address": address, "dependencies": deps}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("--rpc")
    args = parser.parse_args()

    try:
        output = find_dependencies(args.address.strip(), args.rpc)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    print(json.dumps(output))


if __name__ == "__main__":
    main()
