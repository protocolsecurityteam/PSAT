#!/usr/bin/env python3
"""Discover statically embedded dependent contract addresses from EVM bytecode."""

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from utils.rpc import JSON_RPC_TIMEOUT_SECONDS as RPC_TIMEOUT_SECONDS  # noqa: F401 — re-export
from utils.rpc import (
    default_rpc_url,
    get_code,  # noqa: F401 — re-export for backward compat
    normalize_address,  # noqa: F401 — re-export for backward compat
    require_configured_erpc_url,
    require_supported_chain_id,
    rpc_request,
)

EMPTY_CODE_VALUES = {"0x", "0x0"}
logger = logging.getLogger(__name__)


def has_deployed_code(bytecode_hex: str) -> bool:
    """Return True if an eth_getCode response represents deployed contract bytecode."""
    if not isinstance(bytecode_hex, str) or not bytecode_hex.startswith("0x"):
        logger.error("eth_getCode bytecode payload is invalid: %r", bytecode_hex)
        raise ValueError(f"eth_getCode bytecode payload is invalid: {bytecode_hex!r}")
    code = bytecode_hex.lower()
    if code in EMPTY_CODE_VALUES:
        return False
    try:
        bytes.fromhex(code[2:])
    except ValueError as exc:
        logger.error("eth_getCode bytecode payload is malformed hex")
        raise ValueError("eth_getCode bytecode payload is malformed hex") from exc
    return True


def rpc_call(
    rpc_url: str,
    method: str,
    params: list,
    retries: int = 1,
    *,
    chain_id: int,
) -> Any:
    """Backward-compatible wrapper. Prefer utils.rpc.rpc_request for new code."""
    raw = rpc_request(rpc_url, method, params, retries=retries, chain_id=chain_id)
    if raw is None:
        logger.error("RPC method %s returned null result", method)
        raise RuntimeError(f"RPC method {method} returned null result")
    return raw


def extract_push20_addresses(bytecode_hex: str) -> set[str]:
    """Parse EVM bytecode and extract 20-byte constants from PUSH20 (0x73) opcodes."""
    if not isinstance(bytecode_hex, str):
        raise ValueError(f"bytecode must be a string, got {type(bytecode_hex).__name__}")
    raw = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    if len(raw) % 2 != 0:
        raise ValueError("bytecode hex must have even length")
    try:
        code = bytes.fromhex(raw) if raw else b""
    except ValueError as exc:
        raise ValueError("bytecode contains non-hex characters") from exc

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
    *,
    chain_id: int,
    code_cache: dict[str, str] | None = None,
) -> list[str]:
    """BFS-traverse embedded PUSH20 addresses and return deployed contract dependencies.

    Uses ``utils.rpc.get_code_batch`` to probe all candidates extracted
    from one contract's bytecode in a single JSON-RPC roundtrip — saves
    N-1 sequential RTTs per BFS layer when the contract embeds many
    PUSH20 addresses (Solidity hardcoded library refs, factory deploys,
    etc.). Per-call RPC errors raise; missing bytecode is never used to
    mask chain/provider failures.
    """
    from utils.rpc import get_code_batch

    root = normalize_address(root)
    effective_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context=f"static dependency discovery for {root}",
    )
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context=f"static dependency discovery for {root}",
        chain_id=effective_chain_id,
    )
    chain_id = effective_chain_id
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
            code_cache[addr] = results[addr]

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
                if cand not in code_cache:
                    raise RuntimeError(f"Missing eth_getCode batch result for {cand}")
                if has_deployed_code(code_cache[cand]):
                    deps.add(cand)
                    stack.append(cand)

    return sorted(deps)


def find_dependencies(
    address: str,
    code_cache: dict[str, str] | None = None,
    *,
    chain_id: int,
) -> dict:
    """Resolve an RPC endpoint and return discovered static contract dependencies."""
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    effective_rpc = default_rpc_url(chain_id=chain_id)

    address = normalize_address(address)
    deps = discover_dependencies(effective_rpc, address, chain_id=chain_id, code_cache=code_cache)
    return {"address": address, "dependencies": deps}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("--chain-id", type=int, required=True)
    args = parser.parse_args()

    try:
        output = find_dependencies(args.address.strip(), chain_id=args.chain_id)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    print(json.dumps(output))


if __name__ == "__main__":
    main()
