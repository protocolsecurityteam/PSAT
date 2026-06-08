#!/usr/bin/env python3
"""Classify contract dependencies as proxy, implementation, beacon, factory, library, or regular.

Detection methods:
  - EIP-1167 minimal proxy bytecode pattern
  - EIP-1967 storage slots (implementation, beacon, admin)
  - EIP-1822 UUPS logic slot
  - OpenZeppelin legacy implementation slot
  - EIP-2535 diamond proxy (facetAddresses() call)
  - implementation() call (catches custom proxies with non-standard slots)
  - Bytecode heuristic (short code + DELEGATECALL, confirmed via trace probe)
  - Dynamic trace edges (CREATE/CREATE2 -> factory, DELEGATECALL-only -> library)
  - Relational (proxy slot targets -> implementation/beacon)
"""

import json
import logging

from services.discovery.static_dependencies import get_code, normalize_address, rpc_call
from utils.rpc import require_configured_erpc_url, require_supported_chain_id, rpc_batch_request_with_status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Storage slot constants
# ---------------------------------------------------------------------------

# EIP-1967 (keccak256 of label string minus 1)
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

# EIP-1822 UUPS
EIP1822_LOGIC_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

# OpenZeppelin legacy (keccak256("org.zeppelinos.proxy.implementation"))
OZ_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"

# ---------------------------------------------------------------------------
# EIP-1167 minimal proxy bytecode markers
# ---------------------------------------------------------------------------

EIP1167_PREFIX = "363d3d373d3d3d363d73"
EIP1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3"

# GnosisSafe proxy: PUSH20(address_mask) + PUSH1(0) + SLOAD + AND
# Loads implementation from storage slot 0 and delegates — unique to
# GnosisSafe/Safe proxy contracts (v1.0 through v1.3+).
GNOSIS_SLOT0_PATTERN = "73" + "ff" * 20 + "60005416"

# ---------------------------------------------------------------------------
# Thresholds / selectors
# ---------------------------------------------------------------------------

# Max bytecode hex-char length for the DELEGATECALL heuristic (300 bytes).
SHORT_BYTECODE_THRESHOLD = 600

# Max bytecode size (bytes) for trusting the generic implementation()-getter
# proxy signal (step 7). Real forwarding proxies are tiny — EIP-1967 / OZ / USDC
# proxies in practice top out ~2.5 KB. A large contract that merely *exposes*
# implementation() is a logic contract using it as a domain getter (e.g. EtherFi
# StakingManager, 16.5 KB, returns the EtherFiNode template it deploys), not a
# delegating proxy. 8 KB sits well above the largest real proxy and well below
# such logic contracts.
GENERIC_IMPL_PROXY_MAX_BYTES = 8192

# Function selectors
IMPLEMENTATION_SELECTOR = "0x5c60da1b"  # implementation()
FACET_ADDRESSES_SELECTOR = "0x52ef6b2c"  # facetAddresses() — EIP-2535
MASTER_COPY_SELECTOR = "0xa619486e"  # masterCopy() — GnosisSafe
COMPTROLLER_IMPL_SELECTOR = "0xbb82aa5e"  # comptrollerImplementation() — Compound
TARGET_SELECTOR = "0xd4b83992"  # target() — Synthetix

# Proxy types whose upgrade events the monitor recognises.  These get
# needs_polling=False because the event scan loop detects their upgrades.
# Custom/unknown types are excluded — we don't know what events (if any)
# they emit, so they need storage-slot polling as a fallback.
# EIP-1167 is immutable (no upgrade mechanism) so polling is irrelevant.
_KNOWN_EVENT_PROXY_TYPES = frozenset(
    {
        "eip1967",
        "beacon_proxy",
        "eip1822",
        "oz_legacy",
        "eip2535",
        "eip1167",
        "gnosis_safe",
        "compound",
        "synthetix",
    }
)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def get_storage_at(rpc_url: str, address: str, slot: str, *, chain_id: int) -> str:
    """Read a single 32-byte storage slot."""
    return rpc_call(rpc_url, "eth_getStorageAt", [address, slot, "latest"], retries=1, chain_id=chain_id)


def _slot_to_address(slot_value: str) -> str | None:
    """Extract a 20-byte address from a 32-byte storage value.  Returns None for zero/empty."""
    if not isinstance(slot_value, str) or not slot_value.startswith("0x"):
        raise ValueError(f"expected hex storage/address result, got {slot_value!r}")
    if not slot_value or slot_value in ("0x", "0x0"):
        return None
    raw = slot_value[2:]
    if len(raw) > 64:
        raise ValueError(f"expected 32-byte storage/address result, got {slot_value!r}")
    try:
        bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"malformed hex storage/address result: {slot_value!r}") from exc
    raw = raw.zfill(64)
    addr_hex = raw[-40:]
    if all(c == "0" for c in addr_hex):
        return None
    return normalize_address("0x" + addr_hex)


def _normalize_trace_address(raw: object) -> str:
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) != 42:
        raise ValueError(f"malformed trace address: {raw!r}")
    try:
        bytes.fromhex(raw[2:])
    except ValueError as exc:
        raise ValueError(f"malformed trace address hex: {raw!r}") from exc
    return normalize_address(raw)


def detect_eip1167(bytecode_hex: str) -> str | None:
    """Return the implementation address if *bytecode_hex* is an EIP-1167 minimal proxy."""
    raw = (bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex).lower()
    if raw.startswith(EIP1167_PREFIX) and raw.endswith(EIP1167_SUFFIX):
        addr_hex = raw[len(EIP1167_PREFIX) : len(EIP1167_PREFIX) + 40]
        if len(addr_hex) == 40:
            return normalize_address("0x" + addr_hex)
    return None


def _bytecode_has_delegatecall(bytecode_hex: str) -> bool:
    """Return True if the bytecode contains a real DELEGATECALL (0xF4) opcode,
    skipping bytes that are part of PUSH immediates."""
    raw = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    if not raw or len(raw) % 2 != 0:
        return False
    try:
        code = bytes.fromhex(raw)
    except ValueError:
        return False
    i = 0
    while i < len(code):
        op = code[i]
        if op == 0xF4:
            return True
        # PUSH1 (0x60) through PUSH32 (0x7F): skip immediate bytes
        if 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
            continue
        i += 1
    return False


# Synthetic calldata: a 4-byte selector unlikely to match any real function.
_PROBE_CALLDATA = "0xdeadbeef"


def _extract_delegatecall_target_geth(node) -> str | None:
    """Extract the first DELEGATECALL target address from a Geth callTracer result."""
    if not isinstance(node, dict):
        return None
    if str(node.get("type", "")).upper() == "DELEGATECALL":
        return _normalize_trace_address(node.get("to"))
    for child in node.get("calls", []) or []:
        target = _extract_delegatecall_target_geth(child)
        if target is not None:
            return target
    return None


def _extract_delegatecall_target_parity(result) -> str | None:
    """Extract the first DELEGATECALL target address from a Parity-style trace result."""
    traces = result if isinstance(result, list) else (result.get("trace", []) if isinstance(result, dict) else [])
    for item in traces:
        if not isinstance(item, dict):
            continue
        action = item.get("action", {}) or {}
        if str(action.get("callType", "")).lower() == "delegatecall":
            return _normalize_trace_address(action.get("to"))
    return None


def _is_expected_eth_call_probe_miss(exc: RuntimeError) -> bool:
    """True when an optional getter call failed because the contract did not support it."""
    text = str(exc).lower()
    return any(
        marker in text
        for marker in (
            "execution reverted",
            "revert",
            "invalid opcode",
            "out of gas",
        )
    )


def _probe_delegatecall(rpc_url: str, address: str, *, chain_id: int) -> str | None | bool:
    """Send a synthetic eth_call with tracing to check if DELEGATECALL fires.

    Returns:
      - An address string if DELEGATECALL is triggered (the implementation).
      - ``""`` (empty string) if DELEGATECALL fired but the target couldn't be parsed.
      - ``False`` if no DELEGATECALL was triggered (not a proxy).

    Any truthy return means the contract is a proxy.
    """
    call_obj = {"to": address, "data": _PROBE_CALLDATA}
    try:
        result = rpc_call(
            rpc_url,
            "debug_traceCall",
            [call_obj, "latest", {"tracer": "callTracer", "timeout": "10s"}],
            retries=0,
            chain_id=chain_id,
        )
        target = _extract_delegatecall_target_geth(result)
        return target if target is not None else False
    except RuntimeError as exc:
        logger.error("debug_traceCall proxy probe failed for address=%s: %s", address, exc)
        raise RuntimeError(f"debug_traceCall proxy probe failed for {address}") from exc
    except ValueError as exc:
        logger.error("debug_traceCall proxy probe returned malformed trace address=%s: %s", address, exc)
        raise RuntimeError(f"debug_traceCall proxy probe returned malformed trace for {address}") from exc


def _try_implementation_call(
    rpc_url: str,
    address: str,
    selector: str = IMPLEMENTATION_SELECTOR,
    *,
    chain_id: int,
) -> str | None:
    """Call an address-returning getter on a contract.
    Returns the address on success, or None."""
    try:
        result = rpc_call(
            rpc_url,
            "eth_call",
            [{"to": address, "data": selector}, "latest"],
            retries=0,
            chain_id=chain_id,
        )
        return _slot_to_address(result)
    except RuntimeError as exc:
        if _is_expected_eth_call_probe_miss(exc):
            return None
        logger.error(
            "implementation getter probe failed address=%s selector=%s: %s",
            address,
            selector,
            exc,
        )
        raise RuntimeError(f"implementation getter probe failed for {address}") from exc
    except ValueError as exc:
        logger.error(
            "implementation getter returned invalid address data address=%s selector=%s: %s",
            address,
            selector,
            exc,
        )
        raise RuntimeError(f"implementation getter returned invalid data for {address}") from exc


def _decode_address_array(hex_data: str) -> list[str] | None:
    """Decode an ABI-encoded ``address[]`` return value."""
    if not isinstance(hex_data, str) or not hex_data.startswith("0x"):
        raise ValueError(f"expected 0x-prefixed ABI return data, got {hex_data!r}")
    raw = hex_data[2:] if hex_data.startswith("0x") else hex_data
    try:
        data = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("ABI return data is non-hex") from exc
    if len(data) < 64:
        raise ValueError("ABI address[] return data is too short")
    offset = int.from_bytes(data[:32], "big")
    if offset + 32 > len(data):
        raise ValueError("ABI address[] return offset is out of bounds")
    length = int.from_bytes(data[offset : offset + 32], "big")
    if length == 0:
        return None
    if length > 100:
        raise ValueError(f"ABI address[] return length is too large: {length}")
    start = offset + 32
    if start + length * 32 > len(data):
        raise ValueError("ABI address[] return data is truncated")
    addresses = []
    for i in range(length):
        addr = _slot_to_address("0x" + data[start + i * 32 : start + (i + 1) * 32].hex())
        if addr:
            addresses.append(addr)
    return addresses or None


def _try_facet_addresses_call(rpc_url: str, address: str, *, chain_id: int) -> list[str] | None:
    """Call ``facetAddresses()`` (EIP-2535) on a contract.
    Returns a list of facet addresses on success, or None."""
    try:
        result = rpc_call(
            rpc_url,
            "eth_call",
            [{"to": address, "data": FACET_ADDRESSES_SELECTOR}, "latest"],
            retries=0,
            chain_id=chain_id,
        )
        return _decode_address_array(result)
    except RuntimeError as exc:
        if _is_expected_eth_call_probe_miss(exc):
            return None
        logger.error("facetAddresses probe failed address=%s: %s", address, exc)
        raise RuntimeError(f"facetAddresses probe failed for {address}") from exc
    except ValueError as exc:
        logger.error("facetAddresses returned invalid address data address=%s: %s", address, exc)
        raise RuntimeError(f"facetAddresses returned invalid data for {address}") from exc


# ---------------------------------------------------------------------------
# Single-contract classification (Phase 1)
# ---------------------------------------------------------------------------


_PROXY_SLOT_BATCH = (
    EIP1967_IMPL_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_ADMIN_SLOT,
    EIP1822_LOGIC_SLOT,
    OZ_IMPL_SLOT,
)


def _read_proxy_slots_batched(rpc_url: str, address: str, *, chain_id: int) -> tuple[str | None, ...]:
    """Read the five proxy-detection slots in one JSON-RPC batch.

    Returns ``(impl, beacon, admin, uups, oz)`` decoded via :func:`_slot_to_address`.
    Provider or per-slot RPC failures raise. Storage-slot reads do not
    legitimately revert for supported chains, so treating an errored slot as
    empty would hide incomplete proxy classification.
    """
    calls = [("eth_getStorageAt", [address, slot, "latest"]) for slot in _PROXY_SLOT_BATCH]
    results = rpc_batch_request_with_status(rpc_url, calls, chain_id=chain_id)
    if len(results) != len(_PROXY_SLOT_BATCH):
        logger.error(
            "Proxy slot batch returned %d result(s) for %d slot(s) address=%s",
            len(results),
            len(_PROXY_SLOT_BATCH),
            address,
        )
        raise RuntimeError(f"proxy slot batch returned {len(results)} result(s) for {address}")

    decoded: list[str | None] = []
    for idx, (raw, had_error) in enumerate(results):
        if had_error or raw is None:
            logger.error("Proxy slot read failed address=%s slot=%s", address, _PROXY_SLOT_BATCH[idx])
            raise RuntimeError(f"proxy slot read failed for {address} slot={_PROXY_SLOT_BATCH[idx]}")
        try:
            decoded.append(_slot_to_address(raw))
        except ValueError as exc:
            logger.error(
                "Proxy slot read returned invalid payload address=%s slot=%s: %r",
                address,
                _PROXY_SLOT_BATCH[idx],
                raw,
            )
            raise RuntimeError(f"proxy slot read returned invalid payload for {address}") from exc
    return tuple(decoded)


def classify_single(
    address: str,
    rpc_url: str,
    bytecode: str | None = None,
    code_cache: dict[str, str] | None = None,
    *,
    chain_id: int,
) -> dict:
    """Classify one contract via bytecode patterns and storage slot inspection.

    Returns a dict with ``address``, ``type``, and type-specific metadata.
    When *code_cache* is provided, bytecode lookups are cached to avoid
    duplicate ``eth_getCode`` RPC calls across pipeline stages.
    """
    address = normalize_address(address)
    effective_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context=f"classify_single {address}",
    )
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context=f"classify_single {address}",
        chain_id=effective_chain_id,
    )
    if bytecode is None:
        if code_cache is not None and address in code_cache:
            bytecode = code_cache[address]
        else:
            bytecode = get_code(rpc_url, address, chain_id=effective_chain_id)
            if code_cache is not None:
                code_cache[address] = bytecode

    info: dict = {"address": address}
    logger.debug("classify_single %s — starting intrinsic checks", address)

    # 1. EIP-1167 minimal proxy (bytecode pattern)
    eip1167_impl = detect_eip1167(bytecode)
    if eip1167_impl:
        logger.debug("%s → eip1167 proxy, impl=%s", address, eip1167_impl)
        info.update(type="proxy", proxy_type="eip1167", implementation=eip1167_impl)
        return info

    # 2. Batch the proxy-slot reads: EIP-1967 impl/beacon/admin + EIP-1822 logic + OZ legacy.
    # Reading all five upfront costs at most two extra slot reads when a proxy is detected on
    # the first slot (rare: the contract is more often non-proxy, where we'd have read all five
    # anyway), and trades five sequential RTTs for one. Order matches the historical sequential
    # reads so downstream branch logic is unchanged.
    slot_addrs = _read_proxy_slots_batched(rpc_url, address, chain_id=effective_chain_id)
    impl, beacon, admin, uups, oz = slot_addrs
    logger.debug("%s EIP-1967 slots: impl=%s beacon=%s admin=%s", address, impl, beacon, admin)

    if beacon:
        info.update(type="proxy", proxy_type="beacon_proxy", beacon=beacon)
        if impl:
            info["implementation"] = impl
        else:
            # Resolve implementation through the beacon contract
            beacon_impl = _try_implementation_call(rpc_url, beacon, chain_id=effective_chain_id)
            logger.debug("%s beacon %s → resolved impl=%s", address, beacon, beacon_impl)
            if beacon_impl:
                info["implementation"] = beacon_impl
        if admin:
            info["admin"] = admin
        return info

    if impl:
        logger.debug("%s → eip1967 proxy, impl=%s", address, impl)
        info.update(type="proxy", proxy_type="eip1967", implementation=impl)
        if admin:
            info["admin"] = admin
        return info

    # 3. EIP-1822 UUPS (decoded from the batch above)
    if uups:
        logger.debug("%s → eip1822 proxy, impl=%s", address, uups)
        info.update(type="proxy", proxy_type="eip1822", implementation=uups)
        return info

    # 4. OpenZeppelin legacy slot (decoded from the batch above)
    if oz:
        logger.debug("%s → oz_legacy proxy, impl=%s", address, oz)
        info.update(type="proxy", proxy_type="oz_legacy", implementation=oz)
        return info

    # 5. EIP-2535 diamond proxy — facetAddresses() call
    facets = _try_facet_addresses_call(rpc_url, address, chain_id=effective_chain_id)
    if facets:
        logger.debug("%s → eip2535 diamond, %d facets", address, len(facets))
        info.update(type="proxy", proxy_type="eip2535", facets=facets)
        return info

    # 6. Protocol-specific proxy patterns.  Checked before the generic
    #    implementation() call so that proxies get their specific type even
    #    if they also expose implementation().  Only attempt when DELEGATECALL
    #    is present in bytecode — every proxy must use it, and skipping the
    #    eth_calls for non-proxy contracts avoids unnecessary RPC traffic.
    if _bytecode_has_delegatecall(bytecode):
        raw_bc = (bytecode[2:] if bytecode.startswith("0x") else bytecode).lower()
        logger.debug("%s has DELEGATECALL, checking protocol-specific patterns", address)

        # GnosisSafe — bytecode pattern: PUSH20(mask), PUSH1(0), SLOAD, AND
        # Loads implementation from slot 0 and delegates.  Covers v1.0-1.3+
        # including minimal proxies where masterCopy()/singleton() revert.
        if GNOSIS_SLOT0_PATTERN in raw_bc:
            slot0_impl = _slot_to_address(get_storage_at(rpc_url, address, "0x0", chain_id=effective_chain_id))
            if slot0_impl:
                logger.debug("%s → gnosis_safe proxy (slot0 pattern), impl=%s", address, slot0_impl)
                info.update(type="proxy", proxy_type="gnosis_safe", implementation=slot0_impl)
                return info

        # GnosisSafe fallback — masterCopy() getter (older implementations
        # that expose the variable but don't use the slot-0 bytecode pattern).
        master = _try_implementation_call(rpc_url, address, MASTER_COPY_SELECTOR, chain_id=effective_chain_id)
        if master:
            logger.debug("%s → gnosis_safe proxy (masterCopy), impl=%s", address, master)
            info.update(type="proxy", proxy_type="gnosis_safe", implementation=master)
            return info

        # Compound — comptrollerImplementation()
        comp_impl = _try_implementation_call(rpc_url, address, COMPTROLLER_IMPL_SELECTOR, chain_id=effective_chain_id)
        if comp_impl:
            logger.debug("%s → compound proxy, impl=%s", address, comp_impl)
            info.update(type="proxy", proxy_type="compound", implementation=comp_impl)
            return info

        # Synthetix — target()
        target_addr = _try_implementation_call(rpc_url, address, TARGET_SELECTOR, chain_id=effective_chain_id)
        if target_addr:
            logger.debug("%s → synthetix proxy, impl=%s", address, target_addr)
            info.update(type="proxy", proxy_type="synthetix", implementation=target_addr)
            return info

    # 7. implementation() call — catches custom proxies with non-standard
    #    storage slots that still expose the standard interface. Guarded by a
    #    bytecode-size ceiling: a real forwarding proxy is tiny, so a large
    #    contract exposing implementation() is a logic contract using it as a
    #    domain getter (e.g. EtherFi StakingManager returns the EtherFiNode
    #    template it deploys), not a delegation pointer. Every standard proxy
    #    type is already caught deterministically above, so this size-gated
    #    soft signal is the last resort.
    raw_bc = bytecode[2:] if bytecode.startswith("0x") else bytecode
    if len(raw_bc) // 2 <= GENERIC_IMPL_PROXY_MAX_BYTES:
        impl_call = _try_implementation_call(rpc_url, address, chain_id=effective_chain_id)
        if impl_call:
            logger.debug("%s → custom proxy (implementation() call), impl=%s", address, impl_call)
            info.update(type="proxy", proxy_type="custom", implementation=impl_call)
            return info
    else:
        logger.debug(
            "%s exposes implementation() but bytecode is %d bytes (> %d) — treating as logic, not proxy",
            address,
            len(raw_bc) // 2,
            GENERIC_IMPL_PROXY_MAX_BYTES,
        )

    # 8. Heuristic: short bytecode (<= 300 bytes) with DELEGATECALL opcode.
    #    When tracing is available, probe with synthetic calldata to confirm
    #    DELEGATECALL actually fires in the fallback path (eliminates library
    #    false positives) and extract the implementation address from the trace.
    raw = bytecode[2:] if bytecode.startswith("0x") else bytecode
    if 10 <= len(raw) <= SHORT_BYTECODE_THRESHOLD and _bytecode_has_delegatecall(bytecode):
        logger.debug("%s short bytecode (%d chars) with DELEGATECALL, probing", address, len(raw))
        probe = _probe_delegatecall(rpc_url, address, chain_id=effective_chain_id)
        if probe is False:
            # DELEGATECALL exists but isn't triggered by arbitrary calldata —
            # this is a library or utility, not a proxy.
            logger.debug("%s probe returned False — not a proxy (library/utility)", address)
            info["type"] = "regular"
            return info
        # probe is a str: the DELEGATECALL target (implementation address)
        logger.debug("%s probe confirmed proxy, delegatecall target=%s", address, probe or "(empty)")
        info.update(type="proxy", proxy_type="unknown")
        if probe:  # non-empty address string
            info["implementation"] = probe
        return info

    logger.debug("%s → regular (no proxy pattern matched)", address)
    info["type"] = "regular"
    return info


# ---------------------------------------------------------------------------
# Multi-contract classification (Phases 1-3)
# ---------------------------------------------------------------------------


def classify_contracts(
    target: str,
    dependencies: list[str],
    rpc_url: str,
    *,
    chain_id: int,
    dynamic_edges: list[dict] | None = None,
    code_cache: dict[str, str] | None = None,
    pre_classified: dict[str, dict] | None = None,
) -> dict:
    """Classify the target contract and all its dependencies.

    Three phases:
      1. **Intrinsic** -- storage slots and bytecode patterns.
      2. **Relational** -- mark implementations / beacons discovered via proxy pointers.
      3. **Behavioral** -- factory / library labels from dynamic call-graph edges.

    *pre_classified* is an optional mapping of ``{address: classify_single result}``
    for addresses that have already been classified (e.g. by a prior
    ``_resolve_proxy`` call).  These are reused in Phase 1, avoiding
    duplicate RPC calls.
    """
    from utils.concurrency import parallel_map

    target = normalize_address(target)
    effective_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context=f"classify_contracts {target}",
    )
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context=f"classify_contracts {target}",
        chain_id=effective_chain_id,
    )
    all_addrs = list(dict.fromkeys([target] + [normalize_address(a) for a in dependencies]))
    logger.debug("classify_contracts: target=%s, %d dependencies", target, len(dependencies))

    # Phase 1 -- intrinsic classification
    classifications: dict[str, dict] = {}
    impl_to_proxies: dict[str, list[str]] = {}
    beacon_to_proxies: dict[str, list[str]] = {}
    discovered: set[str] = set()
    all_addrs_set = set(all_addrs)

    # Fan out every address that isn't already pre-classified. ``code_cache`` is
    # intentionally not threaded through — ``classify_single`` falls through to
    # the locked process-wide ``_GETCODE_CACHE`` in utils.rpc, which already
    # serialises bytecode reads safely.
    addrs_to_classify = [addr for addr in all_addrs if not (pre_classified and addr in pre_classified)]
    parallel_results = parallel_map(
        lambda addr: classify_single(addr, rpc_url, code_cache=None, chain_id=effective_chain_id),
        addrs_to_classify,
        max_workers=8,
    )
    classified_phase1: dict[str, dict] = {}
    for addr, result in parallel_results:
        if isinstance(result, BaseException):
            logger.error("Phase 1: classify error for %s: %s", addr, result)
            raise RuntimeError(f"contract classification failed for {addr}") from result
        else:
            classified_phase1[addr] = result

    for addr in all_addrs:
        if pre_classified and addr in pre_classified:
            info = pre_classified[addr]
        else:
            info = classified_phase1[addr]
        classifications[addr] = info

        # Track reverse mappings — sequential so the deterministic "first
        # encounter wins" ordering of the proxies list is preserved.
        if impl := info.get("implementation"):
            impl_to_proxies.setdefault(impl, []).append(addr)
            if impl not in all_addrs_set:
                discovered.add(impl)
        if bcon := info.get("beacon"):
            beacon_to_proxies.setdefault(bcon, []).append(addr)
            if bcon not in all_addrs_set:
                discovered.add(bcon)
        for facet in info.get("facets", []):
            impl_to_proxies.setdefault(facet, []).append(addr)
            if facet not in all_addrs_set:
                discovered.add(facet)

    if discovered:
        logger.debug("Phase 1 discovered %d new addresses from proxy slots: %s", len(discovered), sorted(discovered))

    # Classify newly-discovered addresses (found in proxy slots) in parallel, skipping
    # any already covered by Phase 1.
    discovered_to_classify = sorted(addr for addr in discovered if addr not in classifications)
    discovered_results = parallel_map(
        lambda addr: classify_single(addr, rpc_url, code_cache=None, chain_id=effective_chain_id),
        discovered_to_classify,
        max_workers=8,
    )
    for addr, result in discovered_results:
        if isinstance(result, BaseException):
            logger.error("Discovered address classification failed for %s: %s", addr, result)
            raise RuntimeError(f"discovered address classification failed for {addr}") from result
        else:
            classifications[addr] = result

    # Phase 2 -- relational: mark implementations and beacons
    for addr, info in classifications.items():
        # Beacon takes priority: the EIP-1967 beacon slot is a strong signal.
        # Phase 1 may have classified the beacon as "proxy/custom" because
        # UpgradeableBeacon exposes implementation() — override that here.
        if addr in beacon_to_proxies:
            old_type = info.get("type")
            for key in ("proxy_type", "beacon", "admin"):
                info.pop(key, None)
            info["type"] = "beacon"
            info["proxies"] = sorted(beacon_to_proxies[addr])
            if "implementation" not in info:
                impl = _try_implementation_call(rpc_url, addr, chain_id=effective_chain_id)
                if impl:
                    info["implementation"] = impl
            logger.debug("Phase 2: %s reclassified %s → beacon (proxies: %s)", addr, old_type, info["proxies"])
            continue
        if info["type"] != "regular":
            continue
        if addr in impl_to_proxies:
            info["type"] = "implementation"
            info["proxies"] = sorted(impl_to_proxies[addr])
            logger.debug("Phase 2: %s → implementation (proxies: %s)", addr, info["proxies"])

    # Phase 3 -- behavioral: factory / library / created from dynamic edges
    if dynamic_edges:
        creators: set[str] = set()
        created: set[str] = set()
        delegatecall_only: dict[str, bool] = {}

        for edge in dynamic_edges:
            src = normalize_address(edge["from"])
            dst = normalize_address(edge["to"])
            op = edge.get("op", "")

            if op in ("CREATE", "CREATE2"):
                creators.add(src)
                created.add(dst)
            elif op == "DELEGATECALL":
                if dst in classifications and dst not in delegatecall_only:
                    delegatecall_only[dst] = True
            elif op in ("CALL", "STATICCALL", "CALLCODE"):
                if dst in classifications:
                    delegatecall_only[dst] = False

        for addr, info in classifications.items():
            if info["type"] != "regular":
                continue
            if addr in creators:
                info["type"] = "factory"
                logger.debug("Phase 3: %s → factory (CREATE/CREATE2 edges)", addr)
            elif addr in created:
                info["type"] = "created"
                logger.debug("Phase 3: %s → created (spawned by factory)", addr)
            elif delegatecall_only.get(addr, False):
                info["type"] = "library"
                logger.debug("Phase 3: %s → library (DELEGATECALL-only target)", addr)

    # Mark proxies whose upgrade events are unrecognised — these need
    # storage-slot polling to detect implementation changes.
    for info in classifications.values():
        if info["type"] == "proxy":
            info["needs_polling"] = info.get("proxy_type") not in _KNOWN_EVENT_PROXY_TYPES
            if info["needs_polling"]:
                logger.debug(
                    "%s needs_polling=True (proxy_type=%s not in known event types)",
                    info["address"],
                    info.get("proxy_type"),
                )

    return {
        "address": target,
        "classifications": classifications,
        "discovered_addresses": sorted(discovered),
    }


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------


def main():
    import argparse
    from pathlib import Path

    from dotenv import load_dotenv

    from utils.rpc import default_rpc_url

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")

    parser = argparse.ArgumentParser(description="Classify contract dependencies")
    parser.add_argument("address", help="Contract address to classify")
    parser.add_argument("--chain-id", type=int, required=True, help="EIP-155 chain id")
    parser.add_argument("--deps", nargs="*", default=[], help="Dependency addresses")
    args = parser.parse_args()

    try:
        resolved_rpc = default_rpc_url(chain_id=args.chain_id)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    result = classify_contracts(args.address.strip(), args.deps, resolved_rpc, chain_id=args.chain_id)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
