#!/usr/bin/env python3
"""Classify contract dependencies as proxy, implementation, beacon, factory, library, or regular.

Detection:
  - EIP-1167 minimal proxy bytecode
  - EIP-1967 slots (implementation, beacon, admin)
  - EIP-1822 UUPS slot
  - OpenZeppelin legacy implementation slot
  - EIP-2535 diamond (``facetAddresses()``)
  - ``implementation()`` (custom proxies with non-standard slots)
  - short bytecode + DELEGATECALL, confirmed by a trace probe
  - dynamic trace edges (CREATE/CREATE2 → factory, DELEGATECALL-only → library)
  - relational (proxy slot targets → implementation/beacon)
"""

import logging

from services.clients.rpc import rpc_batch_request_with_status
from services.discovery.static_dependencies import get_code, normalize_address, rpc_call
from utils.evm import (
    COMPTROLLER_IMPL_SELECTOR,
    EIP1822_LOGIC_SLOT,
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPL_SLOT,
    GNOSIS_SLOT0_PATTERN,
    IMPLEMENTATION_SELECTOR,
    MASTER_COPY_SELECTOR,
    OWNER_SELECTOR,
    OZ_LEGACY_IMPL_SLOT,
    TARGET_SELECTOR,
)
from utils.logging import record_degraded, record_stage_metric

logger = logging.getLogger(__name__)


class ClassificationIncompleteError(RuntimeError):
    """The proxy-detection slots couldn't be read (transient RPC), as opposed to empty, so a ``regular`` verdict
    built on them is never reported. Transient in ``workers/retry_policy.py``.
    """


EIP1167_PREFIX = "363d3d373d3d3d363d73"
EIP1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3"


# Max hex length (300 bytes) for the DELEGATECALL heuristic.
SHORT_BYTECODE_THRESHOLD = 600

# Size ceiling for trusting the generic ``implementation()`` signal (step 8). Real proxies are ~2.5 KB at most; larger
# contracts exposing ``implementation()`` are logic contracts using it as a domain getter (e.g. EtherFi StakingManager,
# 16.5 KB).
GENERIC_IMPL_PROXY_MAX_BYTES = 8192

FACET_ADDRESSES_SELECTOR = "0x52ef6b2c"  # facetAddresses() — EIP-2535

# Proxy types whose upgrade events the monitor recognises, so ``needs_polling=False``. Custom/unknown types need slot
# polling; EIP-1167 is immutable.
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


def get_storage_at(rpc_url: str, address: str, slot: str, *, chain_id: int | None = None) -> str:
    return rpc_call(rpc_url, "eth_getStorageAt", [address, slot, "latest"], retries=1, chain_id=chain_id)


def _slot_to_address(slot_value: str) -> str | None:
    """A 20-byte address from a 32-byte word.

    ``None`` (no address) requires a full 64-nibble word; anything else raises ``ValueError`` so a truncated response is
    a failed read, never an empty slot or a fabricated address.
    """
    if not isinstance(slot_value, str) or not slot_value.startswith("0x"):
        raise ValueError(f"malformed storage word: {slot_value!r}")
    raw = slot_value[2:].lower()
    if len(raw) != 64 or set(raw) - set("0123456789abcdef"):
        raise ValueError(f"malformed storage word: {slot_value!r}")
    addr_hex = raw[-40:]
    if all(c == "0" for c in addr_hex):
        return None
    return normalize_address("0x" + addr_hex)


def detect_eip1167(bytecode_hex: str) -> str | None:
    raw = (bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex).lower()
    if raw.startswith(EIP1167_PREFIX) and raw.endswith(EIP1167_SUFFIX):
        addr_hex = raw[len(EIP1167_PREFIX) : len(EIP1167_PREFIX) + 40]
        if len(addr_hex) == 40:
            return normalize_address("0x" + addr_hex)
    return None


def _bytecode_has_delegatecall(bytecode_hex: str) -> bool:
    """Whether the bytecode has a real DELEGATECALL (0xF4), skipping PUSH immediates."""
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
        if 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
            continue
        i += 1
    return False


# A selector unlikely to match any real function.
_PROBE_CALLDATA = "0xdeadbeef"


def _extract_delegatecall_target_geth(node) -> str | None:
    if not isinstance(node, dict):
        return None
    if str(node.get("type", "")).upper() == "DELEGATECALL":
        raw = node.get("to")
        return normalize_address(raw) if isinstance(raw, str) and len(raw) >= 42 else ""
    for child in node.get("calls", []) or []:
        target = _extract_delegatecall_target_geth(child)
        if target is not None:
            return target
    return None


def _extract_delegatecall_target_parity(result) -> str | None:
    traces = result if isinstance(result, list) else (result.get("trace", []) if isinstance(result, dict) else [])
    for item in traces:
        if not isinstance(item, dict):
            continue
        action = item.get("action", {}) or {}
        if str(action.get("callType", "")).lower() == "delegatecall":
            raw = action.get("to")
            return normalize_address(raw) if isinstance(raw, str) and len(raw) >= 42 else ""
    return None


def _probe_delegatecall(rpc_url: str, address: str, *, chain_id: int | None = None) -> str | None | bool:
    """Send a traced synthetic eth_call to see whether the fallback DELEGATECALLs.

    Returns the target address, ``""`` if it fired but the target couldn't be parsed, ``False`` if it didn't fire (not a
    proxy), or ``None`` if tracing is unavailable. Any truthy value means proxy.
    """
    call_obj = {"to": address, "data": _PROBE_CALLDATA}

    # Geth-style debug_traceCall.
    for params in [
        [call_obj, "latest", {"tracer": "callTracer", "timeout": "10s"}],
        [call_obj, "latest", {"tracer": "callTracer"}],
    ]:
        try:
            result = rpc_call(rpc_url, "debug_traceCall", params, retries=0, chain_id=chain_id)
            target = _extract_delegatecall_target_geth(result)
            return target if target is not None else False
        except RuntimeError:
            pass

    # Parity/Erigon-style trace_call.
    try:
        result = rpc_call(rpc_url, "trace_call", [call_obj, ["trace"], "latest"], retries=0, chain_id=chain_id)
        target = _extract_delegatecall_target_parity(result)
        return target if target is not None else False
    except RuntimeError:
        pass

    return None  # tracing unavailable


def _try_implementation_call(
    rpc_url: str, address: str, selector: str = IMPLEMENTATION_SELECTOR, *, chain_id: int | None = None
) -> str | None:
    """Call an address-returning getter; the address or None."""
    try:
        result = rpc_call(
            rpc_url,
            "eth_call",
            [{"to": address, "data": selector}, "latest"],
            retries=0,
            chain_id=chain_id,
        )
        return _slot_to_address(result)
    except (RuntimeError, ValueError):
        return None


def _decode_address_array(hex_data: str) -> list[str] | None:
    raw = hex_data[2:] if hex_data.startswith("0x") else hex_data
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(data) < 64:
        return None
    offset = int.from_bytes(data[:32], "big")
    if offset + 32 > len(data):
        return None
    length = int.from_bytes(data[offset : offset + 32], "big")
    if length == 0 or length > 100:
        return None
    start = offset + 32
    if start + length * 32 > len(data):
        return None
    addresses = []
    for i in range(length):
        addr = _slot_to_address("0x" + data[start + i * 32 : start + (i + 1) * 32].hex())
        if addr:
            addresses.append(addr)
    return addresses or None


def _try_facet_addresses_call(rpc_url: str, address: str, *, chain_id: int | None = None) -> list[str] | None:
    """``facetAddresses()`` (EIP-2535); the list or None."""
    try:
        result = rpc_call(
            rpc_url,
            "eth_call",
            [{"to": address, "data": FACET_ADDRESSES_SELECTOR}, "latest"],
            retries=0,
            chain_id=chain_id,
        )
        return _decode_address_array(result)
    except RuntimeError:
        return None


_PROXY_SLOT_BATCH = (
    EIP1967_IMPL_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_ADMIN_SLOT,
    EIP1822_LOGIC_SLOT,
    OZ_LEGACY_IMPL_SLOT,
)


def _read_proxy_slots_batched(
    rpc_url: str, address: str, *, chain_id: int | None = None
) -> tuple[tuple[str | None, ...], bool]:
    """Read the five proxy slots in one JSON-RPC batch, falling back to single reads on batch failure.

    Returns ``((impl, beacon, admin, uups, oz), any_read_failed)``. The flag is True only when a slot's single-call
    fallback also failed, distinguishing "unreadable" from "empty".
    """
    calls = [("eth_getStorageAt", [address, slot, "latest"]) for slot in _PROXY_SLOT_BATCH]
    try:
        results = rpc_batch_request_with_status(rpc_url, calls, chain_id=chain_id)
    except Exception:
        results = [(None, True)] * len(_PROXY_SLOT_BATCH)

    decoded: list[str | None] = []
    any_read_failed = False
    for idx, (raw, had_error) in enumerate(results):
        if had_error or raw is None:
            try:
                raw = get_storage_at(rpc_url, address, _PROXY_SLOT_BATCH[idx], chain_id=chain_id)
            except RuntimeError:
                raw = None
                any_read_failed = True
        try:
            decoded.append(_slot_to_address(raw) if isinstance(raw, str) else None)
        except ValueError:
            # A malformed word is unread, not empty.
            decoded.append(None)
            any_read_failed = True
    return tuple(decoded), any_read_failed


def classify_single(
    address: str,
    rpc_url: str,
    bytecode: str | None = None,
    code_cache: dict[str, str] | None = None,
    *,
    chain_id: int | None = None,
) -> dict:
    """Classify one contract via bytecode patterns and storage slots.

    Returns ``address``, ``type`` and type-specific metadata. *code_cache* avoids duplicate ``eth_getCode`` calls.
    *chain_id* arms the inv-7 URL/chain guard.
    """
    address = normalize_address(address)
    if bytecode is None:
        if code_cache is not None and address in code_cache:
            bytecode = code_cache[address]
        else:
            bytecode = get_code(rpc_url, address, chain_id=chain_id)
            if code_cache is not None:
                code_cache[address] = bytecode

    info: dict = {"address": address}
    logger.debug("classify_single %s — starting intrinsic checks", address)

    # 1. EIP-1167.
    eip1167_impl = detect_eip1167(bytecode)
    if eip1167_impl:
        logger.debug("%s → eip1167 proxy, impl=%s", address, eip1167_impl)
        info.update(type="proxy", proxy_type="eip1167", implementation=eip1167_impl)
        return info

    # 2. Read all five slots in one batch: at most two extra reads on an early proxy hit, and one RTT instead of five
    # for the common non-proxy.
    slot_addrs, proxy_slots_unread = _read_proxy_slots_batched(rpc_url, address, chain_id=chain_id)
    impl, beacon, admin, uups, oz = slot_addrs
    logger.debug("%s EIP-1967 slots: impl=%s beacon=%s admin=%s", address, impl, beacon, admin)

    if beacon:
        info.update(type="proxy", proxy_type="beacon_proxy", beacon=beacon)
        if impl:
            info["implementation"] = impl
        else:
            beacon_impl = _try_implementation_call(rpc_url, beacon, chain_id=chain_id)
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

    # 3. EIP-1822 UUPS.
    if uups:
        logger.debug("%s → eip1822 proxy, impl=%s", address, uups)
        info.update(type="proxy", proxy_type="eip1822", implementation=uups)
        return info

    # 4. OpenZeppelin legacy slot.
    if oz:
        logger.debug("%s → oz_legacy proxy, impl=%s", address, oz)
        info.update(type="proxy", proxy_type="oz_legacy", implementation=oz)
        return info

    # 5. EIP-2535 diamond.
    facets = _try_facet_addresses_call(rpc_url, address, chain_id=chain_id)
    if facets:
        logger.debug("%s → eip2535 diamond, %d facets", address, len(facets))
        info.update(type="proxy", proxy_type="eip2535", facets=facets)
        return info

    # 6. Protocol-specific proxies, before the generic ``implementation()`` so they get their specific type. Only when
    # DELEGATECALL is present, to skip calls for non-proxies.
    if _bytecode_has_delegatecall(bytecode):
        raw_bc = (bytecode[2:] if bytecode.startswith("0x") else bytecode).lower()
        logger.debug("%s has DELEGATECALL, checking protocol-specific patterns", address)

        # GnosisSafe: PUSH20(mask), PUSH1(0), SLOAD, AND loads the implementation from slot 0 (v1.0-1.3+, including
        # minimal proxies where masterCopy()/singleton() revert).
        if GNOSIS_SLOT0_PATTERN in raw_bc:
            try:
                slot0_impl = _slot_to_address(get_storage_at(rpc_url, address, "0x0", chain_id=chain_id))
            except ValueError:
                slot0_impl = None
            if slot0_impl:
                logger.debug("%s → gnosis_safe proxy (slot0 pattern), impl=%s", address, slot0_impl)
                info.update(type="proxy", proxy_type="gnosis_safe", implementation=slot0_impl)
                return info

        # Older GnosisSafe versions expose masterCopy() without the slot-0 pattern.
        master = _try_implementation_call(rpc_url, address, MASTER_COPY_SELECTOR, chain_id=chain_id)
        if master:
            logger.debug("%s → gnosis_safe proxy (masterCopy), impl=%s", address, master)
            info.update(type="proxy", proxy_type="gnosis_safe", implementation=master)
            return info

        comp_impl = _try_implementation_call(rpc_url, address, COMPTROLLER_IMPL_SELECTOR, chain_id=chain_id)
        if comp_impl:
            logger.debug("%s → compound proxy, impl=%s", address, comp_impl)
            info.update(type="proxy", proxy_type="compound", implementation=comp_impl)
            return info

        target_addr = _try_implementation_call(rpc_url, address, TARGET_SELECTOR, chain_id=chain_id)
        if target_addr:
            logger.debug("%s → synthetix proxy, impl=%s", address, target_addr)
            info.update(type="proxy", proxy_type="synthetix", implementation=target_addr)
            return info

    # 7. UpgradeableBeacon: exposes ``implementation()`` and ``owner()`` but never DELEGATECALLs, and its EIP-1967 slots
    # are empty. Classifying it ``beacon`` keeps it analysed so its owner (every instance's upgrade authority) is
    # discovered.
    if not _bytecode_has_delegatecall(bytecode):
        beacon_impl = _try_implementation_call(rpc_url, address, chain_id=chain_id)
        if beacon_impl:
            beacon_owner = _try_implementation_call(rpc_url, address, OWNER_SELECTOR, chain_id=chain_id)
            if beacon_owner:
                logger.debug("%s → beacon (implementation()+owner(), no delegatecall), impl=%s", address, beacon_impl)
                info.update(type="beacon", implementation=beacon_impl, owner=beacon_owner)
                return info

    # 8. ``implementation()`` for custom proxies, size-gated: large contracts use it as a domain getter. A last resort
    # after all standard types.
    raw_bc = bytecode[2:] if bytecode.startswith("0x") else bytecode
    if len(raw_bc) // 2 <= GENERIC_IMPL_PROXY_MAX_BYTES:
        impl_call = _try_implementation_call(rpc_url, address, chain_id=chain_id)
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

    # 9. Short bytecode with DELEGATECALL. With tracing, a synthetic call confirms it fires in the fallback (ruling out
    # libraries) and yields the implementation.
    raw = bytecode[2:] if bytecode.startswith("0x") else bytecode
    if 10 <= len(raw) <= SHORT_BYTECODE_THRESHOLD and _bytecode_has_delegatecall(bytecode):
        logger.debug("%s short bytecode (%d chars) with DELEGATECALL, probing", address, len(raw))
        probe = _probe_delegatecall(rpc_url, address, chain_id=chain_id)
        if probe is False:
            # DELEGATECALL exists but arbitrary calldata doesn't trigger it: a library or utility.
            logger.debug("%s probe returned False — not a proxy (library/utility)", address)
            info["type"] = "regular"
            return info
        if probe is None:
            logger.debug("%s probe unavailable — marking as unknown proxy", address)
            info.update(type="proxy", proxy_type="unknown")
            return info
        logger.debug("%s probe confirmed proxy, delegatecall target=%s", address, probe or "(empty)")
        info.update(type="proxy", proxy_type="unknown")
        if probe:  # non-empty address string
            info["implementation"] = probe
        return info

    # The would-be ``regular`` fallthrough. If the slots were unread, a real proxy would look exactly like this, so fail
    # closed rather than drop its access-control surface. Callers' ``record_degraded`` handlers catch it; positive
    # detections above are unaffected.
    if proxy_slots_unread:
        raise ClassificationIncompleteError(
            f"proxy-slot read failed for {address}; classification incomplete "
            "(cannot distinguish unread slots from a non-proxy)"
        )

    logger.debug("%s → regular (no proxy pattern matched)", address)
    info["type"] = "regular"
    return info


def _incomplete_or_regular(addr: str, exc: BaseException) -> dict:
    """Map a swallowed ``classify_single`` error to a placeholder.

    :class:`ClassificationIncompleteError` becomes ``unknown`` / ``classification_incomplete`` (unresolved, not clean);
    other errors keep the ``regular`` default.
    """
    if isinstance(exc, ClassificationIncompleteError):
        return {"address": addr, "type": "unknown", "classification_incomplete": True}
    return {"address": addr, "type": "regular"}


def classify_contracts(
    target: str,
    dependencies: list[str],
    rpc_url: str,
    dynamic_edges: list[dict] | None = None,
    code_cache: dict[str, str] | None = None,
    pre_classified: dict[str, dict] | None = None,
    *,
    chain_id: int | None = None,
) -> dict:
    """Classify the target and all dependencies:
      1. Intrinsic: storage slots and bytecode.
      2. Relational: implementations/beacons from proxy pointers.
      3. Behavioural: factory/library from dynamic call edges.

    *pre_classified* reuses earlier ``classify_single`` results to avoid repeat RPCs.
    """
    from services.concurrency import parallel_map

    target = normalize_address(target)
    all_addrs = list(dict.fromkeys([target] + [normalize_address(a) for a in dependencies]))
    logger.debug("classify_contracts: target=%s, %d dependencies", target, len(dependencies))

    # Phase 1.
    classifications: dict[str, dict] = {}
    impl_to_proxies: dict[str, list[str]] = {}
    beacon_to_proxies: dict[str, list[str]] = {}
    discovered: set[str] = set()
    all_addrs_set = set(all_addrs)

    # ``code_cache`` isn't threaded through; the locked process-wide ``_GETCODE_CACHE`` in services.clients.rpc handles
    # it.
    addrs_to_classify = [addr for addr in all_addrs if not (pre_classified and addr in pre_classified)]
    parallel_results = parallel_map(
        lambda addr: classify_single(addr, rpc_url, code_cache=None, chain_id=chain_id),
        addrs_to_classify,
        max_workers=8,
    )
    # A swallowed error downgrades to "regular" and can drop an impl/beacon edge; count them and surface one example
    # after the fan-out.
    classify_fallbacks = 0
    classify_fallback_exc: BaseException | None = None
    classified_phase1: dict[str, dict] = {}
    for addr, result in parallel_results:
        if isinstance(result, BaseException):
            logger.debug("Phase 1: classify error for %s (%s) — defaulting to regular", addr, result)
            classify_fallbacks += 1
            classify_fallback_exc = result
            classified_phase1[addr] = _incomplete_or_regular(addr, result)
        else:
            classified_phase1[addr] = result

    for addr in all_addrs:
        if pre_classified and addr in pre_classified:
            info = pre_classified[addr]
        else:
            info = classified_phase1[addr]
        classifications[addr] = info

        # Sequential so first-encounter ordering is deterministic.
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

    # Classify addresses found in proxy slots, in parallel.
    discovered_to_classify = sorted(addr for addr in discovered if addr not in classifications)
    discovered_results = parallel_map(
        lambda addr: classify_single(addr, rpc_url, code_cache=None, chain_id=chain_id),
        discovered_to_classify,
        max_workers=8,
    )
    for addr, result in discovered_results:
        if isinstance(result, BaseException):
            logger.debug("Phase 1 (discovered): classify error for %s (%s) — defaulting to regular", addr, result)
            classify_fallbacks += 1
            classify_fallback_exc = result
            classifications[addr] = _incomplete_or_regular(addr, result)
        else:
            classifications[addr] = result

    record_stage_metric("classify_fallbacks", classify_fallbacks)
    if classify_fallbacks and classify_fallback_exc is not None:
        logger.warning(
            "Classification fell back to 'regular' for %d address(es); proxy edges may be lost",
            classify_fallbacks,
            extra={"classify_fallbacks": classify_fallbacks, "exc_type": type(classify_fallback_exc).__name__},
        )
        record_degraded(
            phase="classify",
            exc=classify_fallback_exc,
            context={"classify_fallbacks": classify_fallbacks, "target": target},
        )

    # Phase 2.
    for addr, info in classifications.items():
        # Beacon wins: Phase 1 may have called an UpgradeableBeacon ``proxy/custom`` because it exposes
        # ``implementation()``.
        if addr in beacon_to_proxies:
            old_type = info.get("type")
            for key in ("proxy_type", "beacon", "admin"):
                info.pop(key, None)
            info["type"] = "beacon"
            info["proxies"] = sorted(beacon_to_proxies[addr])
            if "implementation" not in info:
                impl = _try_implementation_call(rpc_url, addr, chain_id=chain_id)
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

    # Phase 3.
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

    # Unrecognised upgrade events need slot polling.
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
