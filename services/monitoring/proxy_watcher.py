"""Proxy implementation resolution.

Resolves the current implementation address behind a proxy via storage-slot
reads and view-getter calls. Consumed by the static worker; the per-chain
upgrade scanner and poller live in ``services.monitoring.unified_watcher``.
"""

from __future__ import annotations

from utils.rpc import normalize_hex, rpc_request

# Storage slots used for implementation resolution
_EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_EIP1822_LOGIC_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
_OZ_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
_GNOSIS_SLOT = "0x0"

# Getter selectors for protocol-specific proxies
_IMPLEMENTATION_SEL = "0x5c60da1b"  # implementation()
_COMPTROLLER_IMPL_SEL = "0xbb82aa5e"  # comptrollerImplementation()
_TARGET_SEL = "0xd4b83992"  # target()
_MASTER_COPY_SEL = "0xa619486e"  # masterCopy()


def _read_slot(
    rpc_url: str, address: str, slot: str, block: str = "latest", *, chain_id: int | None = None
) -> str | None:
    """Read a storage slot and return the address if non-zero, else None."""
    try:
        result = rpc_request(rpc_url, "eth_getStorageAt", [address, slot, block], chain_id=chain_id)
        if result and result != "0x" + "0" * 64:
            addr = "0x" + result[-40:]
            if addr != "0x" + "0" * 40:
                return normalize_hex(addr)
    except Exception:
        pass
    return None


def _call_getter(rpc_url: str, address: str, selector: str, *, chain_id: int | None = None) -> str | None:
    """Call a view function that returns a single address.  Returns None on revert."""
    try:
        result = rpc_request(rpc_url, "eth_call", [{"to": address, "data": selector}, "latest"], chain_id=chain_id)
        if result and result != "0x" + "0" * 64:
            addr = "0x" + result[-40:]
            if addr != "0x" + "0" * 40:
                return normalize_hex(addr)
    except Exception:
        pass
    return None


# Maps proxy_type to the single resolution method needed.  Each entry is
# either ("slot", slot_hex) for eth_getStorageAt or ("call", selector)
# for eth_call.  This lets a known-type proxy resolve in exactly 1 RPC call.
_RESOLVE_BY_TYPE: dict[str, tuple[str, str]] = {
    "eip1967": ("slot", _EIP1967_IMPL_SLOT),
    "beacon_proxy": ("slot", _EIP1967_IMPL_SLOT),
    "eip1822": ("slot", _EIP1822_LOGIC_SLOT),
    "oz_legacy": ("slot", _OZ_IMPL_SLOT),
    "custom": ("call", _IMPLEMENTATION_SEL),
    "gnosis_safe": ("slot", _GNOSIS_SLOT),
    "compound": ("call", _COMPTROLLER_IMPL_SEL),
    "synthetix": ("call", _TARGET_SEL),
    # eip2535 and eip1167 don't have a single implementation address
    # (diamond has facets, 1167 is immutable) — omitted intentionally.
}


def _build_rpc_call(method_type: str, address: str, arg: str) -> tuple[str, list]:
    """Return a ``(method, params)`` tuple for use in a JSON-RPC batch."""
    if method_type == "slot":
        return ("eth_getStorageAt", [address, arg, "latest"])
    return ("eth_call", [{"to": address, "data": arg}, "latest"])


def resolve_current_implementation(
    proxy_address: str,
    rpc_url: str,
    block: str = "latest",
    proxy_type: str | None = None,
    *,
    chain_id: int | None = None,
) -> str | None:
    """Resolve the current implementation for a proxy.

    When *proxy_type* is provided, dispatches directly to the right
    resolution method — O(1) RPC call.  When omitted, falls back to
    trying all methods in priority order (used at registration time
    before the type is known, and for the Aave V2 fast path).

    When *block* is not ``"latest"`` only the EIP-1967 slot is read —
    the fast path for Aave V2's ``Upgraded(uint256)`` events, which carry
    no implementation address and require a storage read at the event block.

    *chain_id* (the proxy's chain, threaded from the static worker) arms the
    inv-7 URL↔chain_id guard on every underlying read; None keeps it a no-op.
    """
    # Fast path: historical block lookup (Aave V2 revision events)
    if block != "latest":
        return _read_slot(rpc_url, proxy_address, _EIP1967_IMPL_SLOT, block, chain_id=chain_id)

    # Fast path: known proxy_type → single targeted RPC call
    if proxy_type and proxy_type in _RESOLVE_BY_TYPE:
        method, arg = _RESOLVE_BY_TYPE[proxy_type]
        if method == "slot":
            return _read_slot(rpc_url, proxy_address, arg, chain_id=chain_id)
        return _call_getter(rpc_url, proxy_address, arg, chain_id=chain_id)

    # Fallback: try all methods in priority order (registration, unknown type)
    for slot in (_EIP1967_IMPL_SLOT, _EIP1822_LOGIC_SLOT, _OZ_IMPL_SLOT):
        addr = _read_slot(rpc_url, proxy_address, slot, chain_id=chain_id)
        if addr:
            return addr

    addr = _call_getter(rpc_url, proxy_address, _IMPLEMENTATION_SEL, chain_id=chain_id)
    if addr:
        return addr

    for sel in (_MASTER_COPY_SEL, _COMPTROLLER_IMPL_SEL, _TARGET_SEL):
        addr = _call_getter(rpc_url, proxy_address, sel, chain_id=chain_id)
        if addr:
            return addr

    addr = _read_slot(rpc_url, proxy_address, _GNOSIS_SLOT, chain_id=chain_id)
    if addr:
        return addr

    return None
