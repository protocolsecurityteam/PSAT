"""Resolve the current implementation behind a proxy via storage-slot reads and view getters."""

from __future__ import annotations

import ast
import logging
import time
from dataclasses import dataclass

from services.clients.rpc import RpcClientTimeout, normalize_hex, rpc_request
from utils.evm import (
    COMPTROLLER_IMPL_SELECTOR,
    EIP1822_LOGIC_SLOT,
    EIP1967_IMPL_SLOT,
    GNOSIS_MASTERCOPY_SLOT,
    IMPLEMENTATION_SELECTOR,
    MASTER_COPY_SELECTOR,
    OZ_LEGACY_IMPL_SLOT,
    TARGET_SELECTOR,
)
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

# Per-proxy warn window. Not one global clock: the monitor daemon's earlier warning must not silence a static-worker
# job's own degraded record.
_NOT_DETERMINED_WARN_INTERVAL_S = 300.0
_NOT_DETERMINED_WARN_MAX = 4096
_last_warned_at: dict[str, float] = {}


def reset_not_determined_warn_state() -> None:
    _last_warned_at.clear()


@dataclass(frozen=True)
class _Read:
    """One probe's outcome: ``address`` (answered, named one), ``answered`` without address (answered: no implementation
    here), or unanswered (nothing is known, so "no implementation" is not licensed).
    """

    address: str | None
    answered: bool
    exc: BaseException | None = None

    @classmethod
    def absent(cls) -> _Read:
        return cls(address=None, answered=True)

    @classmethod
    def unreachable(cls, exc: BaseException | None = None) -> _Read:
        return cls(address=None, answered=False, exc=exc)


# EIP-1474 revert code (and the message clients use without it). Only a revert speaks about the contract; every other
# error is the provider talking about itself.
_REVERT_CODE = 3
_REVERT_TEXT = "revert"


def _error_payload(exc: BaseException) -> dict | None:
    """The JSON-RPC ``error`` object parsed back from ``rpc_request``'s stringified re-raise, if present. A substring
    test cannot tell a revert from a rate limit.
    """
    if isinstance(exc, RpcClientTimeout) or not isinstance(exc, RuntimeError):
        return None
    try:
        payload = ast.literal_eval(str(exc))
    except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _call_reverted(exc: BaseException) -> bool:
    """Whether an ``eth_call`` failure is the contract answering (a revert) rather than the provider failing. A provider
    fault must never be published as a fact about the contract.
    """
    payload = _error_payload(exc)
    if payload is None:
        return False
    if payload.get("code") == _REVERT_CODE:
        return True
    return _REVERT_TEXT in str(payload.get("message") or "").lower()


def _address_of(result: object) -> str | None:
    if isinstance(result, str) and result and result != "0x" + "0" * 64:
        addr = "0x" + result[-40:]
        if addr != "0x" + "0" * 40:
            return normalize_hex(addr)
    return None


def _read_slot(rpc_url: str, address: str, slot: str, block: str = "latest", *, chain_id: int | None = None) -> _Read:
    try:
        result = rpc_request(rpc_url, "eth_getStorageAt", [address, slot, block], chain_id=chain_id)
    except Exception as exc:
        # Every slot has a value, so any error here is the provider failing, never an empty slot.
        logger.debug(
            "proxy watcher: storage read did not answer",
            extra={"address": address, "slot": slot, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )
        return _Read.unreachable(exc)
    found = _address_of(result)
    return _Read(address=found, answered=True)


def _call_getter(rpc_url: str, address: str, selector: str, *, chain_id: int | None = None) -> _Read:
    try:
        result = rpc_request(rpc_url, "eth_call", [{"to": address, "data": selector}, "latest"], chain_id=chain_id)
    except Exception as exc:
        reverted = _call_reverted(exc)
        logger.debug(
            "proxy watcher: getter reverted" if reverted else "proxy watcher: getter call did not answer",
            extra={"address": address, "selector": selector, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )
        return _Read.absent() if reverted else _Read.unreachable(exc)
    found = _address_of(result)
    return _Read(address=found, answered=True)


# proxy_type -> the single read that resolves it: ("slot", slot_hex) or ("call", selector).
_RESOLVE_BY_TYPE: dict[str, tuple[str, str]] = {
    "eip1967": ("slot", EIP1967_IMPL_SLOT),
    "beacon_proxy": ("slot", EIP1967_IMPL_SLOT),
    "eip1822": ("slot", EIP1822_LOGIC_SLOT),
    "oz_legacy": ("slot", OZ_LEGACY_IMPL_SLOT),
    "custom": ("call", IMPLEMENTATION_SELECTOR),
    "gnosis_safe": ("slot", GNOSIS_MASTERCOPY_SLOT),
    "compound": ("call", COMPTROLLER_IMPL_SELECTOR),
    "synthetix": ("call", TARGET_SELECTOR),
    # eip2535 (facets) and eip1167 (immutable) have no single implementation to resolve.
}


def resolve_current_implementation(
    proxy_address: str,
    rpc_url: str,
    block: str = "latest",
    proxy_type: str | None = None,
    *,
    chain_id: int | None = None,
) -> str | None:
    """Resolve the current implementation for a proxy.

    With *proxy_type*, one targeted read; without, try every method in priority order. A non-latest *block* reads only
    the EIP-1967 slot (Aave V2 ``Upgraded(uint256)`` events carry no address). *chain_id* arms the URL/chain-id guard on
    each read.
    """
    reads: list[_Read] = []

    def _resolved(read: _Read) -> str | None:
        reads.append(read)
        return read.address

    def _single(read: _Read) -> str | None:
        if not read.answered:
            _warn_not_determined(proxy_address, chain_id, proxy_type, probes=1, unanswered=1, exc=read.exc)
        return read.address

    if block != "latest":
        return _single(_read_slot(rpc_url, proxy_address, EIP1967_IMPL_SLOT, block, chain_id=chain_id))

    if proxy_type and proxy_type in _RESOLVE_BY_TYPE:
        method, arg = _RESOLVE_BY_TYPE[proxy_type]
        if method == "slot":
            return _single(_read_slot(rpc_url, proxy_address, arg, chain_id=chain_id))
        return _single(_call_getter(rpc_url, proxy_address, arg, chain_id=chain_id))

    for slot in (EIP1967_IMPL_SLOT, EIP1822_LOGIC_SLOT, OZ_LEGACY_IMPL_SLOT):
        addr = _resolved(_read_slot(rpc_url, proxy_address, slot, chain_id=chain_id))
        if addr:
            return addr

    addr = _resolved(_call_getter(rpc_url, proxy_address, IMPLEMENTATION_SELECTOR, chain_id=chain_id))
    if addr:
        return addr

    for sel in (MASTER_COPY_SELECTOR, COMPTROLLER_IMPL_SELECTOR, TARGET_SELECTOR):
        addr = _resolved(_call_getter(rpc_url, proxy_address, sel, chain_id=chain_id))
        if addr:
            return addr

    addr = _resolved(_read_slot(rpc_url, proxy_address, GNOSIS_MASTERCOPY_SLOT, chain_id=chain_id))
    if addr:
        return addr

    unanswered = [read for read in reads if not read.answered]
    if unanswered:
        _warn_not_determined(
            proxy_address,
            chain_id,
            proxy_type,
            probes=len(reads),
            unanswered=len(unanswered),
            exc=next((read.exc for read in unanswered if read.exc is not None), None),
        )
    return None


def _warn_not_determined(
    proxy_address: str,
    chain_id: int | None,
    proxy_type: str | None,
    *,
    probes: int,
    unanswered: int,
    exc: BaseException | None = None,
) -> None:
    """Log once per resolution, never per probe. The returned ``None`` can't distinguish "no implementation" from
    "unanswered", so the log and ``record_degraded`` carry that. Warn-once is keyed per proxy so one subject's alarm
    can't stand in for another's.
    """
    key = proxy_address.lower()
    now = time.monotonic()
    last = _last_warned_at.get(key)
    first = last is None or now - last >= _NOT_DETERMINED_WARN_INTERVAL_S
    if first:
        if len(_last_warned_at) >= _NOT_DETERMINED_WARN_MAX:
            _last_warned_at.clear()
        _last_warned_at[key] = now
    fields = {
        "address": proxy_address,
        "chain_id": chain_id,
        "proxy_type": proxy_type,
        "probes": probes,
        "probes_unanswered": unanswered,
    }
    if exc is not None:
        record_degraded(phase="proxy_implementation", exc=exc, context=dict(fields))
    logger.log(
        logging.WARNING if first else logging.DEBUG,
        "proxy watcher: implementation not determined; some probe did not answer",
        extra={**fields, "exc_type": None if exc is None else type(exc).__name__},
    )
