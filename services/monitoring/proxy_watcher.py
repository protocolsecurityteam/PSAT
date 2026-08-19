"""Proxy implementation resolution.

Resolves the current implementation address behind a proxy via storage-slot
reads and view-getter calls. Consumed by the static worker; the per-chain
upgrade scanner and poller live in ``services.monitoring.unified_watcher``.
"""

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

# Seconds between two WARNINGs about the SAME proxy's undetermined
# implementation. Keyed by subject rather than held as one module-wide clock:
# this module is called both by the monitor daemon (per watched proxy, on a
# clock) and by the static worker inside a job, and a single global would let
# the daemon's earlier warn silence the job's own degraded resolution — the
# thing that job's ``stage_errors`` is supposed to record. Process-local and
# bounded; a restart re-announces once, and nothing published depends on it.
_NOT_DETERMINED_WARN_INTERVAL_S = 300.0
_NOT_DETERMINED_WARN_MAX = 4096
_last_warned_at: dict[str, float] = {}


def reset_not_determined_warn_state() -> None:
    """Re-arm the WARNING (tests, and any caller wanting a fresh announce)."""
    _last_warned_at.clear()


@dataclass(frozen=True)
class _Read:
    """One probe's outcome, in the three states it actually has.

    ``address`` — the node answered and named one.
    ``answered`` and no address — the node answered, and what it answered says
    there is no implementation at this location (an empty slot, the zero
    address, a reverted getter).
    ``answered is False`` — the node did not answer at all. Nothing is known,
    and in particular nothing is known that would license "no implementation".
    Both used to collapse into a bare ``None`` behind ``except Exception: pass``.
    """

    address: str | None
    answered: bool
    # Kept only for the unanswered arm, so the resolution's WARNING and its
    # ``record_degraded`` name the failure that actually happened rather than
    # the fact that some probe failed.
    exc: BaseException | None = None

    @classmethod
    def absent(cls) -> _Read:
        return cls(address=None, answered=True)

    @classmethod
    def unreachable(cls, exc: BaseException | None = None) -> _Read:
        return cls(address=None, answered=False, exc=exc)


# EIP-1474's code for a reverted call, and the message every client that does
# not use it still writes. A revert is the ONLY error a getter can answer with
# that says anything about the contract; every other error payload — a rate
# limit (-32005), a missing trie node, an exhausted upstream — is the provider
# talking about itself.
_REVERT_CODE = 3
_REVERT_TEXT = "revert"


def _error_payload(exc: BaseException) -> dict | None:
    """The JSON-RPC ``error`` object this exception carries, if it carries one.

    ``rpc_request`` re-raises the node's error object stringified
    (``RuntimeError(str(payload["error"]))``), so its repr parses straight back;
    every other ``RuntimeError`` it raises is a sentence it wrote itself and
    does not. Parsed rather than sniffed because the fields are what decide the
    outcome, and a substring test over the repr cannot tell a revert from a rate
    limit.
    """
    if isinstance(exc, RpcClientTimeout) or not isinstance(exc, RuntimeError):
        return None
    try:
        payload = ast.literal_eval(str(exc))
    except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _call_reverted(exc: BaseException) -> bool:
    """Whether an ``eth_call`` failure is the CONTRACT answering, not the provider.

    Only a revert says "this contract does not implement that getter", and only
    that licenses ``_Read.absent``. Everything else — a rate limit, an upstream
    exhausted, a transport failure, the pre-request chain_id guard, anything a
    later refactor adds — is the provider failing to answer, and a provider
    fault must never be published as a fact about the contract. That direction
    is the whole point of the split: the outage class this exists for
    (eRPC rate limiting) arrives as an error payload too.
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
    """Read a storage slot. See :class:`_Read` for the three outcomes."""
    try:
        result = rpc_request(rpc_url, "eth_getStorageAt", [address, slot, block], chain_id=chain_id)
    except Exception as exc:
        # A storage read has no revert semantics: every slot of every account
        # has a value, and the empty one comes back as a word of zeros through
        # the success path below. So an ERROR of any kind here is the provider
        # failing to answer — never the chain saying the slot is empty.
        logger.debug(
            "proxy watcher: storage read did not answer",
            extra={"address": address, "slot": slot, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )
        return _Read.unreachable(exc)
    found = _address_of(result)
    return _Read(address=found, answered=True)


def _call_getter(rpc_url: str, address: str, selector: str, *, chain_id: int | None = None) -> _Read:
    """Call a view function returning a single address. See :class:`_Read`."""
    try:
        result = rpc_request(rpc_url, "eth_call", [{"to": address, "data": selector}, "latest"], chain_id=chain_id)
    except Exception as exc:
        # A REVERT is the contract answering "I do not implement that", which is
        # an answer. Any other error is the provider talking about itself.
        reverted = _call_reverted(exc)
        logger.debug(
            "proxy watcher: getter reverted" if reverted else "proxy watcher: getter call did not answer",
            extra={"address": address, "selector": selector, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )
        return _Read.absent() if reverted else _Read.unreachable(exc)
    found = _address_of(result)
    return _Read(address=found, answered=True)


# Maps proxy_type to the single resolution method needed.  Each entry is
# either ("slot", slot_hex) for eth_getStorageAt or ("call", selector)
# for eth_call.  This lets a known-type proxy resolve in exactly 1 RPC call.
_RESOLVE_BY_TYPE: dict[str, tuple[str, str]] = {
    "eip1967": ("slot", EIP1967_IMPL_SLOT),
    "beacon_proxy": ("slot", EIP1967_IMPL_SLOT),
    "eip1822": ("slot", EIP1822_LOGIC_SLOT),
    "oz_legacy": ("slot", OZ_LEGACY_IMPL_SLOT),
    "custom": ("call", IMPLEMENTATION_SELECTOR),
    "gnosis_safe": ("slot", GNOSIS_MASTERCOPY_SLOT),
    "compound": ("call", COMPTROLLER_IMPL_SELECTOR),
    "synthetix": ("call", TARGET_SELECTOR),
    # eip2535 and eip1167 don't have a single implementation address
    # (diamond has facets, 1167 is immutable) — omitted intentionally.
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
    reads: list[_Read] = []

    def _resolved(read: _Read) -> str | None:
        reads.append(read)
        return read.address

    def _single(read: _Read) -> str | None:
        """The one-probe paths, whose only probe carries the whole answer."""
        if not read.answered:
            _warn_not_determined(proxy_address, chain_id, proxy_type, probes=1, unanswered=1, exc=read.exc)
        return read.address

    # Fast path: historical block lookup (Aave V2 revision events)
    if block != "latest":
        return _single(_read_slot(rpc_url, proxy_address, EIP1967_IMPL_SLOT, block, chain_id=chain_id))

    # Fast path: known proxy_type → single targeted RPC call
    if proxy_type and proxy_type in _RESOLVE_BY_TYPE:
        method, arg = _RESOLVE_BY_TYPE[proxy_type]
        if method == "slot":
            return _single(_read_slot(rpc_url, proxy_address, arg, chain_id=chain_id))
        return _single(_call_getter(rpc_url, proxy_address, arg, chain_id=chain_id))

    # Fallback: try all methods in priority order (registration, unknown type)
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
    """One line per RESOLUTION, never per probe: a dead route fails all eight.

    The ``None`` this accompanies is not "no implementation" — some probe never
    answered — and the caller cannot tell the two apart from the return value,
    so the log and the job's degraded accumulator are where the difference is
    recorded. ``record_degraded`` fires under the static worker (whose job
    context is bound); it is the documented no-op under the monitor daemon,
    where the alarm is the log.

    Warn-once-then-DEBUG PER PROXY: a dead route fails every watched proxy of
    every pass, so an unkeyed window would let one subject's alarm stand for
    every other subject's silence. Keyed, the storm is bounded by the number of
    proxies rather than by the number of passes.
    """
    key = proxy_address.lower()
    now = time.monotonic()
    last = _last_warned_at.get(key)
    first = last is None or now - last >= _NOT_DETERMINED_WARN_INTERVAL_S
    if first:
        if len(_last_warned_at) >= _NOT_DETERMINED_WARN_MAX:
            # A de-dupe cursor, not a record: the worst a reset costs is one
            # repeated announcement.
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
