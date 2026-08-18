"""Detect split-proxy *secondary-implementation* pointers.

A "secondary implementation" is a logic contract a proxy reaches **beyond** its
EIP-1967 slot impl: the primary impl's ``fallback``/``receive`` delegatecalls to
a logic address held in storage. Two real-world shapes are handled:

  * **unstructured constant slot** (ether.fi LRTSquared, EIP-1967-style): the
    fallback ``sload``s a ``bytes32``/``uint256`` *constant* slot and
    delegatecalls the result. The slot is the constant itself —
    ``keccak256("…")``, the EIP-1967 ``…-1`` variant, or a hex literal.
  * **named address state variable**: the fallback delegatecalls the value of an
    ``address`` state var, possibly via an internal helper.

PSAT otherwise models only the single EIP-1967 impl, so the secondary is analysed
standalone against its own empty storage and renders as an ownerless orphan.

Returns pointer descriptors — ``{name, slot, offset}`` — locating the secondary
impl in the **proxy's** storage; the value is read from there downstream
(``services/discovery/secondary_impl.py``), because the pointer's getter is
typically non-public and reverts. ``slot`` is an ``int`` — a small sequential
layout slot for the named-var case, or the full 256-bit constant for the
unstructured-slot case.

Detection keys on the IR *operation* (a real ``delegatecall``), never a substring
of a variable name (so a ``delegatecallTarget.call(...)`` is not matched), and
walks the fallback transitively through internal/library calls.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from schemas.contract_analysis import SecondaryImplPointer
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

_ADDRESS_TYPES = {"address", "address payable"}
_SLOT_CONST_TYPES = {"bytes32", "uint256"}


def _ir_is_delegatecall(ir: Any) -> bool:
    """True iff ``ir`` is a delegatecall **operation** — the assembly/builtin
    ``SolidityCall delegatecall(...)`` or a high-level ``addr.delegatecall(data)``
    (``LowLevelCall``). A plain ``.call()`` (``LowLevelCall`` with
    ``function:call``) or a variable merely *named* ``delegatecall*`` does NOT
    match."""
    op = type(ir).__name__
    if op == "SolidityCall":
        name = getattr(getattr(ir, "function", None), "name", "") or ""
        return name.startswith("delegatecall(")
    if op == "LowLevelCall":
        return getattr(ir, "function_name", "") == "delegatecall"
    return False


def _ir_is_sload(ir: Any) -> bool:
    if type(ir).__name__ == "SolidityCall":
        name = getattr(getattr(ir, "function", None), "name", "") or ""
        return name.startswith("sload(")
    return False


def _any_transitive_ir(fn: Any, pred: Callable[[Any], bool], seen: set[Any] | None = None) -> bool:
    """Whether any IR in ``fn`` — or in an internal/library function it calls —
    satisfies ``pred``. Bounded by ``seen`` against recursion. Lets a fallback
    that forwards through a helper (``fallback → _delegate(impl)``) still be
    recognised."""
    if seen is None:
        seen = set()
    key = getattr(fn, "canonical_name", None) or id(fn)
    if key in seen:
        return False
    seen.add(key)
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if pred(ir):
                return True
            callee = getattr(ir, "function", None)
            if (
                callee is not None
                and getattr(callee, "nodes", None)
                and type(ir).__name__ in ("InternalCall", "LibraryCall")
                and _any_transitive_ir(callee, pred, seen)
            ):
                return True
    return False


def _has_writer(contract: Any, var: Any) -> bool:
    """A non-constructor function writes ``var`` — the ``set*Impl`` half of the
    split-proxy shape. Guards against misfiring on an immutable-target
    forwarder."""
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        try:
            if var in fn.all_state_variables_written():
                return True
        except Exception:  # pragma: no cover - slither edge
            continue
    return False


def _const_slot_value(var: Any) -> int | None:
    """Folded value (as ``int``) of a slot-typed constant — handles
    ``keccak256("…")``, the EIP-1967 ``bytes32(uint256(keccak256(…)) - 1)``
    variant, and hex literals, via Slither's constant folding."""
    expr = getattr(var, "expression", None)
    if expr is None:
        return None
    try:
        from slither.visitors.expression.constants_folding import ConstantFolding

        result = ConstantFolding(expr, str(var.type)).result()
        val = getattr(result, "value", None)
    except Exception as exc:  # pragma: no cover - slither edge
        record_degraded(
            phase="secondary_impl_const_slot_fold",
            exc=exc,
            context={"var": str(getattr(var, "name", "?"))},
        )
        logger.warning("secondary-impl const-slot fold failed for %s: %s", getattr(var, "name", "?"), exc)
        return None
    if isinstance(val, bool):
        return None
    if isinstance(val, bytes):
        return int.from_bytes(val, "big")
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 16) if val.lower().startswith("0x") else int(val)
        except ValueError:
            return None
    return None


class _SlotLayout:
    """Lazy Slither storage-layout reader, built only when a named-address-var
    pointer needs its sequential slot."""

    def __init__(self, contract: Any) -> None:
        self._contract = contract
        self._srs: Any = None
        self._tried = False

    def slot_offset(self, var: Any) -> tuple[int, int] | None:
        if not self._tried:
            self._tried = True
            try:
                from slither.tools.read_storage import SlitherReadStorage

                self._srs = SlitherReadStorage([self._contract], 20)
            except Exception as exc:  # pragma: no cover - slither tool edge
                record_degraded(
                    phase="secondary_impl_slot_layout",
                    exc=exc,
                    context={"contract": str(getattr(self._contract, "name", "?"))},
                )
                logger.warning("SlitherReadStorage unavailable; secondary-impl var slots unresolved: %s", exc)
                self._srs = None
        if self._srs is None:
            return None
        try:
            info = self._srs.get_storage_slot(var, self._contract)
        except Exception as exc:
            record_degraded(
                phase="secondary_impl_var_slot",
                exc=exc,
                context={"var": str(getattr(var, "name", "?"))},
            )
            logger.warning("secondary-impl slot computation failed for %s: %s", getattr(var, "name", "?"), exc)
            return None
        raw_slot = getattr(info, "slot", None)
        if raw_slot is None:
            return None
        return int(raw_slot), int(getattr(info, "offset", 0) or 0)


def detect_secondary_impl_pointers(contract: Any) -> list[SecondaryImplPointer]:
    """Pointer descriptors for each secondary-impl slot a fallback/receive
    delegatecalls. Empty for the overwhelming majority of contracts (no
    fallback, or a fallback that doesn't delegatecall a stored address)."""
    layout = _SlotLayout(contract)
    pointers: list[SecondaryImplPointer] = []
    seen: set[str] = set()
    for fn in getattr(contract, "functions", []) or []:
        if not (getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False)):
            continue
        if not _any_transitive_ir(fn, _ir_is_delegatecall):
            continue
        reads_through_sload = _any_transitive_ir(fn, _ir_is_sload)
        try:
            reads = list(fn.all_state_variables_read())
        except Exception:  # pragma: no cover - slither edge
            continue
        for var in reads:
            name = getattr(var, "name", None)
            if not name or name in seen:
                continue
            type_name = str(getattr(var, "type", "")).strip()
            is_const = bool(getattr(var, "is_constant", False))
            if type_name in _ADDRESS_TYPES and not is_const:
                # Named address state var (inline or via a helper). Requires a
                # writer (the set*Impl half) and a sequential layout slot.
                if not _has_writer(contract, var):
                    continue
                so = layout.slot_offset(var)
                if so is None:
                    continue
                pointers.append({"name": str(name), "slot": so[0], "offset": so[1]})
                seen.add(name)
            elif is_const and type_name in _SLOT_CONST_TYPES and reads_through_sload:
                # Unstructured constant slot (EIP-1967-style): the fallback
                # sloads this constant and delegatecalls the result. The slot
                # IS the constant's value. Over-inclusive candidates are filtered
                # downstream by the has-code / not-the-primary-impl checks.
                slot_val = _const_slot_value(var)
                if slot_val is None:
                    continue
                pointers.append({"name": str(name), "slot": slot_val, "offset": 0})
                seen.add(name)
    return pointers
