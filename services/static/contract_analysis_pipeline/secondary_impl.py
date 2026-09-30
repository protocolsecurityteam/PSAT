"""Detect split-proxy secondary implementations: logic a proxy reaches beyond its EIP-1967 impl, via the primary
impl's fallback/receive delegatecalling an address in storage (an unstructured constant slot, as in ether.fi
LRTSquared, or a named address state variable). Otherwise the secondary is analysed alone and looks like an
ownerless orphan.

Returns ``{name, slot, offset}`` pointers into the proxy's storage (the getter is usually non-public), read downstream
in ``services/discovery/secondary_impl.py``. Keys on a real delegatecall operation (not variable names) and walks the
fallback transitively.
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
    """True iff ``ir`` is a delegatecall operation (assembly or ``addr.delegatecall``), not a ``.call`` or a variable
    named ``delegatecall*``.
    """
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
    """Whether any IR in ``fn`` or its internal/library callees satisfies ``pred`` (``fallback -> _delegate(impl)``)."""
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
    """Some non-constructor function writes ``var`` (the ``set*Impl`` half), excluding immutable forwarders."""
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
    """Folded int value of a slot constant (``keccak256("...")``, the EIP-1967 ``- 1`` form, or hex)."""
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
    """Lazy storage-layout reader for named-var pointers."""

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
    """Pointer descriptors for each secondary-impl slot a fallback/receive delegatecalls (usually none)."""
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
                # Named address var: needs a writer and a layout slot.
                if not _has_writer(contract, var):
                    continue
                so = layout.slot_offset(var)
                if so is None:
                    continue
                pointers.append({"name": str(name), "slot": so[0], "offset": so[1]})
                seen.add(name)
            elif is_const and type_name in _SLOT_CONST_TYPES and reads_through_sload:
                # The constant is the slot. Over-inclusive candidates are filtered downstream (has code, not the primary
                # impl).
                slot_val = _const_slot_value(var)
                if slot_val is None:
                    continue
                pointers.append({"name": str(name), "slot": slot_val, "offset": 0})
                seen.add(name)
    return pointers
