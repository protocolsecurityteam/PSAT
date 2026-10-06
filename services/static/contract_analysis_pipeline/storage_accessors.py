"""Prove that a nullary address getter returns the low 160 bits of one constant slot."""

from __future__ import annotations

import re
from typing import Any

from .slither_compat import Assignment, Constant, InternalCall, LibraryCall, Return, SolidityCall, TypeConversion


def _name(value: Any) -> str:
    return str(getattr(getattr(value, "non_ssa_version", value), "name", ""))


def _irs(function: Any) -> list[Any]:
    return [ir for node in getattr(function, "nodes", []) for ir in (getattr(node, "irs_ssa", None) or node.irs)]


def _definition(value: Any, function: Any) -> Any:
    name = getattr(value, "name", None)
    matches = [ir for ir in _irs(function) if getattr(getattr(ir, "lvalue", None), "name", None) == name]
    return matches[0] if name and len(matches) == 1 else None


def _constant(value: Any, function: Any, bindings: dict[str, int], depth: int = 0) -> int | None:
    if depth > 8:
        return None
    if _name(value) in bindings:
        return bindings[_name(value)]
    if isinstance(value, Constant):
        try:
            return int(str(value.value), 0)
        except ValueError:
            return None
    var = getattr(value, "non_ssa_version", value)
    if getattr(var, "is_constant", False):
        from .secondary_impl import _const_slot_value

        return _const_slot_value(var)
    ir = _definition(value, function)
    if isinstance(ir, Assignment):
        return _constant(ir.rvalue, function, bindings, depth + 1)
    if isinstance(ir, TypeConversion):
        result = _constant(ir.variable, function, bindings, depth + 1)
        if result is None or result < 0:
            return None
        if str(ir.type) in ("address", "address payable"):
            return result if result < 2**160 else None
        integer = re.fullmatch(r"(u?)int(\d*)", str(ir.type))
        if integer:
            bits = int(integer[2] or "256") - (0 if integer[1] else 1)
            return result if result < 2**bits else None
        # Fixed bytes widening can shift the value; only a full word is safe here.
        if str(ir.type) == "bytes32" and str(getattr(ir.variable, "type", "")) in {"uint256", "bytes32"}:
            return result if result < 2**256 else None
    return None


def _return_slot(function: Any, bindings: dict[str, int], seen: frozenset[int]) -> int | None:
    if id(function) in seen or len(seen) >= 8:
        return None
    returns = [ir for ir in _irs(function) if isinstance(ir, Return)]
    if len(returns) != 1 or len(returns[0].values) != 1:
        return None
    value = returns[0].values[0]
    visited: set[int] = set()
    while value is not None and id(value) not in visited:
        visited.add(id(value))
        ir = _definition(value, function)
        if isinstance(ir, (Assignment, TypeConversion)):
            if isinstance(ir, TypeConversion) and not _preserves_address_bits(ir.type):
                return None
            value = getattr(ir, "rvalue", getattr(ir, "variable", None))
            continue
        if isinstance(ir, SolidityCall) and str(ir.function.name).startswith("sload("):
            return _constant(ir.arguments[0], function, bindings)
        if isinstance(ir, (InternalCall, LibraryCall)):
            callee: Any = ir.function
            if not getattr(callee, "parameters", None):
                return _return_slot(callee, {}, seen | {id(function)})
            bound = {}
            for parameter, argument in zip(callee.parameters, ir.arguments):
                constant = _constant(argument, function, bindings)
                if constant is not None:
                    bound[_name(parameter)] = constant
            return _return_slot(callee, bound, seen | {id(function)})
        # Legacy solc ASTs expose this straight-line Yul only as text, not SlithIR.
        assembly = [n for n in function.nodes if getattr(n, "inline_asm", None)]
        straight_line_legacy = all(
            str(node.type) in {"NodeType.ENTRYPOINT", "NodeType.ASSEMBLY", "NodeType.ENDASSEMBLY", "NodeType.RETURN"}
            for node in function.nodes
        )
        if ir is None and len(assembly) == 1 and straight_line_legacy:
            text = str(assembly[0].inline_asm)
            match = re.fullmatch(r"\s*\{\s*([A-Za-z_]\w*)\s*:=\s*sload\(\s*([A-Za-z_]\w*)\s*\)\s*\}\s*", text)
            if match and match[1] == _name(value) and match[2] in bindings:
                return bindings[match[2]]
        return None
    return None


def _preserves_address_bits(target_type: Any) -> bool:
    from .internal_authority_slot import _is_address_like_type

    if _is_address_like_type(target_type):
        return True
    integer = re.fullmatch(r"u?int(\d*)", str(target_type))
    return integer is not None and int(integer[1] or "256") >= 160


def constant_address_slot(function: Any) -> str | None:
    from .internal_authority_slot import _is_address_like_type

    if function is None or getattr(function, "parameters", None):
        return None
    if not (getattr(function, "view", False) or getattr(function, "pure", False)):
        return None
    returns = getattr(function, "return_type", None)
    if not returns or len(returns) != 1 or not _is_address_like_type(returns[0]):
        return None
    if function.all_solidity_variables_read():
        return None
    slot = _return_slot(function, {}, frozenset())
    return "0x" + format(slot, "064x") if slot is not None and 0 <= slot < 2**256 else None
