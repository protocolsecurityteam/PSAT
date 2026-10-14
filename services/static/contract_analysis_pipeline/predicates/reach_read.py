"""A branch condition as exact operations over storage and constants, for resolution to read whether it held at a
block.

The expression follows the same values ``reach.branch_reads`` checks against earlier writes: locals and temporaries
through their one definition, an inner frame's parameter through the argument its caller passed, an entry point's
parameter as calldata the caller chooses, and a call to one of the contract's own public views. Every conversion,
comparison and connective is kept as written, so an evaluation answers exactly what the condition computes; anything
else (arithmetic, member and index reads, reassigned parameters, calls that see the caller) makes the whole expression
unreadable.
"""

from __future__ import annotations

import re
from typing import Any

from eth_utils.crypto import keccak

from ..slither_compat import (
    Assignment,
    Binary,
    Constant,
    InternalCall,
    LibraryCall,
    SolidityVariable,
    StateVariable,
    TypeConversion,
    Unary,
    UnaryType,
    UserDefinedType,
)
from ._helpers import _binary_op
from .operands import _bytes32_constant_expression_value
from .reach import _definitions

_MAX_DEPTH = 24

_COMPARISONS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte"})

# What a call sees of the transaction or block rather than of storage; a view reading any of these answers
# differently for the read than for the real call, or changes with no transaction at all.
_CALL_CONTEXT = frozenset(
    {
        "msg.sender",
        "tx.origin",
        "msg.value",
        "msg.data",
        "msg.sig",
        "msg.gas",
        "gasleft()",
        "now",
        "block.timestamp",
        "block.number",
        "block.basefee",
        "block.blobbasefee",
        "block.prevrandao",
        "block.difficulty",
        "block.coinbase",
        "block.gaslimit",
        "blockhash(uint256)",
    }
)


def value_type(type_: Any) -> str | None:
    """The elementary type a value of ``type_`` is compared as, or ``None`` for anything else."""
    if isinstance(type_, UserDefinedType):
        declared = getattr(type_, "type", None)
        kind = type(declared).__name__
        if kind == "Contract":
            return "address"
        if kind in ("Enum", "EnumContract", "EnumTopLevel"):
            try:
                size = int(type_.storage_size[0])
            except Exception:
                return None
            return f"uint{8 * size}"
        return None
    text = str(type_)
    if text in ("bool", "address"):
        return text
    if text == "address payable":
        return "address"
    match = re.fullmatch(r"(u?int)(\d*)", text)
    if match:
        width = int(match.group(2) or 256)
        return f"{match.group(1)}{width}" if 8 <= width <= 256 and width % 8 == 0 else None
    match = re.fullmatch(r"bytes(\d+)", text)
    if match and 1 <= int(match.group(1)) <= 32:
        return text
    return None


def reach_read(condition: Any, entry: Any, chain: list[Any]) -> dict[str, Any] | None:
    """``condition``, evaluated in the frame ``chain`` leads into from ``entry``, as a read recipe."""
    frames = [entry, *(getattr(call, "function", None) for call in chain)]
    contract = getattr(entry, "contract", None)
    if contract is None or any(frame is None for frame in frames):
        return None
    return _expression(condition, len(chain), frames, chain, contract, 0)


def _expression(
    value: Any, level: int, frames: list[Any], chain: list[Any], contract: Any, depth: int
) -> dict[str, Any] | None:
    if depth > _MAX_DEPTH or value is None:
        return None
    value = getattr(value, "non_ssa_version", None) or value
    if isinstance(value, Constant):
        return _constant(value)
    if isinstance(value, SolidityVariable):
        name = getattr(value, "name", None)
        if name == "this":
            return {"op": "self", "type": "address"}
        return {"op": "chainid", "type": "uint256"} if name == "block.chainid" else None
    if isinstance(value, StateVariable):
        return _storage(value, contract)
    function = frames[level]
    parameters = list(getattr(function, "parameters", None) or [])
    definitions = _definitions(function).get(str(value), [])
    if value in parameters:
        # A reassigned parameter no longer holds what was passed in.
        if definitions:
            return None
        index = parameters.index(value)
        if not level:
            return _calldata(value, index, function)
        arguments = list(getattr(chain[level - 1], "arguments", None) or [])
        if index >= len(arguments):
            return None
        return _expression(arguments[index], level - 1, frames, chain, contract, depth + 1)
    if len(definitions) != 1:
        return None
    ir = definitions[0]

    def operand(inner: Any) -> dict[str, Any] | None:
        return _expression(inner, level, frames, chain, contract, depth + 1)

    if isinstance(ir, Assignment):
        return operand(ir.rvalue)
    if isinstance(ir, TypeConversion):
        target = value_type(ir.type)
        inner = operand(ir.variable)
        return {"op": "convert", "type": target, "value": inner} if target and inner else None
    if isinstance(ir, Unary):
        inner = operand(ir.rvalue)
        return {"op": "not", "type": "bool", "value": inner} if ir.type == UnaryType.BANG and inner else None
    if isinstance(ir, Binary):
        op = _binary_op(getattr(ir, "type", None))
        if op not in _COMPARISONS and op not in ("and", "or"):
            return None
        left, right = operand(ir.variable_left), operand(ir.variable_right)
        if left is None or right is None:
            return None
        return {"op": op, "type": "bool", "left": left, "right": right}
    if isinstance(ir, InternalCall) and not isinstance(ir, LibraryCall):
        return _view_call(ir, contract, operand)
    return None


def _calldata(parameter: Any, index: int, function: Any) -> dict[str, Any] | None:
    """An entry point's parameter: whatever the caller passes."""
    type_ = value_type(getattr(parameter, "type", None))
    if type_ is None or getattr(function, "visibility", None) not in ("public", "external"):
        return None
    return {"op": "param", "type": type_, "index": index, "name": getattr(parameter, "name", None) or str(index)}


def _constant(value: Any) -> dict[str, Any] | None:
    type_ = value_type(getattr(value, "type", None))
    raw = getattr(value, "value", None)
    if type_ is None:
        return None
    if isinstance(raw, bool):
        number = int(raw)
    elif isinstance(raw, int):
        number = raw
    else:
        try:
            number = int(str(raw), 0)
        except ValueError:
            return None
    # A literal takes the type of what it's compared with; Slither's type for it is a guess.
    return {"op": "const", "type": type_, "value": str(number), "literal": True}


def _storage(variable: Any, contract: Any) -> dict[str, Any] | None:
    type_ = value_type(getattr(variable, "type", None))
    if type_ is None or getattr(variable, "is_transient", False):
        return None
    out: dict[str, Any] = {"op": "storage", "type": type_, "variable": variable.name}
    if getattr(variable, "is_constant", False):
        literal = _constant_value(variable, type_)
        if literal is not None:
            return {"op": "const", "type": type_, "value": str(literal)}
    elif not getattr(variable, "is_immutable", False):
        layout = _layout(contract, variable)
        if layout is not None:
            out.update(layout)
    if getattr(variable, "visibility", None) == "public":
        out["getter"] = "0x" + keccak(text=f"{variable.name}()").hex()[:8]
    return out if "getter" in out or "slot" in out else None


def _constant_value(variable: Any, type_: str) -> int | None:
    expression = getattr(variable, "expression", None)
    if type_ == "bytes32":
        word = _bytes32_constant_expression_value(expression)
        return int(word, 16) if isinstance(word, str) else None
    literal = getattr(expression, "value", None)
    if type_.startswith(("uint", "int")) and isinstance(literal, (int, str)) and not isinstance(literal, bool):
        try:
            return int(str(literal), 0)
        except ValueError:
            return None
    return None


def _layout(contract: Any, variable: Any) -> dict[str, Any] | None:
    unit = getattr(contract, "compilation_unit", None)
    try:
        slot, offset = unit.storage_layout_of(contract, variable)  # pyright: ignore[reportOptionalMemberAccess]
        size = int(variable.type.storage_size[0])
    except Exception:
        return None
    return {"slot": "0x" + format(int(slot), "064x"), "offset": int(offset), "size": size}


def _view_call(ir: Any, contract: Any, operand: Any) -> dict[str, Any] | None:
    """A call to a view of this contract that an ``eth_call`` to its selector reaches, and that reads nothing of the
    transaction, so the call's answer at a block is the condition's.
    """
    callee = getattr(ir, "function", None)
    if callee is None or type(callee).__name__.startswith("Modifier"):
        return None
    if getattr(callee, "visibility", None) not in ("public", "external"):
        return None
    if not (getattr(callee, "view", False) or getattr(callee, "pure", False)):
        return None
    signature = getattr(callee, "solidity_signature", None)
    dispatched = contract.get_function_from_signature(signature) if isinstance(signature, str) else None
    if dispatched is None or getattr(dispatched, "canonical_name", None) != getattr(callee, "canonical_name", None):
        return None
    try:
        read = {str(variable) for variable in callee.all_solidity_variables_read()}
        read |= {str(getattr(getattr(call, "function", None), "name", None)) for call in callee.all_solidity_calls()}
    except Exception:
        return None
    if read & _CALL_CONTEXT:
        return None
    returns = list(getattr(callee, "return_type", None) or [])
    if len(returns) != 1:
        return None
    type_ = value_type(returns[0])
    arguments = [operand(argument) for argument in getattr(ir, "arguments", None) or []]
    if type_ is None or any(argument is None for argument in arguments):
        return None
    if [value_type(getattr(p, "type", None)) for p in callee.parameters] != [a["type"] for a in arguments]:
        return None
    selector = "0x" + keccak(text=signature).hex()[:8]
    return {"op": "call", "type": type_, "selector": selector, "signature": signature, "arguments": arguments}
