"""Shared IR identities, call frames, guard normalization and control-flow primitives.

These operate on declarations and IR values, never contract or helper names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .revert_detect import RevertDetector
from .slither_compat import Assignment, Binary, Condition, Constant, Return, SolidityCall, StateVariable, TypeConversion


@dataclass
class Frame:
    function: Any
    bindings: dict
    chain: tuple = ()
    positive: tuple = ()
    parent: Frame | None = None
    arguments: tuple = ()
    return_checked: bool = False


def base(value: Any) -> Any:
    return getattr(value, "non_ssa_version", value)


def same(a: Any, b: Any) -> bool:
    return base(a) is base(b)


def operations(fn: Any) -> list[tuple[Any, Any]]:
    return [(node, ir) for node in fn.nodes for ir in node.irs]


def definition(value: Any, fn: Any) -> Any:
    found = [ir for _, ir in operations(fn) if getattr(ir, "lvalue", None) is value]
    return found[0] if len(found) == 1 else None


def integer(value: Any, fn: Any, seen: tuple[int, ...] = ()) -> int | None:
    if id(value) in seen:
        return None
    if isinstance(value, Constant):
        if isinstance(value.value, bool):
            return int(value.value)
        try:
            return int(str(value.value), 0)
        except ValueError:
            return None
    if isinstance(value, StateVariable) and value.is_constant:
        expr = value.expression
        # Slither expression literals are separate from SlithIR Constants. Peel exact conversion syntax rather than
        # interpreting arbitrary source text as a number.
        literal = getattr(expr, "expression", None)
        raw = getattr(literal, "value", None)
        if raw is None:
            match = re.fullmatch(r"(?:address|uint\d*)\((0x[0-9a-fA-F]+|\d+)\)", str(expr))
            raw = match.group(1) if match else None
        try:
            return int(str(getattr(expr, "converted_value", None) or getattr(expr, "value", None) or raw), 0)
        except (TypeError, ValueError):
            return None
    ir = definition(value, fn)
    if isinstance(ir, TypeConversion):
        return integer(ir.variable, fn, (*seen, id(value)))
    if isinstance(ir, Assignment):
        return integer(ir.rvalue, fn, (*seen, id(value)))
    return None


def unwrap(value: Any, fn: Any, seen: tuple[int, ...] = ()) -> Any:
    if id(value) in seen:
        return value
    ir = definition(value, fn)
    if isinstance(ir, TypeConversion):
        return unwrap(ir.variable, fn, (*seen, id(value)))
    if isinstance(ir, Assignment):
        return unwrap(ir.rvalue, fn, (*seen, id(value)))
    return value


def relation(ir: Any) -> str:
    return getattr(getattr(ir, "type", None), "name", "")


def conjuncts(value, fn):
    ir = definition(value, fn)
    if isinstance(ir, Binary) and relation(ir) == "ANDAND":
        return conjuncts(ir.variable_left, fn) + conjuncts(ir.variable_right, fn)
    return [ir] if ir is not None else []


def guards(fn):
    out = []
    for gate in RevertDetector(fn).run():
        condition = None
        for ir in gate.node.irs:
            if isinstance(ir, SolidityCall) and ir.function.name.startswith(("require(", "assert(")):
                condition = ir.arguments[0]
                break
            if isinstance(ir, Condition):
                condition = ir.value
        if condition is not None:
            out.append((gate.node, condition, gate.polarity))
    return out


_INVERTED_RELATION = {
    "EQUAL": "NOT_EQUAL",
    "NOT_EQUAL": "EQUAL",
    "GREATER": "LESS_EQUAL",
    "GREATER_EQUAL": "LESS",
    "LESS": "GREATER_EQUAL",
    "LESS_EQUAL": "GREATER",
}


def mandatory_atoms(value, fn, polarity):
    """Atomic conjuncts of the allowed condition; None where normalization would create alternatives."""
    ir = definition(value, fn)
    if not isinstance(ir, Binary):
        return [(ir, None)] if ir is not None else []
    op = relation(ir)
    if (polarity == "allowed_when_true" and op == "ANDAND") or (polarity == "allowed_when_false" and op == "OROR"):
        left = mandatory_atoms(ir.variable_left, fn, polarity)
        right = mandatory_atoms(ir.variable_right, fn, polarity)
        return left + right if left is not None and right is not None else None
    if op in ("ANDAND", "OROR"):
        return None
    return [(ir, _INVERTED_RELATION.get(op, op) if polarity == "allowed_when_false" else op)]


def slot(contract, var):
    try:
        index, offset = contract.compilation_unit.storage_layout_of(contract, var)
        typ = str(var.type)
        size = int(typ.removeprefix("uint")) // 8 if typ.startswith("uint") and typ[4:].isdigit() else 32
        return {"slot": hex(index), "byte_offset": offset, "size_bytes": size, "variable": var.name}
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def scalar(value, frame, seen=()):
    """The storage/constant/caller parameter a threshold reads, including bound helper formals."""
    if id(value) in seen:
        return None
    if str(value) == "msg.sender":
        return {"kind": "caller"}
    if isinstance(value, StateVariable) and not value.is_constant:
        return {"kind": "storage", "variable_object": value}
    literal = integer(value, frame.function)
    if literal is not None:
        return {"kind": "constant", "value": literal}
    for parameter in frame.function.parameters:
        if same(parameter, value):
            return frame.bindings.get(parameter.name)
    ir = definition(value, frame.function)
    if isinstance(ir, Assignment):
        return scalar(ir.rvalue, frame, (*seen, id(value)))
    if isinstance(ir, TypeConversion):
        return scalar(ir.variable, frame, (*seen, id(value)))
    return None


def scalar_key(item):
    if item is None:
        return None
    return item.get("kind"), id(item.get("variable_object")) if item.get("kind") == "storage" else item.get(
        "value", item.get("index")
    )


def exits(fn):
    return [n for n in fn.nodes if not n.sons or any(isinstance(ir, Return) for ir in n.irs)]


def mandatory(node, fn):
    return bool(exits(fn)) and all(node in n.dominators for n in exits(fn))


def loop_region(header):
    todo = [header.son_true]
    seen = set()
    while todo:
        node = todo.pop()
        if node is None or node is header or node in seen or getattr(node.type, "name", "") == "ENDLOOP":
            continue
        seen.add(node)
        todo.extend(node.sons)
    return seen


def _boolean_value(value, function, false_value, seen=()):
    """Evaluate only what is forced when one call result is false; unrelated values remain unknown."""
    if same(value, false_value):
        return False
    if id(value) in seen:
        return None
    if isinstance(value, Constant) and isinstance(value.value, bool):
        return value.value
    ir = definition(value, function)
    nxt = (*seen, id(value))
    if isinstance(ir, Assignment):
        return _boolean_value(getattr(ir, "rvalue", None), function, false_value, nxt)
    if isinstance(ir, Binary):
        left = _boolean_value(ir.variable_left, function, false_value, nxt)
        right = _boolean_value(ir.variable_right, function, false_value, nxt)
        op = relation(ir)
        if op == "ANDAND":
            return False if left is False or right is False else True if left is True and right is True else None
        if op == "OROR":
            return True if left is True or right is True else False if left is False and right is False else None
        if left is not None and right is not None and op in ("EQUAL", "NOT_EQUAL"):
            return (left == right) if op == "EQUAL" else (left != right)
    if type(ir).__name__ == "Unary" and getattr(ir.type, "name", "") == "BANG":
        result = _boolean_value(getattr(ir, "rvalue", None), function, false_value, nxt)
        return not result if result is not None else None
    return None


def call_result_required_true(call, function, required_return=False):
    result = getattr(call, "lvalue", None)
    if result is None:
        return False
    if required_return:
        returns = [value for _, ir in operations(function) if isinstance(ir, Return) for value in ir.values]
        if returns and all(_boolean_value(value, function, result) is False for value in returns):
            return True
    for node, value, polarity in guards(function):
        if not mandatory(node, function):
            continue
        forced = _boolean_value(value, function, result)
        if forced is not None and forced != (polarity == "allowed_when_true"):
            return True
    return False


def frame_guards(frame):
    out = guards(frame.function)
    if not frame.return_checked:
        return out
    for node in frame.function.nodes:
        if getattr(node.type, "name", "") != "IF":
            continue
        condition = next((ir.value for ir in node.irs if isinstance(ir, Condition)), None)
        if condition is None:
            continue
        for branch, polarity in ((node.son_true, "allowed_when_false"), (node.son_false, "allowed_when_true")):
            # A direct false return is a failure only when the caller requires a true result.
            if branch is None:
                continue
            values = [v for ir in branch.irs if isinstance(ir, Return) for v in ir.values]
            if len(values) == 1 and isinstance(values[0], Constant) and values[0].value is False:
                out.append((node, condition, polarity))
    return out


def denied_return(node, frame):
    return frame.return_checked and any(
        isinstance(ir, Return)
        and len(ir.values) == 1
        and isinstance(ir.values[0], Constant)
        and ir.values[0].value is False
        for ir in node.irs
    )
