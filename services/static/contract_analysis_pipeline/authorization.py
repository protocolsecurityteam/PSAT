"""Source-derived signer quorum and membership inventories, independent of contract names and versions.

A quorum is credited only when its counted loop validates membership and strict signer ordering on every iteration,
and every definition of the signer is recovered or explicitly authorized before that check. Unsupported shapes retain
uncertainty. Storage/getter facts describe the registry the code actually consults, never a familiar ABI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .predicate_types import PredicateTree, make_and_node
from .revert_detect import RevertDetector
from .slither_compat import (
    Assignment,
    Binary,
    Condition,
    Constant,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    Return,
    SolidityCall,
    StateVariable,
    TypeConversion,
)


@dataclass
class Frame:
    function: Any
    bindings: dict
    chain: tuple = ()
    positive: tuple = ()


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
        return mandatory_atoms(ir.variable_left, fn, polarity) + mandatory_atoms(ir.variable_right, fn, polarity)
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


def payload_parameters(value, fn, bindings, seen=(), depth=0):
    """Parameters injectively included by ABI encoding / hashing, not arbitrary arithmetic taint.

    An opaque extra field cannot remove a separately encoded parameter. Packed encodings with multiple dynamic
    fields are refused; a dependency passing through arithmetic is not a binding witness.
    """
    # Real typed-data builders commonly cross entry assignment -> helper -> return assignment -> packed envelope ->
    # hash -> inner ABI encoding -> field hash. The limit bounds recursion without truncating that ordinary shape.
    if depth > 12 or id(value) in seen:
        return set()
    for p in fn.parameters:
        if same(value, p):
            return set(bindings.get(p.name, set()))
    ir = definition(value, fn)
    nxt = (*seen, id(value))
    if isinstance(ir, Assignment):
        return payload_parameters(ir.rvalue, fn, bindings, nxt, depth + 1)
    if isinstance(ir, TypeConversion):
        # Narrowing casts discard bits and cannot commit the original parameter.
        old, new = str(getattr(ir.variable, "type", "")), str(ir.type)
        if old.startswith("uint") and new.startswith("uint"):
            try:
                if int(new[4:]) < int(old[4:]):
                    return set()
            except ValueError:
                return set()
        return payload_parameters(ir.variable, fn, bindings, nxt, depth + 1)
    if isinstance(ir, SolidityCall) and ir.function.name.startswith(("abi.encode", "keccak256(")):
        if ir.function.name.startswith("abi.encodePacked"):
            dynamic = sum(
                str(getattr(a, "type", "")) in ("bytes", "string") or "[]" in str(getattr(a, "type", ""))
                for a in ir.arguments
            )
            if dynamic > 1:
                return set()
        return set().union(*(payload_parameters(a, fn, bindings, nxt, depth + 1) for a in ir.arguments))
    if isinstance(ir, (InternalCall, LibraryCall)):
        callee: Any = ir.function
        if callee is None:
            return set()
        returns = [x for _, x in operations(callee) if isinstance(x, Return)]
        if len(returns) != 1 or len(returns[0].values) != 1:
            return set()
        bound = {
            p.name: payload_parameters(a, fn, bindings, nxt, depth + 1) for p, a in zip(callee.parameters, ir.arguments)
        }
        resolved = payload_parameters(returns[0].values[0], callee, bound, (), depth + 1)
        return resolved or _assembly_hash_parameters(returns[0].values[0], callee, bound)
    return set()


def _memory_offset(value, fn, seen=()):
    if id(value) in seen:
        return None
    ir = definition(value, fn)
    nxt = (*seen, id(value))
    if isinstance(ir, Assignment):
        return _memory_offset(ir.rvalue, fn, nxt)
    if isinstance(ir, SolidityCall) and ir.function.name.startswith("mload("):
        if len(ir.arguments) == 1 and integer(ir.arguments[0], fn) == 64:
            return id(ir), 0
    if isinstance(ir, Binary) and relation(ir) == "ADDITION":
        for pointer, delta in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
            base_pointer = _memory_offset(pointer, fn, nxt)
            amount = integer(delta, fn)
            if base_pointer is not None and amount is not None:
                return base_pointer[0], base_pointer[1] + amount
    return None


def _assembly_hash_parameters(value, fn, bindings, seen=()):
    """Parameters stored into a memory range that is subsequently hashed and returned.

    This is deliberately narrower than assembly taint: one free-memory root, constant offsets/lengths, mstore or
    calldatacopy writes inside the hashed interval, and a returned keccak. Unknown pointer arithmetic yields no proof.
    """
    if id(value) in seen:
        return set()
    unwrapped = unwrap(value, fn)
    call = definition(unwrapped, fn)
    if not isinstance(call, SolidityCall) or not call.function.name.startswith("keccak256("):
        return set()
    if len(call.arguments) != 2:
        return set()
    window = _memory_offset(call.arguments[0], fn)
    length = integer(call.arguments[1], fn)
    if window is None or length is None or length <= 0:
        return set()
    root, start = window
    end = start + length
    found = set()
    for _, write in operations(fn):
        if not isinstance(write, SolidityCall) or not write.arguments:
            continue
        name = write.function.name
        location = _memory_offset(write.arguments[0], fn)
        if location is None or location[0] != root or not start <= location[1] < end:
            continue
        if name.startswith("mstore(") and len(write.arguments) == 2:
            stored = write.arguments[1]
            found |= payload_parameters(stored, fn, bindings)
            found |= _assembly_hash_parameters(stored, fn, bindings, (*seen, id(value)))
        elif name.startswith("calldatacopy("):
            for argument in write.arguments[1:]:
                found |= payload_parameters(argument, fn, bindings)
    return found


def inventory(contract, registry):
    """A source-witnessed linked-list traversal; the runtime reader follows the same map to its sentinel.

    A mapping(address => address) by itself is not a list. Require a loop whose cursor starts at a constant head and
    advances through this mapping until that same head, as in enumerable registries of several unrelated standards.
    """
    if str(registry.type) != "mapping(address => address)":
        return None
    layout = slot(contract, registry)
    if layout is None:
        return None
    for fn in contract.functions:
        ops = operations(fn)
        for header, test in ops:
            if (
                getattr(header.type, "name", "") != "IFLOOP"
                or not isinstance(test, Binary)
                or relation(test) != "NOT_EQUAL"
            ):
                continue
            sentinel = integer(test.variable_right, fn)
            if sentinel is None or sentinel <= 0:
                continue
            cursor = test.variable_left
            indexed = [(n, ir) for n, ir in ops if isinstance(ir, Index) and same(ir.variable_left, registry)]
            initial = [
                (n, ir) for n, ir in indexed if integer(ir.variable_right, fn) == sentinel and n in header.dominators
            ]
            advance = [(n, ir) for n, ir in indexed if same(ir.variable_right, cursor) and n in loop_region(header)]
            if not advance:
                continue
            if initial:
                if not any(
                    isinstance(ir, Assignment) and same(ir.lvalue, cursor) and ir.rvalue is initial[0][1].lvalue
                    for _, ir in ops
                ):
                    continue
            else:
                # Pagination-style traversal: a parameter selects the first predecessor, but the loop proves the same
                # linked-map successor relation and sentinel termination. Require the public entry to admit the
                # sentinel as a start, plus an initialization write sentinel -> sentinel, before treating the whole
                # mapping as enumerable from that head.
                parameter_reads = [
                    (n, ir)
                    for n, ir in indexed
                    if any(same(ir.variable_right, parameter) for parameter in fn.parameters) and n in header.dominators
                ]
                initialized = any(
                    integer(ix.variable_right, writer) == sentinel
                    and any(
                        isinstance(write, Assignment)
                        and write.lvalue is ix.lvalue
                        and integer(write.rvalue, writer) == sentinel
                        for _, write in operations(writer)
                    )
                    for writer in contract.functions
                    for _, ix in operations(writer)
                    if isinstance(ix, Index) and same(ix.variable_left, registry)
                )
                if not parameter_reads or not initialized:
                    continue
                if not any(
                    isinstance(ir, Assignment) and same(ir.lvalue, cursor) and ir.rvalue is parameter_reads[0][1].lvalue
                    for _, ir in ops
                ):
                    continue
            if not any(
                isinstance(ir, Assignment) and same(ir.lvalue, cursor) and ir.rvalue is advance[0][1].lvalue
                for _, ir in ops
            ):
                continue
            return {"kind": "linked_list", **layout, "sentinel": hex(sentinel), "traversal_function": fn.full_name}
    return None


def _parameter_index(value, fn):
    return next((index for index, parameter in enumerate(fn.parameters) if same(value, parameter)), None)


def _value_is_bound_to_payload(value, payload, fn, before_node):
    if same(unwrap(value, fn), payload):
        return True
    value_index = _parameter_index(unwrap(value, fn), fn)
    if value_index is None:
        return False
    identity = {parameter.name: {index} for index, parameter in enumerate(fn.parameters)}
    for guard, condition, polarity in guards(fn):
        if guard not in before_node.dominators:
            continue
        for check, normalized in mandatory_atoms(condition, fn, polarity) or []:
            if not isinstance(check, Binary) or normalized != "EQUAL":
                continue
            for encoded, claimed in (
                (check.variable_left, check.variable_right),
                (check.variable_right, check.variable_left),
            ):
                if same(unwrap(claimed, fn), payload) and value_index in payload_parameters(encoded, fn, identity):
                    return True
    return False


def _index_chain(value, fn):
    chain = []
    current = next((ir for _, ir in operations(fn) if isinstance(ir, Index) and ir.lvalue is value), None)
    while isinstance(current, Index):
        chain.append(current)
        current = next(
            (ir for _, ir in operations(fn) if isinstance(ir, Index) and ir.lvalue is current.variable_left), None
        )
    return chain


def _writer_is_signer_gated(writer, signer_registry, write_node):
    for guard, condition, polarity in guards(writer):
        if guard not in write_node.dominators:
            continue
        for test, normalized in mandatory_atoms(condition, writer, polarity) or []:
            if not isinstance(test, Binary) or normalized != "NOT_EQUAL":
                continue
            for read_value, zero in (
                (test.variable_left, test.variable_right),
                (test.variable_right, test.variable_left),
            ):
                read = definition(read_value, writer)
                if (
                    isinstance(read, Index)
                    and same(read.variable_left, signer_registry)
                    and str(unwrap(read.variable_right, writer)) == "msg.sender"
                    and integer(zero, writer) == 0
                ):
                    return True
    return False


def _approval_registry_is_self_service(registry, signer_registry, contract):
    found = False
    for writer in contract.functions:
        for node, write in operations(writer):
            if not isinstance(write, Assignment):
                continue
            chain = _index_chain(write.lvalue, writer)
            if not chain or not same(chain[-1].variable_left, registry):
                continue
            found = True
            # Outer key is the approving identity. Only that identity may write, and it must already be a member of
            # the signer registry; otherwise a public caller could manufacture an authorization.
            if str(unwrap(chain[-1].variable_right, writer)) != "msg.sender":
                return False
            if not _writer_is_signer_gated(writer, signer_registry, node):
                return False
    return found


def _is_caller(value, frame):
    resolved = scalar(unwrap(value, frame.function), frame)
    return resolved is not None and resolved.get("kind") == "caller"


def approves(condition, signer, frame, payload, signer_registry, guard_node, polarity="allowed_when_true"):
    """A mandatory accepted-identity check on a raw signer definition, not a verifier's name."""
    fn = frame.function
    ir = definition(condition, fn)
    if not isinstance(ir, Binary):
        return None
    op = relation(ir)
    if op in ("OROR", "ANDAND"):
        left = approves(ir.variable_left, signer, frame, payload, signer_registry, guard_node, polarity)
        right = approves(ir.variable_right, signer, frame, payload, signer_registry, guard_node, polarity)
        alternatives = (op == "OROR") == (polarity == "allowed_when_true")
        if alternatives:
            return (left or set()) | (right or set()) if left and right else None
        return left or right
    op = _INVERTED_RELATION.get(op, op) if polarity == "allowed_when_false" else op
    if op == "EQUAL":
        left, right = unwrap(ir.variable_left, fn), unwrap(ir.variable_right, fn)
        if (_is_caller(left, frame) and same(right, signer)) or (_is_caller(right, frame) and same(left, signer)):
            return {"caller"}
        for call_value, constant in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
            call = definition(call_value, fn)
            if (
                isinstance(call, HighLevelCall)
                and same(unwrap(call.destination, fn), signer)
                and integer(constant, fn) is not None
            ):
                # Delegated approval is not assumed cryptographic; contract owners remain indeterminate at resolution.
                if any(_value_is_bound_to_payload(a, payload, fn, guard_node) for a in call.arguments):
                    return {"external"}
    if op == "NOT_EQUAL":
        for indexed, constant in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
            inner = definition(indexed, fn)
            if not isinstance(inner, Index) or integer(constant, fn) != 0 or not same(inner.variable_right, payload):
                continue
            outer = definition(inner.variable_left, fn)
            if (
                not isinstance(outer, Index)
                or not same(outer.variable_right, signer)
                or not isinstance(outer.variable_left, StateVariable)
            ):
                continue
            registry = outer.variable_left
            if _approval_registry_is_self_service(registry, signer_registry, fn.contract):
                return {"approval_hash"}
    return None


def authenticated_paths(start, stop, signer, frame, payload, signer_registry, region):
    fn = frame.function
    todo = [(start, False)]
    seen = set()
    modes = set()
    guard_nodes = set()
    requirements = {node: (condition, polarity) for node, condition, polarity in guards(fn)}
    while todo:
        node, accepted = todo.pop()
        if (node, accepted) in seen:
            continue
        seen.add((node, accepted))
        if node is stop:
            if not accepted:
                return None
            continue
        if node not in region:
            return None
        check = requirements.get(node)
        kinds = (
            approves(check[0], signer, frame, payload, signer_registry, node, check[1]) if check is not None else None
        )
        for ir in node.irs:
            if isinstance(ir, (InternalCall, LibraryCall)):
                kinds = kinds or _internal_authentication(ir, signer, frame, payload, signer_registry)
        if kinds:
            accepted = True
            modes |= kinds
            guard_nodes.add(node.node_id)
        if not node.sons:
            return None
        todo.extend((son, accepted) for son in node.sons)
    return modes, guard_nodes


def _internal_authentication(call, signer, frame, payload, signer_registry):
    callee = call.function
    if callee is None or not getattr(callee, "nodes", None):
        return None
    signer_index = next(
        (index for index, argument in enumerate(call.arguments) if same(unwrap(argument, frame.function), signer)),
        None,
    )
    payload_index = next(
        (index for index, argument in enumerate(call.arguments) if same(unwrap(argument, frame.function), payload)),
        None,
    )
    if signer_index is None or payload_index is None:
        return None
    child = Frame(
        callee,
        {parameter.name: scalar(argument, frame) for parameter, argument in zip(callee.parameters, call.arguments)},
        (*frame.chain, frame.function),
        frame.positive,
    )
    child_signer = callee.parameters[signer_index]
    child_payload = callee.parameters[payload_index]
    modes = set()
    for guard, condition, polarity in guards(callee):
        if not mandatory(guard, callee):
            continue
        witnessed = approves(condition, child_signer, child, child_payload, signer_registry, guard, polarity)
        if witnessed:
            modes |= witnessed
    return modes or None


def loop_witness(frame, contract, parameter_bindings):
    fn = frame.function
    ops = operations(fn)
    for header, cond in ops:
        if getattr(header.type, "name", "") != "IFLOOP" or not isinstance(cond, Binary) or relation(cond) != "LESS":
            continue
        counter, bound = cond.variable_left, cond.variable_right
        threshold = scalar(bound, frame)
        if threshold is None:
            continue
        positive = set(frame.positive)
        for positive_guard, positive_condition, positive_polarity in guards(fn):
            if positive_guard not in header.dominators:
                continue
            for test, normalized in mandatory_atoms(positive_condition, fn, positive_polarity) or []:
                if (
                    isinstance(test, Binary)
                    and normalized in ("GREATER", "NOT_EQUAL")
                    and integer(test.variable_right, fn) == 0
                    and str(getattr(test.variable_left, "type", "")).startswith("uint")
                ):
                    positive.add(scalar_key(scalar(test.variable_left, frame)))
        region = loop_region(header)
        updates = [(n, ir) for n, ir in ops if isinstance(ir, Binary) and same(ir.lvalue, counter) and n in region]
        if (
            len(updates) != 1
            or relation(updates[0][1]) != "ADDITION"
            or not same(updates[0][1].variable_left, counter)
            or integer(updates[0][1].variable_right, fn) != 1
        ):
            continue
        increment = updates[0][0]
        if not any(
            isinstance(ir, Assignment)
            and same(ir.lvalue, counter)
            and integer(ir.rvalue, fn) == 0
            and n in header.dominators
            for n, ir in ops
        ):
            continue
        for guard, value, polarity in guards(fn):
            if guard not in region or guard not in increment.dominators:
                continue
            parts = mandatory_atoms(value, fn, polarity)
            for comparison, comparison_op in parts or []:
                if not isinstance(comparison, Binary) or comparison_op != "NOT_EQUAL":
                    continue
                read = definition(comparison.variable_left, fn)
                if (
                    not isinstance(read, Index)
                    or integer(comparison.variable_right, fn) != 0
                    or not isinstance(read.variable_left, StateVariable)
                ):
                    continue
                registry, signer = read.variable_left, read.variable_right
                enumerator = inventory(contract, registry)
                if enumerator is None:
                    continue
                ordering = next(
                    (
                        ir
                        for ir, normalized in parts or []
                        if isinstance(ir, Binary) and normalized == "GREATER" and same(ir.variable_left, signer)
                    ),
                    None,
                )
                if ordering is None:
                    continue
                previous = ordering.variable_right
                if not any(
                    isinstance(ir, Assignment)
                    and same(ir.lvalue, previous)
                    and same(ir.rvalue, signer)
                    and guard in n.dominators
                    and n in increment.dominators
                    for n, ir in ops
                ):
                    continue
                # Every signer-defining branch must authenticate; merely seeing one ecrecover is insufficient.
                assignments = [
                    (n, ir) for n, ir in ops if isinstance(ir, Assignment) and same(ir.lvalue, signer) and n in region
                ]
                if not assignments:
                    continue
                modes, consumed, signed_sets = set(), {guard.node_id}, []
                valid = True
                payload = None
                recoveries = []
                for node, assign in assignments:
                    recovered = definition(unwrap(assign.rvalue, fn), fn)
                    if isinstance(recovered, SolidityCall) and recovered.function.name.startswith("ecrecover("):
                        recoveries.append(recovered)
                        modes.add("ecdsa")
                        signed_sets.append(payload_parameters(recovered.arguments[0], fn, parameter_bindings))
                        if payload is None:
                            payload = unwrap(recovered.arguments[0], fn)
                # Recoveries under an eth_sign prefix use a hash wrapper; use the common bytes32 formal for approval.
                payloads = [p for p in fn.parameters if str(p.type) == "bytes32"]
                if len(payloads) == 1:
                    payload = payloads[0]
                if not recoveries or payload is None:
                    continue
                # Contract-signature and preapproval branches validate this common payload. Intersect it with every
                # recovered hash so one strong ECDSA arm cannot lend bindings to a weaker alternate signer mode.
                signed_sets.append(set(parameter_bindings.get(payload.name, set())))
                for node, assign in assignments:
                    recovered = definition(unwrap(assign.rvalue, fn), fn)
                    if isinstance(recovered, SolidityCall) and recovered.function.name.startswith("ecrecover("):
                        continue
                    accepted = authenticated_paths(node, guard, signer, frame, payload, registry, region)
                    if accepted is None:
                        valid = False
                        break
                    modes |= accepted[0]
                    consumed |= accepted[1]
                if not valid:
                    continue
                threshold_json = dict(threshold)
                var = threshold_json.pop("variable_object", None)
                if var is not None:
                    threshold_json.update(slot(contract, var) or {})
                if threshold_json.get("kind") == "storage" and "slot" not in threshold_json:
                    continue
                return {
                    "kind": "signature_threshold",
                    "registry": enumerator,
                    "threshold": threshold_json,
                    "modes": sorted(modes),
                    "bound_parameters": sorted(set.intersection(*signed_sets)) if signed_sets else [],
                    "source_function": fn.full_name,
                    "consumed_nodes": sorted(consumed),
                    "source_loop": header.node_id,
                    "requires_positive": scalar_key(threshold) in positive,
                }
    return None


def quorum_witness(entry, contract):
    """Follow mandatory helper calls with actual argument bindings; no contract/function-name allowlist."""
    initial = {p.name: {"kind": "parameter", "index": i} for i, p in enumerate(entry.parameters)}
    params = {p.name: {i} for i, p in enumerate(entry.parameters)}
    todo = [(Frame(entry, initial), params)]
    seen = set()
    while todo:
        frame, bindings = todo.pop()
        if len(frame.chain) > 5 or frame.function in frame.chain:
            continue
        key = frame.function.full_name, repr(frame.bindings)
        if key in seen:
            continue
        seen.add(key)
        witness = loop_witness(frame, contract, bindings)
        if witness is not None:
            return witness
        for node, call in operations(frame.function):
            if not isinstance(call, (InternalCall, LibraryCall)) or not mandatory(node, frame.function):
                continue
            callee: Any = call.function
            if not getattr(callee, "nodes", None):
                continue
            positive = list(frame.positive)
            for guard, condition, polarity in guards(frame.function):
                if guard not in node.dominators:
                    continue
                for test, normalized in mandatory_atoms(condition, frame.function, polarity) or []:
                    if (
                        isinstance(test, Binary)
                        and normalized in ("GREATER", "NOT_EQUAL")
                        and integer(test.variable_right, frame.function) == 0
                        and str(getattr(test.variable_left, "type", "")).startswith("uint")
                    ):
                        positive.append(scalar_key(scalar(test.variable_left, frame)))
            child = {p.name: scalar(a, frame) for p, a in zip(callee.parameters, call.arguments)}
            bound = {
                p.name: payload_parameters(a, frame.function, bindings)
                for p, a in zip(callee.parameters, call.arguments)
            }
            todo.append((Frame(callee, child, (*frame.chain, frame.function), tuple(positive)), bound))
    return None


def apply_authorization_pass(contract, trees):
    # Source inventories also help ordinary caller-keyed membership gates, without a quorum or signature API.
    state_variables = getattr(contract, "state_variables", None)
    if state_variables is None:
        return
    registries = {v.name: v for v in state_variables}
    inventories = {
        name: inventory(contract, var)
        for name, var in registries.items()
        if str(var.type) == "mapping(address => address)"
    }

    def attach(tree):
        leaf = tree.get("leaf") or {}
        descriptor = leaf.get("set_descriptor") or {}
        found = inventories.get(descriptor.get("storage_var"))
        if found is not None and leaf.get("kind") == "membership" and leaf.get("operator") == "truthy":
            keys = descriptor.get("key_sources") or []
            if len(keys) == 1 and keys[0].get("source") in ("msg_sender", "tx_origin", "signature_recovery"):
                descriptor["membership_inventory"] = found
                leaf["authority_role"] = "caller_authority"
        for child in tree.get("children") or []:
            attach(child)

    for tree in trees.values():
        attach(tree)
    for fn in contract.functions_entry_points:
        witness = quorum_witness(fn, contract)
        if witness is None:
            continue
        witnessed = witness
        consumed = set(witnessed["consumed_nodes"])

        def retain(tree: PredicateTree) -> PredicateTree | None:
            leaf = tree.get("leaf")
            if leaf is not None:
                if (
                    leaf.get("source_function") == witnessed["source_function"]
                    and leaf.get("source_node_id") in consumed
                ):
                    return None
                return tree
            children = [kept for child in tree.get("children") or [] if (kept := retain(child)) is not None]
            if not children:
                return None
            return {**tree, "children": children}

        remaining = retain(trees[fn.full_name]) if fn.full_name in trees else None
        quorum_leaf: PredicateTree = {
            "op": "LEAF",
            "leaf": {
                "kind": "signature_auth",
                "operator": "truthy",
                "authority_role": "caller_authority",
                "operands": [],
                "references_msg_sender": False,
                "parameter_indices": witnessed["bound_parameters"],
                "expression": "distinct authorized signer quorum",
                "basis": ["source_verified_signature_loop"],
                "set_descriptor": witnessed,
            },
        }
        trees[fn.full_name] = make_and_node([quorum_leaf, remaining]) if remaining is not None else quorum_leaf
