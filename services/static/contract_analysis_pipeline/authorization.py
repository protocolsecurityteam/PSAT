"""Source-derived signer quorum and membership inventories, independent of contract names and versions.

A quorum is credited only when its counted loop validates membership and strict signer ordering on every iteration,
and every definition of the signer is recovered or explicitly authorized before that check. Unsupported shapes retain
uncertainty. Storage/getter facts describe the registry the code actually consults, never a familiar ABI.
"""

from __future__ import annotations

from typing import Any

from .predicate_types import PredicateTree, make_and_node
from .slither_compat import (
    Assignment,
    Binary,
    Constant,
    Delete,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    Return,
    SolidityCall,
    StateVariable,
    TypeConversion,
    Unary,
)
from .structural_evidence import evidence_for, storage_cell
from .structural_ir import (
    _INVERTED_RELATION,
    Frame,
    call_result_required_true,
    definition,
    denied_return,
    exits,
    frame_guards,
    guards,
    integer,
    loop_region,
    mandatory,
    mandatory_atoms,
    operations,
    relation,
    same,
    scalar,
    scalar_key,
    slot,
    unwrap,
)


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
        if ir.function.name.startswith("keccak256(") and len(ir.arguments) == 2:
            # Yul arguments are a memory pointer and a length, not encoded message fields.
            return _assembly_hash_parameters(value, fn, bindings, seen)
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
                offset = base_pointer[1] + amount
                return (base_pointer[0], offset) if 0 <= offset < 1 << 256 else None
    return None


def _reaches(start, end):
    todo, seen = [start], set()
    while todo:
        node = todo.pop()
        if node is end:
            return True
        if node in seen:
            continue
        seen.add(node)
        todo.extend(node.sons)
    return False


def _assembly_hash_parameters(value, fn, bindings, seen=()):
    """Credit complete, surviving words in a bounded memory hash.

    Writes must dominate the hash and share a proved memory root. Overlapping later writes invalidate earlier
    bindings, even when the later value is opaque. Copies invalidate their destination but do not bind their offset
    or length arguments. Unknown aliasing/control flow yields no proof.
    """
    if id(value) in seen:
        return set()
    call = definition(unwrap(value, fn), fn)
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
    ops = operations(fn)
    hash_node = next(n for n, ir in ops if ir is call)
    root_node = next(n for n, ir in ops if id(ir) == root)
    root_ir = next(ir for _, ir in ops if id(ir) == root)
    if root_node not in hash_node.dominators:
        return set()
    writes = []
    for node, write in ops:
        if node is hash_node and node.irs.index(write) >= node.irs.index(call):
            continue
        if node is root_node and node.irs.index(write) <= node.irs.index(root_ir):
            continue
        if not _reaches(root_node, node) or not _reaches(node, hash_node):
            continue
        if isinstance(write, (InternalCall, LibraryCall, HighLevelCall)):
            return set()  # unknown memory effects between allocation and hashing
        if not isinstance(write, SolidityCall):
            continue
        name = write.function.name.split("(", 1)[0]
        if name in {"call", "delegatecall", "staticcall", "callcode"}:
            return set()
        if name not in {"mstore", "mstore8", "calldatacopy", "returndatacopy", "codecopy", "extcodecopy", "mcopy"}:
            continue
        if node not in hash_node.dominators:
            return set()
        # A loop can revisit these writes in a different order.
        if any(_reaches(son, node) for son in node.sons):
            return set()
        destination_index = 1 if name == "extcodecopy" else 0
        location = _memory_offset(write.arguments[destination_index], fn)
        size = 32 if name == "mstore" else 1 if name == "mstore8" else integer(write.arguments[-1], fn)
        if location is None or location[0] != root or size is None or size < 0:
            return set()
        writes.append((node, write, name, location[1], size))
    writes.sort(key=lambda item: (len(item[0].dominators), item[0].irs.index(item[1])))
    live = []
    for _, write, name, offset, size in writes:
        if not size:
            continue
        stop = offset + size
        live = [(lo, hi, params) for lo, hi, params in live if stop <= lo or offset >= hi]
        if name != "mstore" or offset < start or stop > end:
            continue
        stored = write.arguments[1]
        params = payload_parameters(stored, fn, bindings, (*seen, id(value)))
        params |= _assembly_hash_parameters(stored, fn, bindings, (*seen, id(value)))
        live.append((offset, stop, params))
    return set().union(*(params for _, _, params in live))


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


def _value_origin(value, frame, seen=()):
    """Follow exact assignments and actual/formal bindings, retaining the defining frame.

    Parameter taint sets are insufficient here: two encodings can mention the same parameters without being the
    same signed message. Ambiguous definitions and conversions deliberately remain opaque.
    """
    key = id(value), id(frame)
    if key in seen:
        return value, frame
    nxt = (*seen, key)
    index = _parameter_index(value, frame.function)
    if index is not None and frame.parent is not None and index < len(frame.arguments):
        return _value_origin(frame.arguments[index], frame.parent, nxt)
    ir = definition(value, frame.function)
    if isinstance(ir, Assignment):
        return _value_origin(ir.rvalue, frame, nxt)
    return value, frame


def _same_origin(left, right):
    return left[1] is right[1] and same(left[0], right[0])


def _message_is_unchanged(origin, frame, seen=()):
    """Reject writes through aliases of the message, including helpers receiving that memory object.

    This deliberately checks the whole frame, rather than guessing whether a mutation precedes hashing. Assembly
    memory writes have no alias proof here and therefore withhold. Calldata/ABI construction itself is read-only.
    """
    if frame.function in seen or len(seen) > 8:
        return False
    for _, ir in operations(frame.function):
        written = getattr(ir, "lvalue", None)
        target = written if isinstance(ir, Delete) else getattr(written, "points_to_origin", None)
        if target is None and isinstance(ir, Assignment) and definition(written, frame.function) is None:
            target = written  # multiple definitions cannot establish a time-independent message identity
        if isinstance(ir, (Assignment, Binary, Delete)) and target is not None:
            if _same_origin(origin, _value_origin(target, frame)):
                return False
        if isinstance(ir, SolidityCall) and ir.function.name.split("(", 1)[0] in {
            "mstore",
            "mstore8",
            "calldatacopy",
            "returndatacopy",
            "codecopy",
            "extcodecopy",
            "mcopy",
        }:
            return False
        if isinstance(ir, (InternalCall, LibraryCall)) and any(
            _same_origin(origin, _value_origin(arg, frame)) for arg in ir.arguments
        ):
            if not getattr(ir.function, "nodes", None):
                return False
            child = Frame(ir.function, {}, parent=frame, arguments=tuple(ir.arguments))
            if not _message_is_unchanged(origin, child, (*seen, frame.function)):
                return False
    return True


def _value_is_bound_to_payload(value, payload, frame, before_node):
    fn = frame.function
    origin = _value_origin(value, frame)
    digest = _value_origin(payload, frame)
    if _same_origin(origin, digest):
        return True
    hashed = definition(digest[0], digest[1].function)
    if (
        isinstance(hashed, SolidityCall)
        and hashed.function.name.startswith("keccak256(")
        and len(hashed.arguments) == 1
        and _same_origin(origin, _value_origin(hashed.arguments[0], digest[1]))
        and _message_is_unchanged(origin, origin[1])
    ):
        return True
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


def _approval_registry_is_self_service(registry, signer_registry, contract, signer_key_index=0):
    """Only authority-enabling writes need a grant proof. Consumption cannot manufacture a nonzero approval."""
    writes = evidence_for(contract).writes_to(registry)
    grants = []
    for write in writes:
        if write.transition() == "revokes":
            continue
        grants.append(write)
        if len(write.cell.keys) != 2 or write.cell.members:
            return False
        key = write.cell.keys[signer_key_index]
        if str(unwrap(key, write.function)) != "msg.sender":
            return False
        if not _writer_is_signer_gated(write.function, signer_registry, write.node):
            return False
    return bool(grants)


def _is_caller(value, frame):
    resolved = scalar(unwrap(value, frame.function), frame)
    return resolved is not None and resolved.get("kind") == "caller"


def approves(condition, signer, frame, payload, signer_registry, guard_node, polarity="allowed_when_true"):
    """A mandatory accepted-identity check on a raw signer definition, not a verifier's name."""
    fn = frame.function
    condition = unwrap(condition, fn)
    ir = definition(condition, fn)
    if isinstance(ir, Unary) and getattr(ir.type, "name", "") == "BANG":
        opposite = "allowed_when_false" if polarity == "allowed_when_true" else "allowed_when_true"
        return approves(ir.rvalue, signer, frame, payload, signer_registry, guard_node, opposite)
    if isinstance(ir, HighLevelCall) and polarity == "allowed_when_true":
        if same(unwrap(ir.destination, fn), signer) and any(
            _value_is_bound_to_payload(arg, payload, frame, guard_node) for arg in ir.arguments
        ):
            return {"external"}
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
                if any(_value_is_bound_to_payload(a, payload, frame, guard_node) for a in call.arguments):
                    return {"external"}
    if op == "NOT_EQUAL":
        for indexed, constant in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
            cell = storage_cell(unwrap(indexed, fn), fn)
            if cell is None or len(cell.keys) != 2 or cell.members or integer(constant, fn) != 0:
                continue
            for identity_index, key in enumerate(cell.keys):
                if same(unwrap(key, fn), signer) and same(
                    unwrap(cell.keys[1 - identity_index], fn), unwrap(payload, fn)
                ):
                    if _approval_registry_is_self_service(cell.variable, signer_registry, fn.contract, identity_index):
                        return {"approval_hash"}

    return None


def authenticated_paths(start, stop, signer, frame, payload, signer_registry, region):
    todo = [(start, False)]
    seen = set()
    modes = set()
    guard_nodes = set()
    requirements = {node: (condition, polarity) for node, condition, polarity in frame_guards(frame)}
    while todo:
        node, accepted = todo.pop()
        if (node, accepted) in seen:
            continue
        seen.add((node, accepted))
        if denied_return(node, frame):
            continue
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
        frame,
        tuple(call.arguments),
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


def _signature_result(value, function, bindings, seen=()):
    """Interpret a returned identity through reusable helper summaries, preserving its message bindings."""
    if id(value) in seen or len(seen) > 12:
        return None
    ir = definition(value, function)
    if isinstance(ir, Assignment):
        return _signature_result(ir.rvalue, function, bindings, (*seen, id(value)))
    if isinstance(ir, SolidityCall) and ir.function.name.startswith("ecrecover("):
        return ir, payload_parameters(ir.arguments[0], function, bindings)
    if isinstance(ir, (InternalCall, LibraryCall)) and getattr(ir.function, "nodes", None):
        callee: Any = ir.function
        summary = evidence_for(function.contract).summary(callee)
        if len(summary.returns) != 1 or len(summary.returns[0][1]) != 1:
            return None
        actuals = {p.name: payload_parameters(a, function, bindings) for p, a in zip(callee.parameters, ir.arguments)}
        return _signature_result(summary.returns[0][1][0], ir.function, actuals, (*seen, id(value)))
    return None


def loop_witness(frame, contract, parameter_bindings):
    fn = frame.function
    ops = operations(fn)
    for header, cond in ops:
        if getattr(header.type, "name", "") != "IFLOOP" or not isinstance(cond, Binary) or relation(cond) != "LESS":
            continue
        successful_exits = exits(fn)
        if frame.return_checked:
            successful_exits = [
                n
                for n in successful_exits
                if not any(
                    isinstance(ir, Return)
                    and len(ir.values) == 1
                    and isinstance(ir.values[0], Constant)
                    and ir.values[0].value is False
                    for ir in n.irs
                )
            ]
        if not successful_exits or not all(header in n.dominators for n in successful_exits):
            continue
        counter, bound = cond.variable_left, cond.variable_right
        threshold = scalar(bound, frame)
        if threshold is None:
            continue
        positive = set(frame.positive)
        for positive_guard, positive_condition, positive_polarity in frame_guards(frame):
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
        for guard, value, polarity in frame_guards(frame):
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
                ordering_fact = next(
                    (
                        (other_guard, ir)
                        for other_guard, other_value, other_polarity in frame_guards(frame)
                        if other_guard in region and other_guard in increment.dominators
                        for ir, normalized in mandatory_atoms(other_value, fn, other_polarity) or []
                        if isinstance(ir, Binary) and normalized == "GREATER" and same(ir.variable_left, signer)
                    ),
                    None,
                )
                if ordering_fact is None:
                    continue
                ordering_guard, ordering = ordering_fact
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
                previous_writes = [
                    ir
                    for n, ir in ops
                    if n in region and isinstance(ir, (Assignment, Binary)) and same(ir.lvalue, previous)
                ]
                if len(previous_writes) != 1:
                    continue
                # Every signer-defining branch must authenticate; merely seeing one ecrecover is insufficient.
                assignments = [
                    (n, ir) for n, ir in ops if isinstance(ir, Assignment) and same(ir.lvalue, signer) and n in region
                ]
                if not assignments:
                    continue
                modes, consumed, signed_sets = set(), {guard.node_id, ordering_guard.node_id}, []
                valid = True
                payload = None
                recoveries = []
                for node, assign in assignments:
                    recovery = _signature_result(assign.rvalue, fn, parameter_bindings)
                    if recovery is not None:
                        recovered, committed = recovery
                        recoveries.append(recovered)
                        modes.add("ecdsa")
                        signed_sets.append(committed)
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
                    if _signature_result(assign.rvalue, fn, parameter_bindings) is not None:
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
                    "source_function": fn.canonical_name,
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
        key = id(frame.function), repr(frame.bindings), repr(bindings)
        if key in seen:
            continue
        seen.add(key)
        from .approval_counts import count_witness

        witness = loop_witness(frame, contract, bindings) or count_witness(frame, contract, bindings)
        if witness is not None:
            return witness
        for node, call in operations(frame.function):
            if not isinstance(call, (InternalCall, LibraryCall)) or not mandatory(node, frame.function):
                continue
            callee: Any = call.function
            if not getattr(callee, "nodes", None):
                continue
            checked = call_result_required_true(call, frame.function, frame.return_checked)
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
            todo.append(
                (
                    Frame(
                        callee,
                        child,
                        (*frame.chain, frame.function),
                        tuple(positive),
                        frame,
                        tuple(call.arguments),
                        checked,
                    ),
                    bound,
                )
            )
    return None


def attach_membership_inventories(contract, trees):
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
        if not isinstance(tree, dict):
            return
        leaf = tree.get("leaf") or {}
        descriptor = leaf.get("set_descriptor") or {}
        keys = descriptor.get("key_sources") or []
        if leaf.get("kind") == "membership" and any(k.get("source") == "signature_recovery" for k in keys):
            # Membership of a recovered identity is evidence of authentication, not a caller inventory. Only a
            # complete quorum witness can consume it; the resolver must withhold when recognition fails.
            leaf["authority_role"] = "caller_authority"
        found = inventories.get(descriptor.get("storage_var"))
        if found is not None and leaf.get("kind") == "membership" and leaf.get("operator") == "truthy":
            if len(keys) == 1 and keys[0].get("source") in ("msg_sender", "tx_origin"):
                descriptor["membership_inventory"] = found
                leaf["authority_role"] = "caller_authority"
        for child in tree.get("children") or []:
            attach(child)

    for tree in trees.values():
        attach(tree)


def apply_authorization_pass(contract, trees):
    if getattr(contract, "state_variables", None) is None:
        return
    attach_membership_inventories(contract, trees)
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
                "kind": "signature_auth" if witnessed["kind"] == "signature_threshold" else "authorization",
                "operator": "truthy",
                "authority_role": "caller_authority",
                "authority_proof": {
                    "state": "not_determined" if witnessed["kind"] == "authorization_unresolved" else "proven",
                    "requirements": witnessed.get("missing", []),
                    "source_function": witnessed["source_function"],
                },
                "operands": [],
                "references_msg_sender": False,
                "parameter_indices": witnessed["bound_parameters"],
                "expression": "distinct authorized signer quorum",
                "basis": ["source_verified_signature_loop"],
                "set_descriptor": witnessed,
            },
        }
        trees[fn.full_name] = make_and_node([quorum_leaf, remaining]) if remaining is not None else quorum_leaf
