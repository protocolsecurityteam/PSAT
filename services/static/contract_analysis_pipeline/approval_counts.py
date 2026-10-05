"""Count summaries for distinct eligible identities with action-specific approvals.

The traversal proves uniqueness; each increment needs its own authorization proof. A count is not interchangeable
with membership, a balance, or a caller-supplied number. Unsupported counts retain an explicit obligation.
"""

from __future__ import annotations

from .slither_compat import (
    Assignment,
    Binary,
    Condition,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    SolidityCall,
    StateVariable,
)
from .structural_evidence import evidence_for, storage_cell
from .structural_ir import (
    definition,
    guards,
    integer,
    loop_region,
    mandatory,
    mandatory_atoms,
    relation,
    same,
    scalar,
    slot,
    unwrap,
)


def _actions(value, signer, function, seen=()):
    if id(value) in seen:
        return []
    value = unwrap(value, function)
    ir = definition(value, function)
    if isinstance(ir, Binary):
        return _actions(ir.variable_left, signer, function, (*seen, id(value))) + _actions(
            ir.variable_right, signer, function, (*seen, id(value))
        )
    cell = storage_cell(value, function)
    if cell and len(cell.keys) == 2:
        for index, key in enumerate(cell.keys):
            if same(unwrap(key, function), signer):
                return [cell.keys[1 - index]]
    return []


def count_witness(frame, contract, bindings):
    from .authorization import approves, inventory, payload_parameters

    fn = frame.function
    ops = evidence_for(contract).summary(fn).operations
    unresolved = None
    for gate, condition, polarity in guards(fn):
        if not mandatory(gate, fn):
            continue
        for test, op in mandatory_atoms(condition, fn, polarity) or []:
            if not isinstance(test, Binary) or op != "GREATER_EQUAL":
                continue
            counter, required = test.variable_left, test.variable_right
            threshold = scalar(required, frame)
            if threshold is None:
                continue
            increments = [(n, ir) for n, ir in ops if isinstance(ir, Binary) and same(ir.lvalue, counter)]
            if increments and any(
                (cell := storage_cell(getattr(ir, "lvalue", None), fn)) is not None
                and len(cell.keys) >= 2
                and any(str(getattr(key, "type", "")) == "address" for key in cell.keys)
                for _, ir in ops
            ):
                unresolved = {
                    "kind": "authorization_unresolved",
                    "bound_parameters": [],
                    "source_function": fn.canonical_name,
                    "consumed_nodes": [gate.node_id],
                    "source_loop": None,
                    "missing": ["distinct_action_approvals"],
                }
            if len(increments) != 1:
                continue
            inc_node, increment = increments[0]
            if (
                relation(increment) != "ADDITION"
                or not same(increment.variable_left, counter)
                or integer(increment.variable_right, fn) != 1
            ):
                continue
            for header, loop_test in ops:
                if (
                    getattr(header.type, "name", "") != "IFLOOP"
                    or not isinstance(loop_test, Binary)
                    or relation(loop_test) != "NOT_EQUAL"
                ):
                    continue
                region = loop_region(header)
                if inc_node not in region:
                    continue
                signer, sentinel = loop_test.variable_left, integer(loop_test.variable_right, fn)
                reads = [(n, ir) for n, ir in ops if isinstance(ir, Assignment) and same(ir.lvalue, signer)]
                initial = [(n, storage_cell(ir.rvalue, fn)) for n, ir in reads if n in header.dominators]
                advances = [(n, storage_cell(ir.rvalue, fn)) for n, ir in reads if n in region]
                if len(initial) != 1 or len(advances) != 1:
                    continue
                first, advance = initial[0][1], advances[0][1]
                if not first or not advance or len(first.keys) != 1 or len(advance.keys) != 1:
                    continue
                registry = first.variable
                if (
                    not same(registry, advance.variable)
                    or integer(first.keys[0], fn) != sentinel
                    or not same(advance.keys[0], signer)
                ):
                    continue
                # Every iteration advances once; no branch can revisit an identity and count it twice.
                backedges = [
                    n for n in region if any(s is header or getattr(s.type, "name", "") == "ENDLOOP" for s in n.sons)
                ]
                if not backedges or not all(advances[0][0] in n.dominators for n in backedges):
                    continue
                if any(same(w.cell.variable, registry) for w in evidence_for(contract).summary(fn).writes):
                    continue
                if any(isinstance(ir, (InternalCall, LibraryCall)) for n, ir in ops if n in region):
                    continue
                if any(
                    isinstance(ir, LowLevelCall)
                    and str(ir.function_name) != "staticcall"
                    or isinstance(ir, HighLevelCall)
                    and not (getattr(ir.function, "view", False) or getattr(ir.function, "pure", False))
                    or isinstance(ir, SolidityCall)
                    and ir.function.name.startswith(("call(", "callcode(", "delegatecall("))
                    for n, ir in ops
                    if n in region
                ):
                    continue
                enumerator = inventory(contract, registry)
                if enumerator is None:
                    continue
                initial_count = [ir for n, ir in ops if isinstance(ir, Assignment) and same(ir.lvalue, counter)]
                if len(initial_count) != 1 or integer(initial_count[0].rvalue, fn) != 0:
                    continue
                if not any(ir is initial_count[0] and n in header.dominators for n, ir in ops):
                    continue
                unresolved = {
                    "kind": "authorization_unresolved",
                    "registry": enumerator,
                    "bound_parameters": [],
                    "source_function": fn.canonical_name,
                    "consumed_nodes": [gate.node_id],
                    "source_loop": header.node_id,
                    "missing": ["distinct_action_approvals"],
                }
                for control, cond in ops:
                    if not isinstance(cond, Condition) or control not in inc_node.dominators or control not in region:
                        continue
                    true = getattr(control, "son_true", None)
                    false = getattr(control, "son_false", None)

                    # Paths through the next loop iteration are not alternatives for this increment.
                    def reaches_without_header(start):
                        todo, seen = [start], set()
                        while todo:
                            node = todo.pop()
                            if node is inc_node:
                                return True
                            if node is None or node is header or node in seen:
                                continue
                            seen.add(node)
                            todo.extend(node.sons)
                        return False

                    true_reaches, false_reaches = reaches_without_header(true), reaches_without_header(false)
                    if true_reaches == false_reaches:
                        continue
                    accepted_polarity = "allowed_when_true" if true_reaches else "allowed_when_false"
                    for action in _actions(cond.value, signer, fn):
                        modes = approves(cond.value, signer, frame, action, registry, control, accepted_polarity)
                        if not modes:
                            continue
                        threshold_json = dict(threshold)
                        var = threshold_json.pop("variable_object", None)
                        if isinstance(var, StateVariable):
                            threshold_json.update(slot(contract, var) or {})
                        if threshold_json.get("kind") == "storage" and "slot" not in threshold_json:
                            continue
                        return {
                            "kind": "authorization_threshold",
                            "registry": enumerator,
                            "threshold": threshold_json,
                            "modes": sorted(modes),
                            "bound_parameters": sorted(payload_parameters(action, fn, bindings)),
                            "source_function": fn.canonical_name,
                            "consumed_nodes": [gate.node_id],
                            "source_loop": header.node_id,
                            "requires_positive": False,
                            "count_proof": {
                                "increment": inc_node.node_id,
                                "distinctness": "unique_registry_traversal",
                                "approval_condition": control.node_id,
                            },
                        }
    return unresolved
