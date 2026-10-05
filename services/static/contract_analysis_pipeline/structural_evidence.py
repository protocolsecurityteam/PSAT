"""Shared, loss-aware summaries of storage, predicates, calls and writes.

Semantic labels are interpretations of these records, not substitutes for them. A write is classified relative to
an acceptance predicate: clearing a nonzero approval revokes it, while clearing a zero-valued allowlist can grant it.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from .revert_detect import RevertDetector
from .slither_compat import (
    Assignment,
    Binary,
    Constant,
    Delete,
    Index,
    InternalCall,
    LibraryCall,
    Member,
    Return,
    SolidityCall,
    StateVariable,
    TypeConversion,
    Unary,
)
from .structural_ir import definition, integer, operations, relation, same


def declaration(value):
    return str(
        getattr(value, "canonical_name", None) or getattr(value, "full_name", None) or getattr(value, "name", "unknown")
    )


@dataclass(frozen=True)
class StorageCell:
    variable: Any
    keys: tuple = ()
    members: tuple = ()


def storage_cell(value, function, seen=()):
    if id(value) in seen:
        return None
    if isinstance(value, StateVariable):
        return StorageCell(value)
    nxt = (*seen, id(value))
    # Index lvalues are references and can be assigned repeatedly; their address calculation still has one definition.
    address_defs = [ir for _, ir in operations(function) if isinstance(ir, (Index, Member)) and ir.lvalue is value]
    ir = address_defs[0] if len(address_defs) == 1 else definition(value, function)
    if isinstance(ir, Index):
        parent = storage_cell(ir.variable_left, function, nxt)
        return StorageCell(parent.variable, (*parent.keys, ir.variable_right), parent.members) if parent else None
    if isinstance(ir, Member):
        parent = storage_cell(ir.variable_left, function, nxt)
        return StorageCell(parent.variable, parent.keys, (*parent.members, str(ir.variable_right))) if parent else None
    if isinstance(ir, Assignment):
        return storage_cell(ir.rvalue, function, nxt)
    if isinstance(ir, TypeConversion):
        return storage_cell(ir.variable, function, nxt)
    return None


def acceptance_transition(operator: str, rhs: int, after: int | None) -> str:
    """Whether this write can enable a predicate. No assumption that zero always means revoked."""
    if after is None:
        return "unknown"
    accepted = {
        "EQUAL": after == rhs,
        "NOT_EQUAL": after != rhs,
        "GREATER": after > rhs,
        "GREATER_EQUAL": after >= rhs,
        "LESS": after < rhs,
        "LESS_EQUAL": after <= rhs,
    }.get(operator)
    return "unknown" if accepted is None else "may_grant" if accepted else "revokes"


@dataclass
class WriteEvidence:
    node: Any
    operation: Any
    cell: StorageCell
    value: Any
    function: Any

    def transition(self, operator="NOT_EQUAL", rhs=0):
        after = 0 if isinstance(self.operation, Delete) else integer(self.value, self.function)
        return acceptance_transition(operator, rhs, after)


class FunctionSummary:
    def __init__(self, function):
        self.function = function
        self.operations = operations(function)
        self.gates = [g for g in RevertDetector(function, internal_call_depth=0).run() if not g.call_chain]
        self.writes = []
        self.calls = []
        self.returns = []
        for node, ir in self.operations:
            if isinstance(ir, (Assignment, Binary, Delete)):
                target = ir.variable if isinstance(ir, Delete) else ir.lvalue
                # Binding a local storage reference (or loading a cell into a local) does not write that cell.
                cell = (
                    storage_cell(target, function)
                    if isinstance(target, StateVariable) or getattr(target, "points_to_origin", None) is not None
                    else None
                )
                if cell is not None:
                    self.writes.append(WriteEvidence(node, ir, cell, getattr(ir, "rvalue", None), function))
            if isinstance(ir, (InternalCall, LibraryCall)):
                self.calls.append((node, ir))
            if isinstance(ir, Return):
                self.returns.append((node, tuple(ir.values)))

    def expression(self, value, seen=(), depth=0):
        if value is None:
            return {"kind": "unknown", "reason": "missing_value"}
        if depth > 8 or id(value) in seen:
            return {"kind": "unknown", "reason": "recursive_or_bounded_value"}
        nxt = (*seen, id(value))

        def child(v):
            return self.expression(v, nxt, depth + 1)

        if isinstance(value, Constant):
            return {"kind": "constant", "value": str(value.value), "type": str(value.type)}
        if isinstance(value, StateVariable):
            return {"kind": "storage", "declaration": declaration(value), "type": str(value.type)}
        for index, parameter in enumerate(self.function.parameters):
            if same(parameter, value):
                return {"kind": "parameter", "index": index, "type": str(parameter.type)}
        if str(value) in ("msg.sender", "tx.origin", "msg.value", "block.timestamp", "block.number", "this"):
            return {"kind": "context", "value": str(value)}
        cell = storage_cell(value, self.function)
        if cell:
            return {
                "kind": "storage_cell",
                "declaration": declaration(cell.variable),
                "keys": [child(k) for k in cell.keys],
                "members": list(cell.members),
            }
        ir = definition(value, self.function)
        if isinstance(ir, Assignment):
            return child(ir.rvalue)
        if isinstance(ir, TypeConversion):
            return {"kind": "conversion", "type": str(ir.type), "value": child(ir.variable)}
        if isinstance(ir, Unary):
            return {"kind": "unary", "operator": ir.type.name, "value": child(ir.rvalue)}
        if isinstance(ir, Binary):
            return {
                "kind": "binary",
                "operator": relation(ir),
                "left": child(ir.variable_left),
                "right": child(ir.variable_right),
            }
        if isinstance(ir, (InternalCall, LibraryCall, SolidityCall)):
            return {
                "kind": "call",
                "declaration": declaration(ir.function),
                "arguments": [child(a) for a in ir.arguments],
            }
        return {
            "kind": "unknown",
            "reason": "ambiguous_or_unsupported_definition",
            "type": str(getattr(value, "type", "")),
        }

    def publish(self):
        return {
            "declaration": declaration(self.function),
            "parameters": [str(p.type) for p in self.function.parameters],
            "guards": [
                {
                    "node": g.node.node_id if g.node else None,
                    "polarity": g.polarity,
                    "predicate": self.expression(g.condition_value),
                }
                for g in self.gates
            ],
            "writes": [
                {
                    "node": w.node.node_id,
                    "storage": declaration(w.cell.variable),
                    "keys": [self.expression(k) for k in w.cell.keys],
                    "members": list(w.cell.members),
                    "value": {"kind": "constant", "value": "0"}
                    if isinstance(w.operation, Delete)
                    else self.expression(w.value),
                    "nonzero_transition": w.transition(),
                }
                for w in self.writes
            ],
            "calls": [
                {
                    "node": n.node_id,
                    "declaration": declaration(c.function),
                    "arguments": [self.expression(a) for a in c.arguments],
                }
                for n, c in self.calls
            ],
            "returns": [
                {"node": n.node_id, "values": [self.expression(v) for v in values]} for n, values in self.returns
            ],
        }


class StructuralEvidence:
    def __init__(self, contract):
        self.contract = contract
        self.summaries = {}

    def summary(self, function):
        key = id(function)
        if key not in self.summaries:
            self.summaries[key] = FunctionSummary(function)
        return self.summaries[key]

    def writes_to(self, variable):
        return [w for fn in self.contract.functions for w in self.summary(fn).writes if same(w.cell.variable, variable)]

    def publish(self):
        return {
            "schema_version": 1,
            "functions": {
                declaration(s.function): s.publish()
                for s in sorted(self.summaries.values(), key=lambda s: declaration(s.function))
            },
        }


_active_evidence: ContextVar[StructuralEvidence | None] = ContextVar("structural_evidence", default=None)


def evidence_for(contract):
    active = _active_evidence.get()
    return active if active is not None and active.contract is contract else StructuralEvidence(contract)


@contextmanager
def structural_scope(contract):
    evidence = StructuralEvidence(contract)
    token = _active_evidence.set(evidence)
    try:
        yield evidence
    finally:
        _active_evidence.reset(token)


def _requires_authority(tree):
    if not isinstance(tree, dict):
        return False
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf") or {}
        return (leaf.get("authority_proof") or {}).get("state") != "not_determined" and leaf.get("authority_role") in (
            "caller_authority",
            "delegated_authority",
        )
    children = tree.get("children") or []
    checks = [_requires_authority(c) for c in children]
    return bool(checks) and (all(checks) if tree.get("op") == "OR" else any(checks))


def _attach_storage_dependencies_once(contract, scoped_trees, sites_by_function, writer_trees):
    """Relate non-caller-keyed state requirements to the actual sites that can enable them.

    Caller-keyed balances/allowances remain resource constraints. State transitions and writer gates are independent
    facts; a writer guarded only on the same unresolved dependency cannot bootstrap a proof.
    """

    evidence = evidence_for(contract)
    sites = [s for values in sites_by_function.values() for s in values]
    writer_sites = {}
    for site in sites:
        if site["kind"] == "state_write":
            writer_sites.setdefault((site["declaration"], site["node"], site["target"]), []).append(site)
    original = writer_trees
    variables = {v.name: v for v in contract.state_variables}
    relation_names = {
        "eq": "EQUAL",
        "ne": "NOT_EQUAL",
        "gt": "GREATER",
        "gte": "GREATER_EQUAL",
        "lt": "LESS",
        "lte": "LESS_EQUAL",
    }

    def visit(tree):
        if not isinstance(tree, dict):
            return
        leaf = tree.get("leaf") or {}
        descriptor = leaf.get("set_descriptor") or {}
        keys = descriptor.get("key_sources") or []
        value_predicate = descriptor.get("value_predicate") or {}
        variable = variables.get(descriptor.get("storage_var"))
        if (
            leaf.get("kind") == "membership"
            and variable is not None
            and keys
            and not any(k.get("source") in ("msg_sender", "tx_origin", "signature_recovery") for k in keys)
        ):
            op = relation_names.get(value_predicate.get("op") or "")
            rhs_values = value_predicate.get("rhs_values") or []
            try:
                rhs = int(rhs_values[0], 0) if len(rhs_values) == 1 else None
            except (TypeError, ValueError):
                rhs = None
            if op is not None and rhs is not None:
                grants = [w for w in evidence.writes_to(variable) if w.transition(op, rhs) != "revokes"]
                guards = []
                guard_ids = []
                unresolved_dependency = False
                complete = bool(grants)
                for write in grants:
                    located = writer_sites.get((declaration(write.function), write.node.node_id, variable.name), [])
                    if not located:
                        complete = False
                    for site in located:
                        predicate = original.get(site["id"])
                        if not _requires_authority(predicate):
                            complete = False
                            unresolved_dependency |= _has_state_dependency(predicate)
                        else:
                            guards.append(predicate)
                            guard_ids.append(site["id"])
                if not complete and unresolved_dependency:
                    leaf["authority_role"] = "caller_authority"
                    leaf["authority_proof"] = {"state": "not_determined", "requirements": ["state_writer_authority"]}
                if complete and guards:
                    leaf["kind"] = "authorization"
                    leaf["authority_role"] = "caller_authority"
                    leaf["authority_proof"] = {"state": "proven", "basis": "authority_enabling_writes"}
                    leaf["set_descriptor"] = {
                        "kind": "state_authority",
                        "writer_scope_ids": sorted(set(guard_ids)),
                        "storage_var": variable.name,
                        "key_sources": keys,
                    }
        for child in tree.get("children") or []:
            visit(child)

    for tree in scoped_trees.values():
        visit(tree)


def predicate_truth(tree):
    """Three-valued evaluation of source-proven constant conditions after argument binding."""
    if not isinstance(tree, dict):
        return None
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf") or {}
        operands = leaf.get("operands") or []
        if not operands or any(o.get("source") != "constant" for o in operands):
            return None
        values = []
        for operand in operands:
            raw = str(operand.get("constant_value"))
            try:
                values.append(
                    int(raw, 0) if raw not in ("True", "False", "true", "false") else int(raw.lower() == "true")
                )
            except ValueError:
                return None
        op = leaf.get("operator")
        if len(values) == 1 and op in ("truthy", "falsy"):
            return bool(values[0]) == (op == "truthy")
        if len(values) != 2:
            return None
        left, right = values
        return {
            "eq": left == right,
            "ne": left != right,
            "lt": left < right,
            "lte": left <= right,
            "gt": left > right,
            "gte": left >= right,
        }.get(op or "")
    values = [predicate_truth(c) for c in tree.get("children") or []]
    if not values:
        return None
    if tree.get("op") == "AND":
        return False if any(v is False for v in values) else True if all(v is True for v in values) else None
    if tree.get("op") == "OR":
        return True if any(v is True for v in values) else False if all(v is False for v in values) else None
    return None


def _has_state_dependency(tree):
    if not isinstance(tree, dict):
        return False
    leaf = tree.get("leaf") or {}
    if (leaf.get("authority_proof") or {}).get("state") == "not_determined":
        return True
    descriptor = leaf.get("set_descriptor") or {}
    if descriptor.get("storage_var") and descriptor.get("key_sources"):
        return not any(k.get("source") in ("msg_sender", "tx_origin") for k in descriptor["key_sources"])
    return any(_has_state_dependency(c) for c in tree.get("children") or [])


def _unbind_writer_parameters(value):
    if isinstance(value, list):
        return [_unbind_writer_parameters(v) for v in value]
    if isinstance(value, dict):
        if value.get("source") == "parameter":
            return {"source": "computed", "computed_kind": "unbound_writer_argument"}
        return {k: _unbind_writer_parameters(v) for k, v in value.items()}
    return value


def attach_storage_dependencies(contract, scoped_trees, sites_by_function):
    from copy import deepcopy

    raw = deepcopy(scoped_trees)
    previous = scoped_trees
    updated = previous
    # Monotone authority facts propagate from actual caller guards. Cycles without an anchor stay unresolved.
    for _ in range(8):
        updated = deepcopy(raw)
        _attach_storage_dependencies_once(contract, updated, sites_by_function, previous)
        if updated == previous:
            break
        previous = updated
    scoped_trees.clear()
    scoped_trees.update(updated)
