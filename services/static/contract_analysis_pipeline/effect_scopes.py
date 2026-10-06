"""Attach effect sites to the conditions and call bindings that govern them.

A function may expose several different authorities. Site alternatives remain ORs; successful gates on one site
remain ANDs. Unresolved control flow is explicit and is never an empty/public predicate.
"""

from __future__ import annotations

import contextvars
from copy import deepcopy
from dataclasses import replace

from .effects.sinks import _classify_node_irs, _is_modifier_call, _node_kind_state_writes
from .predicate_types import PredicateTree, make_and_node, make_or_node
from .predicates._helpers import _unsupported_leaf
from .predicates.control_flow import _callee_always_reverts, _forward_reachable_node_ids
from .predicates.operands import _operand_for_value
from .predicates.tree import (
    _build_chain_bindings,
    _build_subtree_from_gate,
    _helper_engine_cache,
    _stamp_gate_scope,
)
from .provenance import ProvenanceEngine
from .reentrancy_pause import apply_reentrancy_pause_pass
from .revert_detect import RevertDetector, RevertGate
from .slither_compat import Condition, InternalCall, LibraryCall, LowLevelCall, Send, SolidityCall, Transfer
from .structural_evidence import attach_storage_dependencies, evidence_for, predicate_truth, structural_scope
from .structural_ir import mandatory
from .writer_gate import apply_writer_gate_pass


def unknown(reason) -> PredicateTree:
    return {"op": "LEAF", "leaf": _unsupported_leaf(reason, reason)}


# ``id(start) -> (start, reachable ids)`` for one attach pass; each guard/site pair otherwise re-walks the CFG. The
# node is held so its id can't be reused mid-pass.
_reachable_cache: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "psat_effect_scope_reachable_cache", default=None
)


def _reachable(start, end):
    cache = _reachable_cache.get()
    if cache is None:
        return id(end) in _forward_reachable_node_ids(start)
    hit = cache.get(id(start))
    if hit is None:
        hit = cache[id(start)] = (start, _forward_reachable_node_ids(start))
    return id(end) in hit[1]


# ``key -> lowered, stamped tree`` for one attach pass: a guard is re-lowered at every site it governs. Hits are
# copied because later passes mutate leaves in place.
_lowered_cache: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "psat_effect_scope_lowered_cache", default=None
)


def _lower(gate, provenance, entry, key):
    cache = _lowered_cache.get()
    if cache is not None and key in cache:
        hit = cache[key][1]
        return deepcopy(hit) if hit is not None else None
    tree = _build_subtree_from_gate(gate, provenance, entry)
    if tree is not None:
        _stamp_gate_scope(tree, gate, entry)
    if cache is not None:
        # Held so the ids in the key (one engine per entry) can't be reused mid-pass.
        cache[key] = ((gate, provenance, entry), deepcopy(tree) if tree is not None else None)
    return tree


def _chain_key(chain):
    return tuple(id(call) for call in chain)


def _postdominates(start, guard):
    todo, seen = [start], set()
    found = False
    while todo:
        node = todo.pop()
        if node is guard:
            found = True
            continue
        if node in seen:
            continue
        seen.add(node)
        if not node.sons:
            return False
        todo.extend(node.sons)
    return found


def _guard_trees(unit, site, chain, entry, provenance, gates):
    out = []
    covered_nodes = set()
    for gate in gates:
        owner = gate.containing_function or unit
        anchor = getattr(gate.call_chain[0], "node", None) if gate.call_chain else gate.node
        if anchor is None:
            out.append(unknown("guard_location_not_determined"))
            continue
        dominates = anchor in site.dominators
        after = _reachable(site, anchor)
        if not dominates and not after:
            continue
        if not dominates and not _postdominates(site, anchor):
            out.append(unknown("conditional_post_effect_guard"))
            continue
        if gate.call_chain and not mandatory(gate.node, owner):
            # Loop/branch helper conditions need a summary; they cannot all be conjoined.
            unresolved = unknown("helper_control_requires_summary")
            unresolved_leaf = unresolved.get("leaf")
            assert unresolved_leaf is not None
            unresolved_leaf["source_function"] = owner.canonical_name
            unresolved_leaf["source_node_id"] = gate.node.node_id
            out.append(unresolved)
            continue
        bound = replace(gate, call_chain=[*chain, *gate.call_chain])
        tree = _lower(bound, provenance, entry, ("gate", id(gate), _chain_key(chain), id(provenance)))
        out.append(tree or unknown("effect_guard_not_lowered"))
        if owner is unit:
            covered_nodes.add(gate.node)
    # ``dominators`` is an identity-hashed set; iterate in node order so the AND's children don't follow memory layout.
    for node in sorted(site.dominators, key=lambda n: n.node_id):
        if node is site or node in covered_nodes or getattr(node.type, "name", "") != "IF":
            continue
        true, false = getattr(node, "son_true", None), getattr(node, "son_false", None)
        reaches_true = true is not None and _reachable(true, site)
        reaches_false = false is not None and _reachable(false, site)
        if reaches_true == reaches_false:
            continue
        condition = next((ir.value for ir in node.irs if isinstance(ir, Condition)), None)
        gate = RevertGate(
            kind="if_revert",
            condition_value=condition,
            polarity="allowed_when_true" if reaches_true else "allowed_when_false",
            node=node,
            containing_function=unit,
            call_chain=list(chain),
            expression_text=str(condition),
            basis=["effect_control_dependency"],
        )
        tree = (
            _lower(gate, provenance, entry, ("dominator", id(node), gate.polarity, _chain_key(chain), id(provenance)))
            if condition is not None
            else None
        )
        out.append(tree or unknown("effect_branch_not_lowered"))
    conditional = _conditional_prefix(unit, site, chain, entry, provenance, gates)
    if conditional is not None:
        out.append(conditional)
    return out


def _authorization_leaves(tree):
    if not isinstance(tree, dict):
        return []
    leaf = tree.get("leaf") or {}
    descriptor = leaf.get("set_descriptor") or {}
    if descriptor.get("kind") in ("signature_threshold", "authorization_threshold", "authorization_unresolved"):
        return [deepcopy(tree)]
    if tree.get("op") == "OR":
        return []
    return [leaf for child in tree.get("children", []) for leaf in _authorization_leaves(child)]


def _consume_summary_guards(tree, summaries):
    for summary in summaries:
        proof = (summary.get("leaf") or {})["set_descriptor"]
        leaf = tree.get("leaf") or {}
        if (
            leaf.get("source_function") == proof["source_function"]
            and leaf.get("source_node_id") in proof["consumed_nodes"]
        ):
            return None
    if tree.get("op") == "LEAF":
        return tree
    children = [t for c in tree.get("children", []) if (t := _consume_summary_guards(c, summaries)) is not None]
    return {**tree, "children": children} if children else None


def attach_effect_scopes(contract, predicates, effects):
    # Every guard at every site re-lowers the same helper gates; without the helper-engine cache each one re-runs
    # provenance from scratch.
    engine_token = _helper_engine_cache.set({})
    reachable_token = _reachable_cache.set({})
    lowered_token = _lowered_cache.set({})
    try:
        _attach_effect_scopes(contract, predicates, effects)
    finally:
        _lowered_cache.reset(lowered_token)
        _reachable_cache.reset(reachable_token)
        _helper_engine_cache.reset(engine_token)


def _attach_effect_scopes(contract, predicates, effects):
    if not isinstance(effects, dict) or not isinstance(predicates, dict):
        return
    functions = effects.get("functions")
    if not isinstance(functions, dict) or "error" in predicates:
        return
    with structural_scope(contract):
        scopes = {}
        gate_cache = {}
        sites_by_function = {}
        for entry in getattr(contract, "functions_entry_points", []):
            record = functions.get(entry.full_name)
            if record is None or not record.get("state_changing"):
                continue
            if _callee_always_reverts(entry):
                record["execution_outcome"] = "always_reverts"
                continue
            record_sinks = record.get("sinks") or []
            engine = ProvenanceEngine(entry)
            engine.run()
            sites = []
            entry_params = {id(p): i for i, p in enumerate(entry.parameters)}
            summaries = _authorization_leaves((predicates.get("trees") or {}).get(entry.full_name))
            incomplete = []

            def walk(unit, chain, inherited, ancestors, origin):
                if unit in ancestors or len(chain) > 6 or len(sites) >= 256:
                    incomplete.append("effect_call_graph_incomplete")
                    return
                evidence_for(contract).summary(unit)
                _, unit_prov, _ = _build_chain_bindings(chain, unit, entry, top_prov=engine.provenance)
                unit_prov = unit_prov or engine.provenance
                for node in getattr(unit, "nodes", []):
                    if len(sites) >= 256:
                        incomplete.append("effect_site_budget")
                        break
                    candidates = [("state_write", var, None, None) for var in _node_kind_state_writes(node)]
                    candidates += _classify_node_irs(node, unit, entry_params, contract)
                    for ir in node.irs:
                        if isinstance(ir, (Send, Transfer)):
                            candidates.append(("external_call", str(ir.destination), None, None))
                    calls = [ir for ir in node.irs if isinstance(ir, (InternalCall, LibraryCall))]
                    if not candidates and not calls:
                        continue
                    if id(unit) not in gate_cache:
                        gate_cache[id(unit)] = RevertDetector(unit).run()
                    local = _guard_trees(unit, node, chain, entry, engine.provenance, gate_cache[id(unit)])
                    required = [*inherited, *local]
                    if any(predicate_truth(t) is False for t in required):
                        continue
                    for kind, target, selector, _ in candidates:
                        paths = [str(getattr(getattr(c, "node", None), "node_id", "unknown")) for c in chain]
                        site_id = "/".join(
                            [entry.full_name, *paths, unit.canonical_name, str(node.node_id), kind, target]
                        )
                        tree = make_and_node(deepcopy(required)) if required else None
                        if summaries:
                            tree = _consume_summary_guards(tree, summaries) if tree else None
                            tree = make_and_node([*deepcopy(summaries), *([tree] if tree else [])])
                        matching = [
                            s["id"]
                            for s in record_sinks
                            if s["kind"] == kind and s["target"] == target and s.get("selector") == selector
                        ]
                        sites.append(
                            {
                                "id": site_id,
                                "kind": kind,
                                "target": target,
                                "origin": origin,
                                "sink_ids": matching,
                                "declaration": unit.canonical_name,
                                "node": node.node_id,
                            }
                        )
                        calls_at_site = []
                        for ir in node.irs:
                            destination = payload = None
                            if isinstance(ir, LowLevelCall) and str(ir.function_name) in (
                                "call",
                                "delegatecall",
                                "staticcall",
                            ):
                                destination = ir.destination
                                payload = ir.arguments[0] if ir.arguments else None
                            elif isinstance(ir, SolidityCall) and ir.function.name.startswith(
                                ("call(", "delegatecall(", "staticcall(")
                            ):
                                destination = ir.arguments[1]
                                payload = ir.arguments[3 if ir.function.name.startswith("call(") else 2]
                            if destination is None or payload is None:
                                continue
                            dest = _operand_for_value(destination, unit_prov)
                            data = _operand_for_value(payload, unit_prov)
                            origins = [data, *(data.get("derived_from") or [])]
                            data_indices = {o.get("parameter_index") for o in origins if o.get("source") == "parameter"}
                            dest_index = dest.get("parameter_index") if dest.get("source") == "parameter" else None
                            if dest_index is not None and len(data_indices) == 1:
                                data_index = next(iter(data_indices))
                                if data_index is not None and str(entry.parameters[data_index].type).startswith(
                                    "bytes"
                                ):
                                    calls_at_site.append({"destination": dest_index, "payload": data_index})
                        if kind in ("external_call", "delegatecall") and len(calls_at_site) == 1:
                            sites[-1]["forwarded_parameters"] = calls_at_site[0]
                        scopes[site_id] = tree
                    for call in calls:
                        callee = call.function
                        if getattr(callee, "nodes", None):
                            walk(
                                callee,
                                [*chain, call],
                                required,
                                (*ancestors, unit),
                                "guard" if origin == "guard" or _is_modifier_call(call) else "body",
                            )
                        elif not getattr(callee, "is_implemented", False):
                            incomplete.append("effect_helper_body_unavailable")

            walk(entry, [], [], (), "body")
            if incomplete:
                for site in sites:
                    scopes[site["id"]] = (
                        make_and_node([scopes[site["id"]], unknown(incomplete[0])])
                        if scopes[site["id"]]
                        else unknown(incomplete[0])
                    )
            if incomplete:
                missing_id = entry.full_name + "/unresolved_effects"
                scopes[missing_id] = unknown(incomplete[0])
                sites.append(
                    {
                        "id": missing_id,
                        "kind": "unresolved_effect",
                        "target": "unresolved",
                        "origin": "body",
                        "sink_ids": [s["id"] for s in record_sinks],
                        "declaration": entry.canonical_name,
                        "node": None,
                    }
                )
            record["effect_scopes_complete"] = not incomplete
            sites_by_function[entry.full_name] = sites
        known = deepcopy(predicates.get("trees") or {})
        classified = {**known, **{k: v for k, v in scopes.items() if v is not None}}
        apply_writer_gate_pass(contract, classified)
        apply_reentrancy_pause_pass(contract, classified)
        # Membership inventories are source evidence shared with the entry analysis; do not synthesize per-site quorums.
        from .authorization import attach_membership_inventories

        attach_membership_inventories(contract, classified)
        attach_storage_dependencies(contract, classified, sites_by_function)
        for signature, sites in sites_by_function.items():
            for site in sites:
                tree = classified.get(site["id"])
                site["predicate"] = tree
            functions[signature]["effect_scopes"] = sites
        predicates["effect_scopes"] = {sig: sites for sig, sites in sites_by_function.items() if sites}
        effects["effect_scopes_version"] = 1


def _conditional_prefix(unit, site, chain, entry, provenance, gates):
    """Bounded path summaries for guards before a join. Dominance alone loses these alternatives."""
    import json

    from .predicates.control_flow import _node_terminates_control
    from .structural_evidence import predicate_truth

    anchored = {}
    needed = False
    for gate in gates:
        anchor = getattr(gate.call_chain[0], "node", None) if gate.call_chain else gate.node
        if anchor is None or not _reachable(anchor, site):
            continue
        anchored.setdefault(anchor, []).append(gate)
        needed |= anchor not in site.dominators and not _reachable(site, anchor)
    if not needed:
        return None
    summary = evidence_for(unit.contract).summary(unit)

    def literal_key(value):
        expression = summary.expression(value)
        polarity = True
        while expression.get("kind") == "unary" and expression.get("operator") == "BANG":
            polarity = not polarity
            expression = expression["value"]
        if expression.get("kind") == "binary" and expression.get("operator") == "NOT_EQUAL":
            expression = {**expression, "operator": "EQUAL"}
            polarity = not polarity

        def immutable(expr):
            if not isinstance(expr, dict):
                return True
            if expr.get("kind") in ("unknown", "storage", "storage_cell", "call"):
                return False
            return all(immutable(v) for v in expr.values() if isinstance(v, dict))

        return (json.dumps(expression, sort_keys=True), polarity) if immutable(expression) else (None, True)

    paths = []
    pending = [(unit.entry_point, [], {}, frozenset())]
    visited_steps = 0
    while pending:
        node, facts, literals, visited = pending.pop()
        visited_steps += 1
        if visited_steps > 512 or len(paths) + len(pending) > 64:
            return unknown("effect_path_budget")
        if node is site:
            paths.append(make_and_node(facts) if facts else None)
            continue
        if node in visited:
            return unknown("effect_loop_requires_summary")
        if _node_terminates_control(node):
            continue
        current = list(facts)
        for gate in anchored.get(node, []):
            owner = gate.containing_function or unit
            if gate.call_chain and not mandatory(gate.node, owner):
                current.append(unknown("helper_control_requires_summary"))
                continue
            bound = replace(gate, call_chain=[*chain, *gate.call_chain])
            tree = _lower(bound, provenance, entry, ("gate", id(gate), _chain_key(chain), id(provenance)))
            current.append(tree or unknown("effect_guard_not_lowered"))
        if any(predicate_truth(t) is False for t in current):
            continue
        conditions = [ir.value for ir in node.irs if isinstance(ir, Condition)]
        if conditions and len(node.sons) == 2:
            value = conditions[-1]
            key, orientation = literal_key(value)
            for branch, positive in ((node.son_true, True), (node.son_false, False)):
                if branch is None or not _reachable(branch, site):
                    continue
                state = positive == orientation
                if key is not None and key in literals and literals[key] != state:
                    continue
                gate = RevertGate(
                    kind="if_revert",
                    condition_value=value,
                    polarity="allowed_when_true" if positive else "allowed_when_false",
                    node=node,
                    containing_function=unit,
                    call_chain=list(chain),
                    expression_text=str(value),
                    basis=["effect_path_condition"],
                )
                tree = _lower(
                    gate, provenance, entry, ("path", id(node), gate.polarity, _chain_key(chain), id(provenance))
                )
                if tree is not None and predicate_truth(tree) is False:
                    continue
                if key is None and (tree is None or predicate_truth(tree) is not True):
                    tree = make_and_node(
                        [tree or unknown("effect_branch_not_lowered"), unknown("effect_condition_value_unresolved")]
                    )
                next_literals = {**literals, **({key: state} if key is not None else {})}
                pending.append(
                    (branch, [*current, tree or unknown("effect_branch_not_lowered")], next_literals, visited | {node})
                )
        else:
            pending.extend((son, current, literals, visited | {node}) for son in node.sons if _reachable(son, site))
    if not paths:
        return unknown("effect_path_not_proven")
    if any(p is None for p in paths):
        # An explicitly enumerated path reaches this site without a guard.
        return None
    return make_or_node(paths)
