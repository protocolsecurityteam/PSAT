from typing import Any

from services.static.contract_analysis_pipeline.predicates import build_predicate_tree
from services.static.contract_analysis_pipeline.reentrancy_pause import apply_reentrancy_pause_pass
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass


def _all_leaves(tree):
    if tree is None:
        return []
    if tree.get("op") == "LEAF":
        return [tree["leaf"]] if tree.get("leaf") else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_all_leaves(child))
    return out


def _build_trees(contract):
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    return trees


def _build_pipeline(contract):
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    return trees


def _caller_operand(tree: Any) -> dict[str, Any]:
    out: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            if leaf.get("kind") == "equality" and leaf.get("authority_role") == "caller_authority":
                out.extend(o for o in (leaf.get("operands") or []) if o.get("source") != "msg_sender")
            return
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    assert len(out) == 1, f"expected one caller operand, got {out}"
    return out[0]
