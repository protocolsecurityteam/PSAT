"""Writer-gate pass (pass 2 of the predicate pipeline).

Pass 1 leaves single-key caller-keyed mappings as business because ``claimed[msg.sender]`` (personal flag),
``_blacklist[msg.sender]`` (admin-set) and ``wards[msg.sender]`` (self-administered) look alike. Pass 2 decides from how
the mapping is written: all writers self-keyed (a) stays business; every external-keyed writer caller-gated (b.i) or
gated on the same map (b.ii, Maker wards) promotes to ``caller_authority``; an ungated external-keyed writer (c, open
registration) stays business. Contract-wide, so it lives outside the per-function builder.
"""

from __future__ import annotations

from typing import Any, cast

from .predicate_types import LeafPredicate, PredicateTree
from .slither_compat import SLITHER_AVAILABLE, Assignment, Binary, Constant, Index


def apply_writer_gate_pass(
    contract: Any,
    predicate_trees: dict[str, PredicateTree],
) -> None:
    """Promote single-key caller-keyed membership leaves to ``caller_authority`` when the mapping's writers are
    authority-gated, in place, iterating to a fixed point so chained promotions (M-of-N counters approved by a
    newly promoted owner) converge.
    """
    if not SLITHER_AVAILABLE:
        raise RuntimeError("writer-gate analyzer requires slither")

    writers_by_var: dict[str, list[Any]] = {}
    for fn in contract.functions:
        for sv in fn.state_variables_written:
            writers_by_var.setdefault(sv.name, []).append(fn)

    # Capped at 8; converges in 3 or fewer in practice.
    for _ in range(8):
        before = _snapshot_authority_roles(predicate_trees)
        for tree in predicate_trees.values():
            if tree is None:
                continue
            _walk_and_promote(tree, writers_by_var, predicate_trees, contract)
        after = _snapshot_authority_roles(predicate_trees)
        if after == before:
            break

    # Promoted leaves need fresh confidence.
    from .predicates import apply_confidence_to_tree

    for tree in predicate_trees.values():
        apply_confidence_to_tree(tree)


def _snapshot_authority_roles(trees: dict[str, PredicateTree]) -> tuple:
    """Hashable snapshot of every leaf's ``authority_role``, for convergence."""
    out: list[tuple] = []
    for name in sorted(trees):
        out.append((name, _tree_role_signature(trees[name])))
    return tuple(out)


def _tree_role_signature(tree: PredicateTree | None) -> tuple:
    if tree is None:
        return ()
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf") or {}
        return ("LEAF", leaf.get("authority_role"))
    return tuple(("BR", _tree_role_signature(c)) for c in tree.get("children") or [])


def _walk_and_promote(
    tree: PredicateTree,
    writers_by_var: dict[str, list[Any]],
    all_trees: dict[str, PredicateTree],
    contract: Any,
) -> None:
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is not None:
            _maybe_promote_leaf(leaf, writers_by_var, all_trees, contract)
        return
    for child in tree.get("children") or []:
        _walk_and_promote(child, writers_by_var, all_trees, contract)


def _maybe_promote_leaf(
    leaf: LeafPredicate,
    writers_by_var: dict[str, list[Any]],
    all_trees: dict[str, PredicateTree],
    contract: Any,
) -> None:
    if leaf.get("authority_role") != "business":
        return  # already classified
    descriptor = leaf.get("set_descriptor")
    if not descriptor:
        return
    storage_var = descriptor.get("storage_var")
    if not storage_var:
        return
    writers = writers_by_var.get(storage_var, [])
    if not writers:
        return

    if leaf.get("kind") == "membership":
        keys = descriptor.get("key_sources") or []
        if len(keys) != 1:
            return
        if keys[0]["source"] not in ("msg_sender", "tx_origin", "signature_recovery"):
            return
        classification = _classify_writers(storage_var, writers, all_trees)
        if classification == "promote_self_admin":
            leaf["authority_role"] = "caller_authority"
            leaf["basis"] = list(leaf.get("basis", [])) + [
                f"writer-gate promoted: {storage_var} self-administered (writer reads same map)",
            ]
        elif classification == "promote":
            leaf["authority_role"] = "caller_authority"
            leaf["basis"] = list(leaf.get("basis", [])) + [
                f"writer-gate promoted: {storage_var} writers are authority-gated",
            ]
        return

    # ``map[msg.sender] >= threshold`` is an authority gate when the value can't be self-acquired (its writers are
    # gated), the same signal as the membership path. Authority-derived M-of-N counters are the second shape.
    if leaf.get("kind") == "comparison" and leaf.get("operator") in ("gt", "gte", "lt", "lte"):
        keys = descriptor.get("key_sources") or []
        caller_keyed = len(keys) == 1 and keys[0].get("source") in (
            "msg_sender",
            "tx_origin",
            "signature_recovery",
        )
        if caller_keyed:
            classification = _classify_writers(storage_var, writers, all_trees)
            if classification in ("promote", "promote_self_admin"):
                leaf["authority_role"] = "caller_authority"
                leaf["basis"] = list(leaf.get("basis", [])) + [
                    f"threshold-promote: {storage_var} writers are authority-gated",
                ]
                return
        if _is_authority_derived_counter(storage_var, writers, all_trees):
            leaf["authority_role"] = "caller_authority"
            leaf["basis"] = list(leaf.get("basis", [])) + [
                f"threshold-promote: {storage_var} is authority-derived counter",
            ]
        return


def _index_ref_name(ir: Any) -> str:
    return cast(str, ir.lvalue.name)


def _classify_writers(
    storage_var: str,
    writers: list[Any],
    all_trees: dict[str, PredicateTree],
) -> str:
    """``promote_self_admin`` (b.ii, every external writer gated on the same map; high confidence), ``promote`` (b.i,
    gated by other authority; transitive, medium), or ``keep_business`` (a or c).
    """
    write_kinds: list[str] = []  # per write site
    external_writer_gates: list[str] = []
    for fn in writers:
        kinds = _classify_writer_keys(fn, storage_var)
        write_kinds.extend(kinds)
        if "external_keyed" in kinds:
            gating = _writer_gating_kind(fn, storage_var, all_trees)
            if gating is None:
                return "keep_business"
            external_writer_gates.append(gating)

    if write_kinds and all(k == "self_keyed" for k in write_kinds):
        return "keep_business"

    if not external_writer_gates:
        return "keep_business"

    if all(gating == "self_admin" for gating in external_writer_gates):
        return "promote_self_admin"

    return "promote"


def _classify_writer_keys(fn: Any, storage_var: str) -> list[str]:
    """Per write site to ``storage_var``: whether the index key is ``self_keyed`` (``msg.sender``),
    ``external_keyed`` (parameter or computed) or ``constant_keyed``.
    """
    classifications: list[str] = []
    # Index IRs on the target var whose lvalue is later assigned; the immediate write site is enough here.
    write_index_lvalues: set[str] = set()
    indexes_by_ref: dict[str, Any] = {}
    for node in fn.nodes:
        for ir in node.irs_ssa or []:
            if isinstance(ir, Index):
                base = ir.variable_left
                base_name = getattr(base, "name", None)
                if base_name == storage_var:
                    indexes_by_ref[_index_ref_name(ir)] = ir
            elif isinstance(ir, Assignment):
                lv_name = getattr(ir.lvalue, "name", None)
                if lv_name in indexes_by_ref:
                    write_index_lvalues.add(lv_name)

    for ref_name, ix in indexes_by_ref.items():
        if ref_name not in write_index_lvalues:
            continue  # not actually written — pure read
        key = ix.variable_right
        kind = _classify_key(key)
        classifications.append(kind)
    return classifications


def _classify_key(key: Any) -> str:
    """``msg.sender``, constant, or else ``external_keyed``."""
    if isinstance(key, Constant):
        return "constant_keyed"
    name = getattr(key, "name", "")
    if name == "msg.sender" or name == "tx.origin":
        return "self_keyed"
    return "external_keyed"


def _writer_gating_kind(
    fn: Any,
    storage_var: str,
    all_trees: dict[str, PredicateTree],
) -> str | None:
    """``self_admin`` (b.ii: the writer's gate reads the same map), ``other_auth`` (b.i), or None.

    Self-admin wins when both apply.
    """
    tree = all_trees.get(fn.full_name)
    if tree is None:
        return None
    if _tree_has_self_admin(tree, storage_var):
        return "self_admin"
    if _tree_has_other_authority(tree):
        return "other_auth"
    return None


def _tree_has_self_admin(tree: PredicateTree, storage_var: str) -> bool:
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is None:
            return False
        if leaf.get("kind") == "membership":
            sd = leaf.get("set_descriptor") or {}
            if sd.get("storage_var") == storage_var:
                return True
        return False
    for child in tree.get("children") or []:
        if _tree_has_self_admin(child, storage_var):
            return True
    return False


def _tree_has_other_authority(tree: PredicateTree) -> bool:
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is None:
            return False
        return leaf.get("authority_role") in ("caller_authority", "delegated_authority")
    for child in tree.get("children") or []:
        if _tree_has_other_authority(child):
            return True
    return False


def _is_authority_derived_counter(
    storage_var: str,
    writers: list[Any],
    all_trees: dict[str, PredicateTree],
) -> bool:
    """True iff ``storage_var`` is an authority-derived counter: some writer adds to it under a caller-authority
    tree, keyed by a parameter (the object being authorized, e.g. a txHash, not ``msg.sender``), and no writer
    overwrites it non-additively. Excludes external balance reads, self-keyed rate limits, decrementing transfers
    and ungated vote increments.
    """
    has_authority_additive_writer = False
    has_unguarded_settable_writer = False
    for fn in writers:
        sites = _additive_write_sites(fn, storage_var)
        if not sites:
            # A non-additive writer: reset risk.
            if _has_state_var_assignment(fn, storage_var):
                tree = all_trees.get(fn.full_name)
                if tree is None or not (_tree_has_other_authority(tree) or _tree_has_self_admin(tree, storage_var)):
                    has_unguarded_settable_writer = True
            continue
        all_param_keyed = all(_write_key_sources_from_parameter(site) for site in sites)
        if not all_param_keyed:
            continue
        tree = all_trees.get(fn.full_name)
        if tree is None:
            continue
        if _tree_has_other_authority(tree) or _tree_has_self_admin(tree, storage_var):
            has_authority_additive_writer = True

    return has_authority_additive_writer and not has_unguarded_settable_writer


def _additive_write_sites(fn: Any, storage_var: str) -> list[Any]:
    """Additive write sites for ``storage_var`` in ``fn``: an Index ``REF = map[k]`` followed by a Binary ADD/SUB
    whose lvalue is its own left operand. Returns ``(Index, Binary)`` pairs.
    """
    sites: list[Any] = []
    indexes_by_ref: dict[str, Any] = {}
    for node in fn.nodes:
        for ir in node.irs_ssa or []:
            if isinstance(ir, Index):
                base = ir.variable_left
                if getattr(base, "name", None) == storage_var:
                    indexes_by_ref[_index_ref_name(ir)] = ir
            elif isinstance(ir, Binary):
                lv = ir.lvalue
                lv_name = getattr(lv, "name", None)
                if lv_name in indexes_by_ref:
                    bt_name = getattr(getattr(ir, "type", None), "name", "").upper()
                    if bt_name == "ADDITION":
                        left_name = getattr(ir.variable_left, "name", None)
                        if left_name == lv_name:
                            sites.append((indexes_by_ref[lv_name], ir))
    return sites


def _write_key_sources_from_parameter(site: tuple) -> bool:
    """The additive site's key is a parameter, not ``msg.sender`` (M-of-N vs cooldown)."""
    index_ir, _binary_ir = site
    key = getattr(index_ir, "variable_right", None)
    if key is None:
        return False
    name = getattr(key, "name", "")
    if name in ("msg.sender", "tx.origin"):
        return False
    if isinstance(key, Constant):
        return False  # constant key — bizarre, exclude
    # Rejecting ``msg.sender`` is enough for this structural test.
    return True


def _has_state_var_assignment(fn: Any, storage_var: str) -> bool:
    """True iff ``fn`` directly assigns ``storage_var`` (replace, not add)."""
    indexes_by_ref: dict[str, Any] = {}
    for node in fn.nodes:
        for ir in node.irs_ssa or []:
            if isinstance(ir, Index):
                base = ir.variable_left
                if getattr(base, "name", None) == storage_var:
                    indexes_by_ref[_index_ref_name(ir)] = ir
            elif isinstance(ir, Assignment):
                lv_name = getattr(ir.lvalue, "name", None)
                if lv_name in indexes_by_ref:
                    return True
    return False
