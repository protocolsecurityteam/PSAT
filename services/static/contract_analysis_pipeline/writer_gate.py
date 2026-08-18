"""Writer-gate analyzer — pass 2 of the predicate pipeline.

For 1-key caller-keyed bool/uint mappings, the predicate builder's
pass 1 conservatively classifies them as ``authority_role="business"``
because the same structural shape covers both:
  - ``claimed[msg.sender]``        (personal flag, business)
  - ``_blacklist[msg.sender]``     (auth, set by an admin)
  - ``wards[msg.sender]``          (auth, self-administered Maker style)

Pass 2 disambiguates by inspecting how the underlying storage var is
*written*. The discriminator both auth and personal-flag shapes share:
**how the writer keys the mapping at write time.**

Rules (v7, simplified initial cut):
  a. If ALL writers are self_keyed (``map[msg.sender] = ...``) →
     personal flag → leave as business.
  b.i. If at least one writer is external_keyed (``map[arg] = ...``)
       AND every external_keyed writer's predicate tree contains
       a ``caller_authority`` or ``delegated_authority`` leaf
       → promote the read leaf to ``caller_authority``.
  b.ii. (Self-administered, like Maker wards): the writer reads the
        same map M as its own gate. Detect by checking the writer's
        predicate tree for a membership leaf reading M. Promote if
        present.
  c. (Open registration / public assignment) — at least one writer
     is external_keyed AND ungated. Leaf stays business; future UI
     can surface the open writer.
  d. (Constructor-only init) — TODO.

Implementation lives outside the per-function builder so it can see
the whole contract.
"""

from __future__ import annotations

from typing import Any, cast

from .predicate_types import LeafPredicate, PredicateTree
from .slither_compat import SLITHER_AVAILABLE, Assignment, Binary, Constant, Index


def apply_writer_gate_pass(
    contract: Any,
    predicate_trees: dict[str, PredicateTree],
) -> None:
    """Mutates ``predicate_trees`` in place. Promotes 1-key caller-
    keyed membership leaves from authority_role="business" to
    "caller_authority" when the underlying storage var's writers
    are themselves authority-gated. Iterates to fixed point so
    chained authority dependencies (e.g., M-of-N counter
    promotions that depend on isOwner being promoted first)
    converge.
    """
    if not SLITHER_AVAILABLE:
        raise RuntimeError("writer-gate analyzer requires slither")

    writers_by_var: dict[str, list[Any]] = {}
    for fn in contract.functions:
        for sv in fn.state_variables_written:
            writers_by_var.setdefault(sv.name, []).append(fn)

    # Iterate to fixed point. Each pass may promote more leaves;
    # subsequent passes can use those new authority leaves to
    # promote downstream (M-of-N counters whose approvers are now
    # known authority). Cap at 8 iterations to bound work; in
    # practice converges in ≤3.
    for _ in range(8):
        before = _snapshot_authority_roles(predicate_trees)
        for tree in predicate_trees.values():
            if tree is None:
                continue
            _walk_and_promote(tree, writers_by_var, predicate_trees, contract)
        after = _snapshot_authority_roles(predicate_trees)
        if after == before:
            break

    # Re-stamp confidence on every leaf so writer-gate-promoted
    # leaves don't carry the pre-promotion (low/business) value.
    from .predicates import apply_confidence_to_tree

    for tree in predicate_trees.values():
        apply_confidence_to_tree(tree)


def _snapshot_authority_roles(trees: dict[str, PredicateTree]) -> tuple:
    """Return a hashable snapshot of every leaf's authority_role —
    used to detect fixed-point convergence."""
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


# ---------------------------------------------------------------------------
# Tree walk
# ---------------------------------------------------------------------------


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

    # Path 1: 1-key caller-keyed bool/uint membership (rules a/b.i/b.ii/c).
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

    # Path 2: comparison leaf with threshold shape.
    # ``map[msg.sender] >= threshold`` is an authority gate (not a
    # self-service quantity check) when the keyed value cannot be
    # self-acquired — i.e. the mapping's writers are themselves
    # authority-gated (admin-curated tier/level/allowance). That is the
    # same writer-gating signal the 1-key membership path uses, applied
    # to the caller-keyed READ. The F2 authority-derived M-of-N counter
    # (additive, parameter-keyed) is the second promotion shape.
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


# ---------------------------------------------------------------------------
# Writer classification
# ---------------------------------------------------------------------------


def _index_ref_name(ir: Any) -> str:
    # Slither declares ``lvalue`` optional on the Operation base; an Index always binds one.
    return cast(str, ir.lvalue.name)


def _classify_writers(
    storage_var: str,
    writers: list[Any],
    all_trees: dict[str, PredicateTree],
) -> str:
    """Returns one of:
    - "promote_self_admin"  — every external_keyed writer is gated by
      reading the same storage var (rule b.ii). Tight self-admin ACL
      shape; downstream confidence is HIGH.
    - "promote"  — every external_keyed writer is gated, with at least
      one writer gated by some other authority leaf (rule b.i).
      Confidence is MEDIUM because the auth signal is transitive.
    - "keep_business" — rule a (all self-keyed) or rule c (open
      registration)
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

    # Rule a: ALL self_keyed → business.
    if write_kinds and all(k == "self_keyed" for k in write_kinds):
        return "keep_business"

    if not external_writer_gates:
        return "keep_business"

    if all(gating == "self_admin" for gating in external_writer_gates):
        return "promote_self_admin"

    return "promote"


def _classify_writer_keys(fn: Any, storage_var: str) -> list[str]:
    """For each Index+Assignment pair targeting ``storage_var``,
    classify how the index key is sourced. Returns a list of
    self_keyed / external_keyed / constant_keyed classifications,
    one per write site in the function.

    Self_keyed: key is msg.sender (or aliased to it).
    External_keyed: key is a function parameter or computed value.
    Constant_keyed: key is a literal constant.
    """
    classifications: list[str] = []
    # Find Index IRs whose base is the target storage var, and
    # check whether the Index's lvalue is later assigned to. This is
    # a coarse but adequate detection — we don't need full data-flow
    # for the classification, just the immediate write site.
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
    """Determine whether the key is msg.sender, a parameter, or a
    constant. Falls back to external_keyed when uncertain."""
    if isinstance(key, Constant):
        return "constant_keyed"
    name = getattr(key, "name", "")
    if name == "msg.sender" or name == "tx.origin":
        return "self_keyed"
    # Heuristic: check the Slither variable type. LocalIRVariable
    # / TemporaryVariable from a parameter or computation maps to
    # external_keyed. ProvenanceEngine could give a more precise
    # answer; for now, anything not msg.sender and not Constant is
    # external_keyed (parameter / computed / view-call).
    return "external_keyed"


def _writer_gating_kind(
    fn: Any,
    storage_var: str,
    all_trees: dict[str, PredicateTree],
) -> str | None:
    """Returns 'self_admin' (rule b.ii: writer's own gate reads the
    same map M), 'other_auth' (rule b.i: writer has caller_authority
    or delegated_authority on something else), or None (ungated).
    Self-admin takes precedence when both shapes are present —
    Maker-style wards are the canonical case and treated as the
    tighter signal."""
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


# ---------------------------------------------------------------------------
# F2 — authority-derived state (M-of-N counter detection)
# ---------------------------------------------------------------------------


def _is_authority_derived_counter(
    storage_var: str,
    writers: list[Any],
    all_trees: dict[str, PredicateTree],
) -> bool:
    """Returns True iff the storage var qualifies as an authority-
    derived counter — a counter whose value advances only via
    additions performed by authority-gated functions.

    Per codex round-7 (F2) and false-positive defenses:
      1. At least one writer performs an additive update
         (`map[k] = map[k] + N` or compound `+=`)
      2. That writer's predicate tree contains a caller_authority
         or delegated_authority leaf
      3. The write key sources from a parameter (the "object being
         authorized" — e.g., txHash), NOT msg.sender (which would
         be a self-keyed cooldown / personal counter)
      4. NO writer performs a non-additive overwrite gated by less
         authority (admin-settable counters are reset risks)

    These constraints together exclude the common false positives
    codex enumerated: balanceOf-style external returns (not state),
    rate limits (self-keyed), token transfers (decrement-dominant),
    quorum/votes via ungated public increments.
    """
    has_authority_additive_writer = False
    has_unguarded_settable_writer = False
    for fn in writers:
        sites = _additive_write_sites(fn, storage_var)
        if not sites:
            # Non-additive writer — risk of admin-set / reset.
            if _has_state_var_assignment(fn, storage_var):
                tree = all_trees.get(fn.full_name)
                if tree is None or not (_tree_has_other_authority(tree) or _tree_has_self_admin(tree, storage_var)):
                    has_unguarded_settable_writer = True
            continue
        # All write sites in this function are additive. Check
        # function authority + parameter-keyed writes.
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
    """Find all additive write sites in ``fn`` for ``storage_var``.

    Detects the Slither IR pattern Slither emits for ``map[k] += N``:
      Index: REF = map[k]
      Binary(ADD/SUB): REF (-> map_2) = REF (c)+ N
    The Binary IR's lvalue == its left operand (read-then-write
    self-modification), and the lvalue traces to an Index of the
    target storage var.

    Returns the list of (Index_IR, Binary_IR) tuples for each
    additive site. Empty if the function doesn't additively
    modify ``storage_var``.
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
                        # Self-add pattern: lvalue equals one of the operands' name.
                        left_name = getattr(ir.variable_left, "name", None)
                        if left_name == lv_name:
                            sites.append((indexes_by_ref[lv_name], ir))
    return sites


def _write_key_sources_from_parameter(site: tuple) -> bool:
    """The Index in an additive write site keys on a parameter
    (not msg.sender). Distinguishes M-of-N (key=txHash, parameter)
    from cooldown (key=msg.sender, self-keyed)."""
    index_ir, _binary_ir = site
    key = getattr(index_ir, "variable_right", None)
    if key is None:
        return False
    name = getattr(key, "name", "")
    if name in ("msg.sender", "tx.origin"):
        return False
    if isinstance(key, Constant):
        return False  # constant key — bizarre, exclude
    # If key is a parameter / local / temp, accept. Slither LocalIRVariable
    # for a parameter looks the same as for a local; the predicate
    # builder's provenance engine would distinguish, but for this
    # structural test the rejection of msg.sender is sufficient.
    return True


def _has_state_var_assignment(fn: Any, storage_var: str) -> bool:
    """Returns True iff ``fn`` directly assigns to ``storage_var``
    (write-replace, not additive update)."""
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
