"""Proven caller restriction for the functions that can emit an event: an event may testify to a mapping write only
if its paths are closed to the crowd. Policy's ``authority_openness`` isn't available when the tracking plan is
built, so this proves it from the lowered trees.

The earned-public shape test runs unconditionally here even though resolution gates it behind
``PSAT_AUTHORITY_EARNED_PUBLIC``: there it opens capabilities, here it only withholds a promotion, and honouring the
flag would let a denylist gate qualify every ``Transfer`` (pinned by ``test_the_kill_switch_cannot_promote``).

Only ``restricted`` is minted; trees can't tell "no gate" from "a gate we failed to lower", so unproven is not
determined, which the tier classifier treats like open.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from utils.scoring_status import OPENNESS_NOT_DETERMINED, OPENNESS_RESTRICTED

from .shared import external_bool_leaf_is_gate_shape

# Roles that constrain who calls; the rest constrain when or how.
_AUTHORITY_LEAF_ROLES = frozenset({"caller_authority", "delegated_authority"})


def _leaf_restricts_caller(leaf: Mapping[str, Any]) -> bool:
    """True when this leaf alone admits only a set of callers: it has an authority role, an ``external_bool`` callee
    is gate-shaped, and it isn't an earned-public shape. ``require(!fromDenyList[msg.sender])`` is
    ``caller_authority`` but admits everyone not listed; counting it would qualify every ``Transfer`` on a
    denylisted token.
    """
    # Deferred to avoid an import cycle; the earned-public test is shared, not copied.
    from services.resolution.permissionless_shapes import (
        is_permissionless_caller_shape,
        leaf_is_caller_tainted,
    )

    if leaf.get("authority_role") not in _AUTHORITY_LEAF_ROLES:
        return False
    if leaf.get("kind") == "external_bool":
        descriptor = leaf.get("set_descriptor")
        descriptor_signature = descriptor.get("callee_signature") if isinstance(descriptor, dict) else None
        if not external_bool_leaf_is_gate_shape(
            leaf.get("callee_state_mutability"),
            leaf.get("gate_kind"),
            leaf.get("callee_signature") or descriptor_signature,
        ):
            return False
    if leaf_is_caller_tainted(leaf) and is_permissionless_caller_shape(leaf):  # pyright: ignore[reportArgumentType]
        return False
    return True


def _tree_restricts_caller(node: Any) -> bool:
    """True when every path into the body passes an authority leaf: an AND needs one restricting conjunct, an OR
    needs all branches (no NOT in the grammar).
    """
    if not isinstance(node, dict):
        return False
    op = node.get("op")
    if op == "LEAF":
        leaf = node.get("leaf")
        return isinstance(leaf, dict) and _leaf_restricts_caller(leaf)
    children = node.get("children") or []
    if not children:
        return False
    if op == "AND":
        return any(_tree_restricts_caller(child) for child in children)
    if op == "OR":
        return all(_tree_restricts_caller(child) for child in children)
    return False


def restricted_function_signatures(predicate_trees: Mapping[str, Any] | None) -> frozenset[str]:
    """Full names of functions whose tree proves a caller restriction; treeless functions are absent (unanswered)."""
    if not isinstance(predicate_trees, Mapping):
        return frozenset()
    trees = predicate_trees.get("trees")
    if not isinstance(trees, Mapping):
        return frozenset()
    return frozenset(
        signature
        for signature, tree in trees.items()
        if isinstance(signature, str) and signature and _tree_restricts_caller(tree)
    )


def openness_of_write_paths(emitters: set[str], writers: set[str], restricted: frozenset[str]) -> str:
    """Openness of the mapping whose entry changes an event announces: every emitter restricted, and every writer of
    the mapping restricted.

    The emitter set can't be complete (assembly ``log2`` emits appear in no ``EventCall``), so the writer quantifier
    carries the claim: an unseen emitter that changes the mapping must write it, and effects attributes that write.
    Either set empty is not determined.
    """
    if not emitters or not writers:
        return OPENNESS_NOT_DETERMINED
    if emitters <= restricted and writers <= restricted:
        return OPENNESS_RESTRICTED
    return OPENNESS_NOT_DETERMINED
