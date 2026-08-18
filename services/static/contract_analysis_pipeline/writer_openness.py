"""Proven caller restriction for the functions that can emit an event.

An event may testify to a mapping write only if the paths that emit it are
closed to the crowd (F3's second fact). ``effective_functions.authority_openness``
answers that on the policy plane, but it is resolved from capability rows that
do not exist when the tracking plan is built, so this module proves the same
thing from the artifact the static stage already has: the lowered predicate
trees.

The earned-public shape test is applied unconditionally here, while the
resolution plane gates the same test behind ``PSAT_AUTHORITY_EARNED_PUBLIC``.
That is deliberate and it is the one place the two planes are meant to
disagree: there the test OPENS a capability, so a kill switch that disables it
narrows what gets published; here it only WITHHOLDS a promotion, so honouring
the switch would turn it into a promoter — with the flag off, a cofinite
denylist gate would read as a proof of restriction and every ERC-20 ``Transfer``
on a denylisted token would qualify as a witnessed member change. A kill switch
that widens published claims is not a kill switch, so this one does not reach
here (pinned by ``test_the_kill_switch_cannot_promote``).

Only ``restricted`` is ever minted. Proving ``open`` needs the resolution
plane's earned-public projection over a resolved capability; the static tree
alone cannot distinguish "no gate" from "a gate we failed to lower"
(a ``require`` with a custom error was exactly that blind spot). So this module
reports the third state wherever the restriction is unproven, which for the
tier classifier is behaviourally identical to ``open`` — both refuse the
promotion — and never publishes an unearned "anyone can call this".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from utils.scoring_status import OPENNESS_NOT_DETERMINED, OPENNESS_RESTRICTED

from .shared import external_bool_leaf_is_gate_shape

# The two leaf roles that state a constraint on WHO called. Everything else
# (time, pause, reentrancy, business, one_shot) constrains when or how, and a
# function guarded only by those is callable by anyone who meets them.
_AUTHORITY_LEAF_ROLES = frozenset({"caller_authority", "delegated_authority"})


def _leaf_restricts_caller(leaf: Mapping[str, Any]) -> bool:
    """True when this leaf, on its own, admits only a caller SET.

    Three conditions, each a demotion when it fails:

      * the classifier gave it an authority role — it is about the caller;
      * an ``external_bool`` leaf's callee is gate-shaped (the same guard
        ``tracking._leaf_asserts_caller_gate`` applies, so a value-movement
        call cannot pass as an authorization); and
      * the leaf is not one of the earned-public shapes. This is the arm that
        matters most here: ``require(!fromDenyList[msg.sender])`` carries
        ``caller_authority`` and gates nobody — a cofinite denylist admits
        every address it has not named. Counting it would qualify every ERC-20
        ``Transfer`` on a token with a denylist, which is the exact
        unwitnessed-publication this taxonomy exists to stop.
    """
    # Deferred: ``services.resolution`` imports the static pipeline at package
    # import time, so a module-level import here is a cycle. The earned-public
    # discriminators are shared rather than re-derived — a second copy of that
    # judgement would drift from the plane that owns it.
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
    if leaf_is_caller_tainted(leaf) and is_permissionless_caller_shape(leaf):  # type: ignore[arg-type]
        return False
    return True


def _tree_restricts_caller(node: Any) -> bool:
    """True when EVERY satisfying assignment of *node* passes an authority
    leaf — the gate holds on every path into the function body.

    ``AND`` needs one restricting conjunct; ``OR`` needs all of its branches to
    restrict, because a single open branch is an open function. There is no
    ``NOT`` in the tree grammar, so those two rules are the whole recursion.
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
    """The ``full_name`` of every function whose tree proves a caller
    restriction. A function with no tree is absent: the gate question was not
    answered for it, and an unanswered question is not a proof."""
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
    """The openness of the mapping whose entry changes an event announces.

    Two quantifiers, and the second is the load-bearing one:

      * every function seen to EMIT the event is restricted — otherwise an
        occurrence can come from an open path; and
      * every function that WRITES the mapping is restricted.

    The emitter set alone cannot carry the claim because it cannot be
    complete: it is built by walking ``EventCall`` IR, and a log emitted from
    inline assembly (``log2(0, 0, topic0, key)``) appears in no such node. A
    contract with one gated ``EventCall`` emitter and one open assembly emitter
    of the same topic0 satisfies "every emitter is restricted" over an emitter
    set that never saw the second one.

    Quantifying over writers is what makes that incompleteness harmless. An
    unaccounted emitter that changes nothing is not a member change at all;
    one that does change the mapping has to WRITE it, and the effects
    artifact attributes those writes whether or not the emit was visible. So
    an open writer demotes the event even when the open path's emit is
    invisible. Either set empty is not-determined — nothing was proven about
    paths we could not find.
    """
    if not emitters or not writers:
        return OPENNESS_NOT_DETERMINED
    if emitters <= restricted and writers <= restricted:
        return OPENNESS_RESTRICTED
    return OPENNESS_NOT_DETERMINED
