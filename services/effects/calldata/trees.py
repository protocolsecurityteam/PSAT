"""Predicate-tree walking."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator, Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass


logger = logging.getLogger("services.effects.calldata")

# ---------------------------------------------------------------------------
# Predicate-tree walking (mirrors ``claims.matchers._facts._mandatory_operands``)
# ---------------------------------------------------------------------------


def _mandatory_leaves(tree: Any) -> Iterator[dict[str, Any]]:
    """Leaves reachable with every ancestor a conjunction — the operand's value
    can force a revert with no ``OR`` escape. Same separator the claims plane uses
    to distinguish a real gate from a branch-mode selector."""

    def walk(node: Any, mandatory: bool) -> Iterator[dict[str, Any]]:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf")
            if mandatory and isinstance(leaf, dict):
                yield leaf
            return
        child_mandatory = mandatory and node.get("op") != "OR"
        for child in node.get("children") or []:
            yield from walk(child, child_mandatory)

    yield from walk(tree, True)


def _all_leaves(tree: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _all_leaves(child)


def _operands(leaf: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [op for op in (leaf.get("operands") or []) if isinstance(op, dict)]


def _mandatory_state_pairs(tree: Any) -> set[tuple[str, str | None]]:
    out: set[tuple[str, str | None]] = set()
    for leaf in _mandatory_leaves(tree):
        for op in _operands(leaf):
            name = op.get("state_variable_name")
            if not name:
                continue
            member_path = op.get("member_path") or []
            out.add((str(name), str(member_path[0]) if member_path else None))
    return out


def guarded_functions(trees: Mapping[str, Any], pairs: Iterable[tuple[str, str | None]]) -> list[str]:
    """Every function whose MANDATORY gate reads one of ``pairs`` — static's
    predicted guard set (the scored denominator for the freeze/pause class).

    Matching is on the state-variable NAME; ``member_path`` is a refinement that
    is NOT required to agree. It cannot be: an ERC-7201 latch is recorded as a
    write to the slot var with an EMPTY member path (``PAUSABLE_STORAGE_SLOT``)
    while the read operand carries ``member_path=["paused"]``, so a strict pair
    match returns an empty guard set for every namespaced-storage pause. Var-level
    matching over-includes at worst, which only widens the probe set — the
    observed radius stays a lower bound and the scored denominator is unchanged.
    """
    wanted_vars = {var for var, _member in pairs}
    if not wanted_vars:
        return []
    return sorted(name for name, tree in trees.items() if _mandatory_state_vars(tree) & wanted_vars)


def _mandatory_state_vars(tree: Any) -> set[str]:
    return {var for var, _member in _mandatory_state_pairs(tree)}


def _param_index_by_name(tree: Any) -> dict[str, int]:
    """``param name -> positional index`` recovered from predicate-tree leaf
    operands (the only place the static plane records both). Absent ⇒ the caller
    fails closed rather than guessing a slot."""
    out: dict[str, int] = {}
    for leaf in _all_leaves(tree):
        for op in _operands(leaf):
            name = op.get("parameter_name")
            idx = op.get("parameter_index")
            if isinstance(name, str) and isinstance(idx, int) and idx >= 0:
                out.setdefault(name.lower(), idx)
    return out


def _authority_roles(tree: Any) -> set[str]:
    return {
        str(leaf.get("authority_role")) for leaf in _all_leaves(tree) if isinstance(leaf.get("authority_role"), str)
    }


def _gate_ref(tree: Any) -> str:
    """A gate STRUCTURE descriptor — authority roles, never an address.

    ``gate:none`` is emitted for a tree-less function, which covers BOTH a
    proven-ungated one and one whose real gate the static plane could not lower
    (``guard_extraction_uncertain`` and the rest of the tree-less residue) — so
    it is not on its own a claim that no gate exists. It never has to be: the
    other half of the cache identity is the kernel ``behavior_hash``, which is
    the whole metadata-stripped runtime bytecode (immutables masked).
    The gate lives inside that bytecode, so two rows can share a ``gate:none``
    only when their code — and therefore their gate — is identical, and masking
    an immutable authority erases the ADDRESS a gate compares against, never the
    comparison. ``tests/test_effects_hashing.py`` pins that.

    The consumers of an absent role (the authority-change gate-moving pick, the pauser
    probe) each fail closed to a probe that is not synthesized, so a gate that
    did not lower costs recall, never a widened verdict.
    """
    roles = sorted(_authority_roles(tree))
    return "gate:" + ("+".join(roles) if roles else "none")
