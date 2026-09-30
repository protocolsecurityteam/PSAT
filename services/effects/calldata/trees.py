"""Predicate-tree walking."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator, Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass


logger = logging.getLogger("services.effects.calldata")

# Mirrors ``claims.matchers._facts._mandatory_operands``.


def _mandatory_leaves(tree: Any) -> Iterator[dict[str, Any]]:
    """Leaves reached through conjunctions only, so the operand can force a revert with no ``OR`` escape."""

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
    """Every function whose mandatory gate reads one of ``pairs``: static's predicted guard set.

    Matched on variable name only: an ERC-7201 latch is written with an empty member path but read with
    ``member_path=["paused"]``. Over-inclusion only widens the probe set.
    """
    wanted_vars = {var for var, _member in pairs}
    if not wanted_vars:
        return []
    return sorted(name for name, tree in trees.items() if _mandatory_state_vars(tree) & wanted_vars)


def _mandatory_state_vars(tree: Any) -> set[str]:
    return {var for var, _member in _mandatory_state_pairs(tree)}


def _param_index_by_name(tree: Any) -> dict[str, int]:
    """``param name -> index`` from predicate-tree operands; absent means fail closed."""
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
    """A gate-structure descriptor (roles, never an address).

    ``gate:none`` covers both ungated and un-lowerable gates, which is fine because the cache identity also includes the
    kernel ``behavior_hash`` (whole stripped bytecode), so rows sharing ``gate:none`` share their gate.
    ``tests/test_effects_hashing.py`` pins that. Consumers of an absent role fail closed to no probe.
    """
    roles = sorted(_authority_roles(tree))
    return "gate:" + ("+".join(roles) if roles else "none")
