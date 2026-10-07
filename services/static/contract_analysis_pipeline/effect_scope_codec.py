"""Stored form of effect scopes.

Sites are governed by overlapping guards, so each site's predicate is stored as a skeleton in which a subtree repeated
anywhere in the contract is a ``{"ref": id}`` into one ``effect_guards`` table. Ids are content hashes, so equal guards
in different functions collapse. Expansion restores the exact trees; the stored ``effects`` copy keeps site metadata
only.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

EFFECT_SCOPES_VERSION = 2
# A ref and its table key cost about this much; smaller repeats stay inline.
_MIN_INTERNED_BYTES = 96
_ID_HEX = 24


def _is_ref(node: Any) -> bool:
    return isinstance(node, dict) and len(node) == 1 and isinstance(node.get("ref"), str)


def _children(node: Any) -> list[Any]:
    children = node.get("children") if isinstance(node, dict) else None
    return children if isinstance(children, list) else []


class _Interner:
    def __init__(self) -> None:
        # id(node) -> (node, content id, expanded size); the node is held so its id can't be reused.
        self._nodes: dict[int, tuple[Any, str, int]] = {}
        # content id -> (sorted-key form, exact form)
        self._canonical: dict[str, tuple[str, str]] = {}
        self._uses: dict[str, int] = {}
        self.table: dict[str, Any] = {}

    def _identify(self, node: Any) -> tuple[str, int]:
        if not isinstance(node, dict):
            canonical = json.dumps(node, sort_keys=True, separators=(",", ":"), default=str)
            return hashlib.sha256(canonical.encode()).hexdigest()[:_ID_HEX], len(canonical)
        hit = self._nodes.get(id(node))
        if hit is not None:
            return hit[1], hit[2]
        children = _children(node)
        identified = [self._identify(c) for c in children]
        shell = {**node, "children": [i for i, _ in identified]} if children else node
        canonical = json.dumps(shell, sort_keys=True, separators=(",", ":"), default=str)
        exact = json.dumps(shell, separators=(",", ":"), default=str)
        content_id = hashlib.sha256(canonical.encode()).hexdigest()[:_ID_HEX]
        known = self._canonical.setdefault(content_id, (canonical, exact))
        if known[0] != canonical:
            raise ValueError(f"effect guard id collision on {content_id}")
        if known[1] != exact:
            # Equal content in another key order must still expand byte-for-byte as it was built.
            content_id = hashlib.sha256(b"exact:" + exact.encode()).hexdigest()[:_ID_HEX]
            if self._canonical.setdefault(content_id, (canonical, exact))[1] != exact:
                raise ValueError(f"effect guard id collision on {content_id}")
        size = len(canonical) - sum(len(i) + 2 for i, _ in identified) + sum(s for _, s in identified)
        self._nodes[id(node)] = (node, content_id, size)
        return content_id, size

    def count(self, node: Any) -> None:
        if not isinstance(node, dict):
            return
        content_id, _ = self._identify(node)
        self._uses[content_id] = self._uses.get(content_id, 0) + 1
        if self._uses[content_id] == 1:
            for child in _children(node):
                self.count(child)

    def emit(self, node: Any) -> Any:
        if not isinstance(node, dict):
            return node
        content_id, size = self._identify(node)
        children = _children(node)
        if self._uses.get(content_id, 0) < 2 or size < _MIN_INTERNED_BYTES:
            return {**node, "children": [self.emit(c) for c in children]} if children else node
        if content_id not in self.table:
            self.table[content_id] = {**node, "children": [self.emit(c) for c in children]} if children else node
        return {"ref": content_id}


def encode_effect_scopes(predicate_trees: Any, effects: Any) -> None:
    """Replace both artifacts' in-memory effect scopes with their stored forms."""
    scopes = predicate_trees.get("effect_scopes") if isinstance(predicate_trees, dict) else None
    if isinstance(scopes, dict):
        interner = _Interner()
        for sites in scopes.values():
            for site in sites:
                interner.count(site.get("predicate"))
        predicate_trees["effect_scopes"] = {
            signature: [
                {**site, "predicate": interner.emit(site["predicate"])} if "predicate" in site else dict(site)
                for site in sites
            ]
            for signature, sites in scopes.items()
        }
        predicate_trees["effect_guards"] = interner.table
    functions = effects.get("functions") if isinstance(effects, dict) else None
    if not isinstance(functions, dict):
        return
    for record in functions.values():
        sites = record.get("effect_scopes") if isinstance(record, dict) else None
        if isinstance(sites, list):
            record["effect_scopes"] = [{k: v for k, v in site.items() if k != "predicate"} for site in sites]


def _unavailable_guard() -> dict[str, Any]:
    from .predicates._helpers import _unsupported_leaf

    leaf = _unsupported_leaf("effect_guard_unavailable", "effect_guard_unavailable")
    # A plain unsupported leaf beside a business guard folds into a side condition; this one must stay unproven.
    leaf["authority_proof"] = {"state": "not_determined", "requirements": ["effect_guard_unavailable"]}
    return {"op": "LEAF", "leaf": leaf}


def _expand(node: Any, table: Mapping[str, Any], memo: dict[str, Any], active: frozenset[str]) -> Any:
    if _is_ref(node):
        content_id = node["ref"]
        if content_id in memo:
            return memo[content_id]
        if content_id not in table or content_id in active:
            return _unavailable_guard()
        memo[content_id] = _expand(table[content_id], table, memo, active | {content_id})
        return memo[content_id]
    children = _children(node)
    if not children:
        return node
    expanded = [_expand(c, table, memo, active) for c in children]
    if all(e is c for e, c in zip(expanded, children, strict=True)):
        return node
    return {**node, "children": expanded}


def expand_site_predicate(predicate_trees: Mapping[str, Any], site: Mapping[str, Any], memo: dict | None = None) -> Any:
    """The site's full predicate. Expanded guards are shared between calls given the same ``memo`` and must be treated
    as read-only. v1 sites, which carry inline trees, are returned unchanged.
    """
    table = predicate_trees.get("effect_guards")
    predicate = site.get("predicate")
    if not isinstance(table, Mapping):
        return predicate
    return _expand(predicate, table, memo if memo is not None else {}, frozenset())


def expand_effect_scopes(predicate_trees: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Every function's sites with expanded predicates, sharing each guard across the sites it governs."""
    scopes = predicate_trees.get("effect_scopes")
    if not isinstance(scopes, Mapping):
        return {}
    memo: dict[str, Any] = {}
    return {
        signature: [
            {**site, "predicate": expand_site_predicate(predicate_trees, site, memo)} if "predicate" in site else site
            for site in sites
        ]
        for signature, sites in scopes.items()
    }
