"""Regression pin: OZ v5 (ERC-7201 namespaced-storage) AccessControl role gates.

Mode B of the etherfi controller-recall audit (CumulativeMerkleDrop). The
static pipeline makes a role-gated function's caller set *enumerable* by
discovering its writer event (``_roles[role][account] = true; emit
RoleGranted(role, account, …)``) and attaching it to the gate's
``mapping_membership`` descriptor as an ``enumeration_hint`` — the event-indexed
adapter then enumerates the holders, which become ``FunctionPrincipal`` rows and
ultimately a surfaced controller.

OpenZeppelin v5 stores roles in ERC-7201 *namespaced* storage, reached through
an inline-assembly storage pointer::

    AccessControlStorage storage $ = _getAccessControlStorage();
    return $._roles[role].hasRole[account];

Previously both the writer-event discovery (``mapping_events.discover_mapping_writer_events``)
and the gate's ``storage_var`` resolution (``predicates._find_index_base``) traced through
the assembly storage-pointer local (a ``REF_*`` temp) instead of the logical ``_roles``
mapping. So no writer event was bound, no ``enumeration_hint`` attached, the adapter
returned ``unsupported(no_adapter)``, and the role holders (e.g. CumulativeMerkleDrop's
3/7 admin Safe) were never surfaced. Both walkers now resolve the ``Member`` field back to
the logical mapping name, and ``discover_mapping_writer_events`` gates on the index-write
signal (not the contract-level state-var pre-filter that namespaced storage defeats).

The v4 (direct state-variable) and v5 (ERC-7201 namespaced storage) cases are both passing
regression guards — proving the pipeline resolves role enumeration through either storage
layout.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.static_analysis.mapping_events import (
    discover_mapping_writer_events,
)
from services.static.static_analysis.predicate_artifacts import (
    apply_mapping_event_hint_pass,
)
from services.static.static_analysis.predicate_types import PredicateTree
from services.static.static_analysis.predicates import build_predicate_tree
from services.static.static_analysis.writer_gate import apply_writer_gate_pass

# Same role storage shape, differing only in HOW `_roles` is reached:
# v4 declares it as a state variable; v5 reaches it through an ERC-7201
# assembly storage pointer. Both expose the canonical RoleGranted writer.
_V4_SRC = """
pragma solidity ^0.8.20;
contract AccessV4 {
    struct RoleData { mapping(address => bool) members; }
    mapping(bytes32 => RoleData) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members[account];
    }
    modifier onlyRole(bytes32 role) { require(hasRole(role, msg.sender)); _; }
    function _grantRole(bytes32 role, address account) internal {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }
    function grantRole(bytes32 role, address account) public virtual onlyRole(bytes32(0)) {
        _grantRole(role, account);
    }
}
contract Drop is AccessV4 {
    bytes32 public constant OPS = keccak256("OPS");
    bytes32 public root;
    function setMerkleRoot(bytes32 r) public onlyRole(OPS) { root = r; }
}
"""

_V5_SRC = """
pragma solidity ^0.8.20;
contract AccessV5 {
    struct RoleData { mapping(address => bool) members; }
    struct ACStorage { mapping(bytes32 => RoleData) _roles; }
    bytes32 private constant SLOT = 0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;
    function _getStorage() private pure returns (ACStorage storage $) { assembly { $.slot := SLOT } }
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    function hasRole(bytes32 role, address account) public view returns (bool) {
        ACStorage storage $ = _getStorage();
        return $._roles[role].members[account];
    }
    modifier onlyRole(bytes32 role) { require(hasRole(role, msg.sender)); _; }
    function _grantRole(bytes32 role, address account) internal {
        ACStorage storage $ = _getStorage();
        if (!$._roles[role].members[account]) {
            $._roles[role].members[account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }
    function grantRole(bytes32 role, address account) public virtual onlyRole(bytes32(0)) {
        _grantRole(role, account);
    }
}
contract Drop is AccessV5 {
    bytes32 public constant OPS = keccak256("OPS");
    bytes32 public root;
    function setMerkleRoot(bytes32 r) public onlyRole(OPS) { root = r; }
}
"""


def _first_leaf(node: Any) -> dict[str, Any] | None:
    if not isinstance(node, dict):
        return None
    if node.get("op") == "LEAF":
        return node.get("leaf")
    for child in node.get("children") or []:
        leaf = _first_leaf(child)
        if leaf is not None:
            return leaf
    return None


def _run_pipeline(tmp_path: Path, source: str, gate_fn: str) -> tuple[list[Any], dict[str, Any]]:
    """Compile *source*, run the static role-resolution passes, and return
    ``(writer_specs, gate_descriptor)`` for the ``Drop.<gate_fn>`` gate."""
    sol = tmp_path / "C.sol"
    sol.write_text(textwrap.dedent(source).strip() + "\n")
    contract = next(c for c in Slither(str(sol)).contracts if c.name == "Drop")
    specs = discover_mapping_writer_events(contract)
    trees: dict[str, PredicateTree] = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        tree = build_predicate_tree(fn)
        if tree is not None:
            trees[fn.full_name] = tree
    apply_writer_gate_pass(contract, trees)
    apply_mapping_event_hint_pass(contract, trees)
    leaf = _first_leaf(trees.get(gate_fn)) or {}
    return specs, (leaf.get("set_descriptor") or {})


def test_v4_state_var_access_control_role_gate_is_enumerable(tmp_path: Path) -> None:
    """Control: a direct-state-variable (OZ v4-style) role mapping is recognized
    end to end — the RoleGranted writer is discovered and the gate carries the
    enumeration hint the event-indexed adapter needs."""
    specs, descriptor = _run_pipeline(tmp_path, _V4_SRC, "setMerkleRoot(bytes32)")

    assert any(str(s.get("event_signature", "")).startswith("RoleGranted") for s in specs), specs
    assert descriptor.get("kind") == "mapping_membership"
    assert descriptor.get("storage_var") == "_roles"
    assert descriptor.get("enumeration_hint"), "v4 role gate should carry a RoleGranted enumeration hint"


def test_v5_namespaced_access_control_role_gate_is_enumerable(tmp_path: Path) -> None:
    """Same role logic via ERC-7201 namespaced storage is equally enumerable.

    The static pipeline now resolves the assembly storage-pointer write/read
    (``$._roles[role][account]``) back to the logical ``_roles`` mapping, so the
    RoleGranted writer is discovered and the gate's ``storage_var`` resolves to
    ``_roles`` and carries the enumeration hint — closing the
    CumulativeMerkleDrop (Mode B) recall gap. Regression guard against the
    assembly storage-pointer resolution in mapping_events + predicates."""
    specs, descriptor = _run_pipeline(tmp_path, _V5_SRC, "setMerkleRoot(bytes32)")

    assert any(str(s.get("event_signature", "")).startswith("RoleGranted") for s in specs), specs
    assert descriptor.get("storage_var") == "_roles"
    assert descriptor.get("enumeration_hint"), "v5 namespaced role gate should carry a RoleGranted enumeration hint"
