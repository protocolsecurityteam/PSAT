"""Regression pin: OZ v5 (ERC-7201 namespaced-storage) AccessControl role gates.

Mode B of the etherfi controller-recall audit (CumulativeMerkleDrop). A role-gated
function's caller set is *enumerable* when its writer event (``emit RoleGranted``)
attaches to the gate's ``mapping_membership`` descriptor as an ``enumeration_hint``.
OZ v5 reaches roles through an inline-assembly storage pointer (``$._roles[role]``);
both ``mapping_events.discover_mapping_writer_events`` and
``predicates._find_index_base`` used to trace the ``REF_*`` temp instead of the
logical ``_roles`` mapping, so no hint attached, the adapter returned
``unsupported(no_adapter)`` and the role holders were never surfaced.

The v4 (direct state variable) and v5 (namespaced) cases are both guards that role
enumeration resolves through either storage layout.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.contract_analysis_pipeline.mapping_events import (
    discover_mapping_writer_events,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    apply_mapping_event_hint_pass,
)
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass

# Same role storage shape, differing only in HOW `_roles` is reached (v4 state var vs v5 ERC-7201 pointer).
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


# v4: control -- a direct-state-variable (OZ v4-style) role mapping is recognized end to end: the
# RoleGranted writer is discovered and the gate carries the enumeration hint the event-indexed
# adapter needs. v5: the same role logic via ERC-7201 namespaced storage is equally enumerable; the
# assembly storage-pointer access resolves back to ``_roles``, closing the CumulativeMerkleDrop
# (Mode B) recall gap.
@pytest.mark.parametrize(
    "source",
    [
        pytest.param(_V4_SRC, id="v4-state-var"),
        pytest.param(_V5_SRC, id="v5-namespaced"),
    ],
)
def test_access_control_role_gate_is_enumerable(tmp_path: Path, source: str) -> None:
    specs, descriptor = _run_pipeline(tmp_path, source, "setMerkleRoot(bytes32)")

    assert any(str(s.get("event_signature", "")).startswith("RoleGranted") for s in specs), specs
    assert descriptor.get("kind") == "mapping_membership"
    assert descriptor.get("storage_var") == "_roles"
    assert descriptor.get("enumeration_hint"), "role gate should carry a RoleGranted enumeration hint"
