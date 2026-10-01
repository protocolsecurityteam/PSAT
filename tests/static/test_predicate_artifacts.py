from __future__ import annotations

import json

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from tests.support.slither_compile import _compile  # noqa: E402


def _contract(sl: Slither, name: str | None = None):
    if name is None:
        return sl.contracts[0]
    return next(c for c in sl.contracts if c.name == name)


def _leaves(tree: dict) -> list[dict]:
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return [leaf] if isinstance(leaf, dict) else []
    out: list[dict] = []
    for child in tree.get("children", []) or []:
        out.extend(_leaves(child))
    return out


def test_guarded_bool_returning_checker_gets_tree_and_check_tree(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            mapping(address => bool) public users;
            function canCall(address user) external view returns (bool) {
                require(msg.sender == owner);
                return users[user];
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    assert "canCall(address)" in artifact["trees"]
    assert "canCall(address)" in artifact["check_trees"]
    guard_exprs = {leaf.get("expression") for leaf in _leaves(artifact["trees"]["canCall(address)"])}
    return_storage_vars = {
        leaf.get("set_descriptor", {}).get("storage_var")
        for leaf in _leaves(artifact["check_trees"]["canCall(address)"])
    }
    assert any("owner" in str(expr) for expr in guard_exprs)
    assert return_storage_vars == {"users"}


def test_void_external_guard_survives_non_caller_try_catch(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IGate {
            function arbitrary(address who) external view;
        }
        interface IProbe {
            function probe() external view returns (bytes32);
        }
        contract C {
            IGate public gate;
            bytes32 public constant SLOT = bytes32(uint256(1));
            address public impl;
            function change(address next) external {
                guard();
                try IProbe(next).probe() returns (bytes32 slot) {
                    require(slot == SLOT);
                } catch {
                    revert("bad impl");
                }
                impl = next;
            }
            function guard() internal view {
                gate.arbitrary(msg.sender);
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl, "C"))
    leaves = _leaves(artifact["trees"]["change(address)"])
    delegated = [
        leaf
        for leaf in leaves
        if leaf.get("kind") == "external_bool" and leaf.get("authority_role") == "delegated_authority"
    ]
    assert len(delegated) == 1
    assert delegated[0]["set_descriptor"]["callee_signature"] == "arbitrary(address)"
    unsupported = [leaf for leaf in leaves if leaf.get("kind") == "unsupported"]
    assert all(not leaf.get("references_msg_sender") for leaf in unsupported)


def test_artifact_omits_constructor(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            constructor(address o) {
                require(o != address(0));
                ownerVar = o;
            }
            function f() external {
                require(msg.sender == ownerVar);
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    keys = list(artifact["trees"].keys())
    assert all("constructor" not in k for k in keys)
    assert "f()" in artifact["trees"]


def test_artifact_with_low_level_call_provenance_serializes(tmp_path):
    """``LowLevelCall.function_name`` is a ``Constant``; unstringified, it crashed the workspace write on 4 real
    contracts (PR-161 failed_terminal).
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public target;
            uint256 public x;
            function guarded(bytes32 expected, uint256 v) external {
                (bool ok, bytes memory data) = target.staticcall(
                    abi.encodeWithSignature("check(address)", msg.sender)
                );
                require(ok, "call failed");
                require(keccak256(data) == expected, "bad witness");
                x = v;
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    decoded = json.loads(json.dumps(artifact))
    tree = decoded["trees"]["guarded(bytes32,uint256)"]

    def _iter(node):
        if node.get("op") == "LEAF":
            yield node.get("leaf") or {}
            return
        for child in node.get("children") or []:
            yield from _iter(child)

    def _operands(leaf):
        for op in leaf.get("operands") or []:
            yield op
            for nested in op.get("derived_from") or []:
                yield nested

    callees = {op.get("callee") for leaf in _iter(tree) for op in _operands(leaf) if op.get("callee") is not None}
    assert any(isinstance(c, str) and "staticcall" in c for c in callees), callees


def test_non_address_constant_does_not_make_caller_authority():
    from services.static.contract_analysis_pipeline.predicates import _classify_authority_equality

    leaf = {
        "kind": "equality",
        "operator": "eq",
        "operands": [
            {"source": "msg_sender"},
            {"source": "constant", "constant_value": "0"},
        ],
    }

    assert _classify_authority_equality(leaf, "equality") == "business"  # pyright: ignore[reportArgumentType]


def test_struct_field_mapping_membership_gets_writer_event_hints(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            struct RoleData {
                mapping(address => bool) members;
            }
            mapping(bytes32 => RoleData) private _roles;
            bytes32 public constant MINTER = keccak256("MINTER");
            event Granted(bytes32 indexed role, address indexed account, address indexed sender);
            event Revoked(bytes32 indexed role, address indexed account, address indexed sender);
            function grant(bytes32 role, address account) external {
                _roles[role].members[account] = true;
                emit Granted(role, account, msg.sender);
            }
            function revoke(bytes32 role, address account) external {
                _roles[role].members[account] = false;
                emit Revoked(role, account, msg.sender);
            }
            function f() external view {
                require(_roles[MINTER].members[msg.sender]);
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    leaf = _leaves(artifact["trees"]["f()"])[0]
    descriptor = leaf["set_descriptor"]
    hints = descriptor.get("enumeration_hint") or []

    assert descriptor["storage_var"] == "_roles"
    assert {h["direction"] for h in hints} == {"add", "remove"}
    assert all(h["mapping_name"] == "_roles" for h in hints)
    assert all(h["topics_to_keys"] == {1: 0, 2: 1} for h in hints)


def test_artifact_preserves_bitmask_value_predicate_and_set_hint(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => uint256) public roles;
            uint256 constant MINTER_FLAG = 1;
            event RolesUpdated(address indexed user, uint256 rolesValue);
            function setRole(address user, uint256 rolesValue) external {
                require(msg.sender == ownerVar);
                roles[user] = rolesValue;
                emit RolesUpdated(user, rolesValue);
            }
            function mint() external view {
                require((roles[msg.sender] & MINTER_FLAG) != 0);
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    leaf = _leaves(artifact["trees"]["mint()"])[0]
    descriptor = leaf["set_descriptor"]

    assert descriptor["value_predicate"]["mask"] == "0x1"
    hints = descriptor.get("enumeration_hint") or []
    assert len(hints) == 1
    assert hints[0]["direction"] == "set"
    assert hints[0]["key_position"] == 0
    assert hints[0]["value_position"] == 1
    assert hints[0]["event_signature"] == "RolesUpdated(address,uint256)"


def test_artifact_helper_engine_cache_skips_repeated_callees(tmp_path):
    """Correctness is covered by the corpus tests; this pins that cache hits happen."""
    from services.static.contract_analysis_pipeline import predicates
    from services.static.contract_analysis_pipeline.predicates import (
        _helper_engine_cache,
    )

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            mapping(bytes32 => bytes32) private _admins;
            modifier onlyRole(bytes32 role) {
                _checkRole(role);
                _;
            }
            function _checkRole(bytes32 role) internal view {
                if (!_roles[role][msg.sender]) revert();
            }
            function getRoleAdmin(bytes32 role) public view returns (bytes32) {
                return _admins[role];
            }
            function grantRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
                _roles[role][account] = true;
            }
            function revokeRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
                _roles[role][account] = false;
            }
        }
    """,
    )
    contract = _contract(sl)

    instantiations: list[None] = []
    original_init = predicates.ProvenanceEngine.__init__

    def _counting_init(self, *args, **kwargs):
        instantiations.append(None)
        return original_init(self, *args, **kwargs)

    try:
        predicates.ProvenanceEngine.__init__ = _counting_init
        artifact = build_predicate_artifacts(contract)
        cached_count = len(instantiations)
        assert "grantRole(bytes32,address)" in artifact["trees"]
        assert "revokeRole(bytes32,address)" in artifact["trees"]

        instantiations.clear()
        token = _helper_engine_cache.set(None)
        try:
            for fn in contract.functions:
                if getattr(fn, "visibility", None) in ("external", "public"):
                    if not getattr(fn, "is_constructor", False):
                        from services.static.contract_analysis_pipeline.predicates import (
                            build_predicate_tree,
                        )

                        build_predicate_tree(fn)
        finally:
            _helper_engine_cache.reset(token)
        uncached_count = len(instantiations)
    finally:
        predicates.ProvenanceEngine.__init__ = original_init

    assert cached_count < uncached_count, (
        f"helper-engine cache did not reduce engine count: cached={cached_count} uncached={uncached_count}"
    )
