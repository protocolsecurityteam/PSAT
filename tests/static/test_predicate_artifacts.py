"""Tests for ``build_predicate_artifacts``.

End-to-end: compile a Solidity fixture, run the artifact builder,
assert the trees include the expected functions, exclude unguarded
ones, and serialize cleanly via ``json.dumps``.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    SCHEMA_VERSION,
    build_predicate_artifacts,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


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


def test_artifact_includes_only_guarded_external_functions(tmp_path):
    """The artifact dict has trees for guarded external/public
    functions and OMITS unguarded ones (resolver convention:
    absent = unguarded)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public x;
            function guarded() external {
                require(msg.sender == ownerVar);
                x = 1;
            }
            function open() external {
                x = 2;
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    assert artifact["schema_version"] == SCHEMA_VERSION
    assert artifact["contract_name"] == "C"
    assert "guarded()" in artifact["trees"]
    assert "open()" not in artifact["trees"]


def test_bool_returning_authority_check_goes_to_check_trees(tmp_path):
    """Read-only authorization predicates are resolver inputs, not
    protected entrypoints. They should be available for recursive
    inlining without appearing in the normal function surface."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => mapping(bytes4 => mapping(address => bool))) internal can;
            function allowed(address user, address target, bytes4 sig) external view returns (bool) {
                return can[target][sig][user];
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    assert "allowed(address,address,bytes4)" not in artifact["trees"]
    assert "allowed(address,address,bytes4)" in artifact["check_trees"]
    leaves = _leaves(artifact["check_trees"]["allowed(address,address,bytes4)"])
    assert leaves and leaves[0]["kind"] == "membership"


def test_bool_returning_checker_keeps_literal_true_branch(tmp_path):
    """Checker functions with public fast paths must preserve the
    literal-true branch as a predicate over the preceding if condition."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => mapping(bytes4 => bool)) public publicCapability;
            mapping(address => bool) public users;
            function canCall(address user, address target, bytes4 sig) external view returns (bool) {
                if (publicCapability[target][sig]) return true;
                return users[user];
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    tree = artifact["check_trees"]["canCall(address,address,bytes4)"]
    assert tree["op"] == "OR"
    leaves = _leaves(tree)
    storage_vars = {leaf.get("set_descriptor", {}).get("storage_var") for leaf in leaves}
    assert "publicCapability" in storage_vars
    assert "users" in storage_vars


def test_bool_returning_checker_keeps_unconditional_literal_true(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function canCall(address, address, bytes4) external pure returns (bool) {
                return true;
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    tree = artifact["check_trees"]["canCall(address,address,bytes4)"]
    leaves = _leaves(tree)
    assert len(leaves) == 1
    assert leaves[0]["authority_role"] == "business"
    assert leaves[0]["references_msg_sender"] is False
    assert leaves[0]["expression"] == "literal true"


def test_guarded_bool_returning_checker_gets_tree_and_check_tree(tmp_path):
    """A guarded bool checker is both a callable function and a
    resolver-side authorization provider."""
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


def test_artifact_omits_internal_functions(tmp_path):
    """Internal/private helpers don't appear at the boundary the
    resolver consumes — only external/public surface."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public x;
            function _helper() internal view {
                require(msg.sender == ownerVar);
            }
            function entry() external {
                _helper();
                x = 1;
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    assert "entry()" in artifact["trees"]
    assert "_helper()" not in artifact["trees"]


def test_void_external_precondition_is_callee_selector_based(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IGate {
            function renamed(address who) external view;
        }
        contract C {
            IGate public gate;
            address public impl;
            function entry(address next) external {
                route(next);
                impl = next;
            }
            function route(address) internal view {
                gate.renamed(msg.sender);
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl, "C"))
    leaves = _leaves(artifact["trees"]["entry(address)"])
    external = [leaf for leaf in leaves if leaf.get("kind") == "external_bool"]
    assert len(external) == 1
    leaf = external[0]
    assert leaf["authority_role"] == "delegated_authority"
    descriptor = leaf["set_descriptor"]
    assert descriptor["authority_contract"]["address_source"]["state_variable_name"] == "gate"
    assert descriptor["callee_signature"] == "renamed(address)"


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
    # Constructors aren't part of the public ABI surface; the
    # artifact must omit them so the resolver doesn't conflate
    # construction-time gates with runtime gates.
    keys = list(artifact["trees"].keys())
    assert all("constructor" not in k for k in keys)
    assert "f()" in artifact["trees"]


def test_artifact_serializes_cleanly_to_json(tmp_path):
    """The trees use TypedDict shapes that ``json.dumps`` can
    handle. The set_descriptor's role bytes are encoded as
    str(constant_value) per the existing predicate builder, so the
    JSON roundtrip works end-to-end."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            bytes32 constant MINTER = keccak256("MINTER");
            uint256 public x;
            function mint(uint256 v) external {
                require(_roles[MINTER][msg.sender]);
                x = v;
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    encoded = json.dumps(artifact)
    decoded = json.loads(encoded)
    assert decoded["schema_version"] == SCHEMA_VERSION
    assert "mint(uint256)" in decoded["trees"]


def test_artifact_with_low_level_call_provenance_serializes(tmp_path):
    """A guarded function whose comparison operand derives from a low-level
    ``.staticcall`` through a built-in's ``arg_origins``: Slither's
    ``LowLevelCall.function_name`` is a ``Constant``, and before it was
    stringified at the provenance layer it reached the published
    ``derived_from`` operands and crashed the ``json.dumps`` workspace write
    on 4 real contracts (PriceProvider, EmissionsController, StrategyManager,
    DelegationManager — PR-161, failed_terminal with 'Object of type Constant
    is not JSON serializable')."""
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

    # The low-level call's kind must have survived as a plain string in the
    # published provenance (not been dropped to make serialization pass).
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


def test_artifact_writer_gate_runs_on_full_contract(tmp_path):
    """Writer-gate pass needs every function's tree to evaluate
    writer authority. The artifact builder runs it AFTER collecting
    all trees, so a 1-key blacklist promoted via writer-gate shows
    caller_authority in the output (not the un-promoted business)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => bool) public _blacklist;
            uint256 public x;
            function setBlacklist(address u, bool v) external {
                require(msg.sender == ownerVar);
                _blacklist[u] = v;
            }
            function someAction() external {
                require(!_blacklist[msg.sender]);
                x = 1;
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    action_tree = artifact["trees"]["someAction()"]
    leaves: list = []

    def _walk(node):
        if node.get("op") == "LEAF":
            leaf = node.get("leaf")
            if leaf:
                leaves.append(leaf)
            return
        for c in node.get("children", []) or []:
            _walk(c)

    _walk(action_tree)
    assert leaves, "expected a membership leaf"
    assert leaves[0]["authority_role"] == "caller_authority"
    assert leaves[0]["confidence"] == "medium"  # rule b.i = MEDIUM


def test_artifact_runs_reentrancy_pause_pass(tmp_path):
    """OZ Pausable pattern — the ``whenNotPaused`` modifier's
    leaf classifies as ``pause`` only after the cross-function
    pass. Confirms the artifact builder runs that pass."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            bool public _paused;
            modifier whenNotPaused() {
                require(!_paused);
                _;
            }
            function pause() external {
                require(msg.sender == ownerVar);
                _paused = true;
            }
            function transfer() external whenNotPaused {}
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    transfer_tree = artifact["trees"]["transfer()"]
    leaf = transfer_tree["leaf"]
    assert leaf["authority_role"] == "pause"
    assert leaf["confidence"] == "high"


def test_artifact_attaches_mapping_writer_event_hints(tmp_path):
    """Generic writer events should land on the predicate leaf the
    resolver consumes, not only in a sidecar semantic summary."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => uint256) public wards;
            event Rely(address indexed guy);
            event Deny(address indexed guy);
            function rely(address guy) external {
                require(msg.sender == ownerVar);
                wards[guy] = 1;
                emit Rely(guy);
            }
            function deny(address guy) external {
                require(msg.sender == ownerVar);
                wards[guy] = 0;
                emit Deny(guy);
            }
            function f() external view {
                require(wards[msg.sender] == 1);
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    leaf = _leaves(artifact["trees"]["f()"])[0]
    descriptor = leaf["set_descriptor"]
    hints = descriptor.get("enumeration_hint") or []

    assert {h["direction"] for h in hints} == {"add", "remove"}
    assert all(h["mapping_name"] == "wards" for h in hints)
    assert all(h["topics_to_keys"] == {1: 0} for h in hints)
    assert all(h["data_to_keys"] == {} for h in hints)
    assert {h["event_signature"] for h in hints} == {"Rely(address)", "Deny(address)"}


def test_artifact_does_not_invent_role_event_hints_from_names(tmp_path):
    """Declared events alone are not semantic writer evidence."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            bytes32 public constant MINTER = keccak256("MINTER");
            event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
            event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
            function f() external view {
                require(_roles[MINTER][msg.sender]);
            }
        }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl))
    leaf = _leaves(artifact["trees"]["f()"])[0]
    hints = leaf["set_descriptor"].get("enumeration_hint") or []

    assert hints == []


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
    """Nested mapping fields still resolve to the base storage var."""
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
    """Solady-style bitmask roles need both the mask and the set-event
    value position to resolve semantically."""
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
    """When multiple functions share a cross-fn helper (e.g.
    grantRole / revokeRole / renounceRole all funneling through
    ``_checkRole``), build_predicate_artifacts wires a per-call
    helper-engine cache so the second + third cross-fn build
    don't re-run ProvenanceEngine on the helper.

    Pinned by counting ProvenanceEngine instantiations: with the
    cache active, fewer engines should be created than without.
    Correctness is validated by every other corpus test — this
    test specifically guards the cache HITS HAPPEN."""
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

    # Count ProvenanceEngine constructions during the artifact
    # build. With cache hits across grantRole/revokeRole the
    # number is lower than the no-cache baseline.
    instantiations: list[None] = []
    original_init = predicates.ProvenanceEngine.__init__

    def _counting_init(self, *args, **kwargs):
        instantiations.append(None)
        return original_init(self, *args, **kwargs)

    try:
        predicates.ProvenanceEngine.__init__ = _counting_init
        # With cache active (entered by build_predicate_artifacts).
        artifact = build_predicate_artifacts(contract)
        cached_count = len(instantiations)
        assert "grantRole(bytes32,address)" in artifact["trees"]
        assert "revokeRole(bytes32,address)" in artifact["trees"]

        # Now run the exact same work WITHOUT the cache scope —
        # build_predicate_tree directly without entering the
        # build_predicate_artifacts wrapper.
        instantiations.clear()
        # Ensure no ambient cache.
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

    # Cached path runs strictly fewer engines than uncached.
    assert cached_count < uncached_count, (
        f"helper-engine cache did not reduce engine count: cached={cached_count} uncached={uncached_count}"
    )


def test_artifact_empty_contract(tmp_path):
    """An interface-only contract with no externally-callable
    body produces an empty trees dict (still valid)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IThing { function foo() external; }
    """,
    )
    artifact = build_predicate_artifacts(_contract(sl, "IThing"))
    assert artifact["trees"] == {}
    assert artifact["schema_version"] == SCHEMA_VERSION
