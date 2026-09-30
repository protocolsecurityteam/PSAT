"""Structurally faithful versions of canonical production auth patterns through the full predicate pipeline.

Not bytecode pinning.
"""

from __future__ import annotations

import pytest

slither = pytest.importorskip("slither")

from services.resolution.adapters import AdapterRegistry, EnumerationResult, EvaluationContext  # noqa: E402
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402
from services.resolution.predicate_evaluator import (  # noqa: E402
    evaluate_tree_with_registry,
)
from tests.support.predicate_trees import _all_leaves, _build_pipeline  # noqa: E402
from tests.support.slither_compile import _compile  # noqa: E402

ADDR_OWNER = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_USER = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ADDR_OTHER = "0xcccccccccccccccccccccccccccccccccccccccc"


def _registry() -> AdapterRegistry:
    r = AdapterRegistry()
    r.register(EventIndexedAdapter)
    return r


class FakeEventLogRepo:
    def __init__(self, members: list[str]):
        self.members = members

    def fold_event_writes(
        self, *, chain_id, event_address, topic0, topics_to_keys, data_to_keys, key_sources, direction, block=None
    ):
        return EnumerationResult(
            members=list(self.members) if direction == "add" else [],
            confidence="enumerable",
            last_indexed_block=18_000_000,
        )


def test_oz_ownable_pattern(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address private _owner;
            uint256 public x;
            modifier onlyOwner() {
                require(msg.sender == _owner);
                _;
            }
            function setX(uint256 v) external onlyOwner {
                x = v;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["setX(uint256)"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority"


def test_oz_role_mapping_full_3_hop_helper_chain(tmp_path):
    """OZ 5.0+ reaches ``hasRole`` through three helper hops; pins the ParameterBindingEnv gap until caller-side
    substitution lands.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            struct RoleData {
                mapping(address => bool) hasRoleMembers;
                bytes32 adminRole;
            }
            mapping(bytes32 => RoleData) private _roles;

            error UnauthorizedAccount(address account, bytes32 needed);

            function _msgSender() internal view returns (address) {
                return msg.sender;
            }
            function hasRole(bytes32 role, address account) public view returns (bool) {
                return _roles[role].hasRoleMembers[account];
            }
            function _checkRoleAddr(bytes32 role, address account) internal view {
                if (!hasRole(role, account)) {
                    revert UnauthorizedAccount(account, role);
                }
            }
            function _checkRole(bytes32 role) internal view {
                _checkRoleAddr(role, _msgSender());
            }
            function getRoleAdmin(bytes32 role) public view returns (bytes32) {
                return _roles[role].adminRole;
            }
            modifier onlyRole(bytes32 role) {
                _checkRole(role);
                _;
            }
            function grantRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
                _roles[role].hasRoleMembers[account] = true;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    tree = trees["grantRole(bytes32,address)"]
    assert tree is not None, "3-hop cross-fn revert chain must resolve"
    leaves = _all_leaves(tree)
    assert len(leaves) >= 1
    leaf = leaves[0]
    assert leaf["authority_role"] == "caller_authority"


def test_oz_role_mapping_grantrole_via_onlyrole(tmp_path):
    """EtherFiTimelock's pattern.

    RevertDetector recurses into internal callees so the membership leaf in _checkRole promotes via Rule B.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            mapping(bytes32 => bytes32) private _roleAdmins;
            modifier onlyRole(bytes32 role) {
                _checkRole(role);
                _;
            }
            function _checkRole(bytes32 role) internal view {
                if (!_roles[role][msg.sender]) revert();
            }
            function getRoleAdmin(bytes32 role) public view returns (bytes32) {
                return _roleAdmins[role];
            }
            function grantRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
                _roles[role][account] = true;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    tree = trees["grantRole(bytes32,address)"]
    assert tree is not None, "cross-fn revert detection should find _checkRole gate"
    leaves = _all_leaves(tree)
    assert len(leaves) >= 1
    assert leaves[0]["authority_role"] == "caller_authority"
    assert leaves[0]["kind"] == "membership"
    assert leaves[0]["set_descriptor"]["key_sources"][0]["source"] == "view_call"


def test_revert_message_helpers_do_not_become_guards(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        library StringsLike {
            function toHexString(uint256 value) internal pure returns (string memory) {
                require(value == 0, "hex length insufficient");
                return "";
            }
        }
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            mapping(bytes32 => bytes32) private _roleAdmins;
            modifier onlyRole(bytes32 role) {
                _checkRole(role);
                _;
            }
            function _checkRole(bytes32 role) internal view {
                if (!_roles[role][msg.sender]) {
                    revert(string(abi.encodePacked("account ", StringsLike.toHexString(uint160(msg.sender)))));
                }
            }
            function getRoleAdmin(bytes32 role) public view returns (bytes32) {
                return _roleAdmins[role];
            }
            function grantRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
                _roles[role][account] = true;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    tree = _build_pipeline(contract)["grantRole(bytes32,address)"]
    leaves = _all_leaves(tree)

    assert any(leaf["kind"] == "membership" for leaf in leaves)
    assert all("hex length insufficient" not in leaf.get("expression", "") for leaf in leaves)


def test_oz_role_mapping_inline_check(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            bytes32 constant MINTER_ROLE = keccak256("MINTER_ROLE");
            uint256 public x;
            function mint(uint256 v) external {
                require(_roles[MINTER_ROLE][msg.sender]);
                x = v;
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["mint(uint256)"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["authority_role"] == "caller_authority"


def test_oz_pausable_pattern(tmp_path):
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
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["transfer()"])
    assert len(leaves) == 1
    assert leaves[0]["authority_role"] == "pause"
    assert leaves[0]["confidence"] == "high"


def test_oz_reentrancy_guard_pattern(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 private _status;
            uint256 private constant _NOT_ENTERED = 1;
            uint256 private constant _ENTERED = 2;
            modifier nonReentrant() {
                require(_status != _ENTERED);
                _status = _ENTERED;
                _;
                _status = _NOT_ENTERED;
            }
            function withdraw() external nonReentrant {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["withdraw()"])
    assert len(leaves) == 1
    assert leaves[0]["authority_role"] == "reentrancy"
    assert leaves[0]["confidence"] == "high"


def test_maker_wards_pattern(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public wards;
            uint256 public x;
            function rely(address user) external {
                require(wards[msg.sender] == 1);
                wards[user] = 1;
            }
            function file(uint256 v) external {
                require(wards[msg.sender] == 1);
                x = v;
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["file(uint256)"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["set_descriptor"]["truthy_value"] == "1"
    assert leaf["authority_role"] == "caller_authority"
    # D.1: value_predicate keeps the operator and RHS that ``truthy_value`` flattened.
    vp = leaf["set_descriptor"].get("value_predicate")
    assert vp is not None
    assert vp["op"] == "eq"
    assert vp["rhs_values"] == ["1"]


def test_mapping_value_predicate_polarity_folds_neq_to_eq(tmp_path):
    """D.1: backends never need to know the gate direction."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public owners;
            function touch() external {
                if (owners[msg.sender] != 10) revert();
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["touch()"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    desc = leaf["set_descriptor"]
    assert desc["truthy_value"] == "10"
    vp = desc.get("value_predicate")
    assert vp is not None, "value_predicate must be emitted alongside truthy_value"
    assert vp["op"] == "eq", "!= revert folds to == allowed"
    assert vp["rhs_values"] == ["10"]
    assert vp["value_type"]  # uint256 in this case, but type detection is best-effort


def test_owner_or_business_or_branch_preserved(tmp_path):
    """Codex round-3 blocker #2."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public minThreshold;
            uint256 public x;
            function f(uint256 amount) external {
                require(msg.sender == ownerVar || amount > minThreshold);
                x = amount;
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    cap = evaluate_tree_with_registry(trees["f(uint256)"], _registry(), EvaluationContext(chain_id=1))
    assert cap.kind == "OR"
    assert len(cap.children) == 2
    kinds = sorted(c.kind for c in cap.children)
    assert "conditional_universal" in kinds


def test_combined_authority_and_side_conditions(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            bool public _paused;
            uint256 private _status;
            uint256 private constant _NOT_ENTERED = 1;
            uint256 private constant _ENTERED = 2;
            uint256 public x;
            modifier onlyOwner() {
                require(msg.sender == ownerVar);
                _;
            }
            modifier whenNotPaused() {
                require(!_paused);
                _;
            }
            modifier nonReentrant() {
                require(_status != _ENTERED);
                _status = _ENTERED;
                _;
                _status = _NOT_ENTERED;
            }
            function pause() external onlyOwner {
                _paused = true;
            }
            function execute() external onlyOwner whenNotPaused nonReentrant {
                x = 1;
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["execute()"])
    roles = sorted(leaf["authority_role"] for leaf in leaves)
    assert roles == ["caller_authority", "pause", "reentrancy"]

    cap = evaluate_tree_with_registry(trees["execute()"], _registry(), EvaluationContext(chain_id=1))
    assert cap.kind == "finite_set"
    cond_kinds = sorted(c.kind for c in cap.conditions)
    assert "pause" in cond_kinds
    assert "reentrancy" in cond_kinds


def test_role_shaped_mapping_with_populated_event_repo_resolves_members(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
            function f(bytes32 role) external view {
                require(_roles[role][msg.sender]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["f(bytes32)"])
    assert len(leaves) == 1
    descriptor = leaves[0]["set_descriptor"]
    # The plumbing is tested elsewhere; this checks the resolver consumes the hint.
    descriptor["enumeration_hint"] = [
        {
            "event_address": "0x0",
            "topic0": "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d",
            "topics_to_keys": {1: 0, 2: 1},
            "data_to_keys": {},
            "direction": "add",
        }
    ]

    repo = FakeEventLogRepo([ADDR_OWNER, ADDR_USER])
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=ADDR_OTHER,
        event_log_repo=repo,
    )
    cap = evaluate_tree_with_registry(trees["f(bytes32)"], _registry(), ctx)
    assert cap.kind == "finite_set"
    assert cap.members is not None
    members = set(cap.members)
    assert ADDR_OWNER.lower() in members
    assert ADDR_USER.lower() in members
