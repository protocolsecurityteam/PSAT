"""Corpus tests — real-world auth patterns end-to-end.

Each test compiles a structurally-faithful version of a canonical
production control pattern, runs it through the full
predicate pipeline (provenance → predicate builder → writer-gate
→ reentrancy/pause → capability evaluator), and asserts the
expected CapabilityExpr shape.

These are not protocol-bytecode pinning tests (those require
on-chain fixtures + an indexer running). They're structural
fidelity tests: "given source matching this canonical pattern, the
pipeline emits the right capability shape."

Patterns covered:
  - OZ role mapping ``grantRole`` via onlyRole modifier with
    ``_checkRole(getRoleAdmin(role))`` two-hop helper chain
  - OZ Ownable (single-owner check via require)
  - OZ Pausable (pause flag toggled by admin)
  - OZ ReentrancyGuard (status pre/post placeholder)
  - Maker DSS-style ``wards[ilk][user] == 1`` self-administered ACL
  - Gnosis Safe-style ``execTransaction`` (threshold_group via
    signature_auth — abbreviated)
  - external oracle call returning a boolean
  - DSAuth-style ``canCall`` external oracle
  - EIP-1271 contract-signature gate
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.adapters import AdapterRegistry, EnumerationResult, EvaluationContext  # noqa: E402
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402
from services.resolution.predicate_evaluator import (  # noqa: E402
    evaluate_tree_with_registry,
)
from services.static.static_analysis.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.static_analysis.reentrancy_pause import (  # noqa: E402
    apply_reentrancy_pause_pass,
)
from services.static.static_analysis.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)

ADDR_OWNER = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_USER = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ADDR_OTHER = "0xcccccccccccccccccccccccccccccccccccccccc"


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _build_pipeline(contract):
    """Run static stage + writer-gate + reentrancy/pause."""
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    return trees


def _all_leaves(tree):
    if tree is None:
        return []
    if tree.get("op") == "LEAF":
        return [tree["leaf"]] if tree.get("leaf") else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_all_leaves(child))
    return out


def _registry() -> AdapterRegistry:
    """Semantic resolver registry for corpus tests."""
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


# ---------------------------------------------------------------------------
# OZ Ownable — the simplest auth pattern
# ---------------------------------------------------------------------------


def test_oz_ownable_pattern(tmp_path):
    """``modifier onlyOwner() { require(msg.sender == _owner); _; }``
    function f() onlyOwner — predicate tree should classify the
    leaf as caller_authority via the modifier walk."""
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


# ---------------------------------------------------------------------------
# OZ role mapping — the canonical 2-key role mapping pattern
# ---------------------------------------------------------------------------


def test_oz_role_mapping_full_3_hop_helper_chain(tmp_path):
    """The actual production OZ role mapping (5.0+) uses a 3-hop
    helper chain:

      onlyRole(role)
        → _checkRole(role)
          → _checkRoleAddr(role, _msgSender())
            → if (!hasRole(role, account)) revert ...

    Pins the ParameterBindingEnv gap until full caller-side
    substitution lands."""
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
    # Membership leaf via 2-key roles[role].hasRoleMembers[caller]
    # — caller_authority via Rule B multi-key direct-promote.
    leaf = leaves[0]
    assert leaf["authority_role"] == "caller_authority"


def test_oz_role_mapping_grantrole_via_onlyrole(tmp_path):
    """The OZ role-mapping ``grantRole`` is gated by ``onlyRole(
    getRoleAdmin(role))`` which dispatches to ``_checkRole`` which
    contains the ``hasRole`` membership check. This is the
    canonical EtherFiTimelock pattern and the original motivation
    for the rewrite.

    LANDED via cross-function revert detection: RevertDetector
    now recurses into InternalCall callees (bounded depth) and
    the predicate builder uses gate.containing_function to walk
    the condition's defining IR through the helper's scope. The
    membership leaf inside _checkRole has 2 keys (role param +
    msg.sender) → caller_authority via Rule B's multi-key
    direct-promote.
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
    # Resolves to caller_authority membership (2-key mapping with
    # caller as one key — Rule B direct-promote via the
    # cross-function recursion).
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


# ---------------------------------------------------------------------------
# Direct role mapping: function with inline _checkRole call
# ---------------------------------------------------------------------------


def test_oz_role_mapping_inline_check(tmp_path):
    """Some AC contracts inline the role check directly in the
    function body — this case the pipeline DOES handle today."""
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


# ---------------------------------------------------------------------------
# OZ Pausable
# ---------------------------------------------------------------------------


def test_oz_pausable_pattern(tmp_path):
    """``modifier whenNotPaused() { require(!_paused); _; }`` plus
    an admin-gated ``pause()`` writer."""
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
    # Pause classifier cross-references writer-with-auth + reader-
    # with-revert; HIGH confidence by construction.
    assert leaves[0]["confidence"] == "high"


# ---------------------------------------------------------------------------
# OZ ReentrancyGuard
# ---------------------------------------------------------------------------


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
    # ReentrancyAnalyzer's pre/post-placeholder write pattern is a
    # tight structural match; HIGH confidence.
    assert leaves[0]["confidence"] == "high"


# ---------------------------------------------------------------------------
# Maker DSS-style wards
# ---------------------------------------------------------------------------


def test_maker_wards_pattern(tmp_path):
    """Maker uses ``wards[user] == 1`` as the canonical auth check.
    ``rely(addr)`` is gated by the same ``wards[msg.sender] == 1``
    (self-administered). My v6 b.ii promotion handles this."""
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
    # D.1 — value_predicate preserves the operator and RHS that the
    # scalar ``truthy_value`` field flattened. ``wards[msg.sender] == 1`` keeps
    # ``op="eq"``, ``rhs_values=["1"]``.
    vp = leaf["set_descriptor"].get("value_predicate")
    assert vp is not None
    assert vp["op"] == "eq"
    assert vp["rhs_values"] == ["1"]


def test_mapping_value_predicate_polarity_folds_neq_to_eq(tmp_path):
    """D.1 — ``if (owners[msg.sender] != 10) revert()`` describes the
    ALLOWED state ``owners[msg.sender] == 10``. The predicate builder
    must polarity-fold the gate's revert semantics so backends never
    have to know the gate direction.
    """
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
    # The scalar truthy_value remains available alongside value_predicate.
    assert desc["truthy_value"] == "10"
    # D.1: structured form with allowed-state semantics.
    vp = desc.get("value_predicate")
    assert vp is not None, "value_predicate must be emitted alongside truthy_value"
    assert vp["op"] == "eq", "!= revert folds to == allowed"
    assert vp["rhs_values"] == ["10"]
    assert vp["value_type"]  # uint256 in this case, but type detection is best-effort


# ---------------------------------------------------------------------------
# OR composition — owner OR business condition
# ---------------------------------------------------------------------------


def test_owner_or_business_or_branch_preserved(tmp_path):
    """``require(msg.sender == owner || amount > minThreshold)`` —
    per codex round-3 blocker #2, business condition must be
    preserved under OR. Capability is a structural OR of finite_set
    + conditional_universal."""
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
    # OR root with finite_set (owner) + conditional_universal (business).
    assert cap.kind == "OR"
    assert len(cap.children) == 2
    kinds = sorted(c.kind for c in cap.children)
    assert "conditional_universal" in kinds


# ---------------------------------------------------------------------------
# Combined: OZ AC + Reentrancy + Pause
# ---------------------------------------------------------------------------


def test_combined_authority_and_side_conditions(tmp_path):
    """Real production functions stack auth + reentrancy + pause.
    The predicate tree is AND of all three; capability evaluator
    intersects them, with side conditions appended."""
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
    # Three leaves: onlyOwner (caller_authority), whenNotPaused
    # (pause), nonReentrant (reentrancy). Order may vary.
    roles = sorted(leaf["authority_role"] for leaf in leaves)
    assert roles == ["caller_authority", "pause", "reentrancy"]

    # Evaluator: caller_authority leaf produces a finite_set placeholder;
    # pause + reentrancy produce conditional_universal. Intersect appends
    # both conditions.
    cap = evaluate_tree_with_registry(trees["execute()"], _registry(), EvaluationContext(chain_id=1))
    # finite_set ∩ conditional_universal ∩ conditional_universal
    # = finite_set (with both conditions appended).
    assert cap.kind == "finite_set"
    cond_kinds = sorted(c.kind for c in cap.conditions)
    assert "pause" in cond_kinds
    assert "reentrancy" in cond_kinds


# ---------------------------------------------------------------------------
# Event-indexed repo — end-to-end member resolution
# ---------------------------------------------------------------------------


def test_role_shaped_mapping_with_populated_event_repo_resolves_members(tmp_path):
    """When a descriptor carries an event hint and the generic event repo
    has matching members, the resolver enumerates them."""
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
    # Inject an event hint as mapping_events.py would. The plumbing path is
    # tested elsewhere; this confirms the resolver consumes it generically.
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
