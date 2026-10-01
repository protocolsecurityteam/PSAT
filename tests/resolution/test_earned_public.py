"""A caller-tainted gate matching no known permissionless shape fails closed; public is earned.

Every exclusion is tested in both polarities on real compiled contracts, since dict fakes hide provenance bugs.
"""

from __future__ import annotations

from typing import Any

import pytest

slither = pytest.importorskip("slither")

from services.resolution.capabilities import CapabilityExpr  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.permissionless_shapes import (  # noqa: E402
    is_permissionless_caller_shape,
    leaf_is_caller_tainted,
)
from services.resolution.predicate_evaluator import (  # noqa: E402
    EvaluationContext,
    evaluate_tree,
)
from tests.support.predicate_trees import _build_pipeline  # noqa: E402
from tests.support.slither_compile import _compile  # noqa: E402


@pytest.fixture
def earned_public(monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")


def _cap_for(sl, full_name: str):
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    return evaluate_tree(trees[full_name])


# A chained ACL target (Aragon/Lido ``kernel().acl().canPerform``) traced to ``computed`` and failed open; a direct
# state-var target was already gated.


def test_effectful_library_membership_consume_stays_gated(tmp_path, earned_public):
    """An effectful library call on the contract's own storage only admits curated members
    (PermissionController.acceptAdmin).
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        library AddressSet {
            struct Set { bytes32[] values; mapping(bytes32 => uint256) positions; }
            function _remove(Set storage set, bytes32 value) private returns (bool) {
                uint256 position = set.positions[value];
                if (position == 0) return false;
                uint256 valueIndex = position - 1;
                uint256 lastIndex = set.values.length - 1;
                if (valueIndex != lastIndex) {
                    bytes32 lastValue = set.values[lastIndex];
                    set.values[valueIndex] = lastValue;
                    set.positions[lastValue] = position;
                }
                set.values.pop();
                delete set.positions[value];
                return true;
            }
            function remove(Set storage set, address value) internal returns (bool) {
                return _remove(set, bytes32(uint256(uint160(value))));
            }
        }
        contract C {
            using AddressSet for AddressSet.Set;
            AddressSet.Set private pendingAdmins;
            function acceptAdmin() external {
                require(pendingAdmins.remove(msg.sender), "not pending");
            }
        }
    """,
    )
    cap = _cap_for(sl, "acceptAdmin()")
    assert cap.kind == "external_check_only", f"library membership-consume must stay gated, got {cap.kind}"


def test_wrapper_library_value_movement_stays_open(tmp_path, earned_public):
    """A wrapper library reaching an external call moves another contract's assets like ``transferFrom``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        library SafeERC20 {
            function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
                _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
            }
            function _callOptionalReturn(IERC20 token, bytes memory data) private {
                (bool success, bytes memory returndata) = address(token).call(data);
                require(success, "SafeERC20: low-level call failed");
                if (returndata.length > 0) {
                    require(abi.decode(returndata, (bool)), "SafeERC20: operation failed");
                }
            }
        }
        contract C {
            using SafeERC20 for IERC20;
            IERC20 immutable token;
            constructor(IERC20 t) { token = t; }
            function deposit(uint256 amount) external {
                token.safeTransferFrom(msg.sender, address(this), amount);
            }
        }
    """,
    )
    cap = _cap_for(sl, "deposit(uint256)")
    assert cap.kind == "conditional_universal", f"wrapper-library value movement must stay open, got {cap.kind}"


def test_assembly_wrapper_library_value_movement_stays_open(tmp_path, earned_public):
    """SafeTransferLib's assembly call has no LowLevelCall IR (the BoringVault canary)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        library SafeTransferLib {
            function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
                bool success;
                assembly {
                    let freeMemoryPointer := mload(0x40)
                    mstore(freeMemoryPointer, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
                    mstore(add(freeMemoryPointer, 4), from)
                    mstore(add(freeMemoryPointer, 36), to)
                    mstore(add(freeMemoryPointer, 68), amount)
                    success := and(
                        or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                        call(gas(), token, 0, freeMemoryPointer, 100, 0, 32)
                    )
                }
                require(success, "TRANSFER_FROM_FAILED");
            }
        }
        contract C {
            address immutable token;
            constructor(address t) { token = t; }
            function deposit(uint256 amount) external {
                SafeTransferLib.safeTransferFrom(token, msg.sender, address(this), amount);
            }
        }
    """,
    )
    cap = _cap_for(sl, "deposit(uint256)")
    assert cap.kind == "conditional_universal", f"assembly wrapper value movement must stay open, got {cap.kind}"


def test_void_call_with_merkle_witness_gates_under_flag(tmp_path, earned_public):
    """A merkle witness makes it an allowlist the caller can't self-admit into."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IMembershipNFT {
            function processDepositFromEapUser(
                address user, uint256 snapshotEthAmount, uint256 points, bytes32[] calldata merkleProof
            ) external;
        }
        contract C {
            IMembershipNFT immutable nft;
            constructor(IMembershipNFT n) { nft = n; }
            function wrapForEap(uint256 amount, uint256 points, bytes32[] calldata proof) external payable {
                nft.processDepositFromEapUser(msg.sender, amount, points, proof);
            }
        }
    """,
    )
    cap = _cap_for(sl, "wrapForEap(uint256,uint256,bytes32[])")
    assert cap.kind == "external_check_only", f"void merkle-witness call must gate, got {cap.kind}"


def test_caller_allowlist_membership_gates_under_flag(tmp_path, earned_public):
    """The bespoke E4 arm is bypassed with the flag on."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) public allowed;
            function f() external view {
                require(allowed[msg.sender]);
            }
        }
    """,
    )
    cap = _cap_for(sl, "f()")
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert "caller_keyed_membership_allowlist" in (cap.check.extra.get("basis") or [])


def test_caller_equals_untyped_computed_stays_open(tmp_path, earned_public):
    """Inlining folds caller-keyed reads to ``msg.sender == <scalar>``; gating these manufactured false gates."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(uint256 salt) external view {
                require(msg.sender == address(uint160(uint256(keccak256(abi.encode(salt))))), "no");
            }
        }
    """,
    )
    cap = _cap_for(sl, "f(uint256)")
    assert cap.kind == "conditional_universal", f"untyped computed equality must stay open, got {cap.kind}"


def test_renounce_style_self_service_stays_open_under_flag(tmp_path, earned_public):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) member;
            function renounce(address account) external {
                require(account == msg.sender, "can only renounce own");
                member[account] = false;
            }
        }
    """,
    )
    cap = _cap_for(sl, "renounce(address)")
    assert cap.kind == "conditional_universal", f"self-service equality must stay open, got {cap.kind}"
    assert any(c.kind == "self_service" for c in cap.conditions)


def _leaf(**kw) -> Any:
    leaf = {
        "kind": "equality",
        "operator": "eq",
        "authority_role": "business",
        "operands": [],
        "references_msg_sender": False,
        "parameter_indices": [],
        "expression": "",
        "basis": [],
    }
    leaf.update(kw)
    return leaf


def test_self_comparison_and_signature_self_auth_are_permissionless():
    assert is_permissionless_caller_shape(_leaf(operands=[{"source": "msg_sender"}, {"source": "tx_origin"}]))
    assert is_permissionless_caller_shape(_leaf(operands=[{"source": "msg_sender"}, {"source": "signature_recovery"}]))


def test_caller_vs_parameter_is_permissionless_but_state_var_is_not():
    assert is_permissionless_caller_shape(
        _leaf(operands=[{"source": "msg_sender"}, {"source": "parameter", "parameter_index": 0}])
    )
    assert not is_permissionless_caller_shape(
        _leaf(operands=[{"source": "msg_sender"}, {"source": "state_variable", "state_variable_name": "owner"}])
    )


def test_caller_vs_non_address_scalar_is_permissionless():
    # A folded claim-once, not an identity test.
    assert is_permissionless_caller_shape(
        _leaf(
            operands=[{"source": "msg_sender"}, {"source": "constant", "constant_value": "0", "value_type": "uint256"}]
        )
    )
    assert is_permissionless_caller_shape(
        _leaf(operands=[{"source": "msg_sender"}, {"source": "computed", "computed_kind": "member.REGISTERED"}])
    )
    assert not is_permissionless_caller_shape(
        _leaf(
            operands=[
                {"source": "msg_sender"},
                {"source": "constant", "constant_value": "0x" + "ab" * 20, "value_type": "address"},
            ]
        )
    )


# An unresolved root-caller check AND a public side-condition gates; bound checks and resolved-empty ceilings keep the
# legacy fold.

from services.policy.capability_surface import project_capability_surface  # noqa: E402


def _and_dict(*children):
    return {"kind": "AND", "children": list(children)}


_PUBLIC = {"kind": "conditional_universal", "conditions": [{"kind": "business", "description": "whenNotPaused"}]}
# Only caller-gate-tagged checks block a sibling public path.
_ROOT_CHECK = {
    "kind": "external_check_only",
    "check": {
        "target_address": None,
        "target_call_selector": None,
        "extra": {"basis": ["caller_tainted_authority_unresolved"]},
    },
}
_BOUND_CHECK = {**_ROOT_CHECK, "subject": "bound"}
# Gate provenance, not a caller-gate tag, so never a blocker.
_PROBE_CHECK = {
    "kind": "external_check_only",
    "check": {
        "target_address": "0x" + "cd" * 20,
        "target_call_selector": "0x61a3bcc8",
        "extra": {"basis": ["if-revert via successor NodeType.EXPRESSION"]},
    },
}
_EMPTY_LOWER = {"kind": "finite_set", "members": [], "membership_quality": "lower_bound", "confidence": "partial"}
_EMPTY_EXACT = {"kind": "finite_set", "members": [], "membership_quality": "exact", "confidence": "enumerable"}
_OWNER_SET = {
    "kind": "finite_set",
    "members": ["0x" + "ab" * 20],
    "membership_quality": "exact",
    "confidence": "enumerable",
}


def test_root_check_blocks_public_path_under_flag(earned_public):
    surface = project_capability_surface(_and_dict(_PUBLIC, _ROOT_CHECK))
    assert not surface.authority_public
    assert surface.residual


def test_bound_check_never_blocks_public_path(earned_public):
    surface = project_capability_surface(_and_dict(_PUBLIC, _BOUND_CHECK))
    assert surface.authority_public


def test_untagged_probe_check_never_blocks_public_path(earned_public):
    """test_veda_principal_dimension pins the public surface."""
    surface = project_capability_surface(_and_dict(_PUBLIC, _PROBE_CHECK))
    assert surface.authority_public


def test_unread_owner_equality_blocks_public_path_under_flag(earned_public):
    """An unread owner equality used to vanish, letting a sibling public path open
    WithdrawRequestNFT.seizeInvalidRequest.
    """
    surface = project_capability_surface(_and_dict(_PUBLIC, _EMPTY_LOWER))
    assert not surface.authority_public


def test_resolved_empty_is_not_a_blocker(earned_public):
    surface = project_capability_surface(_and_dict(_PUBLIC, _EMPTY_EXACT))
    assert surface.authority_public


def test_principal_rows_survive_root_check_under_flag(earned_public):
    surface = project_capability_surface(_and_dict(_OWNER_SET, _ROOT_CHECK))
    assert not surface.authority_public
    assert [r["address"] for r in surface.principal_rows] == ["0x" + "ab" * 20]


def test_or_blocks_only_when_every_disjunct_blocks(earned_public):
    blocked = project_capability_surface(_and_dict(_PUBLIC, {"kind": "OR", "children": [_ROOT_CHECK, _EMPTY_LOWER]}))
    assert not blocked.authority_public
    open_or = project_capability_surface(_and_dict(_PUBLIC, {"kind": "OR", "children": [_ROOT_CHECK, dict(_PUBLIC)]}))
    assert open_or.authority_public


def test_eth_send_success_check_stays_open(tmp_path, earned_public):
    """Refunding the caller is value movement, not an allowlist."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public refunds;
            function claimRefund() external {
                uint256 amount = refunds[msg.sender];
                refunds[msg.sender] = 0;
                (bool sent, ) = msg.sender.call{value: amount}("");
                require(sent, "Failed to send Ether");
            }
        }
    """,
    )
    cap = _cap_for(sl, "claimRefund()")
    assert cap.kind == "conditional_universal", f"send-success check must stay open, got {cap.kind}"


def test_caller_equals_param_keyed_view_lookup_stays_open(tmp_path, earned_public):
    """Matching a value keyed by its own argument is self-service, not a fixed authority."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(uint256 => address) private _owners;
            function ownerOf(uint256 tokenId) public view returns (address) {
                return _owners[tokenId];
            }
            function burn(uint256 tokenId) external {
                require(msg.sender == ownerOf(tokenId), "not owner");
                delete _owners[tokenId];
            }
        }
    """,
    )
    cap = _cap_for(sl, "burn(uint256)")
    assert cap.kind == "conditional_universal", f"param-keyed view lookup must stay open, got {cap.kind}"
    assert any(c.kind == "self_service" for c in cap.conditions)


# #111/#112: an admin-curated ``tier[msg.sender] >= K`` is promoted to caller_authority and fails closed when cold,
# while a self-acquirable ``points[msg.sender] >= K`` stays business and opens.

_ADMIN_CURATED_THRESHOLD = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        bool public open;
        mapping(address => uint256) public tier;
        constructor() { owner = msg.sender; }
        function setTier(address a, uint256 t) external {
            require(msg.sender == owner, "only owner");
            tier[a] = t;
        }
        function gated() external {
            require(open, "closed");
            require(tier[msg.sender] >= 2, "tier too low");
        }
    }
"""

_SELF_SERVICE_THRESHOLD = """
    pragma solidity ^0.8.19;
    contract C {
        bool public open;
        mapping(address => uint256) public points;
        function earn() external { points[msg.sender] += 1; }
        function gated() external {
            require(open, "closed");
            require(points[msg.sender] >= 5, "need points");
        }
    }
"""


class _StubAdapter:
    """Models adapter outcomes without smuggling in the routing decision under test."""

    def __init__(self, cap: Any) -> None:
        self._cap = cap

    def enumerate(self, descriptor: Any, contract_address: Any) -> Any:
        return self._cap


def _gate_comparison_subtree(tree: dict) -> Any:
    for child in tree.get("children") or []:
        leaf = child.get("leaf") or {}
        if leaf.get("kind") == "comparison":
            return child
    raise AssertionError("gate tree has no comparison leaf")


def _threshold_caps(sl, full_name: str, adapter: Any = None):
    """The surface includes the public sibling the projection blocker must suppress."""
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    tree = trees[full_name]
    gate_subtree = _gate_comparison_subtree(tree)
    role = (gate_subtree.get("leaf") or {}).get("authority_role")
    ctx = EvaluationContext(contract_address="0x" + "11" * 20, adapter=adapter)
    gate_cap = evaluate_tree(gate_subtree, ctx)
    surface = project_capability_surface(capability_to_dict(evaluate_tree(tree, ctx)))
    return role, gate_cap, surface


def test_admin_curated_threshold_cold_fails_closed(tmp_path, earned_public):
    """Revert-proof for both Part A and Part B."""
    sl = _compile(tmp_path, _ADMIN_CURATED_THRESHOLD)
    role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=None)
    assert role == "caller_authority"
    assert gate_cap.kind == "external_check_only", f"cold admin threshold must gate, got {gate_cap.kind}"
    basis = capability_to_dict(gate_cap)["check"]["extra"]["basis"]
    assert basis == ["caller_tainted_authority_unresolved"]
    assert not surface.authority_public


def test_admin_curated_threshold_exact_empty_is_resolved_not_public(tmp_path, earned_public):
    sl = _compile(tmp_path, _ADMIN_CURATED_THRESHOLD)
    empty_exact = CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
    role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=_StubAdapter(empty_exact))
    assert role == "caller_authority"
    assert gate_cap.kind == "finite_set"
    assert gate_cap.members == []
    assert gate_cap.membership_quality == "exact"
    assert not surface.authority_public


def test_admin_curated_threshold_warm_enumerates_restricted_holders(tmp_path, earned_public):
    sl = _compile(tmp_path, _ADMIN_CURATED_THRESHOLD)
    holders = ["0x" + "aa" * 20, "0x" + "bb" * 20]
    warm = CapabilityExpr.finite_set(holders, quality="lower_bound", confidence="partial")
    _role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=_StubAdapter(warm))
    assert gate_cap.kind == "finite_set"
    assert gate_cap.members == holders
    assert not surface.authority_public


def test_self_service_threshold_stays_public_when_cold(tmp_path, earned_public):
    sl = _compile(tmp_path, _SELF_SERVICE_THRESHOLD)
    role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=None)
    assert role == "business"
    assert gate_cap.kind == "conditional_universal", f"self-service threshold must stay open, got {gate_cap.kind}"
    assert surface.authority_public


# Solady EnumerableRoles: an assembly role read the lifter can't lower was hardcoded ``business`` and published public.

_SOLADY_SELF_GATE = """
    pragma solidity ^0.8.19;
    contract C {
        uint256 public constant UPGRADE_TIMELOCK_ROLE_ID = 1;
        function hasRole(address holder, uint256 role) public view returns (bool result) {
            assembly {
                mstore(0x00, holder)
                mstore(0x20, role)
                result := iszero(iszero(sload(keccak256(0x00, 0x40))))
            }
        }
        function hasRole2(bytes32 role, address account) public view returns (bool) {
            return hasRole(account, uint256(role));
        }
        function onlyUpgradeTimelock(address account) public view {
            if (!hasRole2(bytes32(UPGRADE_TIMELOCK_ROLE_ID), account)) revert();
        }
        function f() external {
            _authorizeUpgrade();
        }
        function _authorizeUpgrade() internal view {
            onlyUpgradeTimelock(msg.sender);
        }
    }
"""

_SOLADY_MODIFIER_GATE = """
    pragma solidity ^0.8.19;
    contract C {
        function hasRole(address holder, uint256 role) internal view returns (bool result) {
            assembly {
                mstore(0x00, holder)
                mstore(0x20, role)
                result := iszero(iszero(sload(keccak256(0x00, 0x40))))
            }
        }
        modifier onlyTL() {
            if (!hasRole(msg.sender, 1)) revert();
            _;
        }
        function f() external onlyTL {}
    }
"""


def _leaves(tree):
    if not isinstance(tree, dict):
        return []
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return [leaf] if leaf else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_leaves(child))
    return out


def test_solady_self_gate_emits_probeable_descriptor_and_gates(tmp_path, earned_public):
    """The self-gate is emitted as the same ``external_set`` shape as an external call, reaching the role-store
    adapter.
    """
    sl = _compile(tmp_path, _SOLADY_SELF_GATE)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    leaves = _leaves(trees["f()"])
    gate = next(leaf for leaf in leaves if leaf.get("set_descriptor"))
    descriptor = gate["set_descriptor"]
    assert descriptor["kind"] == "external_set"
    assert descriptor["callee_signature"] == "onlyUpgradeTimelock(address)"
    assert descriptor["authority_contract"]["address_source"] == {"source": "self_address"}
    assert descriptor["key_sources"] == [{"source": "msg_sender"}]
    assert gate["authority_role"] == "delegated_authority"
    assert leaf_is_caller_tainted(gate) is True
    assert is_permissionless_caller_shape(gate) is False

    cap = evaluate_tree(trees["f()"])
    assert cap.kind != "conditional_universal", "the unlowered-role fail-open"
    assert capability_to_dict(cap)["kind"] != "conditional_universal"


def _tree_verdict(tree):
    dd = capability_to_dict(evaluate_tree(tree))
    return dd.get("kind")


_SIBLING_CHECKERS = """
    pragma solidity ^0.8.19;
    contract C {
        uint256 public constant ROLE_A = 1;
        uint256 public constant ROLE_B = 2;
        function hasRole(address holder, uint256 role) public view returns (bool result) {
            assembly {
                mstore(0x00, holder)
                mstore(0x20, role)
                result := iszero(iszero(sload(keccak256(0x00, 0x40))))
            }
        }
        function onlyA(address account) public view { if (!hasRole(account, ROLE_A)) revert(); }
        function onlyB(address account) public view { if (!hasRole(account, ROLE_B)) revert(); }
        function guarded() external { onlyA(msg.sender); }
    }
"""


def test_sibling_checkers_get_the_same_verdict_regardless_of_callers(tmp_path, earned_public):
    """cid-568: onlyUpgradeTimelock flipped while eight identical siblings stayed public."""
    sl = _compile(tmp_path, _SIBLING_CHECKERS)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    assert _tree_verdict(trees["onlyA(address)"]) == "conditional_universal"
    assert _tree_verdict(trees["onlyB(address)"]) == "conditional_universal"
    assert _tree_verdict(trees["guarded()"]) != "conditional_universal"
    for leaf in _leaves(trees["onlyA(address)"]):
        for op in leaf.get("operands") or []:
            names = {o.get("state_variable_name") for o in (op.get("derived_from") or [])}
            assert "ROLE_B" not in names


def test_solady_modifier_gate_caller_taint_survives_the_digest(tmp_path, earned_public):
    """``derived_from`` shows the caller was an argument of the un-lowerable read."""
    sl = _compile(tmp_path, _SOLADY_MODIFIER_GATE)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    gate = next(leaf for leaf in _leaves(trees["f()"]) if leaf.get("operator") in ("truthy", "falsy"))
    origins = [o.get("source") for o in (gate["operands"][0].get("derived_from") or [])]
    assert "msg_sender" in origins
    assert leaf_is_caller_tainted(gate) is True
    assert is_permissionless_caller_shape(gate) is False
    assert evaluate_tree(trees["f()"]).kind != "conditional_universal"


def test_collapsed_caller_taint_does_not_fire_on_value_bounds_or_signature_checks():
    """``derived_from`` is transitive; the broad form tainted 25 corpus leaves, 23 wrongly."""
    from typing import cast

    from services.resolution.permissionless_shapes import leaf_caller_taint_is_collapsed as _collapsed
    from services.static.contract_analysis_pipeline.predicate_types import LeafPredicate

    def leaf_caller_taint_is_collapsed(leaf: dict) -> bool:
        return _collapsed(cast(LeafPredicate, leaf))

    caller_origin = [{"source": "msg_sender"}]
    computed = {"source": "computed", "computed_kind": "binary", "derived_from": caller_origin}

    assert not leaf_caller_taint_is_collapsed({"kind": "comparison", "operator": "lte", "operands": [computed]})
    assert not leaf_caller_taint_is_collapsed({"kind": "equality", "operator": "ne", "operands": [computed]})
    assert not leaf_caller_taint_is_collapsed({"kind": "equality", "operator": "eq", "operands": [computed]})
    assert not leaf_caller_taint_is_collapsed({"kind": "external_bool", "operator": "truthy", "operands": [computed]})
    assert not leaf_caller_taint_is_collapsed(
        {"kind": "equality", "operator": "truthy", "operands": [computed, {"source": "state_variable"}]}
    )
    assert not leaf_caller_taint_is_collapsed(
        {
            "kind": "equality",
            "operator": "truthy",
            "operands": [{"source": "external_call", "derived_from": caller_origin}],
        }
    )
    assert leaf_caller_taint_is_collapsed({"kind": "equality", "operator": "truthy", "operands": [computed]})
    assert not leaf_caller_taint_is_collapsed(
        {"kind": "equality", "operator": "truthy", "operands": [{"source": "computed", "derived_from": None}]}
    )
