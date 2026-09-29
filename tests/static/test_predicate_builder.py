"""Tests for ``build_predicate_tree`` (services.static...predicates).

End-to-end from a Solidity function through ProvenanceEngine + RevertDetector to a
typed PredicateTree: equality/membership leaves, polarity normalization,
authority_role classification (Rule A caller equality; Rule B multi-key
membership), 1-key caller-only membership defaulting to business (week-3 writer-key
two-pass may promote), external_bool delegated_authority, unguarded -> None.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any, cast

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_types import Operand  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    _operand_sort_key,
    build_predicate_tree,
    build_return_predicate_tree,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _function(sl: Slither, name: str):
    for c in sl.contracts:
        for f in c.functions:
            if f.name == name:
                return f
    raise LookupError(name)


def _all_leaves(tree):
    """Flatten a PredicateTree into its LEAF nodes."""
    if tree is None:
        return []
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return [leaf] if leaf else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_all_leaves(child))
    return out


# Equality leaves


def test_caller_equals_state_var_classifies_caller_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view {
                require(msg.sender == ownerVar);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1, leaves
    leaf = leaves[0]
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority"
    assert leaf["references_msg_sender"] is True


def test_if_revert_inverts_operator(tmp_path):
    """``if (msg.sender != owner) revert()``: the ``!=`` is flipped to eq via the
    polarity rule (allowed_when_false), NOT via a NOT node."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view {
                if (msg.sender != ownerVar) revert();
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    # if (a != b) revert => allowed when a == b; caller_authority as one operand is msg.sender.
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority"


def test_caller_equals_parameter_classifies_caller_authority(tmp_path):
    """``require(account == msg.sender)`` (renounceRole-style): an address parameter
    is 'who is allowed', so this is caller_authority."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function renounce(address account) external {
                require(account == msg.sender);
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "renounce")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority"


# Membership leaves


def test_two_key_membership_with_caller_promotes_to_caller_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) _members;
            function f(bytes32 role) external view {
                require(_members[role][msg.sender]);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["operator"] == "truthy"
    assert leaf["authority_role"] == "caller_authority"


def test_one_key_caller_membership_defaults_to_business(tmp_path):
    """``require(claimed[msg.sender])`` is a 1-key caller-only bool map, auth
    (blacklist) or business (claim flag). Without writer-key analysis (week 3),
    default to business so we don't over-admit."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) claimed;
            function f() external view {
                require(claimed[msg.sender]);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["authority_role"] == "business"


# Multiple gates → AND tree


def test_two_requires_combine_via_and(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public minAmount;
            function f(uint256 amount) external view {
                require(msg.sender == ownerVar);
                require(amount > minAmount);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    assert tree["op"] == "AND"  # pyright: ignore[reportTypedDictNotRequiredAccess]
    assert len(tree["children"]) == 2  # pyright: ignore[reportTypedDictNotRequiredAccess]
    leaves = _all_leaves(tree)
    kinds = sorted(leaf["kind"] for leaf in leaves)
    assert kinds == ["comparison", "equality"]


# Unguarded function


def test_time_gate_classifies_as_time(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public deadline;
            function f() external view {
                require(block.timestamp > deadline);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    assert leaves[0]["authority_role"] == "time"


def test_caller_keyed_time_check_stays_caller_authority(tmp_path):
    """``require(block.timestamp > cooldown[msg.sender])`` has both block_context AND
    msg.sender; caller takes priority, and comparison + caller-key isn't an
    authority shape we recognize, so it stays business."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public cooldown;
            function f() external view {
                require(block.timestamp > cooldown[msg.sender]);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    # msg.sender (cooldown index) and block_context: caller priority, so not time; no auth shape, so business.
    assert leaves[0]["authority_role"] != "time"


def test_logical_or_splits_into_or_subtree(tmp_path):
    """``require(msg.sender == owner || amount > threshold)``: an OR root with a
    caller_authority equality and a business leaf, preserved so admission is correct."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public threshold;
            function f(uint256 amount) external view {
                require(msg.sender == ownerVar || amount > threshold);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    assert tree["op"] == "OR", tree  # pyright: ignore[reportTypedDictNotRequiredAccess]
    leaves = _all_leaves(tree)
    assert len(leaves) == 2
    kinds = sorted(leaf["kind"] for leaf in leaves)
    assert kinds == ["comparison", "equality"]
    auth_roles = [leaf["authority_role"] for leaf in leaves]
    assert "caller_authority" in auth_roles


def test_logical_and_splits_into_and_subtree(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public threshold;
            function f(uint256 amount) external view {
                require(msg.sender == ownerVar && amount > threshold);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    # Either flat AND or nested (top-level gates AND wraps the inner && AND).
    leaves = _all_leaves(tree)
    assert len(leaves) == 2
    kinds = sorted(leaf["kind"] for leaf in leaves)
    assert kinds == ["comparison", "equality"]


def test_ecrecover_equality_classifies_signature_auth(tmp_path):
    """``recovered = ecrecover(...); require(recovered == signerAddr)``: a
    signature_recovery operand equal to an address operand is the canonical
    signature-auth pattern (shape-tight, always caller_authority)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public signerAddr;
            function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) external view {
                address recovered = ecrecover(h, v, r, s);
                require(recovered == signerAddr);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "signature_auth"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority"


def test_inline_ecrecover_in_require(tmp_path):
    """Inline ``require(msg.sender == ecrecover(...))``: the output goes through TMP
    propagation and must still classify as signature_auth."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) external view {
                require(msg.sender == ecrecover(h, v, r, s));
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    assert leaves[0]["kind"] == "signature_auth"
    assert leaves[0]["authority_role"] == "caller_authority"


@pytest.mark.parametrize(
    "source_template,expected_kind,expected_op",
    [
        ("require(a == b);", "equality", "eq"),
        ("require(a != b);", "equality", "ne"),
        ("if (a == b) revert();", "equality", "ne"),
        ("if (a != b) revert();", "equality", "eq"),
        ("require(a > b);", "comparison", "gt"),
        ("require(a < b);", "comparison", "lt"),
        ("require(a >= b);", "comparison", "gte"),
        ("require(a <= b);", "comparison", "lte"),
        ("if (a > b) revert();", "comparison", "lte"),
        ("if (a < b) revert();", "comparison", "gte"),
        ("if (a >= b) revert();", "comparison", "lt"),
        ("if (a <= b) revert();", "comparison", "gt"),
    ],
)
def test_polarity_normalization_truth_table(tmp_path, source_template, expected_kind, expected_op):
    sl = _compile(
        tmp_path,
        f"""
        pragma solidity ^0.8.19;
        contract C {{
            uint256 public x;
            function f(uint256 a, uint256 b) external {{
                {source_template}
                x = 1;
            }}
        }}
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    leaves = _all_leaves(tree)
    assert len(leaves) == 1, f"got {len(leaves)} leaves: {leaves}"
    assert leaves[0]["kind"] == expected_kind, leaves[0]
    assert leaves[0]["operator"] == expected_op, leaves[0]


def test_modifier_only_owner_admits(tmp_path):
    """A gate entirely in an `onlyOwner` modifier: RevertDetector walks modifier
    bodies, so it admits with caller_authority."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public x;
            modifier onlyOwner() {
                require(msg.sender == ownerVar);
                _;
            }
            function f() external onlyOwner {
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    assert len(leaves) == 1, leaves
    leaf = leaves[0]
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority"


def test_caller_equals_external_getter_classified_caller_authority(tmp_path):
    """``require(msg.sender == registry.admin())`` — the non-caller operand is an
    external call returning ``address`` (Solidity forces it, else the ``==`` won't
    type-check). It is a caller-authority gate, not a ``business`` side-condition.
    Dropping it to business lowered the function to ``conditional_universal`` →
    public (the PauserRegistry.unpauser() / avsNodeRunner() false-open class)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IRegistry { function admin() external view returns (address); }
        contract C {
            IRegistry public registry;
            function f() external view {
                require(msg.sender == registry.admin());
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    assert len(leaves) == 1, leaves
    leaf = leaves[0]
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority", (
        f"caller==external.getter() misclassified as {leaf['authority_role']} "
        "(should be caller_authority; business lowers it to a public false-open)"
    )


def test_modifier_with_external_bool_call(tmp_path):
    """A modifier body with an external authority call: provenance finds the
    HighLevelCall on a state-var target with msg.sender in args -> delegated_authority."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function canCall(address) external view returns (bool);
        }
        contract C {
            IAuthority public authority;
            uint256 public x;
            modifier authed() {
                require(authority.canCall(msg.sender));
                _;
            }
            function f() external authed {
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "external_bool"
    assert leaf["authority_role"] == "delegated_authority"
    descriptor = leaf.get("set_descriptor")
    assert isinstance(descriptor, dict)
    authority = descriptor.get("authority_contract")
    assert isinstance(authority, dict)
    address_source = authority.get("address_source")
    assert isinstance(address_source, dict)
    assert descriptor.get("kind") == "external_set"
    assert address_source.get("state_variable_name") == "authority"
    assert descriptor.get("callee_signature") == "canCall(address)"


def test_external_bool_descriptor_is_not_name_based(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function permitted(address who, bytes32 role) external view returns (bool);
        }
        contract C {
            bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
            IAuthority public authority;
            function f() external view {
                require(authority.permitted(msg.sender, OPERATOR_ROLE));
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "external_bool"
    assert leaf["authority_role"] == "delegated_authority"
    descriptor = leaf.get("set_descriptor")
    assert isinstance(descriptor, dict)
    authority = descriptor.get("authority_contract")
    assert isinstance(authority, dict)
    address_source = authority.get("address_source")
    assert isinstance(address_source, dict)
    assert descriptor.get("kind") == "external_set"
    assert address_source.get("state_variable_name") == "authority"
    assert descriptor.get("callee_signature") == "permitted(address,bytes32)"
    assert descriptor.get("callee_function") == "permitted"


def test_bare_void_state_var_call_becomes_delegated_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IGate {
            function check(address who) external view;
        }
        contract C {
            IGate public gate;
            uint256 public x;
            function f() external {
                gate.check(msg.sender);
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "external_bool"
    assert leaf["authority_role"] == "delegated_authority"
    descriptor = leaf.get("set_descriptor")
    assert isinstance(descriptor, dict)
    assert descriptor.get("callee_signature") == "check(address)"
    authority = descriptor.get("authority_contract")
    assert isinstance(authority, dict)
    assert authority.get("address_source") == {"source": "state_variable", "state_variable_name": "gate"}


def test_try_catch_external_bool_call_builds_delegated_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function canCall(address who) external view returns (bool);
        }
        contract C {
            IAuthority public authority;
            function f() external {
                try authority.canCall(msg.sender) returns (bool ok) {
                    require(ok);
                } catch {
                    revert("denied");
                }
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    leaf = next(
        leaf
        for leaf in leaves
        if leaf.get("kind") == "external_bool" and leaf.get("authority_role") == "delegated_authority"
    )
    assert leaf["kind"] == "external_bool"
    assert leaf["authority_role"] == "delegated_authority"
    descriptor = leaf.get("set_descriptor")
    assert isinstance(descriptor, dict)
    assert descriptor.get("callee_signature") == "canCall(address)"


def test_modifier_chained_yields_multiple_gates(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public threshold;
            uint256 public x;
            modifier onlyOwner() {
                require(msg.sender == ownerVar);
                _;
            }
            modifier minThreshold(uint256 amount) {
                require(amount > threshold);
                _;
            }
            function f(uint256 amount) external onlyOwner minThreshold(amount) {
                x = amount;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    assert len(leaves) == 2
    kinds = sorted(leaf["kind"] for leaf in leaves)
    assert kinds == ["comparison", "equality"]


def test_unguarded_function_returns_none(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f() external {
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is None


# Confidence levels (HIGH / MEDIUM / LOW)


def test_confidence_high_for_caller_equals_state_var(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view {
                require(msg.sender == ownerVar);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] == "caller_authority"
    assert leaves[0]["confidence"] == "high"  # pyright: ignore[reportTypedDictNotRequiredAccess]


def test_confidence_high_for_multi_key_caller_membership(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            bytes32 constant MINTER = keccak256("MINTER");
            function f() external {
                require(_roles[MINTER][msg.sender]);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] == "caller_authority"
    assert leaves[0]["confidence"] == "high"  # pyright: ignore[reportTypedDictNotRequiredAccess]


def test_confidence_low_for_business_residual(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            bool public flag;
            function f() external {
                require(flag);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] == "business"
    assert leaves[0]["confidence"] == "low"  # pyright: ignore[reportTypedDictNotRequiredAccess]


def test_confidence_low_for_unsupported(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function externalCheck() external pure returns (bool) { return true; }
            function f() external {
                bool a = (block.timestamp + block.number) % 2 == 0;
                require(a);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["confidence"] == "low"  # pyright: ignore[reportTypedDictNotRequiredAccess]


# AuthorityClassifier rule expansion


def test_caller_equals_constant_address_classifies_caller_authority(tmp_path):
    """``require(msg.sender == 0x1234...)``: a hardcoded auth check; expanded Rule A
    accepts ``constant`` as address-typed."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f() external {
                require(msg.sender == 0x1111111111111111111111111111111111111111);
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] == "caller_authority"


def test_caller_equals_block_context_does_not_classify_as_caller_authority(tmp_path):
    """``require(uint256(uint160(msg.sender)) == block.number)`` is nonsense as auth
    (block.number isn't address-typed); after the Rule A expansion it stays business."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f() external {
                require(uint256(uint160(msg.sender)) == block.number);
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] != "caller_authority"


def test_parameter_indices_resolved_caller_side_through_modifier(tmp_path):
    """``parameter_indices`` must reference the FUNCTION's parameter positions, not
    the modifier's. Without caller-side ParameterBindingEnv substitution a modifier
    index (0) coincides with f's index 0, so use a function with >=2 params and a
    modifier taking one to make the mapping distinguishable."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            modifier onlyAddr(address authorized) {
                require(msg.sender == authorized);
                _;
            }
            // The 'extra' first param ensures the modifier-side
            // param index (0) is NOT the same as the function-side
            // index for 'admin' (1) — a regression where the
            // modifier's index leaks would show parameter_indices=[0].
            function guarded(uint256 extra, address admin) external onlyAddr(admin) {}
        }
    """,
    )
    fn = _function(sl, "guarded")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["parameter_indices"] == [1]
    operand_param = next(o for o in leaves[0]["operands"] if o.get("source") == "parameter")
    assert operand_param.get("parameter_index") == 1
    assert operand_param.get("parameter_name") == "admin"


def test_parameter_indices_resolved_caller_side_through_helper(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            modifier onlyAddr(address authorized) {
                _check(authorized);
                _;
            }
            function _check(address allowed) internal view {
                require(msg.sender == allowed);
            }
            function guarded(uint256 extra, address admin) external onlyAddr(admin) {}
        }
    """,
    )
    fn = _function(sl, "guarded")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["parameter_indices"] == [1]


def test_caller_equals_keccak_does_not_classify_as_caller_authority(tmp_path):
    """``require(uint256(uint160(msg.sender)) == keccak256(...))``: the other side is
    computed (hash), so after Rule A expansion it stays business."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f(bytes calldata seed) external {
                require(uint256(uint160(msg.sender)) == uint256(keccak256(seed)));
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] != "caller_authority"


def test_confidence_high_for_time_gate(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public deadline;
            function f() external view {
                require(block.timestamp >= deadline);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] == "time"
    assert leaves[0]["confidence"] == "high"  # pyright: ignore[reportTypedDictNotRequiredAccess]


def test_multi_statement_caller_guard_yields_caller_authority_leaf(tmp_path):
    """#115 -> #114 end-to-end: a multi-statement caller guard
    ``if (msg.sender != owner) { emit Denied(...); revert(); }`` (revert two hops below
    the IF) recovers the same ``caller_authority`` leaf as ``require(msg.sender ==
    owner)``. HEAD produced no gate -> ``None`` tree -> the function defaulted to public."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public n;
            event Denied(address caller);
            function f() external {
                if (msg.sender != ownerVar) {
                    emit Denied(msg.sender);
                    revert();
                }
                n = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert len(leaves) == 1, leaves
    leaf = leaves[0]
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"  # ne flipped to eq via allowed_when_false polarity
    assert leaf["authority_role"] == "caller_authority"
    assert leaf["references_msg_sender"] is True


# ---------------------------------------------------------------------------
# #120 — bool-authority ``return true`` polarity + multi-IF deny fork. A tail
# ``return true`` must carry the negation of EVERY dominating deny-IF (or fail
# closed), never an always-true leaf and never the deny set re-cast as the allow set.
# ---------------------------------------------------------------------------


def _membership_var(leaf):
    return (leaf.get("set_descriptor") or {}).get("storage_var")


def test_issue120_single_early_deny_returns_complement_not_deny_set(tmp_path):
    """``if (blocked[src]) return false; return true;``: the tail is the ELSE of the
    deny-IF, so the leaf must be ``falsy`` (cofinite), NOT ``truthy`` (deny set as
    allow set: fail-open)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) blocked;
            function isAuthorized(address src) internal view returns (bool) {
                if (blocked[src]) return false;
                return true;
            }
        }
    """,
    )
    leaves = _all_leaves(build_return_predicate_tree(_function(sl, "isAuthorized")))
    assert len(leaves) == 1, leaves
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["operator"] == "falsy"  # complement of the deny set, not the deny set
    assert _membership_var(leaf) == "blocked"


def test_issue120_multi_deny_chain_ands_all_negations_zero_fabrication(tmp_path):
    """THE FORK. ``if (a[src]) return false; if (b[src]) return false; return true;``:
    the tail must AND the negation of BOTH deny-IFs. Attributing it to only the
    closest (``falsy[b]``) drops ``!a`` and re-admits every principal in ``a`` (a NEW
    fail-open). Expect AND(``falsy[a]``, ``falsy[b]``) with NO ``truthy`` membership."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) a;
            mapping(address => bool) b;
            function isAuthorized(address src) internal view returns (bool) {
                if (a[src]) return false;
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    # Top node is the conjunction of both deny negations.
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("a", "falsy"),
        ("b", "falsy"),
    }, leaves
    # Fail-open guard: not a single ``truthy`` membership survived, so no
    # denied principal is re-cast as allowed.
    assert not any(le["kind"] == "membership" and le["operator"] == "truthy" for le in leaves), leaves


def test_issue120_unconditional_true_fails_closed_to_unsupported(tmp_path):
    """A ``return true`` with no dominating IF is unattributable: fail-closed
    ``unsupported``, never an empty always-true ``business`` leaf (trivially public)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function isAuthorized(address) internal pure returns (bool) {
                return true;
            }
        }
    """,
    )
    leaves = _all_leaves(build_return_predicate_tree(_function(sl, "isAuthorized")))
    assert len(leaves) == 1, leaves
    leaf = leaves[0]
    assert leaf["kind"] == "unsupported"
    assert leaf.get("unsupported_reason") == "unattributable_return_true"


def test_issue120_maker_dsauth_allow_chain_unchanged(tmp_path):
    """Regression bar: verbatim Maker ds-auth ``DSAuth.isAuthorized``. Its ``return
    true`` paths are the THEN-side of their IFs (genuine allows), so the tree stays
    ``OR(eq[this], eq[owner], external_bool:canCall)`` with NO ``falsy`` and NO
    ``unsupported`` introduced by the fix."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface DSAuthority {
            function canCall(address src, address dst, bytes4 sig) external view returns (bool);
        }
        contract C {
            address owner;
            DSAuthority authority;
            function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
                if (src == address(this)) {
                    return true;
                } else if (src == owner) {
                    return true;
                } else if (authority == DSAuthority(address(0))) {
                    return false;
                } else {
                    return authority.canCall(src, address(this), sig);
                }
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "OR", tree
    leaves = _all_leaves(tree)
    kinds = sorted(le["kind"] for le in leaves)
    assert kinds == ["equality", "equality", "external_bool"], leaves
    assert sorted(le["operator"] for le in leaves) == ["eq", "eq", "truthy"], leaves
    # The fix must not touch this allow-chain: no manufactured negation,
    # no fail-closed downgrade.
    assert not any(le["operator"] == "falsy" for le in leaves), leaves
    assert not any(le["kind"] == "unsupported" for le in leaves), leaves


def test_issue120_mixed_allow_then_deny_then_tail(tmp_path):
    """Both branches of the fix in one function: an allow-IF (its own OR child, SKIPPED
    when negating the tail) then a deny-IF (negated on the tail). Result
    ``OR(truthy[a], falsy[b])`` = ``a ∨ ¬b``, not the fail-open ``OR(truthy[a], truthy[b])``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) a;
            mapping(address => bool) b;
            function isAuthorized(address src) internal view returns (bool) {
                if (a[src]) return true;
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "OR", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("a", "truthy"),
        ("b", "falsy"),
    }, leaves


def test_issue120_revert_if_deny_ands_positive_guard(tmp_path):
    """#120 — a revert-IF guard is a CFG sink, not a leak. The revert son keeps a
    fall-through edge to the ENDIF merge, so without terminator-as-sink the ``!auth``
    guard leaks and the tail collapses to a lone ``falsy[b]`` (public-minus-b, a
    fabrication). Must AND ``auth`` with the ``b`` negation."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) auth;
            mapping(address => bool) b;
            function isAuthorized(address src) internal view returns (bool) {
                if (!auth[src]) revert();
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("auth", "truthy"),
        ("b", "falsy"),
    }, leaves
    # The revert guard's positive constraint must survive — NOT a lone
    # ``falsy[b]`` opening.
    assert any(le["operator"] == "truthy" and _membership_var(le) == "auth" for le in leaves), leaves


def test_issue120_standalone_require_not_projected_public(tmp_path):
    """#120 — a standalone ``require(cond)`` is a dominating positive guard. The
    builder only inspects IF nodes, so ``require(wl)`` was dropped and the tail became
    a bare ``falsy[bl]`` = public-minus-bl. The fix conjoins the require."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) wl;
            mapping(address => bool) bl;
            function isAuthorized(address src) internal view returns (bool) {
                require(wl[src]);
                if (bl[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("wl", "truthy"),
        ("bl", "falsy"),
    }, leaves
    # The whitelist gate must survive so the provider is NOT public-minus-bl.
    assert any(le["operator"] == "truthy" and _membership_var(le) == "wl" for le in leaves), leaves


def test_issue120_two_revert_guards_and_both_never_public(tmp_path):
    """#120 — a multi-revert guard chain must AND EVERY guard. Pre-fix both reverts
    leaked their fall-through son and the tail went ``unsupported`` (safe but lossy);
    with terminator-as-sink each ``!authX`` negates to a positive membership. Never
    public, no fabricated ``falsy`` opening."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) authA;
            mapping(address => bool) authB;
            function isAuthorized(address src) internal view returns (bool) {
                if (!authA[src]) revert();
                if (!authB[src]) revert();
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("authA", "truthy"),
        ("authB", "truthy"),
    }, leaves
    # Both guards required (AND), no cofinite opening → never public.
    assert not any(le["operator"] == "falsy" for le in leaves), leaves
    assert not any(le["kind"] == "unsupported" for le in leaves), leaves


def test_issue120_single_revert_guard_is_positive_membership(tmp_path):
    """#120 — the ``_branch_value_is_only_true`` sink change. Without treating the
    revert as a sink it reaches ``return true`` and is misread as an *allow* branch,
    so the tail goes ``unsupported``; with it the tail is ``truthy[auth]``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) auth;
            function isAuthorized(address src) internal view returns (bool) {
                if (!auth[src]) revert();
                return true;
            }
        }
    """,
    )
    leaves = _all_leaves(build_return_predicate_tree(_function(sl, "isAuthorized")))
    assert len(leaves) == 1, leaves
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["operator"] == "truthy"
    assert _membership_var(leaf) == "auth"


def _assert_no_lone_falsy(tree):
    """The #120 safety invariant: a cofinite ``falsy`` membership (public
    minus a set) must never survive alone — a dropped positive guard would
    otherwise re-admit every principal outside the set. Either a truthy
    membership co-requires it (the guard was captured) or the whole child is
    ``unsupported`` (fail-closed)."""
    leaves = _all_leaves(tree)
    has_falsy = any(le["kind"] == "membership" and le["operator"] == "falsy" for le in leaves)
    has_truthy = any(le["kind"] == "membership" and le["operator"] == "truthy" for le in leaves)
    is_unsupported = any(le["kind"] == "unsupported" for le in leaves)
    assert (not has_falsy) or has_truthy or is_unsupported, leaves


def test_issue120_internal_call_revert_deny_ands_positive_guard(tmp_path):
    """#120 — a deny via an internal helper call (``_deny()``, always reverts) is
    still a CFG sink. Its EXPRESSION node keeps a fall-through edge to ENDIF, so
    unless a provably always-reverting callee is sunk the ``!auth`` guard leaks and
    the tail becomes a lone ``falsy[b]`` (a fabrication). Never a lone ``falsy``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) auth;
            mapping(address => bool) b;
            function _deny() internal pure { revert("denied"); }
            function isAuthorized(address src) internal view returns (bool) {
                if (!auth[src]) _deny();
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("auth", "truthy"),
        ("b", "falsy"),
    }, leaves
    # The invariant: no ``membership:falsy`` without a co-required
    # ``truthy[auth]``.
    assert any(le["operator"] == "truthy" and _membership_var(le) == "auth" for le in leaves), leaves
    _assert_no_lone_falsy(tree)


def test_issue120_library_call_revert_deny_ands_positive_guard(tmp_path):
    """#120, library variant: a ``LibraryCall`` to an always-reverting function
    (``Guard.enforce()``) sinks control like the internal-call and inline-``revert``
    forms, yielding ``AND(truthy[auth], falsy[b])``, never a lone ``falsy[b]``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        library Guard { function enforce() internal pure { revert("denied"); } }
        contract C {
            mapping(address => bool) auth;
            mapping(address => bool) b;
            function isAuthorized(address src) internal view returns (bool) {
                if (!auth[src]) Guard.enforce();
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("auth", "truthy"),
        ("b", "falsy"),
    }, leaves
    assert any(le["operator"] == "truthy" and _membership_var(le) == "auth" for le in leaves), leaves
    _assert_no_lone_falsy(tree)


def test_issue120_unclassified_call_deny_fails_closed(tmp_path):
    """#120 backstop: a deny through a call whose revert can't be PROVEN (an external
    call, so ``_callee_always_reverts`` can't see its body) must fail closed. An
    unclassified mid-body call sits on the path to a ``return true`` whose guards
    already opened cofinite, so the child becomes ``unsupported``, never the lone
    public-minus-b opening."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IGuard { function enforce(address s) external; }
        contract C {
            mapping(address => bool) auth;
            mapping(address => bool) b;
            IGuard g;
            function isAuthorized(address src) internal returns (bool) {
                if (!auth[src]) g.enforce(src);
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    leaves = _all_leaves(tree)
    # Fail-closed: no lone cofinite opening survives.
    assert any(le["kind"] == "unsupported" for le in leaves), leaves
    _assert_no_lone_falsy(tree)


def test_hash_commitment_leaf_keeps_its_computed_operand_and_names_what_it_commits(tmp_path):
    """The Teller ``refundDeposit`` shape, reduced. Two things must hold at once:

    1. The gate names the parameters the hash commits; otherwise a consumer cannot
       tell which arguments the commitment pins.
    2. The ``computed`` operand SURVIVES: it is the only thing saying *hash
       commitment* rather than *equality against storage*, and promoting a committed
       parameter into the operand slot would read as ``parameter`` (self-service,
       anyone on their own argument), an opening from a fix.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(uint256 => bytes32) history;
            function refund(uint256 nonce, address receiver, uint256 amount) external {
                require(history[nonce] == keccak256(abi.encode(receiver, amount)), "bad");
                delete history[nonce];
            }
        }
    """,
    )
    leaves = _all_leaves(build_predicate_tree(_function(sl, "refund")))
    leaf = next(le for le in leaves if "keccak256" in str(le.get("operands")))
    computed = next(o for o in leaf["operands"] if o["source"] == "computed")
    computed_kind = computed.get("computed_kind")
    assert computed_kind is not None and computed_kind.startswith("keccak256")
    assert leaf["kind"] == "equality"
    # (1) the commitment is bound to what it commits
    derived_from = computed.get("derived_from")
    assert derived_from is not None
    bound = {(o.get("parameter_index"), o.get("parameter_name")) for o in derived_from if o["source"] == "parameter"}
    assert bound == {(1, "receiver"), (2, "amount")}
    # (2) and the committed parameters did NOT displace the operand or leak into
    # the leaf's direct-operand parameter list.
    assert [o["source"] for o in leaf["operands"]] == ["parameter", "computed"]
    assert leaf["parameter_indices"] == [0]


def test_computed_operand_without_argument_provenance_says_not_determined(tmp_path):
    """``derived_from`` is ``None``, never omitted and never ``[]``, on a
    computed operand nothing populated. ``op.get("derived_from") or []`` would
    read this as "no parameter reaches it", which is a claim the pipeline has
    not made."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public price;
            function buy(uint256 qty) external payable {
                require(msg.value == price * qty, "bad");
            }
        }
    """,
    )
    leaves = _all_leaves(build_predicate_tree(_function(sl, "buy")))
    computed = [o for le in leaves for o in le["operands"] if o["source"] == "computed"]
    assert computed, leaves
    assert all("derived_from" in o for o in computed)
    assert all(o.get("derived_from") is None for o in computed)


# ---------------------------------------------------------------------------
# guard_extraction_uncertain — the producer half. Over the 88-contract replay every
# tree-less predicate target has ZERO revert gates, so the marker has zero realised
# rows (a lower bound, not proof of unreachability). These tests are the fallback:
# the sentinel is reachable by construction and the discriminator is precise both ways.
# ---------------------------------------------------------------------------


_CALLER_EQ_GATED = """
    pragma solidity ^0.8.19;
    contract C {
        address public ownerVar;
        function sweep(address to) external {
            if (msg.sender != ownerVar) revert();
            payable(to).transfer(address(this).balance);
        }
    }
"""

_VALUE_GATED = """
    pragma solidity ^0.8.19;
    contract C {
        function sweep(uint256 amount) external {
            require(amount > 0);
            payable(msg.sender).transfer(amount);
        }
    }
"""


def test_uncertain_marker_fires_on_unlowerable_caller_eq_gate(tmp_path, monkeypatch):
    """Constructed lowering failure: when no subtree can be built for a function whose
    gate IS a direct caller EQ/NEQ compare, flag the full_name instead of returning
    None (which the policy would read as 'unguarded')."""
    import services.static.contract_analysis_pipeline.predicates.tree as predicates_mod

    sl = _compile(tmp_path, _CALLER_EQ_GATED)
    fn = _function(sl, "sweep")

    monkeypatch.setattr(predicates_mod, "_build_subtree_from_gate", lambda gate, prov, function: None)
    uncertain: set[str] = set()
    tree = predicates_mod.build_predicate_tree(fn, uncertain_out=uncertain)
    assert tree is None
    assert uncertain == {"sweep(address)"}


def test_uncertain_marker_not_fired_for_value_gate_under_same_failure(tmp_path, monkeypatch):
    """Adverse direction: the SAME failure on a value-check gate (``require(amount >
    0)``) must NOT flag the function; marking real public functions unsupported is an
    over-hedge the spec forbids."""
    import services.static.contract_analysis_pipeline.predicates.tree as predicates_mod

    sl = _compile(tmp_path, _VALUE_GATED)
    fn = _function(sl, "sweep")

    monkeypatch.setattr(predicates_mod, "_build_subtree_from_gate", lambda gate, prov, function: None)
    uncertain: set[str] = set()
    tree = predicates_mod.build_predicate_tree(fn, uncertain_out=uncertain)
    assert tree is None
    assert uncertain == set()


def test_uncertain_marker_not_fired_when_gate_lowers(tmp_path):
    """Production path: the caller-eq gate lowers into a tree, so nothing is flagged;
    the marker only names functions whose guard was seen AND lost."""
    sl = _compile(tmp_path, _CALLER_EQ_GATED)
    fn = _function(sl, "sweep")
    uncertain: set[str] = set()
    tree = build_predicate_tree(fn, uncertain_out=uncertain)
    assert tree is not None
    assert uncertain == set()


def test_uncertain_marker_reaches_artifact_and_policy_routes_unsupported(tmp_path, monkeypatch):
    """End-to-end (source -> artifact -> policy): the flagged signature is carried as
    ``guard_extraction_uncertain`` and routed to ``unsupported`` with the truthful
    reason, while a genuinely gate-less public function on the same contract stays public."""
    import services.static.contract_analysis_pipeline.predicates.tree as predicates_mod
    from services.policy.effective_permissions import build_effective_permissions
    from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public counter;
            function sweep(address to) external {
                if (msg.sender != ownerVar) revert();
                payable(to).transfer(address(this).balance);
            }
            function ping() external {
                counter += 1;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")

    monkeypatch.setattr(predicates_mod, "_build_subtree_from_gate", lambda gate, prov, function: None)
    artifact = build_predicate_artifacts(contract)
    assert artifact.get("guard_extraction_uncertain") == ["sweep(address)"]
    assert "sweep(address)" not in (artifact.get("trees") or {})

    target = {"subject": {"address": "0x" + "ab" * 20, "name": "C"}}
    effects = {
        "functions": {
            "sweep(address)": {
                "function": "sweep(address)",
                "state_changing": True,
                "state_writes": [],
                "sinks": [],
                "writer_selectors": [],
            },
            "ping()": {
                "function": "ping()",
                "state_changing": True,
                "state_writes": ["counter"],
                "sinks": [{"kind": "external_call", "target": "hook"}],
                "writer_selectors": [],
            },
        }
    }
    payload = build_effective_permissions(
        target,
        capability_resolver_output={},
        effects=effects,
        predicate_trees=artifact,
    )
    sweep = next(f for f in payload["functions"] if f["function"] == "sweep(address)")
    assert sweep.get("status") == "unsupported"
    assert sweep.get("capability_expr", {}).get("unsupported_reason") == "guard_extraction_uncertain"
    assert sweep.get("authority_public") is not True
    # The unmarked sink-bearing sibling keeps the historical fall-through:
    # genuinely ungated functions must stay public (no over-hedge).
    ping = next(f for f in payload["functions"] if f["function"] == "ping()")
    assert ping.get("status") == "public"
    assert ping["authority_public"] is True


def test_operand_sort_key_totally_orders_element_fields():
    """``absorbed_operands`` is evidence, so its order must come from content: two
    operands differing only in the element fields must not settle on input order, and
    an operand with none of them must order against one that has them without raising."""

    def key(op: dict[str, Any]) -> tuple[str, ...]:
        # A plain dict, because ``bare`` is the shape an operand that resolved
        # no element read still has, and the order has to accept it.
        return _operand_sort_key(cast(Operand, op))

    bare = {"source": "state_variable", "state_variable_name": "bids"}
    keyed = {
        **bare,
        "element_base_variable": "C.bids",
        "element_member_path": ["amount"],
        "element_key_param_index": 0,
    }
    other_key = {**keyed, "element_key_param_index": 2}

    assert key(bare) != key(keyed)
    assert key(keyed) != key(other_key)
    # Absent sorts before present, and every slot is a str, so mixed operands
    # compare rather than raise.
    assert sorted([keyed, bare, other_key], key=key)[0] is bare
    assert all(isinstance(slot, str) for slot in key(keyed))


# ---------------------------------------------------------------------------
# Element-read operand fields (element_base_variable / element_member_path /
# element_key_param_index)
# ---------------------------------------------------------------------------

_ELEMENT_FIELDS = ("element_base_variable", "element_member_path", "element_key_param_index")

_ELEMENT_SRC = """
pragma solidity ^0.8.19;
contract C {
    struct Bid { address bidderAddress; uint256 amount; }
    mapping(uint256 => Bid) public bids;
    mapping(address => uint256) public balances;
    mapping(uint256 => mapping(uint256 => address)) public nested;
    address[] public admins;

    function guardedRecord(uint256 _bidId) external view {
        require(bids[_bidId].bidderAddress == msg.sender);
    }
    function scalarCollection(uint256 _idx) external view {
        require(admins[_idx] == msg.sender);
    }
    function bareParameter(address who) external view {
        require(msg.sender == who);
    }
    function callerKeyed() external view {
        require(balances[msg.sender] > 0);
    }
    function constantKey() external view {
        require(admins[3] == msg.sender);
    }
    function computedKey(uint256 _bidId) external view {
        require(bids[_bidId + 1].bidderAddress == msg.sender);
    }
    function storagePointer(uint256 _bidId) external view {
        Bid storage b = bids[_bidId];
        require(b.bidderAddress == msg.sender);
    }
    function twoKeyLevels(uint256 a, uint256 b) external view {
        require(nested[a][b] == msg.sender);
    }
    function mergedChain(uint256 _id, bool flag) external view {
        address who = flag ? bids[_id].bidderAddress : admins[_id];
        require(who == msg.sender);
    }
    function mergedKeyTernary(uint256 a, uint256 b, bool flag) external view {
        uint256 k = flag ? a : b;
        require(bids[k].bidderAddress == msg.sender);
    }
    function mergedKeyIfElse(uint256 a, uint256 b, bool flag) external view {
        uint256 k;
        if (flag) { k = a; } else { k = b; }
        require(bids[k].bidderAddress == msg.sender);
    }
    function mergedCallerOrParameterKey(address who, bool flag) external view {
        address k = flag ? msg.sender : who;
        require(balances[k] > 0);
    }
}
"""


@pytest.fixture(scope="module")
def element_slither(tmp_path_factory):
    return _compile(tmp_path_factory.mktemp("element"), _ELEMENT_SRC)


def _operands(sl: Slither, name: str) -> list[dict[str, Any]]:
    tree = build_predicate_tree(_function(sl, name))
    out: list[dict[str, Any]] = []
    for leaf in _all_leaves(tree):
        out.extend(cast("list[dict[str, Any]]", leaf.get("operands") or []))
    assert out, f"{name} produced no operands"
    # The three are one fact about one cell: a base without its key is not a
    # cell, and a consumer must never see half of one.
    for op in out:
        present = [field for field in _ELEMENT_FIELDS if field in op]
        assert present in ([], list(_ELEMENT_FIELDS)), op
    return out


def test_element_read_stamps_record_on_the_parameter_polarity(element_slither):
    """``bids[_bidId].bidderAddress == msg.sender``: the pick publishes the bare
    parameter, so without the stamp the record the guard names is gone. The
    caller side of the same comparison reads no element and stays bare."""
    element, caller = _operands(element_slither, "guardedRecord")
    assert element["element_base_variable"] == "C.bids"
    assert element["element_member_path"] == ["bidderAddress"]
    assert element["element_key_param_index"] == 0
    # Additive: what the operand already published is untouched.
    assert element["source"] == "parameter"
    assert element["parameter_index"] == 0
    assert element["parameter_name"] == "_bidId"
    assert caller["source"] == "msg_sender"
    assert not any(field in caller for field in _ELEMENT_FIELDS)


def test_scalar_collection_read_stamps_an_empty_member_path(element_slither):
    """``admins[_idx]`` reads a whole element, not a member of one. The empty
    path is the proven answer to "which member", not a missing one — which is
    why it rides with the other two rather than standing alone."""
    element, _caller = _operands(element_slither, "scalarCollection")
    assert element["element_base_variable"] == "C.admins"
    assert element["element_member_path"] == []
    assert element["element_key_param_index"] == 0


def test_caller_keyed_read_stamps_a_proven_null_key_slot(element_slither):
    """``balances[msg.sender]``: the key is proven to be the caller, so no entry
    parameter names the cell. That is an earned negative and must reach the
    consumer as a present ``None``, distinguishable from the absence that means
    no element read was resolved."""
    element = next(op for op in _operands(element_slither, "callerKeyed") if "element_base_variable" in op)
    assert element["element_base_variable"] == "C.balances"
    assert element["element_member_path"] == []
    assert "element_key_param_index" in element
    assert element["element_key_param_index"] is None
    # The caller won the source pick; the element fields ride the same operand.
    assert element["source"] == "msg_sender"


def test_collection_polarity_refuses_a_key_it_cannot_pin(element_slither):
    """``admins[3] == msg.sender`` is the collection-wins fold — the stamp runs
    over it too, and refuses, because a constant key names no entry parameter
    and this pass proves nothing else about it."""
    collection = next(op for op in _operands(element_slither, "constantKey") if op["source"] == "state_variable")
    assert collection["state_variable_name"] == "admins"
    assert not any(field in collection for field in _ELEMENT_FIELDS)


@pytest.mark.parametrize(
    "function_name",
    [
        # ``msg.sender == who`` reads no storage element at all.
        pytest.param("bareParameter", id="bare_parameter_comparison"),
        # ``bids[_bidId + 1]`` carries ``_bidId``'s own source alongside the arithmetic. Reading the slot off it
        # would publish agreement with ``bids[_bidId]`` over two different cells.
        pytest.param("computedKey", id="computed_key"),
        # The member is read off a storage-pointer local, so the walk never reaches the state variable and
        # publishes no cell rather than guessing one.
        pytest.param("storagePointer", id="storage_pointer_local"),
        # One published slot cannot name two key levels; an ambiguous cell is not a narrower one.
        pytest.param("twoKeyLevels", id="two_key_levels"),
        # A value joined from two different collections has no single record.
        pytest.param("mergedChain", id="merged_chain"),
    ],
)
def test_unpinnable_element_read_stamps_nothing(element_slither, function_name):
    for op in _operands(element_slither, function_name):
        assert not any(field in op for field in _ELEMENT_FIELDS)


def test_ternary_merged_key_stamps_nothing(element_slither):
    """``bids[flag ? a : b]`` is keyed by ``a`` OR ``b``. Provenance folds the
    merged local back to one source, so the source-set test that refuses
    ``bids[_bidId + 1]`` sees nothing wrong here — only the SSA ``Phi`` does."""
    for op in _operands(element_slither, "mergedKeyTernary"):
        assert not any(field in op for field in _ELEMENT_FIELDS)
    # Non-vacuity: the sibling differing only in the merge does stamp.
    sibling, _caller = _operands(element_slither, "guardedRecord")
    assert sibling["element_key_param_index"] == 0


def test_if_else_merged_key_stamps_nothing(element_slither):
    """The statement form of the same merge, which reaches the read through a
    ``Phi`` in a different node than the one holding the ``Index``."""
    for op in _operands(element_slither, "mergedKeyIfElse"):
        assert not any(field in op for field in _ELEMENT_FIELDS)
    sibling, _caller = _operands(element_slither, "guardedRecord")
    assert sibling["element_base_variable"] == "C.bids"


def test_caller_or_parameter_merged_key_stamps_nothing(element_slither):
    """``balances[flag ? msg.sender : who]`` is the merge that matters most: the
    surviving source is the parameter, so a slot-only reading would publish a
    cell that may be the CALLER's as one an entry parameter names — inverting
    the distinction the fields carry. It publishes neither."""
    for op in _operands(element_slither, "mergedCallerOrParameterKey"):
        assert not any(field in op for field in _ELEMENT_FIELDS)
    # Non-vacuity: the unmerged caller-keyed sibling still earns its null slot.
    sibling = next(op for op in _operands(element_slither, "callerKeyed") if "element_base_variable" in op)
    assert sibling["element_base_variable"] == "C.balances"
    assert sibling["element_key_param_index"] is None


def test_element_stamp_does_not_widen_the_leaf_classification(element_slither):
    """The stamp is operand vocabulary only. An element-read operand recognized
    as one must not change what the leaf was classified as."""
    guarded = _all_leaves(build_predicate_tree(_function(element_slither, "guardedRecord")))
    scalar = _all_leaves(build_predicate_tree(_function(element_slither, "scalarCollection")))
    assert [leaf["kind"] for leaf in guarded] == ["equality"]
    assert [leaf["authority_role"] for leaf in guarded] == ["caller_authority"]
    assert [leaf["kind"] for leaf in scalar] == ["equality"]
    assert [leaf["authority_role"] for leaf in scalar] == ["caller_authority"]
