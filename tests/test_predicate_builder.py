"""Tests for ``build_predicate_tree`` (services.static…predicates).

End-to-end: from a Solidity function source through ProvenanceEngine +
RevertDetector to a fully-typed PredicateTree. Focuses on:
  - basic equality + membership leaves
  - polarity normalization (require vs if-revert)
  - authority_role classification (Rule A: caller equality;
    Rule B: auth-shaped membership for multi-key)
  - 1-key caller-only membership defaults to business (week-3
    writer-key two-pass promotes if applicable)
  - external_bool delegated_authority (state-var target + sender arg)
  - unguarded function returns None
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
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


# ---------------------------------------------------------------------------
# Equality leaves
# ---------------------------------------------------------------------------


def test_caller_equals_state_var_classifies_caller_authority(tmp_path):
    """``require(msg.sender == owner)`` is the canonical Rule A
    case: equality, op=eq, msg_sender vs state_variable."""
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
    """``if (msg.sender != owner) revert()`` — polarity
    allowed_when_false. After normalization the leaf is
    equality, op=eq (the original ``!=`` is flipped via the
    polarity rule, NOT via a NOT node)."""
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
    # Source: if (a != b) revert  ⇒ allowed when a == b.
    # ne with allowed_when_false flips to eq. caller_authority because
    # one operand is msg.sender, the other is state_var.
    assert leaf["kind"] == "equality"
    assert leaf["operator"] == "eq"
    assert leaf["authority_role"] == "caller_authority"


def test_caller_equals_parameter_classifies_caller_authority(tmp_path):
    """``require(account == msg.sender)`` (renounceRole-style) — the
    other operand is a parameter (an address-typed parameter is
    treated as 'who is allowed', so this is caller_authority)."""
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


# ---------------------------------------------------------------------------
# Membership leaves
# ---------------------------------------------------------------------------


def test_two_key_membership_with_caller_promotes_to_caller_authority(tmp_path):
    """``require(_members[role][msg.sender])`` is a 2-key mapping
    with msg.sender as a key — Rule B's multi-key direct promotion
    to caller_authority (a permission table by structure)."""
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
    """``require(claimed[msg.sender])`` is a 1-key caller-only bool
    map — could be auth (blacklist) or business (claim flag).
    Without writer-key analysis (week 3), default to business so we
    don't over-admit."""
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


# ---------------------------------------------------------------------------
# Multiple gates → AND tree
# ---------------------------------------------------------------------------


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
    assert tree["op"] == "AND"  # type: ignore[typeddict-item]
    assert len(tree["children"]) == 2  # type: ignore[typeddict-item]
    leaves = _all_leaves(tree)
    kinds = sorted(leaf["kind"] for leaf in leaves)
    assert kinds == ["comparison", "equality"]


# ---------------------------------------------------------------------------
# Unguarded function
# ---------------------------------------------------------------------------


def test_time_gate_classifies_as_time(tmp_path):
    """``require(block.timestamp > deadline)`` — at least one operand
    is block_context and no operand is caller-related, so leaf
    authority_role is "time"."""
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
    """``require(block.timestamp > cooldown[msg.sender])`` has both
    block_context AND msg.sender — caller takes priority. The leaf
    classifies based on the comparison structure; current logic
    keeps it as business since comparison + caller-key isn't an
    authority shape we recognize. Documents the expectation."""
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
    # The leaf has both msg.sender (in the cooldown index) and
    # block_context. Caller-priority means it doesn't classify as
    # time. Without a writer-gate or explicit auth shape this is
    # business.
    assert leaves[0]["authority_role"] != "time"


def test_logical_or_splits_into_or_subtree(tmp_path):
    """``require(msg.sender == owner || amount > threshold)`` should
    produce an OR root with two leaves: a caller_authority equality
    and a comparison/business. Codex round-3 blocker #2 fix:
    business preserved under OR so admission is correct."""
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
    assert tree["op"] == "OR", tree  # type: ignore[typeddict-item]
    leaves = _all_leaves(tree)
    assert len(leaves) == 2
    kinds = sorted(leaf["kind"] for leaf in leaves)
    assert kinds == ["comparison", "equality"]
    # Caller authority leaf is present.
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
    # Multiple AND levels are allowed (top-level AND from gates wraps
    # the inner AND from && operator). Either flat AND or nested.
    leaves = _all_leaves(tree)
    assert len(leaves) == 2
    kinds = sorted(leaf["kind"] for leaf in leaves)
    assert kinds == ["comparison", "equality"]


def test_ecrecover_equality_classifies_signature_auth(tmp_path):
    """``address recovered = ecrecover(...); require(recovered == signerAddr)``
    — an equality between a signature_recovery operand and an
    address operand is the canonical signature-auth pattern. Leaf
    kind must be ``signature_auth`` (shape-tight by construction;
    always caller_authority)."""
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
    """Inline form: ``require(msg.sender == ecrecover(...))``. The
    ecrecover output goes through TMP propagation. Should still
    classify as signature_auth."""
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
        # Equality / inequality
        ("require(a == b);", "equality", "eq"),
        ("require(a != b);", "equality", "ne"),
        ("if (a == b) revert();", "equality", "ne"),
        ("if (a != b) revert();", "equality", "eq"),
        # Comparison
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
    """For each of {require, if-revert} × {eq, ne, lt, lte, gt, gte},
    assert the normalized leaf has the expected kind + operator.
    No NOT survives the normalization."""
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
    """Function gated entirely by an `onlyOwner` modifier (no inline
    require) — RevertDetector now walks modifier bodies, so the gate
    is found and the function admits with caller_authority."""
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
    """Modifier body contains an external authority call. Provenance
    runs over the modifier nodes, finds the HighLevelCall whose
    target is a state-var and whose args include msg.sender. Leaf
    classifies as delegated_authority."""
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
    """Two modifiers chained — both reverts get captured."""
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


# ---------------------------------------------------------------------------
# Confidence levels (HIGH / MEDIUM / LOW)
# ---------------------------------------------------------------------------


def test_confidence_high_for_caller_equals_state_var(tmp_path):
    """Rule A (msg.sender == state_var address) is shape-tight:
    the operands are caller + state_variable directly. HIGH."""
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
    assert leaves[0]["confidence"] == "high"  # type: ignore[typeddict-item]


def test_confidence_high_for_multi_key_caller_membership(tmp_path):
    """Multi-key (>=2) membership with caller key direct-promotes to
    caller_authority. Shape-tight by structure → HIGH."""
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
    assert leaves[0]["confidence"] == "high"  # type: ignore[typeddict-item]


def test_confidence_low_for_business_residual(tmp_path):
    """Bare-bool flag check that doesn't match any authority shape
    classifies as business → LOW."""
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
    assert leaves[0]["confidence"] == "low"  # type: ignore[typeddict-item]


def test_confidence_low_for_unsupported(tmp_path):
    """An opaque condition we can't classify ends up unsupported,
    which is LOW."""
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
    assert leaves[0]["confidence"] == "low"  # type: ignore[typeddict-item]


# ---------------------------------------------------------------------------
# AuthorityClassifier rule expansion (v6 round-5 #1)
# ---------------------------------------------------------------------------


def test_caller_equals_constant_address_classifies_caller_authority(tmp_path):
    """``require(msg.sender == 0x1234...)`` — the other operand is
    a constant address. This is a hardcoded auth check; the
    expanded Rule A accepts ``constant`` as address-typed."""
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
    """Pre-expansion this would have classified as caller_authority
    just because msg.sender appears, but `require(uint256(uint160(
    msg.sender)) == block.number)` is nonsense as auth — block.number
    isn't address-typed. After Rule A expansion this stays
    business."""
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
    """The leaf's ``parameter_indices`` field must reference the
    FUNCTION's parameter positions, not the modifier's. Without
    caller-side ParameterBindingEnv substitution, a modifier-bound
    operand would carry the modifier's parameter index (0) which
    happens to coincide with f's index 0 — so use a function with
    ≥2 params and a modifier that takes one to make the mapping
    distinguishable."""
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
    """Two-hop chain (modifier → internal helper) — the leaf still
    reports the function's parameter_index, not the helper's."""
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
    """``require(uint256(uint160(msg.sender)) == keccak256(...))``
    — the other side is computed (hash output). After Rule A
    expansion this stays business, since the operand isn't
    address-typed by source."""
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
    """``require(block.timestamp >= deadline)`` is a time gate.
    The classifier reads block_context with no caller, so the
    authority_role is ``time`` → HIGH."""
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
    assert leaves[0]["confidence"] == "high"  # type: ignore[typeddict-item]


def test_multi_statement_caller_guard_yields_caller_authority_leaf(tmp_path):
    """#115 -> #114 end-to-end at the builder: a multi-statement caller guard
    ``if (msg.sender != owner) { emit Denied(...); revert(); }`` (the revert is
    two hops below the IF) recovers the same ``caller_authority`` equality leaf
    as the single-statement ``require(msg.sender == owner)``. HEAD produced no
    gate -> ``None`` tree -> the function defaulted to public; the fix restores
    correct owner attribution so the policy no longer projects it public."""
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
# #120 — bool-authority ``return true`` polarity + multi-IF deny fork
#
# ``build_return_predicate_tree`` lifts a bool-returning authority
# provider's if/else chain into an OR of per-path predicates. A tail
# ``return true`` must carry the negation of EVERY dominating deny-IF (or
# fail closed), never an always-true leaf and never the deny set re-cast
# as the allow set.
# ---------------------------------------------------------------------------


def _membership_var(leaf):
    return (leaf.get("set_descriptor") or {}).get("storage_var")


def test_issue120_single_early_deny_returns_complement_not_deny_set(tmp_path):
    """``if (blocked[src]) return false; return true;`` — the tail
    ``return true`` is the ELSE of the deny-IF, so ``allowed ⇔ src ∉
    blocked``. The leaf must be ``falsy`` (complement / cofinite), NOT
    ``truthy`` (which would make the deny set the allow set — fail-open)."""
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
    """THE FORK. ``if (a[src]) return false; if (b[src]) return false;
    return true;`` — the tail ``return true`` must AND the negation of
    BOTH deny-IFs: ``allowed ⇔ src ∉ a ∧ src ∉ b``. Attributing it to
    only the closest deny-IF (``falsy[b]`` alone) drops ``!a`` and
    re-admits every principal in ``a`` (a NEW fail-open). The tree must
    be an AND of ``falsy[a]`` and ``falsy[b]`` with NO ``truthy``
    membership anywhere (zero fabricated access)."""
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
    """A ``return true`` with no dominating IF is unattributable; it must
    become a fail-closed ``unsupported`` leaf, never an empty always-true
    ``business`` leaf that makes the OR tree trivially public."""
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
    """Regression bar: verbatim Maker ds-auth ``DSAuth.isAuthorized``. Its
    ``return true`` paths are the THEN-side (``son_true``) of their IFs —
    genuine allows — so they stay positive equality leaves, and the dropped
    null-authority guard leaves the ``canCall`` path an external_bool. The
    tree must remain ``OR(eq[this], eq[owner], external_bool:canCall)`` with
    NO negation (``falsy``) and NO ``unsupported`` introduced by the fix."""
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
    """Combined shape exercising both branches of the fix in one function:
    ``if (a[src]) return true;`` (an allow-IF — emitted as its own OR child
    and SKIPPED when negating the tail) then ``if (b[src]) return false;``
    (a deny-IF — negated on the tail). Result: ``OR(truthy[a], falsy[b])``
    = ``a ∨ ¬b``, not the fail-open ``OR(truthy[a], truthy[b])``."""
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
    """#120 round-2 point 1 — a revert-IF guard is a CFG sink, not a leak.
    ``if (!auth[src]) revert(); if (b[src]) return false; return true;`` — the
    revert son of the first IF keeps a structural fall-through edge to the
    ENDIF merge, so without terminator-as-sink the ``!auth`` guard leaks into
    the post-join region and the tail collapses to a lone ``falsy[b]`` =
    public-minus-b (a fabrication). The fix must AND the positive ``auth``
    guard with the ``b`` negation: ``allowed ⇔ src ∈ auth ∧ src ∉ b``."""
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
    """#120 round-2 point 2 — a standalone ``require(cond)`` is a dominating
    positive guard, not an ignorable non-IF statement.
    ``require(wl[src]); if(bl[src]) return false; return true;`` — the builder
    only inspects IF nodes, so the ``require(wl)`` guard was dropped and the
    tail became a bare ``falsy[bl]`` = public-minus-bl. The fix conjoins the
    dominating require: ``allowed ⇔ src ∈ wl ∧ src ∉ bl`` — never public."""
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
    """#120 round-2 points 1+3c — a multi-revert guard chain must AND EVERY
    guard. ``if(!authA[src]) revert(); if(!authB[src]) revert(); return true;``
    — both reverts leak their fall-through son to ENDIF, so pre-fix the tail
    dropped both guards (→ unattributable ``unsupported``, safe but lossy).
    With terminator-as-sink each ``!authX`` else path negates to a positive
    membership: ``allowed ⇔ src ∈ authA ∧ src ∈ authB``. Never public, and
    no fabricated ``falsy`` opening."""
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
    """#120 round-2 point 1 — the ``_branch_value_is_only_true`` sink change.
    ``if (!auth[src]) revert(); return true;`` — without treating the revert
    as a sink, the revert branch reaches the downstream ``return true`` and is
    misread as an *allow* branch, so its else-guard is skipped and the tail
    goes ``unsupported``. With the sink the revert branch is a deny, so the
    tail negates ``!auth`` to ``truthy[auth]`` (``allowed ⇔ src ∈ auth``)."""
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
    """#120 round-3 point 1 — a deny expressed as an internal helper call
    (not an inline ``revert``) is still a CFG sink. ``if (!auth[src]) _deny();
    if (b[src]) return false; return true;`` where ``_deny`` always reverts.
    The ``_deny()`` EXPRESSION node keeps a structural fall-through edge to
    the ENDIF merge, so unless a call to a provably always-reverting callee is
    sunk, the ``!auth`` guard leaks and the tail collapses to a lone
    ``falsy[b]`` = public-minus-b (a fabrication). The fix ANDs the positive
    ``auth`` guard with the ``b`` negation: ``allowed ⇔ src ∈ auth ∧ src ∉ b``.
    Never a lone ``falsy``."""
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
    # The invariant the reviewer requires: no ``membership:falsy`` without a
    # co-required ``truthy[auth]``.
    assert any(le["operator"] == "truthy" and _membership_var(le) == "auth" for le in leaves), leaves
    _assert_no_lone_falsy(tree)


def test_issue120_library_call_revert_deny_ands_positive_guard(tmp_path):
    """#120 round-3 point 1, library variant — a ``LibraryCall`` to an
    always-reverting library function (``Guard.enforce()``) sinks control
    identically to the internal-call and inline-``revert`` forms. Same shape
    (``if (!auth[src]) Guard.enforce(); if (b[src]) return false; return
    true;``) must yield ``AND(truthy[auth], falsy[b])``, never a lone
    ``falsy[b]``."""
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
    """#120 round-3 point 2 backstop — a deny routed through a call whose
    revert can't be PROVEN (an external call) must fail closed, not leak.
    ``if (!auth[src]) g.enforce(src); if (b[src]) return false; return true;``
    where ``g.enforce`` is an external interface call: ``_callee_always_reverts``
    can't see its body, so the ``!auth`` edge is not sunk and the ``!auth``
    guard leaks. Because an unclassified mid-body call sits on the path to the
    ``return true`` whose guards already opened cofinite (``falsy[b]``), the
    child fails closed to ``unsupported`` — never the lone public-minus-b
    opening."""
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
    """The Teller ``refundDeposit`` shape, reduced.

    Two things must hold at once and they pull against each other:

    1. The gate names the parameters the hash commits — without that a consumer
       cannot tell which arguments the commitment pins, and the guard reads as a
       constraint on ``nonce`` alone.
    2. The ``computed`` operand SURVIVES. It is the only thing that says
       *hash commitment* rather than *equality against storage*, and the
       resolver routes on it: promoting a committed parameter into the operand
       slot would turn a commitment gate into ``parameter``, i.e. "self-service,
       anyone on their own argument" — an opening, from a fix.
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


def test_non_computed_operands_do_not_carry_derived_from(tmp_path):
    """Absence means "the question does not apply", so it must be reserved for
    operands that are not computed at all."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            function f() external view {
                require(msg.sender == owner, "no");
            }
        }
    """,
    )
    leaves = _all_leaves(build_predicate_tree(_function(sl, "f")))
    operands = [o for le in leaves for o in le["operands"]]
    assert operands
    assert all("derived_from" not in o for o in operands if o["source"] != "computed")
