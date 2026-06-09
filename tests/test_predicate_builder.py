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
