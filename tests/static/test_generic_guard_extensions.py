"""Regression tests for the generic guard extensions (codex F1–F4).

Each test compiles a real-world auth pattern — Diamond ACL storage, a
bitwise role flag, a custom M-of-N threshold, EIP-1271, a hashed
composite key — and asserts the *generic* predicate pipeline classifies
it structurally, with no per-protocol adapter. Every one of these
landed; each test's docstring records the production path that carries
it, so a regression names the mechanism it broke.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.contract_analysis_pipeline.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _build_pipeline(contract):
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
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


# ---------------------------------------------------------------------------
# 1. Diamond ACL — storage at hashed slot via assembly
# ---------------------------------------------------------------------------


def test_diamond_acl_membership_classifies_caller_authority(tmp_path):
    """SURPRISE PASS: the existing pipeline handles Diamond ACL
    structurally via internal-call recursion + Member/Index chaining.
    Slither models ``LibDiamond.aclStorage()`` as a library function
    returning a storage pointer; ProvenanceEngine recurses into the
    library (within internal_call_depth), the subsequent
    ``.members[role][msg.sender]`` chain produces a 2-key membership
    leaf with caller as one key, and AuthorityClassifier promotes it
    to caller_authority. No assembly-slot detection needed.

    Caveat: the membership leaf's set_descriptor.storage_var is the
    Slither SSA reference (e.g. "REF_1"), not the underlying mapping
    name. This means the writer-gate pass-2 won't find writers
    keyed to "REF_1". For now: the read-side classification is
    correct; the writer-gate enrichment for Diamond requires
    follow-up to map SSA references back to library-storage slots.
    """

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;

        library LibDiamond {
            bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.storage.acl");

            struct AclStorage {
                mapping(bytes32 => mapping(address => bool)) members;
            }

            function aclStorage() internal pure returns (AclStorage storage s) {
                bytes32 slot = DIAMOND_STORAGE_POSITION;
                assembly { s.slot := slot }
            }
        }

        contract C {
            function f(bytes32 role) external view {
                require(LibDiamond.aclStorage().members[role][msg.sender]);
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["f(bytes32)"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership", f"expected membership leaf for diamond ACL, got {leaf['kind']}"
    assert leaf["authority_role"] == "caller_authority"


# ---------------------------------------------------------------------------
# 2. Bitwise role flags — (roles[msg.sender] & FLAG) != 0
# ---------------------------------------------------------------------------


def test_bitwise_flag_membership_classifies_caller_authority(tmp_path):
    """LANDED (codex F1): bitwise role flag check
    ``(roles[msg.sender] & FLAG) != 0`` recognized as a value-
    predicate membership. The bitwise AND between an Index lvalue
    and a constant mask folds into the descriptor's truthy_value;
    the outer != 0 yields operator=falsy (canonical "value not
    masked-out"). Mask operand accepts both literal Constants and
    state-level `constant`/`immutable` declarations — both are
    fixed structurally, so the value-predicate adapter can fold
    the mask in at enumeration time. Mutable state vars are
    excluded.

    Implementation: predicates.py:_find_index_value_pair extended
    to recognize ``Binary(AND, Index_lvalue, Constant_or_immutable)``
    as the same shape as plain ``Index_lvalue == const``. Writer-
    gate rule b.i then promotes to caller_authority when the
    underlying mapping is admin-written."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => uint256) public roles;
            uint256 constant MINTER_FLAG = 1;
            function setRole(address user, uint256 mask) external {
                require(msg.sender == ownerVar);
                roles[user] = mask;
            }
            function f() external view {
                require((roles[msg.sender] & MINTER_FLAG) != 0);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["f()"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership", f"expected membership leaf for bitwise flag, got {leaf['kind']}"
    assert leaf["authority_role"] == "caller_authority"


# ---------------------------------------------------------------------------
# 3. Custom M-of-N — counter map + threshold compare
# ---------------------------------------------------------------------------


def test_custom_m_of_n_classifies_threshold_group(tmp_path):
    """LANDED (codex F2 + fixed-point writer-gate): authority-derived
    state inference. ``approvals[txHash] >= THRESHOLD`` promotes to
    caller_authority when:
      1. The counter is incremented additively (``map[k] += N``)
      2. The incrementing function is itself authority-gated
      3. The increment key sources from a parameter (M-of-N
         object), NOT msg.sender (which would be a cooldown)
      4. No unguarded settable writers exist (admin-reset risk)

    Implementation:
      - predicates.py:_try_threshold_membership emits a comparison
        leaf with set_descriptor populated for ``Index_lvalue [op]
        constant`` with op ∈ gt/gte/lt/lte
      - writer_gate.py:_is_authority_derived_counter walks writers,
        finds additive sites via _additive_write_sites (Binary ADD
        whose lvalue equals one operand — Slither's compound-assign
        IR shape), checks parameter-keyed writes, requires writer's
        predicate to have caller_authority/delegated_authority
      - apply_writer_gate_pass now iterates to fixed point so
        chained promotions (isOwner promotes via b.i, then approve's
        predicate gains caller_authority, then execute's threshold
        check promotes) all converge
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => bool) public isOwner;
            mapping(bytes32 => uint256) public approvals;
            uint256 constant THRESHOLD = 2;
            function addOwner(address user) external {
                require(msg.sender == ownerVar);
                isOwner[user] = true;
            }
            function approve(bytes32 txHash) external {
                require(isOwner[msg.sender]);
                approvals[txHash] += 1;
            }
            function execute(bytes32 txHash) external view {
                require(approvals[txHash] >= THRESHOLD);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["execute(bytes32)"])
    assert len(leaves) == 1
    leaf = leaves[0]
    # After the fix, the leaf should be a typed threshold-membership
    # leaf with authority_role=caller_authority. The capability
    # evaluator turns it into a threshold_group on the resolver side.
    assert leaf["authority_role"] == "caller_authority", (
        f"expected caller_authority for M-of-N execute gate, got {leaf['authority_role']}"
    )


# ---------------------------------------------------------------------------
# 4. EIP-1271 contract signatures — should classify as signature_auth
# ---------------------------------------------------------------------------


def test_eip1271_classifies_signature_auth(tmp_path):
    """LANDED (codex F3): EIP-1271 magic-value comparison
    ``call_result == 0x1626ba7e`` recognized as signature_auth.
    Detection is purely structural — by the magic value (which is
    a structural protocol fingerprint), not by function-name match.

    Implementation: predicates.py:_try_external_auth_oracle
    detects ``Binary(EQ, external_call_result, constant)``. When
    the constant matches 0x1626ba7e (in any representation: hex
    string, decimal int, decimal string, bytes), emit
    signature_auth leaf with caller_authority. For other constants
    (generic external-auth oracle), require the call args to
    include msg.sender / signature_recovery — otherwise it's not
    an authentication predicate.

    Codex's broader generalization preserved: this is the
    'external-auth oracle' pattern; EIP-1271 is one specialization.
    Aragon canPerform / AccessManager canCall would surface here
    too once those structural shapes are exercised in tests."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IERC1271 {
            function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
        }
        contract C {
            address public signerContract;
            function f(bytes32 hash, bytes calldata sig) external view {
                require(IERC1271(signerContract).isValidSignature(hash, sig) == 0x1626ba7e);
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["f(bytes32,bytes)"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "signature_auth", f"expected signature_auth, got {leaf['kind']}"
    assert leaf["authority_role"] == "caller_authority"


# ---------------------------------------------------------------------------
# 5. Computed-key membership — _members[keccak(role,msg.sender)]
# ---------------------------------------------------------------------------


def test_hashed_key_membership_classifies_caller_authority(tmp_path):
    """LANDED (codex F4): hashed-key membership unwrapped via
    symbolic-tuple-key recognition. ``_authorized[keccak256(
    abi.encode(role, msg.sender))]`` now produces a 2-key
    membership leaf where the key_sources are ``[parameter(role),
    msg_sender]`` instead of a single ``computed`` source. Multi-key
    rule then promotes to caller_authority directly.

    Implementation: predicates.py:_expand_key_operand walks back
    through hash and abi.encode calls and returns one Operand per
    ultimate input. Detection is by Solidity built-in signature
    (``keccak256(bytes)``, ``abi.encode()``, etc.) — structural
    metadata, not user-identifier-name matching."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(bytes32 => bool) public _authorized;
            function authorize(bytes32 role, address user) external {
                require(msg.sender == ownerVar);
                _authorized[keccak256(abi.encode(role, user))] = true;
            }
            function f(bytes32 role) external view {
                require(_authorized[keccak256(abi.encode(role, msg.sender))]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_pipeline(contract)
    leaves = _all_leaves(trees["f(bytes32)"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["authority_role"] == "caller_authority", (
        f"expected caller_authority for hashed-key membership, got {leaf['authority_role']}"
    )
