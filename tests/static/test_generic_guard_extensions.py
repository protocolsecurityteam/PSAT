"""Regression tests for the generic guard extensions (codex F1-F4).

Each test compiles a real-world auth pattern (Diamond ACL storage, bitwise role
flag, M-of-N threshold, EIP-1271, hashed composite key) and asserts the *generic*
predicate pipeline classifies it structurally, with no per-protocol adapter. Each
docstring records the production path that carries it.
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


# 1. Diamond ACL — storage at hashed slot via assembly


def test_diamond_acl_membership_classifies_caller_authority(tmp_path):
    """SURPRISE PASS: handled structurally via internal-call recursion + Member/Index
    chaining; no assembly-slot detection needed.

    Caveat: the membership leaf's ``set_descriptor.storage_var`` is the Slither SSA
    reference (e.g. "REF_1"), not the mapping name, so writer-gate pass-2 won't find
    its writers. Read-side classification is correct; writer-gate enrichment needs
    to map SSA references back to library-storage slots.
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


# 2. Bitwise role flags — (roles[msg.sender] & FLAG) != 0


def test_bitwise_flag_membership_classifies_caller_authority(tmp_path):
    """LANDED (codex F1): ``(roles[msg.sender] & FLAG) != 0`` is a value-predicate
    membership. Mask operands may be literals or ``constant``/``immutable`` (fixed
    structurally); mutable state vars are excluded.

    Path: predicates.py:_find_index_value_pair treats ``Binary(AND, Index_lvalue,
    Constant_or_immutable)`` like ``Index_lvalue == const``; writer-gate rule b.i
    then promotes to caller_authority when the mapping is admin-written."""
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


# 3. Custom M-of-N — counter map + threshold compare


def test_custom_m_of_n_classifies_threshold_group(tmp_path):
    """LANDED (codex F2 + fixed-point writer-gate): ``approvals[txHash] >= THRESHOLD``
    promotes to caller_authority when the counter is incremented additively, the
    incrementing function is itself authority-gated, the increment key is a
    parameter (M-of-N object, NOT msg.sender, which would be a cooldown), and no
    unguarded settable writers exist (admin-reset risk).

    Path: predicates.py:_try_threshold_membership; writer_gate.py:
    _is_authority_derived_counter; ``apply_writer_gate_pass`` iterates to a fixed
    point so chained promotions (isOwner -> approve -> execute) converge."""
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
    # A typed threshold-membership leaf with authority_role=caller_authority.
    assert leaf["authority_role"] == "caller_authority", (
        f"expected caller_authority for M-of-N execute gate, got {leaf['authority_role']}"
    )


# 4. EIP-1271 contract signatures — should classify as signature_auth


def test_eip1271_classifies_signature_auth(tmp_path):
    """LANDED (codex F3): ``call_result == 0x1626ba7e`` is signature_auth, detected by
    the magic value (a structural fingerprint), not by function name.

    Path: predicates.py:_try_external_auth_oracle matches the constant in any
    representation. Other constants (generic external-auth oracle) need
    msg.sender / signature_recovery among the call args, or it is not an
    authentication predicate."""
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


# 5. Computed-key membership — _members[keccak(role,msg.sender)]


def test_hashed_key_membership_classifies_caller_authority(tmp_path):
    """LANDED (codex F4): ``_authorized[keccak256(abi.encode(role, msg.sender))]``
    yields a 2-key membership leaf (key_sources ``[parameter(role), msg_sender]``)
    instead of one ``computed`` source; the multi-key rule then promotes it.

    Path: predicates.py:_expand_key_operand walks back through hash/abi.encode
    calls by Solidity built-in signature, not identifier names."""
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
