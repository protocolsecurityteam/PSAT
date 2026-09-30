"""Codex F1-F4: real auth patterns the generic predicate pipeline must classify structurally, with no per-protocol
adapter.
"""

from __future__ import annotations

import pytest

slither = pytest.importorskip("slither")

from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.contract_analysis_pipeline.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)
from tests.support.predicate_trees import _all_leaves  # noqa: E402
from tests.support.slither_compile import _compile  # noqa: E402


def _build_pipeline(contract):
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    return trees


def test_diamond_acl_membership_classifies_caller_authority(tmp_path):
    """Handled via internal-call recursion and Member/Index chaining.

    ``storage_var`` is the SSA ref ("REF_1"), so writer-gate pass 2 can't find its writers yet.
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


def test_bitwise_flag_membership_classifies_caller_authority(tmp_path):
    """F1: mask operands must be literal/``constant``/``immutable``; ``_find_index_value_pair`` treats ``Binary(AND,
    Index, Const)`` like ``Index == const``.
    """
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


def test_custom_m_of_n_classifies_threshold_group(tmp_path):
    """F2: promotes when the counter is incremented additively by an authority-gated function keyed on a parameter
    (msg.sender would be a cooldown) with no unguarded writers. ``apply_writer_gate_pass`` iterates to a fixed
    point for chained promotions.
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
    assert leaf["authority_role"] == "caller_authority", (
        f"expected caller_authority for M-of-N execute gate, got {leaf['authority_role']}"
    )


def test_eip1271_classifies_signature_auth(tmp_path):
    """F3: detected by the 0x1626ba7e magic value, not the function name.

    Other constants need msg.sender or signature recovery among the call args.
    """
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


def test_hashed_key_membership_classifies_caller_authority(tmp_path):
    """F4: ``_expand_key_operand`` walks back through hash/abi.encode by built-in signature, not identifier names."""
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
