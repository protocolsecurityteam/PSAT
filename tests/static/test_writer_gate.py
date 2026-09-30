"""A 1-key caller-keyed mapping can't be told apart as auth vs personal flag from the read site; the discriminator is
how it's written.
"""

from __future__ import annotations

import pytest

slither = pytest.importorskip("slither")

from services.static.contract_analysis_pipeline.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)
from tests.support.predicate_trees import _all_leaves, _build_trees  # noqa: E402
from tests.support.slither_compile import _compile  # noqa: E402

# Rule a: all writers self-keyed stays business.


def test_personal_flag_stays_business(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) public claimed;
            function claim() external {
                claimed[msg.sender] = true;
            }
            function f() external view {
                require(claimed[msg.sender]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    fn_tree = trees["f()"]
    leaves = _all_leaves(fn_tree)
    assert len(leaves) == 1
    assert leaves[0]["authority_role"] == "business"


# Rule b.i: an auth-gated external-keyed writer promotes.


def test_blacklist_writer_gated_promotes(tmp_path):
    """MEDIUM confidence because the signal comes from the writer side."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => bool) public _blacklist;
            function setBlacklist(address user, bool val) external {
                require(msg.sender == ownerVar);
                _blacklist[user] = val;
            }
            function someAction() external view {
                require(!_blacklist[msg.sender]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    leaves = _all_leaves(trees["someAction()"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["operator"] == "falsy"
    assert leaf["authority_role"] == "caller_authority"
    assert leaf["confidence"] == "medium"


# Rule b.ii: self-administered (Maker wards).


def test_self_administered_wards_promotes(tmp_path):
    """Without ``map[k]==1`` recognition wards looks like a uint read. HIGH confidence: a tight structural match."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public wards;
            function rely(address addr) external {
                require(wards[msg.sender] == 1);
                wards[addr] = 1;
            }
            function someAction() external view {
                require(wards[msg.sender] == 1);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    leaves = _all_leaves(trees["someAction()"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["set_descriptor"]["truthy_value"] == "1"
    assert leaf["authority_role"] == "caller_authority"
    assert leaf["confidence"] == "high"


# Rule c: an ungated external-keyed writer stays business.


def test_open_registration_stays_business(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) public _registered;
            function register(address addr) external {
                _registered[addr] = true;
            }
            function someAction() external view {
                require(_registered[msg.sender]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    leaves = _all_leaves(trees["someAction()"])
    assert len(leaves) == 1
    assert leaves[0]["authority_role"] == "business"
    assert leaves[0]["confidence"] == "low"


def test_mixed_gated_and_public_external_writers_stays_business(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            mapping(address => bool) public _registered;
            function setRegistered(address user, bool val) external {
                require(msg.sender == ownerVar);
                _registered[user] = val;
            }
            function registerFor(address user) external {
                _registered[user] = true;
            }
            function someAction() external view {
                require(_registered[msg.sender]);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    leaves = _all_leaves(trees["someAction()"])
    assert len(leaves) == 1
    assert leaves[0]["authority_role"] == "business"


# Inherited OZ Ownable through ``_checkOwner`` (EtherFi LiquidityPool): the builder must bind the operand to ``_owner``.


def test_owner_eq_msgsender_through_helper_call(tmp_path):
    # EtherFi inherits OwnableUpgradeable, so the helper lives in a different contract; same-contract is already
    # handled.
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        abstract contract Context {
            function _msgSender() internal view virtual returns (address) { return msg.sender; }
        }
        abstract contract Ownable is Context {
            address private _owner;
            function owner() public view virtual returns (address) { return _owner; }
            function _checkOwner() internal view virtual {
                require(owner() == _msgSender(), "not owner");
            }
            modifier onlyOwner() { _checkOwner(); _; }
            function _transferOwnership(address newOwner) internal virtual { _owner = newOwner; }
        }
        contract C is Ownable {
            constructor() { _transferOwnership(msg.sender); }
            function transferOwnership(address newOwner) public onlyOwner {
                _transferOwnership(newOwner);
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    leaves = _all_leaves(trees["transferOwnership(address)"])
    assert leaves, "expected at least one leaf for transferOwnership"
    auth_leaves = [leaf for leaf in leaves if leaf["authority_role"] == "caller_authority"]
    assert auth_leaves, (
        f"expected a caller_authority leaf for transferOwnership; got "
        f"{[(leaf.get('authority_role'), leaf.get('kind')) for leaf in leaves]}"
    )
    leaf = auth_leaves[0]
    operands_have_owner = any(
        op.get("source") == "state_variable" and op.get("state_variable_name") == "_owner"
        for op in leaf.get("operands", [])
    )
    assert operands_have_owner, (
        f"expected an operand pointing at state_variable '_owner'; got operands={leaf.get('operands')}"
    )
