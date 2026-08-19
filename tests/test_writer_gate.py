"""Tests for the writer-gate two-pass analyzer.

Per v6/v7 plan: 1-key caller-keyed bool/uint mappings can't be
classified as auth or personal-flag from the read-site alone — the
discriminator is how the storage var is *written*. The analyzer
walks the contract, finds writer functions of each candidate
mapping, classifies the write key, and promotes leaves when the
writer is itself authority-gated.
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
from services.static.contract_analysis_pipeline.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _all_leaves(tree):
    if tree is None:
        return []
    if tree.get("op") == "LEAF":
        return [tree["leaf"]] if tree.get("leaf") else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_all_leaves(child))
    return out


def _build_trees(contract):
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    return trees


# ---------------------------------------------------------------------------
# Rule a: ALL writers self_keyed → leave as business
# ---------------------------------------------------------------------------


def test_personal_flag_stays_business(tmp_path):
    """``claimed[msg.sender] = true`` is the only writer (and self-
    keyed). Reading ``require(claimed[msg.sender])`` stays business."""
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


# ---------------------------------------------------------------------------
# Rule b.i: external_keyed writer is auth-gated → promote to caller_authority
# ---------------------------------------------------------------------------


def test_blacklist_writer_gated_promotes(tmp_path):
    """``_blacklist[user] = true`` is written by an Ownable function.
    Reading ``require(!_blacklist[msg.sender])`` should promote to
    caller_authority via rule b.i.

    Confidence is MEDIUM on a rule-b.i promotion: the auth signal comes
    from writer-side analysis, not from the read site's own shape."""
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


# ---------------------------------------------------------------------------
# Rule b.ii: self-administered (Maker wards style) → promote
# ---------------------------------------------------------------------------


def test_self_administered_wards_promotes(tmp_path):
    """Maker wards-style: ``rely(addr)`` is gated by ``wards[msg.
    sender] == 1`` (same map, value-compare form). Reading
    ``wards[msg.sender] == 1`` in someAction should promote via
    rule b.ii because the writer is gated by the same storage var.

    Critical for real Maker contracts: this is THE canonical 'auth'
    pattern in MakerDAO. Without ``map[k]==1`` recognition the leaf
    stays equality, the writer-gate pass-2 doesn't see a membership
    leaf to gate on, and the wards mapping looks like just a uint
    state-var read.

    Confidence is HIGH here (unlike rule b.i): the writer reads the same
    map M as its own gate, which is a tight structural match."""
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
    # Recognized as membership (value-compare pattern) with
    # truthy_value="1".
    assert leaf["kind"] == "membership"
    assert leaf["set_descriptor"]["truthy_value"] == "1"
    # Promoted via rule b.ii (self-administered).
    assert leaf["authority_role"] == "caller_authority"
    assert leaf["confidence"] == "high"


# ---------------------------------------------------------------------------
# Rule c: external_keyed writer is open (ungated) → keep business
# ---------------------------------------------------------------------------


def test_open_registration_stays_business(tmp_path):
    """``register(addr)`` writes ``_registered[addr] = true`` with no
    gate. Reading ``require(_registered[msg.sender])`` should stay
    business — anyone can register anyone, and confidence stays LOW."""
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
    """A public external-keyed writer can grant membership, so an
    otherwise gated writer is not enough to promote the mapping."""
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


# ---------------------------------------------------------------------------
# Regression pin: inherited OZ Ownable through ``_checkOwner`` helper.
# The predicate builder must walk ``owner() == _msgSender()`` through the
# inherited helper and bind the operand to the underlying ``_owner`` storage
# var — otherwise the leaf classifies as ``business`` (or empty) and the
# downstream resolver has nothing to enumerate. Confirmed working on the
# EtherFi LiquidityPool artifact (``operands: [_owner, msg_sender]``,
# ``authority_role: caller_authority``), pinned here so a regression in
# the cross-fn provenance walk surfaces immediately.
# ---------------------------------------------------------------------------


def test_owner_eq_msgsender_through_helper_call(tmp_path):
    """OZ-shaped Ownable: ``onlyOwner`` modifier calls ``_checkOwner()``,
    which calls a view function ``owner()`` whose body is
    ``return _owner;``. The condition is ``owner() == _msgSender()``.
    The predicate builder should classify this leaf as
    ``caller_authority`` because ``owner()`` resolves to ``_owner``."""
    # Inheritance pattern matters: same-contract _checkOwner is already handled
    # by the existing cross-fn helper traversal. EtherFi inherits from
    # OwnableUpgradeable so the modifier + _checkOwner + owner() live in a
    # different contract from transferOwnership.
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
    # Use the most-derived contract (the inheriting one), not the abstract base.
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    leaves = _all_leaves(trees["transferOwnership(address)"])
    assert leaves, "expected at least one leaf for transferOwnership"
    # The owner-check leaf should classify as caller_authority — not business
    # (the empty fallback) and not unsupported.
    auth_leaves = [leaf for leaf in leaves if leaf["authority_role"] == "caller_authority"]
    assert auth_leaves, (
        f"expected a caller_authority leaf for transferOwnership; got "
        f"{[(leaf.get('authority_role'), leaf.get('kind')) for leaf in leaves]}"
    )
    # And the descriptor or operand should reference the underlying storage var.
    leaf = auth_leaves[0]
    operands_have_owner = any(
        op.get("source") == "state_variable" and op.get("state_variable_name") == "_owner"
        for op in leaf.get("operands", [])
    )
    assert operands_have_owner, (
        f"expected an operand pointing at state_variable '_owner'; got operands={leaf.get('operands')}"
    )
