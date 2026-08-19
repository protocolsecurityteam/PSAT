"""P4 guard: caller-keyed time predicates under the Part-2 openness.

Part-2 decision (plan §5): **open-modulo-condition** by default — a caller-keyed
time/threshold predicate lowers to a runtime side-condition, not a caller set — EXCEPT a
deny-by-default time **allowlist**, which is an authorization and stays gated.
``predicate_evaluator._is_caller_keyed_time_allowlist`` is the discriminator: it gates a
comparison of the caller's keyed value against ``block.timestamp`` whose proceed-relation
*lower-bounds* the caller value (``value >= now``), so the unset (0) default is excluded.

These guards pin the four boundary shapes (all share the ``mapping[caller] <op> X`` skeleton):

  1. ``require(allowlist[msg.sender])`` — a TRUTHY caller-authority allowlist — GATED. The
     Part-2 safety invariant: a positive membership gate is never negated.
  2. ``if(allowedUntil[msg.sender] < now) revert`` — a deny-by-default caller-keyed time
     ALLOWLIST — GATED (the discriminator). Only pre-approved callers (until expiry) proceed.
  3. ``if(shareUnlockTime[msg.sender] > now) revert`` — a caller-keyed share-LOCK — OPENS.
     Same caller-keyed/timestamp skeleton, OPPOSITE operator direction (allow-by-default):
     once unlocked, anyone proceeds. The operator direction is the whole distinction.
  4. ``if(shareUnlockTime[from] > now) revert`` — a param-keyed share-LOCK — OPENS.

The discriminator has zero blast radius on etherfi: every caller-keyed comparison there is
a balance/allowance condition (compared against a parameter, not a timestamp) or the
LayerZeroTeller share-lock (operator ``lte``) — neither matches. No deny-by-default time
allowlist exists in the set, so this is a forward guard for a shape that could appear.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import _column_values_for_capability  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.predicate_evaluator import evaluate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.reentrancy_pause import apply_reentrancy_pause_pass  # noqa: E402
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass  # noqa: E402

# Admin-written mappings (owner-gated setters) so the allowlist reads classify as
# caller_authority rather than inert business reads.
_SOURCE = """
pragma solidity ^0.8.19;
contract C {
    address public owner;
    mapping(address => bool) public adminAllowlist;
    mapping(address => uint256) public allowedUntil;
    mapping(address => uint256) public shareUnlockTime;

    function setAllowed(address u, bool v) external { require(msg.sender == owner); adminAllowlist[u] = v; }
    function setUntil(address u, uint256 t) external { require(msg.sender == owner); allowedUntil[u] = t; }

    // (1) truthy caller-authority allowlist — GATED (positive gate, never negated).
    function boolAllowlistGate() external view { require(adminAllowlist[msg.sender]); }
    // (2) deny-by-default caller-keyed time ALLOWLIST — GATED (the discriminator).
    function timeAllowlistGate() external view { if (allowedUntil[msg.sender] < block.timestamp) revert(); }
    // (2b) same allowlist, reversed operand order (timestamp on LHS) — still GATED.
    function timeAllowlistReversed() external view { if (block.timestamp > allowedUntil[msg.sender]) revert(); }
    // (3) caller-keyed share-LOCK — OPENS (same skeleton, opposite operator direction).
    function shareLockKeyedOnCaller() external view {
        if (shareUnlockTime[msg.sender] > block.timestamp) revert();
    }
    // (4) param-keyed share-LOCK — OPENS.
    function shareLockKeyedOnParam(address from) external view {
        if (shareUnlockTime[from] > block.timestamp) revert();
    }
}
"""


def _status(tmp_path: Path, signature: str) -> str | None:
    src = textwrap.dedent(_SOURCE).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    contract = Slither(str(f)).contracts[0]
    trees = {
        fn.full_name: tree
        for fn in contract.functions
        if not fn.is_constructor and (tree := build_predicate_tree(fn)) is not None
    }
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    cap = evaluate_tree(trees[signature])
    return _column_values_for_capability(capability_to_dict(cap))["status"]


def test_truthy_caller_allowlist_stays_gated(tmp_path):
    # The Part-2 safety invariant: a positive caller-membership gate is `truthy`, never
    # negated, so it never reaches the cofinite/openness path.
    assert _status(tmp_path, "boolAllowlistGate()") != "public", (
        "require(adminAllowlist[msg.sender]) is a positive caller gate — must NOT open to public"
    )


def test_caller_keyed_time_allowlist_stays_gated(tmp_path):
    # The P4 discriminator: a deny-by-default time allowlist (only callers permitted until
    # expiry; unset default denied) is an authorization and must stay gated, never public.
    assert _status(tmp_path, "timeAllowlistGate()") != "public", (
        "a caller-keyed deny-by-default time allowlist must NOT silently grant public access"
    )


def test_caller_keyed_time_allowlist_gated_regardless_of_operand_order(tmp_path):
    # Operand order varies with how the source writes the comparison; the discriminator
    # keys on the proceed-relation (caller value lower-bounded by the timestamp), so the
    # reversed form (``block.timestamp > allowedUntil[msg.sender]``) gates too.
    assert _status(tmp_path, "timeAllowlistReversed()") != "public", (
        "the time-allowlist must gate regardless of which side the caller value is written on"
    )


def test_caller_keyed_share_lock_opens(tmp_path):
    # The discriminating boundary: a caller-keyed share-LOCK shares the
    # mapping[caller]/timestamp skeleton but the OPPOSITE operator direction (allow-by-
    # default) — once unlocked anyone proceeds, so it must still open. If the discriminator
    # ever caught this, every share-lock would be wrongly gated.
    assert _status(tmp_path, "shareLockKeyedOnCaller()") == "public", (
        "a caller-keyed share-lock (allow-by-default) must open, not gate"
    )


def test_param_keyed_share_lock_opens_modulo_condition(tmp_path):
    # The deliberate open-modulo-condition decision: a share-lock keyed on a parameter is
    # a restriction, not an authorization — anyone may call once unlocked.
    assert _status(tmp_path, "shareLockKeyedOnParam(address)") == "public", (
        "a param-keyed share-lock should open with the time-lock as a side-condition"
    )
