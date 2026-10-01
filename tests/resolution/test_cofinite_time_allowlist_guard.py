"""P4 guard: caller-keyed time predicates under the Part-2 openness.

Part-2 decision (plan): a caller-keyed time/threshold predicate lowers to a runtime
side-condition (open-modulo-condition), EXCEPT a deny-by-default time **allowlist**, which
stays gated. ``predicate_evaluator._is_caller_keyed_time_allowlist`` discriminates on the
proceed-relation lower-bounding the caller value (``value >= now``), so the unset (0)
default is excluded. Four boundary shapes, all ``mapping[caller] <op> X``:

  1. ``require(allowlist[msg.sender])`` - truthy allowlist - GATED (a positive membership
     gate is never negated).
  2. ``if(allowedUntil[msg.sender] < now) revert`` - deny-by-default time allowlist - GATED.
  3. ``if(shareUnlockTime[msg.sender] > now) revert`` - share-LOCK, OPPOSITE operator
     direction (allow-by-default) - OPENS.
  4. ``if(shareUnlockTime[from] > now) revert`` - param-keyed share-LOCK - OPENS.

No such allowlist exists on etherfi today; this is a forward guard.
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


@pytest.mark.parametrize(
    ("signature", "opens_public", "reason"),
    [
        pytest.param(
            "boolAllowlistGate()",
            False,
            "require(adminAllowlist[msg.sender]) is a positive caller gate — must NOT open to public",
            id="truthy_caller_allowlist_stays_gated",
        ),
        # CRITICAL: a deny-by-default time allowlist must never silently open to public.
        pytest.param(
            "timeAllowlistGate()",
            False,
            "a caller-keyed deny-by-default time allowlist must NOT silently grant public access",
            id="caller_keyed_time_allowlist_stays_gated",
        ),
        # Operand order varies; the discriminator keys on the proceed-relation, so the reversed form
        # (``block.timestamp > allowedUntil[msg.sender]``) gates too.
        pytest.param(
            "timeAllowlistReversed()",
            False,
            "the time-allowlist must gate regardless of which side the caller value is written on",
            id="time_allowlist_gated_regardless_of_operand_order",
        ),
        # If the discriminator ever caught this, every share-lock would be wrongly gated.
        pytest.param(
            "shareLockKeyedOnCaller()",
            True,
            "a caller-keyed share-lock (allow-by-default) must open, not gate",
            id="caller_keyed_share_lock_opens",
        ),
        pytest.param(
            "shareLockKeyedOnParam(address)",
            True,
            "a param-keyed share-lock should open with the time-lock as a side-condition",
            id="param_keyed_share_lock_opens_modulo_condition",
        ),
    ],
)
def test_time_allowlist_and_share_lock_openness(tmp_path, signature, opens_public, reason):
    assert (_status(tmp_path, signature) == "public") is opens_public, reason
