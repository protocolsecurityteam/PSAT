"""P4 guard: caller-keyed time/threshold predicates under the Part-2 openness.

Part-2 decision (plan §5): **open-modulo-condition**. A caller-keyed time/threshold
predicate lowers to a runtime side-condition, not a caller set. In etherfi the only such
predicate is a share-LOCK (``shareUnlockTime[from] > now``, keyed on a PARAMETER) where
opening is correct — a share-lock is a restriction, not an authorization. No production
code beyond P3 is needed for the current data, so the discriminator that would keep a
caller-keyed time ALLOWLIST gated is deferred until such a shape actually appears.

These guards pin the boundary so the deferral stays safe:

  1. ``require(allowlist[msg.sender])`` — a TRUTHY caller-authority allowlist — stays
     GATED (never public). This is the Part-2 safety invariant: a positive membership
     gate is never negated, so the cofinite/openness path can never reach it.
  2. ``if(shareUnlockTime[from] > now) revert`` — a param-keyed share-LOCK — opens
     (public, modulo the time condition). The deliberate, correct decision.
  3. ``if(allowedUntil[msg.sender] < now) revert`` — a caller-keyed time ALLOWLIST —
     SHOULD be gated, but today resolves ``public`` (it lowers to a ``comparison``/business
     leaf with no value-predicate descriptor → ``conditional_universal``). This path is
     PRE-EXISTING and orthogonal to the Part-2 negate/cofinite change (negate is never
     reached). It is marked ``xfail(strict=True)``: the desired invariant is ``not public``,
     and when a discriminator at ``_has_caller_keyed_value_predicate`` (predicate_evaluator
     L323) is added, this xpasses → strict fails → forcing removal of the marker. No such
     shape exists in etherfi today.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import _column_values_for_capability  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.predicate_evaluator import evaluate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.reentrancy_pause import apply_reentrancy_pause_pass  # noqa: E402
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass  # noqa: E402

# Admin-written mappings (the owner-gated setters) so the allowlist reads classify as
# caller_authority (membership branch) rather than inert business reads.
_SOURCE = """
pragma solidity ^0.8.19;
contract C {
    address public owner;
    mapping(address => bool) public adminAllowlist;
    mapping(address => uint256) public allowedUntil;
    mapping(address => uint256) public shareUnlockTime;

    function setAllowed(address u, bool v) external { require(msg.sender == owner); adminAllowlist[u] = v; }
    function setUntil(address u, uint256 t) external { require(msg.sender == owner); allowedUntil[u] = t; }

    // (1) truthy caller-authority allowlist — MUST stay gated.
    function boolAllowlistGate() external view { require(adminAllowlist[msg.sender]); }
    // (2) param-keyed share-LOCK — opens modulo the time condition (correct).
    function shareLockKeyedOnParam(address from) external view {
        if (shareUnlockTime[from] > block.timestamp) revert();
    }
    // (3) caller-keyed time ALLOWLIST — SHOULD be gated (currently opens; see module docstring).
    function timeAllowlistGate() external view { if (allowedUntil[msg.sender] < block.timestamp) revert(); }
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


def test_param_keyed_share_lock_opens_modulo_condition(tmp_path):
    # The deliberate open-modulo-condition decision: a share-lock keyed on a parameter is
    # a restriction, not an authorization — anyone may call once unlocked.
    assert _status(tmp_path, "shareLockKeyedOnParam(address)") == "public", (
        "a param-keyed share-lock should open with the time-lock as a side-condition"
    )


@pytest.mark.xfail(
    strict=True,
    reason="caller-keyed time allowlist opens via the pre-existing comparison→conditional_universal "
    "path (orthogonal to the Part-2 negate/cofinite change). The fix is a discriminator at "
    "_has_caller_keyed_value_predicate (predicate_evaluator L323), deferred until such a shape exists "
    "in real data. Remove this marker when that discriminator lands.",
)
def test_caller_keyed_time_allowlist_should_not_be_public(tmp_path):
    # DESIRED invariant: a caller-keyed time allowlist (only callers permitted before T)
    # is an authorization and must stay gated. Currently it opens (xfail).
    assert _status(tmp_path, "timeAllowlistGate()") != "public", (
        "a caller-keyed time-bounded allowlist must NOT silently grant public access"
    )
