"""Regression tests for inlined-helper internal revert-gate conjunction.

``require(helper(msg.sender))`` admits a caller only when the helper returns true AND none
of its own ``require`` gates reverted. The predicate builder used to inline ONLY the
helper's return expression (RevertDetector skips callees whose result is read), so a
caller-keyed allowlist inside the helper vanished and the caller classified public.

Production false-open: ``EtherFiOracle.submitReport`` gates on ``shouldSubmitReport(msg.sender)``,
whose body requires ``committeeMemberStates[_member].registered``. The fix
(``_internal_call_revert_gate_subtrees``, kill-switch ``PSAT_INLINE_HELPER_REVERT_GATES``)
conjoins the helper's caller-tainted revert gates at the call site. Real Slither fixture,
production path (``build_predicate_artifacts`` -> null-adapter ``evaluate_tree`` -> policy
projection). No DB, no RPC.
"""

from __future__ import annotations

import textwrap

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)

# Mirrors the cid-342 shape: an owner-written allowlist (plain mapping AND the
# struct-member variant), checked inside a view helper that then returns a
# business expression; external entry points gate on require(helper(msg.sender)).
# ``_openHelper``/``poke`` pin the conservative side: a business-only internal
# gate must NOT be conjoined (no manufactured false-gate).
SOURCE = """
pragma solidity ^0.8.19;

contract InlinedAllowlist {
    struct MemberState { bool registered; bool enabled; uint32 lastReportRefSlot; }

    address public owner;
    mapping(address => bool) internal registered;
    mapping(address => MemberState) internal memberStates;
    uint256 internal lastSlot;

    constructor() { owner = msg.sender; }

    function addMember(address u) external {
        require(msg.sender == owner, "auth");
        registered[u] = true;
        memberStates[u] = MemberState(true, true, 0);
    }

    function _allowed(address u) internal view returns (bool) {
        require(registered[u], "not registered");
        return lastSlot > 0;
    }

    function shouldSubmit(address m) public view returns (bool) {
        require(memberStates[m].registered, "not registered");
        require(memberStates[m].enabled, "disabled");
        return lastSlot > memberStates[m].lastReportRefSlot;
    }

    function _openHelper(uint256 x) internal view returns (bool) {
        require(lastSlot > 0, "not started");
        return x > 0;
    }

    function act() external {
        require(_allowed(msg.sender), "denied");
        lastSlot = block.number;
    }

    function submitReport(uint256 v) external returns (bool) {
        require(shouldSubmit(msg.sender), "no need");
        lastSlot = v;
        return true;
    }

    function poke(uint256 x) external {
        require(_openHelper(x), "nope");
        lastSlot = x;
    }

    function ping() external {
        lastSlot += 1;
    }
}
"""


@pytest.fixture(scope="module")
def subject(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("inline_gates")
    f = tmp / "InlinedAllowlist.sol"
    f.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    return next(c for c in Slither(str(f)).contracts if c.name == "InlinedAllowlist")


def _authority_public(tree) -> bool:
    """Null-adapter evaluation + policy projection (harness.evaluate_tree_verdict's chain).
    Imports are function-scope to stay clear of the policy<->resolution init cycle."""
    from services.policy.capability_surface import project_capability_surface
    from services.resolution.capability_resolver import capability_to_dict
    from services.resolution.predicate_evaluator import evaluate_tree

    if tree is None:
        # effective_permissions._public_capability(): absent from trees -> public.
        return True
    cap = evaluate_tree(tree)
    cap_dict = capability_to_dict(cap)
    surface = project_capability_surface(cap_dict)
    return bool(surface.authority_public)


def _verdicts(subject, monkeypatch, inline_gates_flag: str) -> dict[str, bool]:
    """Build trees under the given PSAT_INLINE_HELPER_REVERT_GATES value and evaluate every
    entry point under the earned-public default."""
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")
    monkeypatch.setenv("PSAT_INLINE_HELPER_REVERT_GATES", inline_gates_flag)
    trees = build_predicate_artifacts(subject).get("trees") or {}
    return {
        full_name: _authority_public(trees.get(full_name))
        for full_name in ("act()", "submitReport(uint256)", "poke(uint256)", "addMember(address)", "ping()")
    }


def test_helper_allowlist_gates_survive_inlining(subject, monkeypatch):
    """The cid-342 regression: an entry point whose only caller gate lives inside an
    inlined helper resolves GATED, for plain-mapping and struct-member allowlists."""
    verdicts = _verdicts(subject, monkeypatch, inline_gates_flag="1")

    assert verdicts["act()"] is False, "registered[msg.sender] allowlist dropped on inlining"
    assert verdicts["submitReport(uint256)"] is False, (
        "memberStates[msg.sender].registered allowlist dropped on inlining"
    )


def test_conjunction_only_adds_caller_gates(subject, monkeypatch):
    """A business-only internal gate is NOT conjoined (poke stays public), gate-less
    functions stay public, and the direct owner gate still gates."""
    verdicts = _verdicts(subject, monkeypatch, inline_gates_flag="1")

    assert verdicts["poke(uint256)"] is True, "business-only helper gate manufactured a false-gate"
    assert verdicts["ping()"] is True
    assert verdicts["addMember(address)"] is False


def test_kill_switch_restores_return_only_inlining(subject, monkeypatch):
    """PSAT_INLINE_HELPER_REVERT_GATES=0 reproduces the pre-fix trees (helper-gated entry
    points fall open), proving this suite fails if the fix is reverted."""
    verdicts = _verdicts(subject, monkeypatch, inline_gates_flag="0")

    assert verdicts["act()"] is True
    assert verdicts["submitReport(uint256)"] is True
    assert verdicts["poke(uint256)"] is True
    assert verdicts["addMember(address)"] is False
