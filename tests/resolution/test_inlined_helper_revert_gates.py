"""``require(helper(msg.sender))`` also depends on the helper's own ``require`` gates, which inlining the return
expression dropped; ``EtherFiOracle.submitReport`` fell open this way. Real Slither fixture, no DB or RPC.
"""

from __future__ import annotations

import textwrap

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)

# Mirrors cid-342; ``_openHelper``/``poke`` pin that a business-only internal gate is not conjoined.
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
    """Function-scope imports avoid the policy/resolution init cycle."""
    from services.policy.capability_surface import project_capability_surface
    from services.resolution.capability_resolver import capability_to_dict
    from services.resolution.predicate_evaluator import evaluate_tree

    if tree is None:
        return True
    cap = evaluate_tree(tree)
    cap_dict = capability_to_dict(cap)
    surface = project_capability_surface(cap_dict)
    return bool(surface.authority_public)


def _verdicts(subject, monkeypatch, inline_gates_flag: str) -> dict[str, bool]:
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")
    monkeypatch.setenv("PSAT_INLINE_HELPER_REVERT_GATES", inline_gates_flag)
    trees = build_predicate_artifacts(subject).get("trees") or {}
    return {
        full_name: _authority_public(trees.get(full_name))
        for full_name in ("act()", "submitReport(uint256)", "poke(uint256)", "addMember(address)", "ping()")
    }


def test_helper_allowlist_gates_survive_inlining(subject, monkeypatch):
    verdicts = _verdicts(subject, monkeypatch, inline_gates_flag="1")

    assert verdicts["act()"] is False, "registered[msg.sender] allowlist dropped on inlining"
    assert verdicts["submitReport(uint256)"] is False, (
        "memberStates[msg.sender].registered allowlist dropped on inlining"
    )
