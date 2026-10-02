"""``is_pausable`` reads the Plane-1 pause claims. The structural ``PauseAnalyzer`` only sees top-level scalar
latches, missing struct-member latches (Veda ``accountantState.isPaused``) and ERC-7201 namespaced slots
(false on 33 of 46 contracts with a ``pause*`` entry). EigenLayer's bitmap ``pause(uint256)`` assigns a
parameter, so the matcher fails closed on it structurally, not by name list.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.claims import attach_claims_to_effects, build_claims, project_effect_labels
from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts_with_pause_info,
)
from services.static.contract_analysis_pipeline.summaries import (
    _detect_pausability,
    _pause_claims,
)

pytestmark = pytest.mark.compile


def _analyse(tmp_path: Path, source: str, name: str = "C"):
    path = tmp_path / "C.sol"
    path.write_text(textwrap.dedent(source).strip() + "\n")
    contract = next(c for c in Slither(str(path)).contracts if c.name == name)
    trees, pause_info = build_predicate_artifacts_with_pause_info(contract)
    effects = build_effects(contract)
    attach_claims_to_effects(effects, build_claims(contract, effects, trees))
    project_effect_labels(effects)
    return _detect_pausability(contract, tmp_path, pause_info, effects, trees), effects


def _pausability(tmp_path: Path, source: str, name: str = "C"):
    return _analyse(tmp_path, source, name)[0]


STRUCT_MEMBER_LATCH = """
    pragma solidity ^0.8.19;
    contract C {
        struct State { uint96 rate; bool isPaused; }
        address public owner;
        State public state;
        error Paused();
        modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
        function pause() external onlyOwner { state.isPaused = true; }
        function unpause() external onlyOwner { state.isPaused = false; }
        function paused() external view returns (bool) { return state.isPaused; }
        function poke(uint96 r) external {
            if (state.isPaused) revert Paused();
            state.rate = r;
        }
    }
"""

# The real one is an abstract base with a private flag, assigned from a parameter.
BITMAP_LATCH = """
    pragma solidity ^0.8.19;
    abstract contract Pausable {
        address public pauser;
        uint256 private _paused;
        error OnlyPauser();
        error CurrentlyPaused();
        error InvalidNewPausedStatus();
        modifier onlyPauser() { if (msg.sender != pauser) revert OnlyPauser(); _; }
        function pause(uint256 newPausedStatus) external onlyPauser {
            if (newPausedStatus & _paused != _paused) revert InvalidNewPausedStatus();
            _setPausedStatus(newPausedStatus);
        }
        function pauseAll() external onlyPauser { _setPausedStatus(type(uint256).max); }
        function unpause(uint256 newPausedStatus) external onlyPauser {
            if (newPausedStatus & _paused != newPausedStatus) revert InvalidNewPausedStatus();
            _setPausedStatus(newPausedStatus);
        }
        function paused() public view returns (uint256) { return _paused; }
        function _setPausedStatus(uint256 s) internal { _paused = s; }
        function _checkNotPaused() internal view { if (_paused != 0) revert CurrentlyPaused(); }
        modifier whenNotPaused() { _checkNotPaused(); _; }
    }
    contract C is Pausable {
        uint256 public value;
        function poke(uint256 v) external whenNotPaused { value = v; }
    }
"""

NO_LATCH = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        mapping(address => bool) public isPauser;
        modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
        // Names a pauser; is not itself pausable. The corpus analogue is
        // EigenLayer's PauserRegistry, which stays false.
        function setIsPauser(address who, bool ok) external onlyOwner { isPauser[who] = ok; }
    }
"""


def test_struct_member_latch_is_pausable(tmp_path):
    """7 corpus contracts move on this shape alone."""
    result, effects = _analyse(tmp_path, STRUCT_MEMBER_LATCH)
    assert result["is_pausable"] is True
    assert "state.isPaused" in result["pause_variables"], result["pause_variables"]
    assert "pause()" in result["pause_functions"]
    assert "unpause()" in result["unpause_functions"]
    assert _pause_claims(effects) == ({"pause()"}, {"unpause()"}, {"state.isPaused"})


def test_bitmap_pause_family_is_not_widened_into(tmp_path):
    """The bitmap family must not publish a pause capability before A7 can bound the duration."""
    result, effects = _analyse(tmp_path, BITMAP_LATCH)
    assert _pause_claims(effects) == (set(), set(), set()), "the widening's input must be empty here"
    assert result["is_pausable"] is False, result
    assert result["pause_functions"] == []
    assert result["unpause_functions"] == []


def test_pauser_registry_shape_stays_clean(tmp_path):
    result = _pausability(tmp_path, NO_LATCH)
    assert result["is_pausable"] is False
    assert result["pause_variables"] == []


CLASSIC_PAUSABLE = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        bool public paused;
        uint256 public value;
        error Paused();
        modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
        modifier whenNotPaused() { if (paused) revert Paused(); _; }
        function pause() external onlyOwner { paused = true; }
        function unpause() external onlyOwner { paused = false; }
        function poke(uint256 v) external whenNotPaused { value = v; }
    }
"""


@pytest.mark.parametrize(
    "label, source",
    [
        pytest.param("struct_member", STRUCT_MEMBER_LATCH, id="struct_member"),
        # ``PauseInfo`` comes from inside the same degraded stage, so the structural route goes blind too.
        pytest.param("classic", CLASSIC_PAUSABLE, id="classic"),
    ],
)
def test_is_pausable_is_not_determined_when_the_trees_stage_raised(tmp_path, monkeypatch, label, source):
    """``core.py`` catches the trees stage and substitutes an empty ``PauseInfo`` while claims still run; ``false``
    was published on every pausable contract. The healthy arm runs first so the fixture can't go vacuous.
    """
    from services.static.contract_analysis_pipeline import core
    from tests.support.foundry_project import write_foundry_project

    body = textwrap.dedent(source).strip() + "\n"

    healthy_project = write_foundry_project(tmp_path / "healthy", "C", body)
    healthy, _t, _e = core.collect_contract_analysis_with_artifacts(healthy_project)
    assert healthy["pausability"]["is_pausable"] is True, f"{label}: fixture must be pausable when nothing raises"

    def _boom(*_a, **_k):
        raise RuntimeError("forced predicate_trees_emit failure")

    monkeypatch.setattr(core, "build_predicate_artifacts_with_pause_info", _boom)
    degraded_project = write_foundry_project(tmp_path / "degraded", "C", body)
    degraded, trees_artifact, effects_artifact = core.collect_contract_analysis_with_artifacts(degraded_project)

    assert isinstance(trees_artifact, dict) and isinstance(effects_artifact, dict)
    assert "error" in trees_artifact, "guard: the trees stage must actually have degraded"
    assert any("claims" in record for record in (effects_artifact.get("functions") or {}).values()), (
        "guard: the claims key is written anyway — that is why it cannot be the only discriminator"
    )

    assert degraded["pausability"]["is_pausable"] is None, degraded["pausability"]
