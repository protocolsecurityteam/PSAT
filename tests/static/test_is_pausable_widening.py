"""``is_pausable`` reads the Plane-1 pause claims, and the EigenLayer bitmap
family is excluded by construction.

Measured on the local corpus before the change: 46 contracts publish a
``pause*`` entry point and ``is_pausable`` was ``false`` on 33 of them. The
structural ``PauseAnalyzer`` only ever sees a latch that is a top-level scalar
state variable, so it misses the two families that hold most of the corpus:

* **struct member** -- Veda ``AccountantWithRateProviders`` keeps the latch in
  ``accountantState.isPaused``; ``_lookup_state_var`` finds the struct, and
  ``_is_pause_typed`` rejects it because the STRUCT is not a bool.
* **ERC-7201 namespaced slot** -- the EtherFi ``Pausable`` base and OZ-v5
  ``PausableUpgradeable`` reach the flag through a local storage pointer whose
  slot is assembly-assigned, so it is not in ``contract.state_variables`` at
  all and no writer is ever indexed.

The claims matcher already resolves both through member-path facts, so the
summary reads it instead of re-deriving it.

**The bitmap exclusion is structural, not a name list.** EigenLayer's
``pause(uint256 newPausedStatus)`` assigns the new bitmap from a *parameter*,
so the matcher's toggle polarity is never a definite constant bool and it fails
closed. Measured: 0 of the 8 local bitmap contracts mint a ``pause.*`` claim,
and their 24 ``effective_functions`` rows are inert
(``status`` NULL, ``authority_public`` false, ``effect_labels`` [], 0 claims).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import attach_claims_to_effects, build_claims, project_effect_labels  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _detect_pausability,
    _pause_claims,
)


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

# EigenLayer `Pausable`, reduced to the shape that matters and kept in an
# abstract base with a `private` flag, which is how the real one is written:
# a uint256 bitmap assigned from a PARAMETER, plus the `pauseAll()` alias.
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
    """POSITIVE CONTROL. ``accountantState.isPaused`` in the corpus; 7
    contracts move on this shape alone."""
    result, effects = _analyse(tmp_path, STRUCT_MEMBER_LATCH)
    assert result["is_pausable"] is True
    assert "state.isPaused" in result["pause_variables"], result["pause_variables"]
    assert "pause()" in result["pause_functions"]
    assert "unpause()" in result["unpause_functions"]
    # The widening's own input, so a later matcher change that silently stops
    # minting the claim fails here rather than quietly reverting the column.
    assert _pause_claims(effects) == ({"pause()"}, {"unpause()"}, {"state.isPaused"})


def test_bitmap_pause_family_is_not_widened_into(tmp_path):
    """NEGATIVE CONTROL, and the leg's hard ordering constraint: the bitmap
    family must not start publishing a pause capability before A7 can bound the
    duration. The exclusion is a property of the evidence -- the new bitmap
    comes from a parameter, so no definite constant-bool toggle exists -- not a
    contract-name or signature list."""
    result, effects = _analyse(tmp_path, BITMAP_LATCH)
    assert _pause_claims(effects) == (set(), set(), set()), "the widening's input must be empty here"
    assert result["is_pausable"] is False, result
    assert result["pause_functions"] == []
    assert result["unpause_functions"] == []


def test_struct_member_latch_is_not_determined_when_only_the_claims_stage_raised(tmp_path):
    """R1 on the POSITIVE control, in the degradation that a populated
    ``functions`` map cannot distinguish.

    ``core`` runs ``build_effects`` (``core.py:225-235``) and the claims block
    (``:243-253``) under separate ``try``/``except``. When only the claims
    block raises, the effects map is complete and claim-free — and this
    contract, which demonstrably HAS a latch, is invisible to every other
    detector (``PauseInfo`` is empty on it by construction). ``False`` there is
    a proven absence of a latch that exists."""
    path = tmp_path / "C.sol"
    path.write_text(textwrap.dedent(STRUCT_MEMBER_LATCH).strip() + "\n")
    contract = next(c for c in Slither(str(path)).contracts if c.name == "C")
    _trees, pause_info = build_predicate_artifacts_with_pause_info(contract)
    claim_free = build_effects(contract)

    assert pause_info["pause_state_vars"] == [], "guard: the structural pass cannot see this latch"
    assert claim_free["functions"], "guard: the effects plane succeeded"
    assert all("claims" not in record for record in claim_free["functions"].values())
    assert _detect_pausability(contract, tmp_path, pause_info, claim_free)["is_pausable"] is None


def test_pauser_registry_shape_stays_clean(tmp_path):
    """NEGATIVE CONTROL. Naming a pauser is not being pausable."""
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
        # The leg's own POSITIVE control: only the claims matcher can see it.
        pytest.param("struct_member", STRUCT_MEMBER_LATCH, id="struct_member"),
        # The *structural* family, which the claims matcher is not the only
        # route to — it goes blind here anyway, because the pass that produces
        # ``PauseInfo`` lives inside the same degraded stage.
        pytest.param("classic", CLASSIC_PAUSABLE, id="classic"),
    ],
)
def test_is_pausable_is_not_determined_when_the_trees_stage_raised(tmp_path, monkeypatch, label, source):
    """R1 end-to-end on the THIRD independently degradable plane, through the
    real ``core`` path rather than a hand-built input.

    ``core.py:206-221`` catches the predicate-trees stage on its own,
    substitutes ``{"schema_version": "semantic", "error": ...}`` and an empty
    ``PauseInfo``, and carries on. Nothing downstream raises: ``build_claims``
    runs on the stub, ``attach_claims_to_effects``
    (``services/static/claims/builder.py:79-81``) writes ``claims`` onto every
    record, and the claims-key discriminator answers True. Because
    ``apply_reentrancy_pause_pass`` lives *inside* that same stage
    (``predicate_artifacts.py:383``), the structural detector is blind too —
    so on a trees degradation ``false`` was published on 100% of pausable
    contracts, of both families.

    The healthy arm runs first and must say ``True``, so a fixture that
    silently stopped being pausable cannot make this test vacuous."""
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

    # The trap, asserted rather than assumed: the claims plane looks healthy.
    assert isinstance(trees_artifact, dict) and isinstance(effects_artifact, dict)
    assert "error" in trees_artifact, "guard: the trees stage must actually have degraded"
    assert any("claims" in record for record in (effects_artifact.get("functions") or {}).values()), (
        "guard: the claims key is written anyway — that is why it cannot be the only discriminator"
    )

    assert degraded["pausability"]["is_pausable"] is None, degraded["pausability"]
