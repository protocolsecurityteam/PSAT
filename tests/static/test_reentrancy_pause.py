"""Structural detection must not depend on identifier names."""

from __future__ import annotations

from pathlib import Path

import pytest

slither = pytest.importorskip("slither")

from services.static.contract_analysis_pipeline.reentrancy_pause import (  # noqa: E402
    PauseAnalyzer,
    apply_reentrancy_pause_pass,
)
from tests.support.predicate_trees import _build_trees  # noqa: E402
from tests.support.slither_compile import _compile  # noqa: E402

# ---------------------------------------------------------------------------
# Regression pin: a function with BOTH a role check and a pause check in the same require
# chain must keep the role leaf's authority and add a SEPARATE pause leaf (confirmed on
# EtherFi LiquidityPool.pauseContract). The downstream target_address/selector-null
# regression is covered in tests/resolution/test_capability_resolver.py.
# ---------------------------------------------------------------------------


def test_apply_pass_returns_pause_info_for_canonical_reentrancy(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 private _status;
            uint256 private constant _NOT_ENTERED = 1;
            uint256 private constant _ENTERED = 2;
            modifier nonReentrant() {
                require(_status != _ENTERED);
                _status = _ENTERED;
                _;
                _status = _NOT_ENTERED;
            }
            function f() external nonReentrant {}
            function g() external nonReentrant {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    pause_info = apply_reentrancy_pause_pass(contract, trees)
    assert "_status" in pause_info["reentrancy_state_vars"]
    assert {"f()", "g()"}.issubset(set(pause_info["reentrancy_guarded_functions"]))


def test_apply_pass_returns_empty_pause_info_when_nothing_detected(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f() external { x = 1; }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    pause_info = apply_reentrancy_pause_pass(contract, trees)
    assert pause_info["pause_state_vars"] == []
    assert pause_info["pause_toggle_functions"] == []
    assert pause_info["reentrancy_state_vars"] == []
    assert pause_info["reentrancy_guarded_functions"] == []


def test_detect_pausability_consumes_pause_info(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            bool public _paused;
            modifier whenNotPaused() {
                require(!_paused);
                _;
            }
            function pause() external {
                require(msg.sender == ownerVar);
                _paused = true;
            }
            function unpause() external {
                require(msg.sender == ownerVar);
                _paused = false;
            }
            function someAction() external whenNotPaused {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    pause_info = apply_reentrancy_pause_pass(contract, trees)
    pausability = _detect_pausability(contract, tmp_path, pause_info)
    assert pausability["is_pausable"] is True
    assert "_paused" in pausability["pause_variables"]
    assert "pause()" in pausability["pause_functions"]
    assert "unpause()" in pausability["unpause_functions"]
    assert "whenNotPaused" in pausability["gating_modifiers"]


_NO_PAUSE = """
    pragma solidity ^0.8.19;
    contract C {
        uint256 public x;
        function f() external { x = 1; }
    }
"""


def _pause_inputs(tmp_path: Path, source: str):
    """What ``core`` hands ``_detect_pausability`` when nothing raises vs when only claims raises; trees are the
    third degradable input.
    """
    from services.static.claims import attach_claims_to_effects, build_claims, project_effect_labels
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.predicate_artifacts import (
        build_predicate_artifacts_with_pause_info,
    )

    contract = _compile(tmp_path, source).contracts[0]
    trees_artifact, pause_info = build_predicate_artifacts_with_pause_info(contract)
    with_claims = build_effects(contract)
    attach_claims_to_effects(with_claims, build_claims(contract, with_claims, trees_artifact))
    project_effect_labels(with_claims)
    return contract, pause_info, trees_artifact, with_claims, build_effects(contract)


def test_detect_pausability_is_not_determined_without_the_claims_plane(tmp_path):
    """R1/R2: ``core`` runs effects and claims under separate try/except, so a claims failure leaves every record
    present but claim-free.
    """
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, _, claim_free = _pause_inputs(tmp_path, _NO_PAUSE)
    degraded = {"schema_version": "semantic", "error": "boom"}
    assert _detect_pausability(contract, tmp_path, pause_info, degraded, trees)["is_pausable"] is None
    assert _detect_pausability(contract, tmp_path, pause_info, None, trees)["is_pausable"] is None
    assert claim_free["functions"], "guard: this arm is only meaningful on a populated map"
    assert all("claims" not in record for record in claim_free["functions"].values())
    assert _detect_pausability(contract, tmp_path, pause_info, claim_free, trees)["is_pausable"] is None


def test_detect_pausability_is_not_determined_without_the_trees_plane(tmp_path):
    """``core.py`` substitutes an empty ``PauseInfo`` when the trees stage fails, so the claims discriminator says
    True while both detectors were blind.
    """
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, _pause_info, _trees, with_claims, _ = _pause_inputs(tmp_path, _NO_PAUSE)
    degraded_trees = {"schema_version": "semantic", "error": "boom"}
    empty_pause_info = {
        "pause_state_vars": [],
        "pause_toggle_functions": [],
        "reentrancy_state_vars": [],
        "reentrancy_guarded_functions": [],
    }
    assert with_claims["functions"], "guard: this arm is only meaningful on a populated map"
    assert any("claims" in record for record in with_claims["functions"].values())

    assert _detect_pausability(contract, tmp_path, empty_pause_info, with_claims, degraded_trees)["is_pausable"] is None
    assert _detect_pausability(contract, tmp_path, empty_pause_info, with_claims, None)["is_pausable"] is None


_TIMELOCK_MIN_DELAY = """
pragma solidity ^0.8.19;
contract TL {
    uint256 private _minDelay;
    mapping(bytes32 => uint256) private _timestamps;
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);
    constructor(uint256 minDelay) { _minDelay = minDelay; }
    function getMinDelay() public view returns (uint256) { return _minDelay; }
    function updateDelay(uint256 newDelay) external {
        require(msg.sender == address(this), "unauthorized");
        emit MinDelayChange(_minDelay, newDelay);
        _minDelay = newDelay;
    }
    function schedule(bytes32 id, uint256 delay) external {
        require(_timestamps[id] == 0, "exists");
        require(delay >= getMinDelay(), "insufficient delay");
        _timestamps[id] = block.timestamp + delay;
    }
}
"""


def test_timelock_min_delay_detect_pausability_false_end_to_end(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _TIMELOCK_MIN_DELAY)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is False
    assert pausability["pause_variables"] == []
    assert pausability["pause_functions"] == []
    assert pausability["unpause_functions"] == []


_MODIFIER_RELATIONAL_BOUND = """
pragma solidity ^0.8.19;
contract Timelock2 {
    uint256 private _minDelay;
    address public admin;
    mapping(bytes32 => uint256) public timestamps;
    function updateDelay(uint256 d) external { require(msg.sender == admin, "no"); _minDelay = d; }
    function getMinDelay() public view returns (uint256) { return _minDelay; }
    modifier respectsDelay(uint256 delay) { require(delay >= _minDelay, "insufficient delay"); _; }
    function schedule(bytes32 id, uint256 delay) external respectsDelay(delay) {
        timestamps[id] = block.timestamp + delay;
    }
}
"""


def test_modifier_hosted_relational_bound_publishes_false_end_to_end(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _MODIFIER_RELATIONAL_BOUND)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is False
    assert pausability["pause_variables"] == []
    assert pausability["pause_functions"] == []
    assert pausability["unpause_functions"] == []


def test_uint_latch_with_gating_modifier_still_detected(tmp_path):
    """R4: EigenLayer's parameter-written ``uint256 _paused``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract EP {
            address public pauser;
            uint256 private _paused;
            modifier onlyWhenNotPaused(uint8 index) {
                require(_paused & (1 << uint256(index)) == 0, "paused");
                _;
            }
            function pause(uint256 newPausedStatus) external {
                require(msg.sender == pauser, "not pauser");
                _paused = newPausedStatus;
            }
            function deposit() external onlyWhenNotPaused(0) {}
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "EP")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"_paused"}


def test_uint_constant_toggle_latch_still_detected(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract UT {
            address public admin;
            uint256 private stopped;
            function stop() external { require(msg.sender == admin); stopped = 1; }
            function start() external { require(msg.sender == admin); stopped = 0; }
            function act() external { require(stopped == 0, "stopped"); }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "UT")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"stopped"}


def test_uint_latch_read_through_helper_in_modifier_detected(tmp_path):
    """Without the helper hop, EigenStrategy's pausability rode on a fabricated ``totalShares`` latch (PR-161
    contract 635).
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract EPI {
            address public pauser;
            uint256 private _paused;
            uint256 public totalShares;
            function paused(uint8 index) public view returns (bool) {
                uint256 mask = 1 << uint256(index);
                return ((_paused & mask) == mask);
            }
            modifier onlyWhenNotPaused(uint8 index) {
                require(!paused(index), "paused");
                _;
            }
            function pause(uint256 newStatus) external {
                require(msg.sender == pauser, "not pauser");
                _paused = newStatus;
            }
            function pauseAll() external {
                require(msg.sender == pauser, "not pauser");
                _paused = type(uint256).max;
            }
            function deposit(uint256 shares) external onlyWhenNotPaused(0) {
                require(totalShares + shares >= shares, "overflow");
                totalShares += shares;
            }
            function withdraw(uint256 shares) external onlyWhenNotPaused(1) {
                require(totalShares >= shares, "insufficient");
                totalShares -= shares;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "EPI")
    trees = _build_trees(contract)
    detected = PauseAnalyzer(contract, trees).run()
    assert "_paused" in detected
    assert "totalShares" not in detected


_UINT_CUSTOM_ERROR_LATCH = """
pragma solidity ^0.8.19;
contract CE {
    error Paused();
    address public admin;
    uint8 private pausedFlag;
    function setPaused(uint8 s) external { require(msg.sender == admin, "no"); pausedFlag = s; }
    function act() external { if (pausedFlag != 0) revert Paused(); }
}
"""


def test_uint_latch_custom_error_if_revert_publishes_true(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _UINT_CUSTOM_ERROR_LATCH)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is True
    assert pausability["pause_variables"] == ["pausedFlag"]
    assert "setPaused(uint8)" in pausability["pause_functions"]


_PRIVATE_BASE_LATCH = """
pragma solidity ^0.8.19;
abstract contract BasePausable {
    address public pauser;
    uint256 private _paused;
    function paused(uint8 index) public view returns (bool) {
        uint256 mask = 1 << uint256(index);
        return ((_paused & mask) == mask);
    }
    modifier onlyWhenNotPaused(uint8 index) {
        require(!paused(index), "paused");
        _;
    }
    function pause(uint256 newStatus) external {
        require(msg.sender == pauser, "not pauser");
        _paused = newStatus;
    }
}

contract DerivedStrategy is BasePausable {
    uint256 public totalShares;
    function deposit(uint256 shares) external onlyWhenNotPaused(0) {
        require(totalShares + shares >= shares, "overflow");
        totalShares += shares;
    }
    function withdraw(uint256 shares) external onlyWhenNotPaused(1) {
        require(totalShares >= shares, "insufficient");
        totalShares -= shares;
    }
}
"""


def test_private_latch_declared_in_abstract_base_detected(tmp_path):
    """``contract.state_variables`` excludes private ancestor declarations while the writer index sees the writers,
    so the lookup must cover the inheritance chain (PR-161 contract 635).
    """
    sl = _compile(tmp_path, _PRIVATE_BASE_LATCH)
    contract = next(c for c in sl.contracts if c.name == "DerivedStrategy")
    trees = _build_trees(contract)
    detected = PauseAnalyzer(contract, trees).run()
    assert "_paused" in detected
    assert "totalShares" not in detected
