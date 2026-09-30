"""Structural detection must not depend on identifier names."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.contract_analysis_pipeline.reentrancy_pause import (  # noqa: E402
    PauseAnalyzer,
    ReentrancyAnalyzer,
    apply_reentrancy_pause_pass,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _build_trees(contract):
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    return trees


def _all_leaves(tree):
    if tree is None:
        return []
    if tree.get("op") == "LEAF":
        return [tree["leaf"]] if tree.get("leaf") else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_all_leaves(child))
    return out


def test_canonical_oz_reentrancy_guard_detected(tmp_path):
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
        }
    """,
    )
    contract = sl.contracts[0]
    guards = ReentrancyAnalyzer(contract).run()
    assert "_status" in guards


def test_renamed_reentrancy_guard_detected(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 private _foo;
            uint256 private constant _A = 1;
            uint256 private constant _B = 2;
            modifier myModifier() {
                require(_foo != _B);
                _foo = _B;
                _;
                _foo = _A;
            }
            function f() external myModifier {}
        }
    """,
    )
    contract = sl.contracts[0]
    guards = ReentrancyAnalyzer(contract).run()
    assert "_foo" in guards


def test_no_reentrancy_pattern_returns_empty(tmp_path):
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
    guards = ReentrancyAnalyzer(contract).run()
    assert guards == set()


def test_canonical_oz_pause_detected(tmp_path):
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
            function someAction() external whenNotPaused {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    pause_vars = PauseAnalyzer(contract, trees).run()
    assert "_paused" in pause_vars


def test_renamed_pause_detected(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            bool public flag;
            modifier gate() {
                require(!flag);
                _;
            }
            function freeze() external {
                require(msg.sender == ownerVar);
                flag = true;
            }
            function someAction() external gate {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    pause_vars = PauseAnalyzer(contract, trees).run()
    assert "flag" in pause_vars


def test_unauth_writer_does_not_trigger_pause(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            bool public _paused;
            function pause() external { _paused = true; }
            function someAction() external view {
                require(!_paused);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    pause_vars = PauseAnalyzer(contract, trees).run()
    assert pause_vars == set()


def test_apply_pass_classifies_reentrancy_leaf(tmp_path):
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
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_reentrancy_pause_pass(contract, trees)
    leaves = _all_leaves(trees["f()"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["authority_role"] == "reentrancy", leaf


def test_apply_pass_classifies_pause_leaf(tmp_path):
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
            function someAction() external whenNotPaused {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_reentrancy_pause_pass(contract, trees)
    leaves = _all_leaves(trees["someAction()"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["authority_role"] == "pause", leaf


# ---------------------------------------------------------------------------
# Regression pin: a function with BOTH a role check and a pause check in the same require
# chain must keep the role leaf's authority and add a SEPARATE pause leaf (confirmed on
# EtherFi LiquidityPool.pauseContract). The downstream target_address/selector-null
# regression is covered in tests/resolution/test_capability_resolver.py.
# ---------------------------------------------------------------------------


def test_pause_does_not_clobber_sibling_role_check(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IRoleRegistry {
            function hasRole(bytes32 role, address account) external view returns (bool);
        }
        contract C {
            IRoleRegistry public roleRegistry;
            bool public _paused;
            bytes32 public constant PAUSER_ROLE = keccak256("PAUSER");
            constructor(address rr) { roleRegistry = IRoleRegistry(rr); }
            function pauseContract() external {
                require(roleRegistry.hasRole(PAUSER_ROLE, msg.sender), "no pauser");
                require(!_paused, "paused");
                _paused = true;
            }
        }
    """,
    )
    # Slither also returns the interface.
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_trees(contract)
    apply_reentrancy_pause_pass(contract, trees)
    leaves = _all_leaves(trees["pauseContract()"])
    assert leaves, "expected at least one leaf for pauseContract"
    auth_leaves = [leaf for leaf in leaves if leaf["authority_role"] in ("caller_authority", "delegated_authority")]
    assert auth_leaves, (
        f"role-check leaf was clobbered or dropped — got authority_roles={[leaf['authority_role'] for leaf in leaves]}"
    )


def test_apply_pass_returns_pause_info_for_canonical_pause(tmp_path):
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
    assert pause_info is not None
    assert "_paused" in pause_info["pause_state_vars"]
    assert "pause()" in pause_info["pause_toggle_functions"]
    assert "unpause()" in pause_info["pause_toggle_functions"]


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


def test_detect_pausability_renamed_pause_modifier(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            bool public flag;
            modifier gate() {
                require(!flag);
                _;
            }
            function freeze() external {
                require(msg.sender == ownerVar);
                flag = true;
            }
            function someAction() external gate {}
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    pause_info = apply_reentrancy_pause_pass(contract, trees)
    pausability = _detect_pausability(contract, tmp_path, pause_info)
    assert pausability["is_pausable"] is True
    assert "flag" in pausability["pause_variables"]
    assert "gate" in pausability["gating_modifiers"]


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


def test_detect_pausability_empty_when_no_pause(tmp_path):
    """R4: either degraded input would pin ``False`` on a run that never computed the evidence."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _NO_PAUSE)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is False
    assert pausability["pause_variables"] == []


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


def test_timelock_min_delay_is_not_a_pause_latch(tmp_path):
    """``_minDelay`` matches the auth-written, revert-read fingerprint but is a duration; it published
    ``is_pausable=true`` on two chain-refuted TimelockControllers (PR-161 contracts 471/554).
    """
    sl = _compile(tmp_path, _TIMELOCK_MIN_DELAY)
    contract = next(c for c in sl.contracts if c.name == "TL")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == set()

    pause_info = apply_reentrancy_pause_pass(contract, trees)
    assert pause_info["pause_state_vars"] == []
    assert pause_info["pause_toggle_functions"] == []
    for tree in trees.values():
        for leaf in _all_leaves(tree):
            assert leaf.get("authority_role") != "pause"


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


def test_modifier_hosted_relational_bound_is_not_a_latch(tmp_path):
    """Otherwise ``updateDelay`` publishes as both pause and unpause."""
    sl = _compile(tmp_path, _MODIFIER_RELATIONAL_BOUND)
    contract = next(c for c in sl.contracts if c.name == "Timelock2")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == set()


def test_modifier_hosted_relational_bound_publishes_false_end_to_end(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _MODIFIER_RELATIONAL_BOUND)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is False
    assert pausability["pause_variables"] == []
    assert pausability["pause_functions"] == []
    assert pausability["unpause_functions"] == []


def test_modifier_hosted_relational_bound_inherited_variant(tmp_path):
    for vis in ("private", "internal"):
        sl = _compile(
            tmp_path,
            f"""
            pragma solidity ^0.8.19;
            abstract contract DelayBase {{
                uint256 {vis} _minDelay;
                address public admin;
                function updateDelay(uint256 d) external {{ require(msg.sender == admin, "no"); _minDelay = d; }}
                function getMinDelay() public view returns (uint256) {{ return _minDelay; }}
                modifier respectsDelay(uint256 delay) {{ require(delay >= _minDelay, "insufficient delay"); _; }}
            }}
            contract Timelock is DelayBase {{
                mapping(bytes32 => uint256) public timestamps;
                function schedule(bytes32 id, uint256 delay) external respectsDelay(delay) {{
                    timestamps[id] = block.timestamp + delay;
                }}
            }}
        """,
        )
        contract = next(c for c in sl.contracts if c.name == "Timelock")
        trees = _build_trees(contract)
        assert PauseAnalyzer(contract, trees).run() == set(), vis


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


_UINT_INLINE_LATCH = """
pragma solidity ^0.8.19;
contract UInline {
    address public owner;
    uint256 private pausedStatus;
    function setPaused(uint256 p) external { require(msg.sender == owner, "no"); pausedStatus = p; }
    function act(uint256 v) external { require(pausedStatus == 0, "paused"); }
    function act2(uint256 v) external { require(pausedStatus == 0, "paused"); }
}
"""


def test_uint_latch_parameter_written_inline_require_detected(tmp_path):
    """The equality-vs-constant read is the flag evidence; ``_minDelay``'s relational read stays out."""
    sl = _compile(tmp_path, _UINT_INLINE_LATCH)
    contract = next(c for c in sl.contracts if c.name == "UInline")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"pausedStatus"}


def test_uint_latch_parameter_written_inline_require_publishes_true(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _UINT_INLINE_LATCH)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is True
    assert pausability["pause_variables"] == ["pausedStatus"]
    assert "setPaused(uint256)" in pausability["pause_functions"]


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


def test_uint_latch_custom_error_if_revert_detected(tmp_path):
    """The revert is in a separate node, so the flag test reads the polarity-folded leaf."""
    sl = _compile(tmp_path, _UINT_CUSTOM_ERROR_LATCH)
    contract = next(c for c in sl.contracts if c.name == "CE")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"pausedFlag"}


def test_uint_latch_custom_error_if_revert_publishes_true(tmp_path):
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _UINT_CUSTOM_ERROR_LATCH)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is True
    assert pausability["pause_variables"] == ["pausedFlag"]
    assert "setPaused(uint8)" in pausability["pause_functions"]


def test_uint_latch_read_through_getter_inline_detected(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract G {
            address public admin;
            uint256 private _paused;
            function pausedStatus() public view returns (uint256) { return _paused; }
            function setPaused(uint256 s) external { require(msg.sender == admin, "no"); _paused = s; }
            function act() external { require(pausedStatus() == 0, "paused"); }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "G")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"_paused"}


def test_uint_latch_inline_mask_no_modifier_detected(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract IM {
            address public pauser;
            uint256 private _paused;
            function pause(uint256 s) external { require(msg.sender == pauser, "no"); _paused = s; }
            function deposit() external { require(_paused & 1 == 0, "paused"); }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "IM")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"_paused"}


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


def test_private_latch_declared_in_abstract_base_publishes_true(tmp_path):
    from services.static.contract_analysis_pipeline.predicate_artifacts import (
        build_predicate_artifacts_with_pause_info,
    )
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    sl = _compile(tmp_path, _PRIVATE_BASE_LATCH)
    contract = next(c for c in sl.contracts if c.name == "DerivedStrategy")
    trees_artifact, pause_info = build_predicate_artifacts_with_pause_info(contract)
    pausability = _detect_pausability(contract, tmp_path, pause_info, None, trees_artifact)
    assert pausability["is_pausable"] is True
    assert pausability["pause_variables"] == ["_paused"]
    assert "pause(uint256)" in pausability["pause_functions"] or "pause(uint256)" in pausability["unpause_functions"]
