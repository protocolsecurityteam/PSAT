"""Tests for ReentrancyAnalyzer + PauseAnalyzer.

Validates the structural detection rules don't depend on identifier
names (so a renamed-equivalent contract classifies the same way as
the canonical OZ source)."""

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


# ---------------------------------------------------------------------------
# ReentrancyAnalyzer
# ---------------------------------------------------------------------------


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
    """Renamed-equivalent contract: same structural pattern, different
    identifier names. Detection must be name-free."""
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


# ---------------------------------------------------------------------------
# PauseAnalyzer
# ---------------------------------------------------------------------------


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
    """Renamed pattern: pause var is `flag`, modifier `gate`, admin
    function `freeze`. Detection name-free."""
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
    """A bool toggled by anyone isn't a pause flag — needs an
    auth-gated writer."""
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


# ---------------------------------------------------------------------------
# Apply pass: leaves get reclassified
# ---------------------------------------------------------------------------


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
    # The leaf reads _status (via the modifier require) and should
    # now be classified as reentrancy.
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
# Regression pin: a function with BOTH an external-role check and a pause
# check in the same require chain must keep the role-check leaf's authority
# (delegated_authority for hasRole(role, sender)) and produce a SEPARATE
# pause leaf. PauseAnalyzer only mutates leaves whose authority_role is
# 'business' or unset, so the role leaf survives. Confirmed on EtherFi
# LiquidityPool's pauseContract; pinned here in case the analyzer's guard
# clause ever loosens.
#
# The corresponding EtherFi-visible regression (target_address / selector
# null on the resolved external_check_only capability) lives downstream in
# the resolver and is covered by the indexed-event test in
# test_capability_resolver.py.
# ---------------------------------------------------------------------------


def test_pause_does_not_clobber_sibling_role_check(tmp_path):
    """The function carries TWO require statements: one external-role
    check, one pause check. The resulting tree must keep the role-check
    leaf (authority_role='caller_authority' / 'delegated_authority',
    not 'pause') and surface the pause as a condition."""
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
    # Use the most-derived contract (the inheriting one), not the interface
    # which Slither also returns.
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_trees(contract)
    apply_reentrancy_pause_pass(contract, trees)
    leaves = _all_leaves(trees["pauseContract()"])
    assert leaves, "expected at least one leaf for pauseContract"
    # At least one leaf retains the role-check authority (not overwritten to
    # 'pause'). 'business' is also a regression — the role check should
    # surface as some flavor of caller/delegated authority.
    auth_leaves = [leaf for leaf in leaves if leaf["authority_role"] in ("caller_authority", "delegated_authority")]
    assert auth_leaves, (
        f"role-check leaf was clobbered or dropped — got authority_roles={[leaf['authority_role'] for leaf in leaves]}"
    )


# ---------------------------------------------------------------------------
# A.4 — apply_reentrancy_pause_pass returns PauseInfo
# ---------------------------------------------------------------------------


def test_apply_pass_returns_pause_info_for_canonical_pause(tmp_path):
    """apply_reentrancy_pause_pass returns a PauseInfo dict; the OZ
    Pausable shape produces non-empty pause state vars + toggle list.
    """
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
    # Both pause/unpause functions should appear in the toggle list
    # (PauseAnalyzer admits the var since one writer is auth-gated;
    # _build_pause_info enumerates all writers).
    assert "pause()" in pause_info["pause_toggle_functions"]
    assert "unpause()" in pause_info["pause_toggle_functions"]


def test_apply_pass_returns_pause_info_for_canonical_reentrancy(tmp_path):
    """apply_reentrancy_pause_pass returns a PauseInfo dict; OZ
    ReentrancyGuard's ``_status`` shape populates the reentrancy
    fields."""
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
    """No pause / reentrancy vars → all four lists empty."""
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


# ---------------------------------------------------------------------------
# A.4 — _detect_pausability consumes PauseInfo
# ---------------------------------------------------------------------------


def test_detect_pausability_consumes_pause_info(tmp_path):
    """_detect_pausability now takes a ``pause_info`` dict and surfaces
    the structural pause vars + toggle functions without relying on
    modifier names."""
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
    # whenNotPaused reads _paused → it's a structural gating modifier.
    assert "whenNotPaused" in pausability["gating_modifiers"]


def test_detect_pausability_renamed_pause_modifier(tmp_path):
    """A non-standard modifier name still gets surfaced as gating because
    it READS the pause var."""
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
    # ``gate`` is a structural pause-reader → gating_modifier.
    assert "gate" in pausability["gating_modifiers"]


_NO_PAUSE = """
    pragma solidity ^0.8.19;
    contract C {
        uint256 public x;
        function f() external { x = 1; }
    }
"""


def _pause_inputs(tmp_path: Path, source: str):
    """``(contract, pause_info, trees_artifact, effects_with_claims, effects_without_claims)``.

    The two effects artifacts are what ``core`` can hand ``_detect_pausability``
    when nothing raises vs when only the claims block raises: identical
    ``functions`` maps, one carrying the ``claims`` key and one not.
    ``trees_artifact`` is the third, independently degradable input."""
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
    """R4 positive arm for the un-hedged ``False``: no pause shape and ALL
    THREE planes ran → proven absence.

    The effects artifact is passed **with claims attached** and the real trees
    artifact alongside it, because those are the two things that prove the
    detectors could see: passing either degraded input would pin ``False`` on
    a run where the discriminating evidence was never computed (and, since the
    fix, answers ``None``)."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _NO_PAUSE)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is False
    assert pausability["pause_variables"] == []


def test_detect_pausability_is_not_determined_without_the_claims_plane(tmp_path):
    """R1/R2: three ways ``core`` reaches ``_detect_pausability`` without the
    claims matcher having run, all of which must answer not-determined.

    The third is the one a populated-``functions`` test cannot see: ``core``
    runs ``build_effects`` (``core.py:225-235``) and the claims block
    (``:243-253``) under separate ``try``/``except``. When only the claims
    block raises, every function record is present and every record is
    claim-free — so "the effects map is non-empty" is not evidence that the
    only detector able to see a struct-member latch ever looked."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, _, claim_free = _pause_inputs(tmp_path, _NO_PAUSE)
    degraded = {"schema_version": "semantic", "error": "boom"}
    assert _detect_pausability(contract, tmp_path, pause_info, degraded, trees)["is_pausable"] is None
    assert _detect_pausability(contract, tmp_path, pause_info, None, trees)["is_pausable"] is None
    # The claims stage raised; the effects map is fully populated.
    assert claim_free["functions"], "guard: this arm is only meaningful on a populated map"
    assert all("claims" not in record for record in claim_free["functions"].values())
    assert _detect_pausability(contract, tmp_path, pause_info, claim_free, trees)["is_pausable"] is None


def test_detect_pausability_is_not_determined_without_the_trees_plane(tmp_path):
    """R1/R2 on the THIRD independently degradable plane.

    ``core.py:206-221`` catches the trees stage on its own and substitutes
    ``{"schema_version": "semantic", "error": ...}`` plus an empty
    ``PauseInfo``. Downstream nothing raises: ``build_claims`` runs on the
    stub and ``attach_claims_to_effects`` still writes ``claims`` on every
    record, so the claims-key discriminator answers True while BOTH pause
    detectors were blind. ``None`` is the only honest verdict.

    The shapes here are the two ways that input can arrive wrong — the stub
    ``core`` actually builds, and an omitted argument."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, _pause_info, _trees, with_claims, _ = _pause_inputs(tmp_path, _NO_PAUSE)
    degraded_trees = {"schema_version": "semantic", "error": "boom"}
    empty_pause_info = {
        "pause_state_vars": [],
        "pause_toggle_functions": [],
        "reentrancy_state_vars": [],
        "reentrancy_guarded_functions": [],
    }
    # Guard: the claims plane looks healthy, which is exactly the trap.
    assert with_claims["functions"], "guard: this arm is only meaningful on a populated map"
    assert any("claims" in record for record in with_claims["functions"].values())

    assert _detect_pausability(contract, tmp_path, empty_pause_info, with_claims, degraded_trees)["is_pausable"] is None
    assert _detect_pausability(contract, tmp_path, empty_pause_info, with_claims, None)["is_pausable"] is None


# ---------------------------------------------------------------------------
# Latch shape — a pause var is a FLAG, not a governed quantity
# ---------------------------------------------------------------------------

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
    """OZ TimelockController's ``uint256 _minDelay`` matches the
    written-by-auth + read-with-revert fingerprint (``updateDelay`` is
    self-gated; ``schedule`` reverts on insufficient delay) but is a governed
    DURATION, not a latch. Classifying it as one published
    ``is_pausable=true`` on two mainnet TimelockControllers with no pause
    mechanism at all (PR-161 contracts 471/554, chain-refuted:
    ``paused()`` reverts, ``getMinDelay()`` returns a duration)."""
    sl = _compile(tmp_path, _TIMELOCK_MIN_DELAY)
    contract = next(c for c in sl.contracts if c.name == "TL")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == set()

    pause_info = apply_reentrancy_pause_pass(contract, trees)
    assert pause_info["pause_state_vars"] == []
    assert pause_info["pause_toggle_functions"] == []
    # The comparison leaves reading _minDelay must not be promoted to the
    # pause authority role either.
    for tree in trees.values():
        for leaf in _all_leaves(tree):
            assert leaf.get("authority_role") != "pause"


def test_timelock_min_delay_detect_pausability_false_end_to_end(tmp_path):
    """With all three planes demonstrably run, the timelock publishes the
    affirmative ``is_pausable=False`` — not ``true`` (the refuted claim) and
    not ``None`` (the planes did run)."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _TIMELOCK_MIN_DELAY)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is False
    assert pausability["pause_variables"] == []
    assert pausability["pause_functions"] == []
    assert pausability["unpause_functions"] == []


def test_uint_latch_with_gating_modifier_still_detected(tmp_path):
    """R4 positive control for the latch-shape narrowing: the EigenLayer
    shape — ``uint256 _paused`` written from a PARAMETER (no constant
    toggle) but read by a gating modifier — is a real latch and must keep
    detecting after ``_minDelay`` is rejected."""
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
    """R4 positive control: a uint flag toggled by CONSTANT writes
    (``stopped = 1`` / ``stopped = 0``) with the revert read in a function
    body (no modifier) is a latch."""
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
    """EigenLayer Pausable shape: the modifier's require reads the latch
    THROUGH a helper (``require(!paused(index))`` with the ``_paused`` read
    inside ``paused(index)``). Before the helper hop the real latch was
    invisible, and EigenStrategy's ``is_pausable=true`` rode entirely on a
    fabricated ``totalShares`` quantity latch (PR-161 contract 635)."""
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
    # The real latch is admitted; the quantity var is not (it is written
    # from computed values and gates nothing through a modifier).
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
    """R4 positive control for the third flag-evidence arm: a uint latch
    that is PARAMETER-written (no constant toggle) and gated by an INLINE
    ``require(pausedStatus == 0)`` in ordinary function bodies (no
    modifier) satisfies neither of the first two arms — dropping it
    published the affirmative ``is_pausable=False`` on a genuinely
    pausable contract. The equality-vs-CONSTANT revert read is the flag
    evidence: ``_minDelay``'s revert read is relational against a
    parameter and stays out (the two tests above)."""
    sl = _compile(tmp_path, _UINT_INLINE_LATCH)
    contract = next(c for c in sl.contracts if c.name == "UInline")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"pausedStatus"}


def test_uint_latch_parameter_written_inline_require_publishes_true(tmp_path):
    """End-to-end on the published surface: all three planes run and the
    inline uint latch publishes the affirmative ``is_pausable=True`` —
    not ``False`` (a proven-absence claim the detector cannot make here)
    and not ``None``."""
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
    """R4 positive control: the mainstream post-0.8.4 gate shape
    ``if (pausedFlag != 0) revert Paused();`` — the revert lives in a
    SEPARATE node from the comparison, so a same-node IR scan never sees
    both together. The predicate builder polarity-folds the if/revert
    gate into an ``eq``-vs-constant leaf, which is where the flag test
    must look."""
    sl = _compile(tmp_path, _UINT_CUSTOM_ERROR_LATCH)
    contract = next(c for c in sl.contracts if c.name == "CE")
    trees = _build_trees(contract)
    assert PauseAnalyzer(contract, trees).run() == {"pausedFlag"}


def test_uint_latch_custom_error_if_revert_publishes_true(tmp_path):
    """End-to-end on the published surface for the custom-error shape:
    ``is_pausable=True`` with the latch var — not the fabricated
    proven-absence ``False``."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, trees, with_claims, _ = _pause_inputs(tmp_path, _UINT_CUSTOM_ERROR_LATCH)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims, trees)
    assert pausability["is_pausable"] is True
    assert pausability["pause_variables"] == ["pausedFlag"]
    assert "setPaused(uint8)" in pausability["pause_functions"]


def test_uint_latch_read_through_getter_inline_detected(tmp_path):
    """R4 positive control: the revert read reaches the latch through a
    GETTER (``require(pausedStatus() == 0)`` with ``_paused`` read inside
    the getter, no modifier anywhere). The leaf plane resolves the hop to
    the underlying state var; the same-node IR scan sees only a TMP."""
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
    """R4 positive control: bit-mask latch read inline in a function body
    (``require(_paused & 1 == 0)``, no modifier). The equality's direct
    operand is the mask TMP, not the var — the leaf plane folds the
    arithmetic and pairs the var with the constant."""
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
