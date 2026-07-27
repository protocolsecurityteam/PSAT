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
    """``(contract, pause_info, effects_with_claims, effects_without_claims)``.

    The two artifacts are the two things ``core`` can hand ``_detect_pausability``
    when nothing raises vs when only the claims block raises: identical
    ``functions`` maps, one carrying the ``claims`` key and one not."""
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
    return contract, pause_info, with_claims, build_effects(contract)


def test_detect_pausability_empty_when_no_pause(tmp_path):
    """R4 positive arm for the un-hedged ``False``: no pause shape and BOTH
    detectors ran → proven absence.

    The effects artifact is passed **with claims attached**, because the claims
    matcher is the thing that proves it; passing a claim-free artifact would
    pin ``False`` on an input where the discriminating evidence was never
    computed (and, since the fix, would answer ``None``)."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, with_claims, _ = _pause_inputs(tmp_path, _NO_PAUSE)
    pausability = _detect_pausability(contract, tmp_path, pause_info, with_claims)
    assert pausability["is_pausable"] is False
    assert pausability["pause_variables"] == []


def test_detect_pausability_is_not_determined_without_the_claims_plane(tmp_path):
    """R1/R2: three ways ``core`` reaches ``_detect_pausability`` without the
    claims matcher having run, all of which must answer not-determined.

    The third is the one a populated-``functions`` test cannot see: ``core``
    runs ``build_effects`` (``core.py:225-235``) and the claims block
    (``:243-250``) under separate ``try``/``except``. When only the claims
    block raises, every function record is present and every record is
    claim-free — so "the effects map is non-empty" is not evidence that the
    only detector able to see a struct-member latch ever looked."""
    from services.static.contract_analysis_pipeline.summaries import _detect_pausability

    contract, pause_info, _, claim_free = _pause_inputs(tmp_path, _NO_PAUSE)
    degraded = {"schema_version": "semantic", "error": "boom"}
    assert _detect_pausability(contract, tmp_path, pause_info, degraded)["is_pausable"] is None
    assert _detect_pausability(contract, tmp_path, pause_info, None)["is_pausable"] is None
    # The claims stage raised; the effects map is fully populated.
    assert claim_free["functions"], "guard: this arm is only meaningful on a populated map"
    assert all("claims" not in record for record in claim_free["functions"].values())
    assert _detect_pausability(contract, tmp_path, pause_info, claim_free)["is_pausable"] is None
