"""Tests that expose weaknesses in effect label detection.

Each test creates a minimal Solidity contract targeting a specific gap
in semantic effect label detection, runs the full static analysis
pipeline through Slither, and checks whether the expected effect labels
are present.

Tests that currently FAIL (labels are missed) are marked with
``pytest.mark.xfail`` — once we fix the detection, we flip them to pass.
"""

import sys
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from slither.slither import Slither

from services.static.claims import attach_claims_to_effects, build_claims, project_effect_labels
from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.shared import _select_subject_contract
from services.static.contract_analysis_pipeline.summaries import (
    _build_semantic_control_summary,
)


def _scaffold_and_analyze(solidity_source: str, contract_name: str = "Target") -> dict:
    """Write a Solidity file, run Slither directly on the .sol file, and analyze."""
    with tempfile.TemporaryDirectory(prefix="psat_test_effects_") as tmp:
        project_dir = Path(tmp)

        sol_path = project_dir / f"{contract_name}.sol"
        sol_path.write_text(solidity_source)

        # Slither on the .sol file directly
        slither = Slither(str(sol_path))
        subject = _select_subject_contract(slither, contract_name)
        if subject is None:
            raise RuntimeError(f"Contract {contract_name} not found")

        # Full production label sequence: facts -> Plane-1 claims -> projection.
        predicate_trees = build_predicate_artifacts(subject)
        effects = build_effects(subject)
        claims_artifact = build_claims(subject, effects, predicate_trees)
        attach_claims_to_effects(effects, claims_artifact)
        project_effect_labels(effects)
        semantic_control = _build_semantic_control_summary(subject, project_dir, predicate_trees, effects)

        return {"semantic_control": semantic_control, "effects": effects}


def _get_function_labels(analysis: dict, function_name: str) -> set[str]:
    """Extract effect_labels for a specific function from the analysis."""
    for pf in analysis.get("semantic_control", {}).get("semantic_functions", []):
        fn = pf.get("function", "")
        # Match by name prefix (before the parens)
        if fn.split("(")[0] == function_name:
            return set(pf.get("effect_labels", []))
    return set()


def _all_labels(analysis: dict) -> dict[str, set[str]]:
    """Return {function_name: set(labels)} for all semantic functions."""
    result = {}
    for pf in analysis.get("semantic_control", {}).get("semantic_functions", []):
        fn = pf.get("function", "").split("(")[0]
        result[fn] = set(pf.get("effect_labels", []))
    return result


# =========================================================================
# WEAKNESS 1: Non-standard naming for implementation slots
# The bespoke same-contract impl-slot dataflow detector is retired (0 firings
# on prod + both local samples). ``upgrade.implementation`` is standard-gated;
# a non-standard ``setLogic``/``_logic`` proxy pattern yields no upgrade claim,
# and the delegatecall remains a fact on the fallback.
# =========================================================================


def test_nonstandard_impl_slot_name():
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract Target {
            address private _logic;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            function setLogic(address newLogic) external onlyOwner {
                _logic = newLogic;
            }

            fallback() external payable {
                address impl = _logic;
                assembly {
                    calldatacopy(0, 0, calldatasize())
                    let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    returndatacopy(0, 0, returndatasize())
                    switch result
                    case 0 { revert(0, returndatasize()) }
                    default { return(0, returndatasize()) }
                }
            }
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, "setLogic")
    assert "implementation_update" not in labels, f"Expected NO implementation_update for setLogic, got: {labels}"
    assert "delegatecall_execution" in _get_function_labels(analysis, "fallback")


# =========================================================================
# WEAKNESS 2: Non-standard naming for pause variables
# Pause toggles should be found from guarded bool-state semantics, not
# from the state-variable name.
# =========================================================================


def test_nonstandard_pause_var_name():
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract Target {
            bool public stopped;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            modifier whenNotStopped() {
                require(!stopped, "stopped");
                _;
            }

            function emergencyStop() external onlyOwner {
                stopped = true;
            }

            function resume() external onlyOwner {
                stopped = false;
            }

            function deposit() external payable whenNotStopped {
                // business logic
            }
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels_stop = _get_function_labels(analysis, "emergencyStop")
    labels_resume = _get_function_labels(analysis, "resume")
    assert "pause_toggle" in labels_stop, f"Expected pause_toggle for emergencyStop, got: {labels_stop}"
    assert "pause_toggle" in labels_resume, f"Expected pause_toggle for resume, got: {labels_resume}"


# =========================================================================
# WEAKNESS 3: Value transfer via low-level call instead of safeTransfer
# Value transfer should be found from call/value semantics. Raw
# address.call{value:} must not require a helper-library spelling.
# =========================================================================


def test_raw_eth_transfer():
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract Target {
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            function sweep(address payable to) external onlyOwner {
                (bool ok,) = to.call{value: address(this).balance}("");
                require(ok, "transfer failed");
            }

            receive() external payable {}
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, "sweep")
    assert "asset_send" in labels, f"Expected asset_send for sweep (raw ETH transfer), got: {labels}"


# =========================================================================
# WEAKNESS 4: ERC20 transfer() instead of safeTransfer()
# Many contracts use IERC20(token).transfer() directly instead of
# SafeERC20.safeTransfer(). Direct ERC20 calls should classify from the
# called selector as asset movement.
# =========================================================================


def test_raw_erc20_transfer():
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        interface IERC20 {
            function transfer(address to, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }

        contract Target {
            address public owner;
            IERC20 public token;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            function withdrawTokens(address to) external onlyOwner {
                uint256 bal = token.balanceOf(address(this));
                token.transfer(to, bal);
            }
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, "withdrawTokens")
    assert "asset_send" in labels, f"Expected asset_send for withdrawTokens (ERC20.transfer), got: {labels}"


# =========================================================================
# WEAKNESS 5: Indirect mint through another contract
# If contract A calls contract B.mint(), the semantic effect should carry
# enough selector/callee evidence to classify the supply-changing action.
# =========================================================================


def test_cross_contract_mint():
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        interface IMintable {
            function mint(address to, uint256 amount) external;
        }

        contract Target {
            address public owner;
            IMintable public token;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            function mintRewards(address to, uint256 amount) external onlyOwner {
                token.mint(to, amount);
            }
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, "mintRewards")
    assert "mint" in labels, f"Expected mint for mintRewards (cross-contract), got: {labels}"


# =========================================================================
# CONTROL: Tests that SHOULD pass with current detection
# These verify the baseline works correctly.
# =========================================================================


def test_standard_ownable_transfer():
    """Standard ownership transfer via owner variable should be detected."""
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract Target {
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            function transferOwnership(address newOwner) external onlyOwner {
                owner = newOwner;
            }
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, "transferOwnership")
    assert "ownership_transfer" in labels, f"Expected ownership_transfer, got: {labels}"


def test_standard_pause():
    """A pause flag that gates another function should be detected."""
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract Target {
            bool private _paused;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            modifier whenNotPaused() {
                require(!_paused, "paused");
                _;
            }

            function pause() external onlyOwner {
                _paused = true;
            }

            function unpause() external onlyOwner {
                _paused = false;
            }

            function execute() external whenNotPaused {
            }
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels_pause = _get_function_labels(analysis, "pause")
    labels_unpause = _get_function_labels(analysis, "unpause")
    assert "pause_toggle" in labels_pause, f"Expected pause_toggle for pause, got: {labels_pause}"
    assert "pause_toggle" in labels_unpause, f"Expected pause_toggle for unpause, got: {labels_unpause}"


def test_standard_mint_burn_names_are_not_inferred_without_semantic_evidence():
    """Internal helper names alone should not produce mint/burn labels."""
    source = textwrap.dedent("""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract Target {
            mapping(address => uint256) public balances;
            uint256 public totalSupply;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "not owner");
                _;
            }

            function mint(address to, uint256 amount) external onlyOwner {
                _mint(to, amount);
            }

            function burn(address from, uint256 amount) external onlyOwner {
                _burn(from, amount);
            }

            function _mint(address to, uint256 amount) internal {
                balances[to] += amount;
                totalSupply += amount;
            }

            function _burn(address from, uint256 amount) internal {
                balances[from] -= amount;
                totalSupply -= amount;
            }
        }
    """)
    analysis = _scaffold_and_analyze(source)
    labels_mint = _get_function_labels(analysis, "mint")
    labels_burn = _get_function_labels(analysis, "burn")
    assert "mint" not in labels_mint, f"Did not expect mint label from helper name, got: {labels_mint}"
    assert "burn" not in labels_burn, f"Did not expect burn label from helper name, got: {labels_burn}"
