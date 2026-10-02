"""Randomized names force detection from what the code does.

That strengthens positive assertions but weakens negative ones, so conventional-name controls at the end make the earned
negatives falsifiable.
"""

import random
import string
import tempfile
import textwrap
from pathlib import Path

from slither.slither import Slither

from services.static.claims import attach_claims_to_effects, build_claims, project_effect_labels
from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.shared import _select_subject_contract
from services.static.contract_analysis_pipeline.summaries import _build_semantic_control_summary


def _rand(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _scaffold_and_analyze(solidity_source: str, contract_name: str = "Target") -> dict:
    with tempfile.TemporaryDirectory(prefix="psat_test_adv_") as tmp:
        project_dir = Path(tmp)
        sol_path = project_dir / f"{contract_name}.sol"
        sol_path.write_text(solidity_source)
        slither = Slither(str(sol_path))
        subject = _select_subject_contract(slither, contract_name)
        if subject is None:
            raise RuntimeError(f"Contract {contract_name} not found")
        predicate_trees = build_predicate_artifacts(subject)
        effects = build_effects(subject)
        claims_artifact = build_claims(subject, effects, predicate_trees)
        attach_claims_to_effects(effects, claims_artifact)
        project_effect_labels(effects)
        semantic_control = _build_semantic_control_summary(subject, project_dir, predicate_trees, effects)
        return {"semantic_control": semantic_control, "effects": effects}


def _get_function_labels(analysis: dict, function_name: str) -> set[str]:
    for pf in analysis.get("semantic_control", {}).get("semantic_functions", []):
        if pf.get("function", "").split("(")[0] == function_name:
            return set(pf.get("effect_labels", []))
    return set()


def test_selfdestruct_value_drain():
    fn_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn_name}(address payable to) external onlyOwner {{
        selfdestruct(to);
    }}
    receive() external payable {{}}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, fn_name)
    assert "selfdestruct_capability" in labels, (
        f"selfdestruct fn '{fn_name}': expected selfdestruct_capability, got {labels}"
    )


# 6. Cross-contract "mint" via a randomized interface method name. The retired
# ``str(ir)`` totalSupply-sandwich parser is gone: ``supply.mint`` keys on
#    the canonical ``mint`` selector or an ERC-20 gate, so a bespoke call is not a
#    supply claim; the honest label is the external-call fact.


def test_erc20_transfer_via_encode_selector():
    fn_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    address public token;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn_name}(address to, uint256 amount) external onlyOwner {{
        (bool ok,) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        require(ok);
    }}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, fn_name)
    assert "asset_send" in labels, f"ERC20 via encodeWithSelector fn '{fn_name}': expected asset_send, got {labels}"


# Conventional-name controls for each randomized test above.


def test_nonstandard_impl_slot_name():
    """A reintroduced name-keyed impl-slot heuristic would pass the randomized test and fail this one."""
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


def test_standard_mint_burn_names_are_not_inferred_without_semantic_evidence():
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
