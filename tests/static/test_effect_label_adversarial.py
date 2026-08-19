"""Adversarial effect label tests — simulating a malicious developer.

Names are randomized so detection can't rely on naming conventions.
These test whether the detection works based on *what the code does*
(AST structure, data flow, IR) rather than *what things are called*.

Randomization strengthens a *positive* assertion and weakens a *negative*
one: for an assertion-of-absence, conventional naming is the adversarial
input. So the file ends with conventional-name controls (merged from the
former ``test_effect_label_weaknesses.py``) — the pairs are what make the
earned negatives falsifiable in both directions.
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
    """Generate a random lowercase identifier."""
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
        # Full production label sequence: facts -> Plane-1 claims -> projection.
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


def _get_function_claims(analysis: dict, function_name: str) -> set[str]:
    for sig, info in (analysis.get("effects", {}).get("functions") or {}).items():
        if sig.split("(")[0] == function_name:
            return {claim["claim_id"] for claim in (info.get("claims") or [])}
    return set()


# =========================================================================
# 1. Randomized impl slot name + delegatecall fallback
#    The variable storing the implementation has a random name.
#    Detection must rely on: "writes var X" + "fallback reads X and delegatecalls"
# =========================================================================


def test_random_impl_slot_with_delegatecall():
    slot_name = f"_{_rand()}"
    setter_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address private {slot_name};
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {setter_name}(address a) external onlyOwner {{ {slot_name} = a; }}
    fallback() external payable {{
        address t = {slot_name};
        assembly {{ calldatacopy(0,0,calldatasize()) let r := delegatecall(gas(),t,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize()) switch r case 0 {{ revert(0,returndatasize()) }} default {{ return(0,returndatasize()) }} }}
    }}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, setter_name)
    # The bespoke same-contract impl-slot detector is retired; ``upgrade.*`` is
    # standard-gated. The delegatecall stays a fact on the fallback.
    assert "implementation_update" not in labels, (
        f"Random impl slot '{slot_name}', setter '{setter_name}': expected NO implementation_update, got {labels}"
    )
    assert "delegatecall_execution" in _get_function_labels(analysis, "fallback")


# =========================================================================
# 2. Randomized pause variable name
#    A bool with a random name gates a modifier, and a function flips it.
#    Detection must rely on: "writes a bool that gates other functions"
#    (Currently we expanded the name list, but random names will fail.)
# =========================================================================


def test_random_pause_variable():
    var_name = f"_{_rand()}"
    pause_fn = _rand()
    unpause_fn = _rand()
    guarded_fn = _rand()
    modifier_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    bool public {var_name};
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    modifier {modifier_name}() {{ require(!{var_name}); _; }}
    function {pause_fn}() external onlyOwner {{ {var_name} = true; }}
    function {unpause_fn}() external onlyOwner {{ {var_name} = false; }}
    function {guarded_fn}() external payable {modifier_name} {{ }}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, pause_fn)
    assert "pause_toggle" in labels, (
        f"Random pause var '{var_name}', fn '{pause_fn}': expected pause_toggle, got {labels}"
    )


# =========================================================================
# 3. Raw storage slot write via assembly (no named variable at all)
#    Malicious dev uses sstore to a hardcoded slot that the fallback
#    reads via sload and delegatecalls to.
# =========================================================================


def test_raw_assembly_storage_slot_impl():
    setter_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {setter_name}(address newImpl) external onlyOwner {{
        bytes32 slot = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
        assembly {{ sstore(slot, newImpl) }}
    }}
    fallback() external payable {{
        bytes32 slot = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
        assembly {{
            let impl := sload(slot)
            calldatacopy(0,0,calldatasize())
            let r := delegatecall(gas(),impl,0,calldatasize(),0,0)
            returndatacopy(0,0,returndatasize())
            switch r case 0 {{ revert(0,returndatasize()) }} default {{ return(0,returndatasize()) }}
        }}
    }}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, setter_name)
    assert "implementation_update" not in labels, (
        f"Assembly sstore impl setter '{setter_name}': expected NO implementation_update, got {labels}"
    )
    assert "delegatecall_execution" in _get_function_labels(analysis, "fallback")


# =========================================================================
# 4. ETH drain via selfdestruct (sends all ETH to an address)
#    Not a .call{value:} — uses selfdestruct as a value transfer mechanism.
# =========================================================================


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


# =========================================================================
# 5. Randomized function name for cross-contract mint
#    Calls token.mint() but the calling function has a random name.
#    The label comes from the called selector, not the caller name.
# =========================================================================


def test_random_named_cross_contract_mint():
    fn_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IMintable {{ function mint(address to, uint256 amount) external; }}
contract Target {{
    address public owner;
    IMintable public token;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn_name}(address to, uint256 amount) external onlyOwner {{ token.mint(to, amount); }}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, fn_name)
    assert "mint" in labels, f"Cross-contract mint fn '{fn_name}': expected mint, got {labels}"


# =========================================================================
# 6. Cross-contract "mint" via a randomized interface method name.
#    The retired ``str(ir)`` totalSupply-sandwich parser used to infer mint
#    from an observed totalSupply delta around an arbitrarily-named call. It is
#    gone (§5): ``supply.mint`` keys on the canonical ``mint`` selector or an
#    ERC-20 gate, so a bespoke, non-selector call is not a supply claim — the
#    honest label is the external-call fact.
# =========================================================================


def test_random_interface_mint_name():
    fn_name = _rand()
    mint_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IToken {{
    function {mint_name}(address to, uint256 amount) external;
    function totalSupply() external view returns (uint256);
}}
contract Target {{
    address public owner;
    IToken public token;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn_name}(address to, uint256 amount) external onlyOwner {{
        uint256 before = token.totalSupply();
        token.{mint_name}(to, amount);
        require(token.totalSupply() > before, "supply must increase");
    }}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, fn_name)
    assert "mint" not in labels, (
        f"Randomized interface mint '{mint_name}', fn '{fn_name}': expected NO mint, got {labels}"
    )
    assert labels == {"external_contract_call"}


# =========================================================================
# 7. Value transfer hidden behind an internal helper with random name
#    The external function calls an internal function with a random name,
#    which does the actual .call{value:}.
# =========================================================================


def test_value_transfer_via_random_internal_helper():
    fn_name = _rand()
    helper_name = f"_{_rand()}"
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn_name}(address payable to, uint256 amt) external onlyOwner {{
        {helper_name}(to, amt);
    }}
    function {helper_name}(address payable to, uint256 amt) internal {{
        (bool ok,) = to.call{{value: amt}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, fn_name)
    assert "asset_send" in labels, (
        f"Value transfer via internal helper '{helper_name}', fn '{fn_name}': expected asset_send, got {labels}"
    )


# =========================================================================
# 8. ERC20 transfer via abi.encodeWithSelector (low-level obfuscation)
#    Instead of calling token.transfer(), uses address.call with encoded selector.
# =========================================================================


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


# =========================================================================
# 9. Ownership transfer with randomized variable name
#    The "owner" variable has a random name; detection should still find
#    the ownership pattern via the modifier.
# =========================================================================


def test_random_owner_variable_name():
    var_name = f"_{_rand()}"
    fn_name = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public {var_name};
    constructor() {{ {var_name} = msg.sender; }}
    modifier auth() {{ require(msg.sender == {var_name}); _; }}
    function {fn_name}(address newAdmin) external auth {{ {var_name} = newAdmin; }}
}}
"""
    analysis = _scaffold_and_analyze(source)
    labels = _get_function_labels(analysis, fn_name)
    claims = _get_function_claims(analysis, fn_name)
    # No ownership standard on this contract (no owner()/transferOwnership),
    # so the bespoke caller-authority scalar rotation is authorized_caller.rotate
    # rather than the ghost-prone ownership_transfer.
    assert "authorized_caller.rotate" in claims, (
        f"Random owner var '{var_name}', fn '{fn_name}': expected authorized_caller.rotate, got {claims}"
    )
    assert "ownership_transfer" not in labels


# =========================================================================
# Conventional-name controls (merged from tests/test_effect_label_weaknesses.py)
#
# Same pipeline, ordinary identifiers. Each is the paired control for a
# randomized test above: together they prove a label comes from what the code
# does, in both directions.
# =========================================================================


def test_nonstandard_impl_slot_name():
    """Conventional-name control for ``test_random_impl_slot_with_delegatecall``.

    The load-bearing assertion is an earned negative, so ordinary names
    (``_logic`` / ``setLogic``) are the adversarial input here: a
    reintroduced name-keyed impl-slot heuristic would pass the randomized
    test and fail this one.
    """
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
