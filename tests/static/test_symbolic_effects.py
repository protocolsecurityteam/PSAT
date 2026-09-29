"""Symbolic effect detection: Pass 1 classifies each state variable by its ROLE (not its name),
Pass 2 labels each semantic function by the roles it writes. Every test uses randomized names
to prove zero name dependence, grouped by the security question answered.
"""

import random
import string
import tempfile
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


def _analyze(source: str, name: str = "Target"):
    """Run the production static label sequence (``build_effects`` -> Plane-1 claims ->
    ``project_effect_labels``); per-function claim ids are stashed on the returned summary for
    tests asserting a claim with no legacy label projection."""
    with tempfile.TemporaryDirectory(prefix="psat_test_sym_") as tmp:
        p = Path(tmp) / f"{name}.sol"
        p.write_text(source)
        slither = Slither(str(p))
        subject = _select_subject_contract(slither, name)
        if subject is None:
            raise RuntimeError(f"Contract {name} not found")
        # _build_semantic_control_summary reads predicate_trees + effects.
        predicate_trees = build_predicate_artifacts(subject)
        effects = build_effects(subject)
        claims_artifact = build_claims(subject, effects, predicate_trees)
        attach_claims_to_effects(effects, claims_artifact)
        project_effect_labels(effects)
        ac: dict = dict(_build_semantic_control_summary(subject, Path(tmp), predicate_trees, effects))
        ac["_claims_by_fn"] = {
            sig: [claim["claim_id"] for claim in (info.get("claims") or [])]
            for sig, info in effects["functions"].items()
        }
        return ac


def _labels(ac, fn_name: str) -> set[str]:
    for pf in ac.get("semantic_functions", []):
        if pf["function"].split("(")[0] == fn_name:
            return set(pf.get("effect_labels", []))
    return set()


def _claims(ac, fn_name: str) -> set[str]:
    for sig, claim_ids in ac.get("_claims_by_fn", {}).items():
        if sig.split("(")[0] == fn_name:
            return set(claim_ids)
    return set()


# =========================================================================
# Q1: CAN VALUE LEAVE THE CONTRACT?
#
# Storage role: "balance store" — mapping(address => uint256) that decreases,
# or ETH sent via any mechanism.
# =========================================================================


def test_q1_eth_leaves_via_call_value():
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address payable to, uint256 amt) external onlyOwner {{
        (bool ok,) = to.call{{value: amt}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}
"""
    ac = _analyze(source)
    assert "asset_send" in _labels(ac, fn)


def test_q1_erc20_leaves_via_transfer():
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 {{ function transfer(address, uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }}
contract Target {{
    address public owner;
    IERC20 public token;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address to) external onlyOwner {{ token.transfer(to, token.balanceOf(address(this))); }}
}}
"""
    ac = _analyze(source)
    assert "asset_send" in _labels(ac, fn)


def test_q1_erc20_leaves_via_encoded_selector():
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    address public token;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address to, uint256 amt) external onlyOwner {{
        (bool ok,) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amt));
        require(ok);
    }}
}}
"""
    ac = _analyze(source)
    assert "asset_send" in _labels(ac, fn)


def test_q1_eth_leaves_via_selfdestruct():
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address payable to) external onlyOwner {{ selfdestruct(to); }}
    receive() external payable {{}}
}}
"""
    ac = _analyze(source)
    assert "selfdestruct_capability" in _labels(ac, fn)


def test_q1_value_leaves_via_internal_helper():
    fn = _rand()
    helper = f"_{_rand()}"
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address payable to, uint256 amt) external onlyOwner {{ {helper}(to, amt); }}
    function {helper}(address payable to, uint256 amt) internal {{
        (bool ok,) = to.call{{value: amt}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}
"""
    ac = _analyze(source)
    assert "asset_send" in _labels(ac, fn)


# =========================================================================
# Q2: CAN DEPOSITS/WITHDRAWALS BE BLOCKED?
#
# Storage role: "guard variable" — a bool that a modifier reads, and that
# modifier gates other functions. Writing this bool = pause_toggle.
# =========================================================================


def test_q2_random_bool_gates_functions():
    var = f"_{_rand()}"
    mod = _rand()
    stop_fn = _rand()
    resume_fn = _rand()
    guarded_fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    bool public {var};
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    modifier {mod}() {{ require(!{var}); _; }}
    function {stop_fn}() external onlyOwner {{ {var} = true; }}
    function {resume_fn}() external onlyOwner {{ {var} = false; }}
    function {guarded_fn}() external payable {mod} {{ }}
}}
"""
    ac = _analyze(source)
    assert "pause_toggle" in _labels(ac, stop_fn)
    assert "pause_toggle" in _labels(ac, resume_fn)


def test_q2_inverted_bool_guard():
    """Guard checks require(active) instead of require(!paused) — same pattern, inverted."""
    var = f"_{_rand()}"
    mod = _rand()
    disable_fn = _rand()
    guarded_fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    bool public {var};
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    modifier {mod}() {{ require({var}); _; }}
    function {disable_fn}() external onlyOwner {{ {var} = false; }}
    function {guarded_fn}() external payable {mod} {{ }}
}}
"""
    ac = _analyze(source)
    assert "pause_toggle" in _labels(ac, disable_fn)


# =========================================================================
# Q3: CAN NEW VALUE BE CREATED? (minting)
#
# Detected via: internal _mint/mint calls, cross-contract .mint() calls,
# or known selectors.
# =========================================================================


def test_q3_internal_mint_helper_name_does_not_drive_label():
    """Internal helper names alone are not semantic mint evidence."""
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address to, uint256 amt) external onlyOwner {{ _mint(to, amt); }}
    function _mint(address to, uint256 amt) internal {{ balances[to] += amt; totalSupply += amt; }}
}}
"""
    ac = _analyze(source)
    assert "mint" not in _labels(ac, fn)


def test_q3_cross_contract_mint():
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IMintable {{ function mint(address to, uint256 amount) external; }}
contract Target {{
    address public owner;
    IMintable public token;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address to, uint256 amt) external onlyOwner {{ token.mint(to, amt); }}
}}
"""
    ac = _analyze(source)
    assert "mint" in _labels(ac, fn)


def test_q3_mint_via_encoded_selector():
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    address public token;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address to, uint256 amt) external onlyOwner {{
        (bool ok,) = token.call(abi.encodeWithSelector(0x40c10f19, to, amt));
        require(ok);
    }}
}}
"""
    ac = _analyze(source)
    assert "mint" in _labels(ac, fn)


# =========================================================================
# Q4: CAN THE CODE CHANGE? (implementation update)
#
# The bespoke impl-slot dataflow detectors are RETIRED (0 fires on prod). ``upgrade.implementation``
# is standard-gated (UUPS/1967/proxy-shell selectors), so a bespoke impl-slot setter gets no
# claim; the delegatecall stays a Plane-0 fact on the fallback (``delegatecall_execution``).
# =========================================================================


def test_q4_random_impl_slot_delegatecall():
    """Bespoke impl-slot var + fallback delegatecall: no standard upgrade selector, so no ``implementation_update``."""
    var = f"_{_rand()}"
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address private {var};
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address a) external onlyOwner {{ {var} = a; }}
    fallback() external payable {{
        address t = {var};
        assembly {{ calldatacopy(0,0,calldatasize()) let r := delegatecall(gas(),t,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize()) switch r case 0 {{ revert(0,returndatasize()) }} default {{ return(0,returndatasize()) }} }}
    }}
}}
"""
    ac = _analyze(source)
    assert "implementation_update" not in _labels(ac, fn)
    # The delegatecall is a fact carried on the fallback, not the setter.
    assert "delegatecall_execution" in _labels(ac, "fallback")


def test_q4_assembly_sstore_sload_delegatecall():
    """Pure-assembly sstore/sload delegatecall: the retired detector no longer mints ``implementation_update``."""
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address newImpl) external onlyOwner {{
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
    ac = _analyze(source)
    assert "implementation_update" not in _labels(ac, fn)
    assert "delegatecall_execution" in _labels(ac, "fallback")


# =========================================================================
# Q5: CAN WHO'S IN CHARGE CHANGE? (ownership vs caller-authority rotation)
#
# ``ownership.transfer`` is standards-gated (canonical selectors + ``owner()`` sibling / two-step)
# so it stays ghost-immune. A bespoke caller-authority scalar rotated by a random function is
# ``authorized_caller.rotate``: same admin weight, but not the "Transfers contract ownership"
# sentence (no legacy ownership_transfer projection).
# =========================================================================


def test_q5_random_owner_var():
    """Bespoke scalar rotated by a random function, no ownership standard: ``authorized_caller.rotate``."""
    var = f"_{_rand()}"
    mod = _rand()
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public {var};
    constructor() {{ {var} = msg.sender; }}
    modifier {mod}() {{ require(msg.sender == {var}); _; }}
    function {fn}(address newAdmin) external {mod} {{ {var} = newAdmin; }}
}}
"""
    ac = _analyze(source)
    assert "authorized_caller.rotate" in _claims(ac, fn)
    assert "ownership_transfer" not in _labels(ac, fn)


def test_q5_two_step_ownership():
    """Two-step nominate + accept over bespoke scalars: accept rotates the admin scalar
    (``authorized_caller.rotate``, no ownership_transfer)."""
    admin_var = f"_{_rand()}"
    pending_var = f"_{_rand()}"
    nominate_fn = _rand()
    accept_fn = _rand()
    mod = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public {admin_var};
    address public {pending_var};
    modifier {mod}() {{ require(msg.sender == {admin_var}); _; }}
    function {nominate_fn}(address a) external {mod} {{ {pending_var} = a; }}
    function {accept_fn}() external {{
        require(msg.sender == {pending_var});
        {admin_var} = msg.sender;
        {pending_var} = address(0);
    }}
}}
"""
    ac = _analyze(source)
    assert "authorized_caller.rotate" in _claims(ac, accept_fn)
    assert "ownership_transfer" not in _labels(ac, accept_fn)


# =========================================================================
# Q6: CAN THE RULES CHANGE? (authority/hook update)
#
# Storage role: "authority reference" — address that is CALLED (not just
# compared) within a modifier body. Writing this = authority_update.
#
# Storage role: "hook reference" — address called during transfer-like
# function execution. Writing this = hook_update.
# =========================================================================


def test_q6_random_authority_var():
    """Authority var called in a modifier. The structural ``dest:{name}`` detector is RETIRED (a
    category error: a data-freshness call in a modifier matched too), so a bespoke non-``setAuthority``
    setter is silent; ``authority.replace`` is reserved for the canonical Solmate selector."""
    auth_var = f"_{_rand()}"
    mod = _rand()
    set_fn = _rand()
    guarded_fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IAuth {{ function canCall(address, address, bytes4) external view returns (bool); }}
contract Target {{
    address public owner;
    IAuth public {auth_var};
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    modifier {mod}(bytes4 sig) {{ require(address({auth_var}) == address(0) || {auth_var}.canCall(msg.sender, address(this), sig)); _; }}
    function {set_fn}(IAuth a) external onlyOwner {{ {auth_var} = a; }}
    function {guarded_fn}() external {mod}(msg.sig) {{ }}
}}
"""
    ac = _analyze(source)
    assert "authority_update" not in _labels(ac, set_fn)


def test_q6_random_hook_var():
    hook_var = f"_{_rand()}"
    set_fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IHook {{ function beforeTransfer(address, address, uint256) external; }}
contract Target {{
    mapping(address => uint256) public balances;
    address public owner;
    IHook public {hook_var};
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {set_fn}(IHook h) external onlyOwner {{ {hook_var} = h; }}
    function transfer(address to, uint256 amt) external {{
        if (address({hook_var}) != address(0)) {hook_var}.beforeTransfer(msg.sender, to, amt);
        balances[msg.sender] -= amt;
        balances[to] += amt;
    }}
}}
"""
    ac = _analyze(source)
    assert "hook_update" in _labels(ac, set_fn)


# =========================================================================
# COMPOUND SCENARIOS — multiple effects in one function
# =========================================================================


def test_compound_drain_and_selfdestruct():
    fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    address public owner;
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {fn}(address payable to) external onlyOwner {{
        (bool ok,) = to.call{{value: address(this).balance}}("");
        require(ok);
        selfdestruct(to);
    }}
    receive() external payable {{}}
}}
"""
    ac = _analyze(source)
    labels = _labels(ac, fn)
    assert "asset_send" in labels
    assert "selfdestruct_capability" in labels


def test_compound_pause_and_ownership():
    """One function pauses AND rotates the scalar: ``pause.set`` -> ``pause_toggle``, and the
    bespoke rotation is ``authorized_caller.rotate`` with no ``ownership_transfer`` label."""
    bool_var = f"_{_rand()}"
    admin_var = f"_{_rand()}"
    mod_auth = _rand()
    mod_guard = _rand()
    fn = _rand()
    guarded_fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Target {{
    bool public {bool_var};
    address public {admin_var};
    constructor() {{ {admin_var} = msg.sender; }}
    modifier {mod_auth}() {{ require(msg.sender == {admin_var}); _; }}
    modifier {mod_guard}() {{ require(!{bool_var}); _; }}
    function {fn}(address newAdmin) external {mod_auth} {{
        {bool_var} = true;
        {admin_var} = newAdmin;
    }}
    function {guarded_fn}() external payable {mod_guard} {{ }}
}}
"""
    ac = _analyze(source)
    labels = _labels(ac, fn)
    assert "pause_toggle" in labels
    assert "authorized_caller.rotate" in _claims(ac, fn)
    assert "ownership_transfer" not in labels


# =========================================================================
# Q6 RECURSIVE: Authority/hook hidden behind internal helpers
# =========================================================================


def test_q6_recursive_authority():
    """Helper-hidden auth check + setter: same retirement as the direct case, so no ``authority_update``."""
    auth_var = f"_{_rand()}"
    mod = _rand()
    set_fn = _rand()
    helper = f"_{_rand()}"
    auth_helper = f"_{_rand()}"
    guarded_fn = _rand()
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IAuth {{ function canCall(address, address, bytes4) external view returns (bool); }}
contract Target {{
    address public owner;
    IAuth public {auth_var};
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {auth_helper}(bytes4 sig) internal view returns (bool) {{
        return address({auth_var}) == address(0) || {auth_var}.canCall(msg.sender, address(this), sig);
    }}
    modifier {mod}(bytes4 sig) {{ require({auth_helper}(sig)); _; }}
    function {helper}(IAuth a) internal {{ {auth_var} = a; }}
    function {set_fn}(IAuth a) external onlyOwner {{ {helper}(a); }}
    function {guarded_fn}() external {mod}(msg.sig) {{ }}
}}
"""
    ac = _analyze(source)
    assert "authority_update" not in _labels(ac, set_fn)


def test_q6_recursive_hook():
    hook_var = f"_{_rand()}"
    set_fn = _rand()
    helper = f"_{_rand()}"
    call_helper = f"_{_rand()}"
    source = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IHook {{ function beforeTransfer(address, address, uint256) external; }}
contract Target {{
    mapping(address => uint256) public balances;
    address public owner;
    IHook public {hook_var};
    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    function {call_helper}(address from, address to, uint256 amt) internal {{
        if (address({hook_var}) != address(0)) {hook_var}.beforeTransfer(from, to, amt);
    }}
    function {helper}(IHook h) internal {{ {hook_var} = h; }}
    function {set_fn}(IHook h) external onlyOwner {{ {helper}(h); }}
    function transfer(address to, uint256 amt) external {{
        {call_helper}(msg.sender, to, amt);
        balances[msg.sender] -= amt;
        balances[to] += amt;
    }}
}}
"""
    ac = _analyze(source)
    assert "hook_update" in _labels(ac, set_fn)
