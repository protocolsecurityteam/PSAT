"""State variables are classified by role, not name; every test uses randomized names."""

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
    """Claim ids are stashed on the summary for tests asserting a claim with no legacy label."""
    with tempfile.TemporaryDirectory(prefix="psat_test_sym_") as tmp:
        p = Path(tmp) / f"{name}.sol"
        p.write_text(source)
        slither = Slither(str(p))
        subject = _select_subject_contract(slither, name)
        if subject is None:
            raise RuntimeError(f"Contract {name} not found")
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


# Q1: can value leave the contract?


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


# Q2: can deposits/withdrawals be blocked? A bool a gating modifier reads.


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


# Q3: can new value be created?


def test_q3_internal_mint_helper_name_does_not_drive_label():
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


# Q4: can the code change? The bespoke impl-slot detectors are retired (0 fires on prod); ``upgrade.implementation`` is
# standard-gated.


def test_q4_random_impl_slot_delegatecall():
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
    assert "delegatecall_execution" in _labels(ac, "fallback")


def test_q4_assembly_sstore_sload_delegatecall():
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


# Q5: can who's in charge change? A bespoke rotation is ``authorized_caller.rotate``, not ownership.


def test_q5_random_owner_var():
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


# Q6: can the rules change? An address called in a modifier is an authority; one called during transfers is a hook.


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


def test_q6_recursive_authority():
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
