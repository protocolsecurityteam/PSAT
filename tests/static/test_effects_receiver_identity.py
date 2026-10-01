"""D2: an external call's RECEIVER must publish what it structurally is, and
nothing the evidence does not carry.

A sink ``target`` name is not an identity: it does not say whether the CALLER chose
the asset, whether it is this unit's storage, or how it could be read. Tests
compile the shapes and drive production ``build_effects`` and the claims phase.

Three refusals, one test each: ``visibility`` may not decide the binding (a
``LocalVariable`` answers like an internal state variable); the auto-getter
selector is licensed by the DECLARED TYPE, not the name; a formal of an internal
helper is not an ABI slot of the entry point. Protocol-agnostic by construction:
shapes only, never a named protocol.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("slither")
from eth_utils.crypto import keccak
from slither import Slither

from services.static.contract_analysis_pipeline.effects import build_effects
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount));
    }
}

// A collection-typed receiver: ``xs.total()`` binds a STORAGE ARRAY as the
// library call's head, which is how a non-address declaration reaches the
// receiver arm at all.
library ArrayLib {
    function total(uint256[] storage xs) internal view returns (uint256) {
        return xs.length;
    }
}

// A library with its OWN public constant receiver. The sink walk recurses into
// library calls, so this declaration reaches the receiver arm — but it belongs
// to the library, not to the analysed contract.
library LConst {
    IERC20 public constant T = IERC20(address(0x3333333333333333333333333333333333333333));

    function go(address to, uint256 amount) internal {
        T.transfer(to, amount);
    }
}

library MapLib {
    function get(mapping(address => uint256) storage m, address key) internal view returns (uint256) {
        return m[key];
    }
}

contract Receivers {
    using SafeERC20 for IERC20;
    using ArrayLib for uint256[];
    using MapLib for mapping(address => uint256);

    IERC20 public immutable immToken;
    IERC20 internal hiddenToken;
    IERC20 public constant CONST_TOKEN = IERC20(address(0x1111111111111111111111111111111111111111));
    uint256[] public amounts;
    mapping(address => uint256) public balances;

    constructor(IERC20 token) {
        immToken = token;
    }

    // The caller names the asset in ABI slot 0.
    function payParam(address token, address to, uint256 amount) external {
        IERC20(token).safeTransfer(to, amount);
    }

    // The send is sited in a helper whose formal occupies no ABI slot here.
    function payHelper(address token, address to, uint256 amount) external {
        _pay(IERC20(token), to, amount);
    }

    function _pay(IERC20 token, address to, uint256 amount) internal {
        token.safeTransfer(to, amount);
    }

    function payImmutable(address to, uint256 amount) external {
        immToken.safeTransfer(to, amount);
    }

    function payInternal(address to, uint256 amount) external {
        hiddenToken.safeTransfer(to, amount);
    }

    function payConstant(address to, uint256 amount) external {
        CONST_TOKEN.safeTransfer(to, amount);
    }

    // The receiver is a LOCAL copied out of storage. The cast walk does not
    // follow assignment edges (a non-SSA assignment names an arbitrary branch's
    // value), so the binding stops here — and ``getToken()`` below is a
    // HAND-WRITTEN getter, not a compiler-minted one, so nothing may pair them.
    function payLocal(address to, uint256 amount) external {
        IERC20 local = hiddenToken;
        local.safeTransfer(to, amount);
    }

    function getToken() public view returns (IERC20) {
        return hiddenToken;
    }

    // Two different assets moved by one function: two sinks, one selector.
    function payTwoTokens(address to, uint256 amount) external {
        immToken.transfer(to, amount);
        hiddenToken.transfer(to, amount);
    }

    // Two sites that fold onto ONE sink record and disagree about the binding.
    function payBothScopes(IERC20 token, address to, uint256 amount) external {
        token.transfer(to, amount);
        _forward(token, to, amount);
    }

    function _forward(IERC20 token, address to, uint256 amount) internal {
        token.transfer(to, amount);
    }

    function readAmounts() external view returns (uint256) {
        return amounts.total();
    }

    function readBalance(address key) external view returns (uint256) {
        return balances.get(key);
    }
}

contract LibConstUser {
    function pay(address to, uint256 amount) external {
        LConst.go(to, amount);
    }
}

// The same identifier declared on BOTH the contract and the library, holding
// two different addresses. Both sites key to the same sink record.
contract Collide {
    IERC20 public constant T = IERC20(address(0x4444444444444444444444444444444444444444));

    function pay(address to, uint256 amount) external {
        T.transfer(to, amount);
        LConst.go(to, amount);
    }
}
"""


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    path = tmp_path_factory.mktemp("receivers") / "Receivers.sol"
    path.write_text(textwrap.dedent(_SRC).strip() + "\n")
    return {c.name: c for c in Slither(str(path)).contracts}


@pytest.fixture(scope="module")
def effects(compiled):
    return build_effects(compiled["Receivers"])


@pytest.fixture(scope="module")
def foreign(compiled):
    return {name: build_effects(compiled[name]) for name in ("LibConstUser", "Collide")}


def _receiver(effects, signature: str, target: str) -> dict | None:
    sinks = [s for s in effects["functions"][signature]["sinks"] if s["target"] == target]
    assert len(sinks) == 1, f"{signature} {target}: {sinks}"
    return sinks[0].get("receiver")


def test_entry_parameter_receiver_is_caller_named(effects):
    assert _receiver(effects, "payParam(address,address,uint256)", "token.safeTransfer") == {
        "binding": "parameter",
        "param_scope": "entry_point",
        "param_index": 0,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": "token",
        "receiver_provenance": "caller_named",
    }


def test_receiver_schema_invariants(effects):
    for info in effects["functions"].values():
        for sink in info["sinks"]:
            if sink["kind"] != "external_call":
                assert "receiver" not in sink, sink
            receiver = sink.get("receiver")
            if receiver is None:
                continue
            assert "asset_address" not in receiver
            assert receiver["receiver_provenance"] in {
                "caller_named",
                "contract_state_unresolved",
                "not_determined",
            }


def test_witness_joins_each_receiver_to_its_own_sink(tmp_path):
    """Two assets in one function share a flow key; keying by sink id keeps the join exact."""
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    project = write_foundry_project(tmp_path, "Receivers", textwrap.dedent(_SRC).strip() + "\n")
    _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project)
    assert effects is not None

    record = effects["functions"]["payTwoTokens(address,uint256)"]
    flow_claims = [c for c in record["claims"] if c["claim_id"].startswith("flow.")]
    assert flow_claims, record["claims"]
    witness = flow_claims[0]["witness"]
    receivers = witness["sink_receivers"]

    assert set(receivers) <= set(witness["sink_ids"])
    variables = {r["variable"] for r in receivers.values()}
    assert {"immToken", "hiddenToken"} <= variables, receivers
    by_variable = {r["variable"]: r for r in receivers.values()}
    assert by_variable["immToken"]["auto_getter_selector"] == "0x8e0191b5"
    assert by_variable["hiddenToken"]["auto_getter_selector"] is None


def test_library_constant_is_not_this_contract_s_storage(foreign):
    """The walk recurses into libraries; a library's ``public constant`` isn't in this contract's ABI, and a pinned
    read would revert.
    """
    receiver = _receiver(foreign["LibConstUser"], "pay(address,uint256)", "T.transfer")
    assert receiver is not None
    assert receiver == {
        "binding": "not_determined",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": None,
        "receiver_provenance": "not_determined",
        "not_determined_reason": "foreign_declaration",
    }
    assert receiver["auto_getter_selector"] is None
