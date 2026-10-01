"""Fixtures are named adversarially, so hygiene classification must come from IR shape; negative controls have
identifiers that look like slots or guards but aren't.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.summaries import _extract_value_flows


def _compile(tmp_path: Path, source: str, name: str):
    path = tmp_path / f"{name}.sol"
    path.write_text(textwrap.dedent(source).strip() + "\n")
    return next(c for c in Slither(str(path)).contracts if c.name == name)


def _hygiene(effects, signature: str) -> dict[str, str]:
    info = effects["functions"].get(signature)
    assert info is not None, f"expected {signature} in {sorted(effects['functions'])}"
    return {w["var"]: w["hygiene_class"] for w in info["state_writes"]}


_SSTORE_SRC = """
pragma solidity ^0.8.20;

contract Handle {
    // Written through raw sstore; identifier carries no slot/storage token.
    bytes32 internal constant ADMIN_HANDLE =
        0x8b78c6d8000000000000000000000000000000000000000000000000000000ff;

    bytes32 internal constant ADMIN_ROLE = keccak256("acme.role.admin");

    function setAdmin(address v) public {
        assembly { sstore(ADMIN_HANDLE, v) }
    }

    function role() public pure returns (bytes32) { return ADMIN_ROLE; }
}
"""


def test_sstore_target_constant_is_pseudo_and_a_value_constant_is_not(tmp_path):
    """Assigning a constant is illegal, so an ``Assignment`` to one can only be ``sstore(C, …)``; ``ADMIN_ROLE`` is
    the control a name rule couldn't give.
    """
    effects = build_effects(_compile(tmp_path, _SSTORE_SRC, "Handle"))
    classes = _hygiene(effects, "setAdmin(address)")
    assert classes["ADMIN_HANDLE"] == "storage_location_pseudo"
    assert classes.get("ADMIN_ROLE") in (None, "constant")


_HELPER_GUARD_SRC = """
pragma solidity ^0.8.20;

contract HelperGuarded {
    uint256 private gateWord = 1;
    uint256 public counter;

    function _enter() private { require(gateWord == 1, "REENTRANCY"); gateWord = 2; }
    function _leave() private { gateWord = 1; }

    modifier single() { _enter(); _; _leave(); }

    function bump() public single { counter += 1; }
}
"""


def test_guard_split_into_helpers_is_still_classified(tmp_path):
    effects = build_effects(_compile(tmp_path, _HELPER_GUARD_SRC, "HelperGuarded"))
    classes = _hygiene(effects, "bump()")
    assert classes["gateWord"] == "reentrancy_guard"
    assert classes["counter"] == "normal"


_TOKEN_FIRST_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function totalSupply() external view returns (uint256); }

library Mover {
    // Real ERC-20 moves, assembly-only bodies (the Solmate / Solady shape), and
    // names that match nothing: only the selector literal identifies them.
    function push(IERC20 token, address to, uint256 amount) internal {
        bool ok;
        assembly {
            let p := mload(0x40)
            mstore(p, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(p, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 36), amount)
            ok := call(gas(), token, 0, p, 68, 0, 32)
        }
        require(ok, "FAIL");
    }

    function grab(IERC20 token, address from, address to, uint256 amount) internal {
        bool ok;
        assembly {
            let p := mload(0x40)
            mstore(p, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
            mstore(add(p, 4), and(from, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 36), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 68), amount)
            ok := call(gas(), token, 0, p, 100, 0, 32)
        }
        require(ok, "FAIL");
    }

    // Decoy: the canonical name and the canonical trailing types, but the body
    // moves nothing. Under the name rule this minted a value_router flow.
    function safeTransfer(IERC20 token, address to, uint256 amount) internal view {
        require(token.totalSupply() >= amount && to != address(0), "NO");
    }
}

contract Vault {
    using Mover for IERC20;
    uint256 public totalShares;

    function enter(address from, IERC20 asset, uint256 amount, uint256 sh) external {
        asset.grab(from, address(this), amount);
        totalShares += sh;
    }
    function exit(address to, IERC20 asset, uint256 amount, uint256 sh) external {
        totalShares -= sh;
        asset.push(to, amount);
    }
    function decoy(address to, IERC20 asset, uint256 amount) external {
        asset.safeTransfer(to, amount);
    }
}

contract Router {
    Vault public vault;
    IERC20 public asset;

    function deposit(uint256 amount) external { vault.enter(msg.sender, asset, amount, amount); }
    function withdraw(uint256 amount, address to) external { vault.exit(to, asset, amount, amount); }
    function decoyRoute(uint256 amount, address to) external { vault.decoy(to, asset, amount); }
}
"""


@pytest.fixture(scope="module")
def _token_first(tmp_path_factory):
    path = tmp_path_factory.mktemp("token_first") / "mover.sol"
    path.write_text(textwrap.dedent(_TOKEN_FIRST_SRC).strip() + "\n")
    return Slither(str(path))


def _routed(unit, contract_name: str, signature: str) -> list[Any]:
    contract = next(c for c in unit.contracts if c.name == contract_name)
    info = build_effects(contract)["functions"][signature]
    return [f for f in info["value_flows"] if f["direction"] == "value_router"]


def test_routed_send_is_recovered_from_the_issued_selector(_token_first):
    """The ``transfer`` selector literal in an assembly ``mstore`` is the only evidence."""
    routed = _routed(_token_first, "Router", "withdraw(uint256,address)")
    assert len(routed) == 1, routed
    assert routed[0]["from_is_self"] is True
    assert routed[0]["target_param_index"] == 1


def test_routed_pull_is_recovered_from_the_issued_selector(_token_first):
    routed = _routed(_token_first, "Router", "deposit(uint256)")
    assert len(routed) == 1, routed
    assert routed[0]["target_kind"]["kind"] == "self"
    assert routed[0]["amount_param_index"] == 0


_LEGACY_FLOW_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }

contract Payer {
    function payToken(IERC20 token, address to, uint256 amount) external {
        token.transfer(to, amount);
    }
    function payEth(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ETH");
    }
}
"""


def test_value_flows_survive_an_unreadable_ir_repr(tmp_path, monkeypatch):
    """``str(ir)`` is a debug rendering that can change upstream silently."""
    from slither.slithir.operations.high_level_call import HighLevelCall
    from slither.slithir.operations.low_level_call import LowLevelCall

    contract = _compile(tmp_path, _LEGACY_FLOW_SRC, "Payer")
    functions = {fn.full_name: fn for fn in contract.functions}
    expected = {
        sig: _extract_value_flows(functions[sig])
        for sig in ("payToken(IERC20,address,uint256)", "payEth(address,uint256)")
    }
    assert expected["payToken(IERC20,address,uint256)"] == [
        {
            "direction": "out",
            "token_var": "token",
            "token_type": "IERC20",
            "method": "transfer(address,uint256)",
            "is_parameter": True,
        }
    ]
    assert expected["payEth(address,uint256)"] == [
        {
            "direction": "eth_out",
            "token_var": "to",
            "token_type": "ETH",
            "method": "call{value}",
            "is_parameter": True,
        }
    ]

    monkeypatch.setattr(HighLevelCall, "__str__", lambda self: "<opaque>")
    monkeypatch.setattr(LowLevelCall, "__str__", lambda self: "<opaque>")
    for sig, flows in expected.items():
        assert _extract_value_flows(functions[sig]) == flows, sig
