"""A library call publishes no selector of its own: the receiver it is handed never answers the library's selector.

``weth.safeApprove(spender, amount)`` compiles to a library call whose Slither spelling is
``safeApprove(IERC20,address,uint256)``; its hash (what the sink used to publish) is a selector WETH never answers. The
token-first value flow publishes the ERC-20 move the token provably receives instead. Pinned on real compiled
Solidity.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


SOURCE = """
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        (bool ok, bytes memory data) = address(token).call(abi.encodeWithSelector(token.transfer.selector, to, value));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory payload = abi.encodeWithSelector(token.approve.selector, spender, value);
        (bool ok, bytes memory data) = address(token).call(payload);
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "approve failed");
    }
}

library Calls {
    function poke(address target, uint256 value) internal returns (bool ok) {
        (ok, ) = target.call(abi.encodeWithSignature("poke(uint256)", value));
    }
}

library Scale {
    enum Rounding { Down, Up }
    function by(uint256 x, uint256 d) internal pure returns (uint256) { return x / d; }
    function by(uint256 x, uint256 d, Rounding r) internal pure returns (uint256) {
        return r == Rounding.Up ? (x + d - 1) / d : x / d;
    }
}

contract Payer {
    function pay(IERC20 token, address to, uint256 value) external {
        (bool ok, ) = address(token).call(abi.encodeWithSelector(token.transfer.selector, to, value));
        require(ok, "pay failed");
    }
}

contract Vault {
    using SafeERC20 for IERC20;
    using Calls for address;
    using Scale for uint256;

    IERC20 public weth;
    address public hook;

    function pay(address to, uint256 amount) external { weth.safeTransfer(to, amount); }
    function allow(address spender, uint256 amount) external { weth.safeApprove(spender, amount); }
    function direct(address to, uint256 amount) external { weth.transfer(to, amount); }
    function nudge(uint256 value) external { hook.poke(value); }
    function both(address to, address other, uint256 amount) external {
        weth.transfer(to, amount);
        weth.safeTransfer(other, amount);
    }
    function rounded(uint256 amount) external returns (uint256) {
        _n = amount.by(3) + amount.by(3, Scale.Rounding.Up);
        return _n;
    }
    uint256 internal _n;
    Payer public payer;
    function viaHelper(address to, uint256 amount) external { payer.pay(weth, to, amount); }
}
"""

LIBRARY_SPELLINGS = (
    "safeTransfer(IERC20,address,uint256)",
    "safeApprove(IERC20,address,uint256)",
    "poke(address,uint256)",
)


@pytest.fixture(scope="module")
def effects(tmp_path_factory) -> dict[str, Any]:
    path = tmp_path_factory.mktemp("library_selectors") / "Vault.sol"
    path.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    vault = next(c for c in Slither(str(path)).contracts if c.name == "Vault")
    return build_effects(vault)["functions"]


def _sink(effects: dict[str, Any], function: str, target: str) -> dict[str, Any]:
    (sink,) = [s for s in effects[function]["sinks"] if s["kind"] == "external_call" and s["target"] == target]
    return sink


@pytest.mark.parametrize(
    ("function", "target"),
    [
        ("pay(address,uint256)", "weth.safeTransfer"),
        ("allow(address,uint256)", "weth.safeApprove"),
        ("nudge(uint256)", "hook.poke"),
    ],
)
def test_a_library_call_sink_has_no_selector(effects, function, target):
    assert _sink(effects, function, target)["selector"] is None


def test_a_high_level_call_sink_keeps_the_dispatch_selector(effects):
    assert _sink(effects, "direct(address,uint256)", "weth.transfer")["selector"] == _sel("transfer(address,uint256)")


def test_a_token_first_library_flow_carries_the_move_the_token_receives(effects):
    flows = [f for f in effects["pay(address,uint256)"]["value_flows"] if f["kind"] == "callee_erc20_selector"]
    assert flows, "guard: the token-first recognizer must see SafeERC20.safeTransfer"
    assert {f["selector"] for f in flows} == {_sel("transfer(address,uint256)")}


def test_no_record_publishes_a_library_spelling_hash(effects):
    library_hashes = {_sel(spelling) for spelling in LIBRARY_SPELLINGS}
    published = {
        selector
        for record in effects.values()
        for item in [*record["sinks"], *record["value_flows"]]
        for selector in [item.get("selector"), *(op.get("selector") for op in item.get("router_ops") or [])]
        if selector
    }
    assert not published & library_hashes


def test_library_overloads_on_one_receiver_stay_distinct_sinks(effects):
    """With no selector to tell them apart, the library spelling (text, never hashed) keeps the overloads apart."""
    sinks = [s for s in effects["rounded(uint256)"]["sinks"] if s["target"] == "amount.by"]
    assert sorted(s["library_signature"] for s in sinks) == [
        "by(uint256,uint256)",
        "by(uint256,uint256,Scale.Rounding)",
    ]
    assert {s["selector"] for s in sinks} == {None}


def test_a_library_carried_move_stays_apart_from_a_direct_transfer(effects):
    flows = [f for f in effects["both(address,address,uint256)"]["value_flows"] if f["kind"] == "callee_erc20_selector"]
    assert sorted(tuple(f.get("library_callees") or ()) for f in flows) == [(), ("safeTransfer",)]
    assert {f["selector"] for f in flows} == {_sel("transfer(address,uint256)")}


def test_a_high_level_helper_flow_keeps_the_selector_its_sink_carries(effects):
    """A token-first move through a resolved helper keeps the helper's own selector: its sink publishes that one, and
    the flow claim finds its carrier by it.
    """
    helper = _sel("pay(address,address,uint256)")
    assert _sink(effects, "viaHelper(address,uint256)", "payer.pay")["selector"] == helper
    flows = [f for f in effects["viaHelper(address,uint256)"]["value_flows"] if f["kind"] == "callee_erc20_selector"]
    assert flows and {f["selector"] for f in flows} == {helper}
    assert not any(f.get("library_callees") for f in flows)
