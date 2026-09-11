"""The cross-contract join matches a caller's body sink against the callee's OWN
canonical selector. So the emitter must record a *canonical* selector for a
direct high-level call, lowering user-defined parameter types the same way the
callee's selector was derived — otherwise a call to a sibling function taking a
struct / enum / interface parameter joins on a keccak of ``addAsset(ERC20)`` that
is not the real EVM selector, and the claim silently fails to propagate.

A LibraryCall's callee is a library internal with no external selector, and
nothing joins against it, so its notional selector is left untouched (its shape
is ubiquitous — churning it would bury the real change).
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.static_analysis.effects import build_effects  # noqa: E402


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

enum Mode { A, B }
struct Report { uint256 amount; address who; }

interface IToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
interface ISibling {
    function addAsset(IToken token) external;             // interface param -> address
    function configure(Report calldata r, Mode m) external;  // struct + enum
}

library SafeERC20 {
    function safeTransferFrom(IToken token, address from, address to, uint256 amount) internal {
        require(token.transferFrom(from, to, amount));
    }
}

contract Caller {
    using SafeERC20 for IToken;
    ISibling public sib;
    IToken public underlying;

    function doAdd() external { sib.addAsset(underlying); }
    function doCfg(Report calldata r) external { sib.configure(r, Mode.A); }
    function doPull(uint256 a) external {
        IToken(address(underlying)).safeTransferFrom(msg.sender, address(this), a);
    }
}
"""


@pytest.fixture(scope="module")
def effects(tmp_path_factory):
    f = tmp_path_factory.mktemp("xc") / "Caller.sol"
    f.write_text(textwrap.dedent(_SRC).strip() + "\n")
    sl = Slither(str(f))
    contract = next(c for c in sl.contracts if c.name == "Caller")
    return build_effects(contract)


def _selector_for(effects, fn_sig: str, target: str) -> str:
    sinks = [s for s in effects["functions"][fn_sig]["sinks"] if s["kind"] == "external_call" and s["target"] == target]
    assert sinks, (fn_sig, target, effects["functions"][fn_sig]["sinks"])
    return sinks[0]["selector"]


def test_interface_param_call_selector_is_canonical(effects):
    # ``sib.addAsset(IToken)`` must record the selector of ``addAsset(address)``,
    # which is the sibling's own canonical selector on the join.
    assert _selector_for(effects, "doAdd()", "sib.addAsset") == _sel("addAsset(address)")


def test_struct_and_enum_param_call_selector_is_canonical(effects):
    assert _selector_for(effects, "doCfg(Report)", "sib.configure") == _sel("configure((uint256,address),uint8)")


def test_library_call_selector_is_left_notional(effects):
    # The library internal has no external selector; the derived value keeps the
    # un-lowered interface param and is NOT the canonical form.
    lib_sel = _selector_for(effects, "doPull(uint256)", "underlying.safeTransferFrom")
    assert lib_sel == _sel("safeTransferFrom(IToken,address,address,uint256)")
    assert lib_sel != _sel("safeTransferFrom(address,address,address,uint256)")
