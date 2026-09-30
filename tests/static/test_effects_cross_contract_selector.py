"""The join keys on the callee's canonical selector, so struct/enum/interface params must be lowered as the callee
did.

A LibraryCall has no external selector.
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402


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
    assert _selector_for(effects, "doAdd()", "sib.addAsset") == _sel("addAsset(address)")


def test_struct_and_enum_param_call_selector_is_canonical(effects):
    assert _selector_for(effects, "doCfg(Report)", "sib.configure") == _sel("configure((uint256,address),uint8)")
