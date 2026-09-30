"""``param_derived``: the amount is a call's return value with a caller parameter among its arguments (the ERC-4626
redeem / unwrap shape). Not a bound and not proof of caller control. No rule keys on a callee name.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402


def _compile(tmp_path: Path, source: str, name: str):
    f = tmp_path / f"{name}.sol"
    f.write_text(textwrap.dedent(source).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == name)


def _out_flow(info) -> Any:
    flows = [vf for vf in info["value_flows"] if vf["direction"] == "out"]
    assert flows, f"no out-flow in {info['value_flows']}"
    return flows[0]


PARAM_DERIVED_SRC = """
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address to, uint256 amount) external returns (bool); }

interface IRateLike {
    function convertToAssets(uint256 shares) external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function quote(uint256 a, uint256 b) external view returns (uint256);
    function payeeOf(uint256 id) external view returns (address);
}

contract Wrapper {
    IERC20Like public token;
    IRateLike public rate;
    uint256 public storedShares;

    // THE SHAPE: the caller names an input, an external contract scales it, the
    // scaled result leaves.
    function unwrap(uint256 shares) external {
        token.transfer(msg.sender, rate.convertToAssets(shares));
    }

    // The same shape behind an internal hop. Nested must classify EXACTLY as the
    // inline entry does — never more specific.
    function unwrapVia(uint256 shares) external { _send(shares); }
    function _send(uint256 shares) internal {
        token.transfer(msg.sender, rate.convertToAssets(shares));
    }

    // A second caller input in a LATER slot: the kind holds, and so does the
    // index, which must name the converted input (slot 1) and not slot 0.
    function unwrapFor(address to, uint256 shares) external {
        token.transfer(to, rate.convertToAssets(shares));
    }

    // NEGATIVE: a plain caller-supplied amount stays ``param``.
    function payout(uint256 amount) external {
        token.transfer(msg.sender, amount);
    }

    // NEGATIVE: a call with NO caller input among its arguments. Nothing the
    // caller supplied reached the conversion.
    function drain() external {
        token.transfer(msg.sender, rate.totalAssets());
    }

    // NEGATIVE: the conversion's input is contract storage, not a caller input.
    function drainStored() external {
        token.transfer(msg.sender, rate.convertToAssets(storedShares));
    }

    // TWO distinct caller inputs feed the call: still param-derived, but no slot
    // may be published — either choice would be a guess.
    function unwrapPair(uint256 a, uint256 b) external {
        token.transfer(msg.sender, rate.quote(a, b));
    }

    // NEGATIVE: the amount is only TAINTED by the call, it is not the call's
    // return value. The positive def-chain test must refuse it.
    function unwrapMangled(uint256 shares) external {
        token.transfer(msg.sender, rate.convertToAssets(shares) + 1);
    }

    // NEGATIVE: a two-branch merge. The union must not collapse onto either arm.
    function unwrapUnion(uint256 shares, bool flag) external {
        token.transfer(msg.sender, flag ? rate.convertToAssets(shares) : storedShares);
    }

    // The DESTINATION twin of the shape: an address read back from a call whose
    // argument is a caller input. ``param_derived`` is amount-only and must never
    // appear on a destination.
    function payLookup(uint256 id) external {
        token.transfer(rate.payeeOf(id), 1);
    }
}
"""


@pytest.fixture(scope="module")
def flows(tmp_path_factory):
    contract = _compile(tmp_path_factory.mktemp("param_derived"), PARAM_DERIVED_SRC, "Wrapper")
    fns = build_effects(contract)["functions"]
    return {
        name: _out_flow(info) for name, info in fns.items() if any(f["direction"] == "out" for f in info["value_flows"])
    }


def test_external_conversion_of_a_caller_input_is_param_derived(flows):
    flow = flows["unwrap(uint256)"]
    assert flow["amount_kind"] == {"kind": "param_derived", "tier": "static_trace"}, flow
    assert flow["amount_param_index"] == 0, flow


def test_param_derived_index_names_the_converted_input_slot(flows):
    flow = flows["unwrapFor(address,uint256)"]
    assert flow["amount_kind"]["kind"] == "param_derived", flow
    assert flow["amount_param_index"] == 1, flow


def test_param_derived_nested_matches_inline_entry(flows):
    assert flows["unwrapVia(uint256)"]["amount_kind"] == flows["unwrap(uint256)"]["amount_kind"]
    assert flows["unwrapVia(uint256)"]["amount_param_index"] == flows["unwrap(uint256)"]["amount_param_index"]


def test_call_without_a_caller_input_stays_indeterminate(flows):
    flow = flows["drain()"]
    assert flow["amount_kind"]["kind"] == "indeterminate", flow
    assert "amount_param_index" not in flow, flow


def test_conversion_of_storage_stays_indeterminate(flows):
    flow = flows["drainStored()"]
    assert flow["amount_kind"]["kind"] == "indeterminate", flow


def test_two_caller_inputs_keep_the_kind_but_publish_no_slot(flows):
    flow = flows["unwrapPair(uint256,uint256)"]
    assert flow["amount_kind"]["kind"] == "param_derived", flow
    assert "amount_param_index" not in flow, flow


def test_arithmetic_on_a_conversion_is_not_param_derived(flows):
    flow = flows["unwrapMangled(uint256)"]
    assert flow["amount_kind"]["kind"] == "indeterminate", flow


def test_merge_with_storage_names_both_amounts(flows):
    flow = flows["unwrapUnion(uint256,bool)"]
    assert flow["amount_kind"]["kind"] == "several", flow
    assert {e["kind"] for e in flow["amount_kinds"]} == {"param_derived", "bounded_by_storage"}, flow
    assert "amount_param_index" not in flow, flow


def test_param_derived_never_reaches_a_destination(flows):
    for name, flow in flows.items():
        assert flow["target_kind"]["kind"] != "param_derived", (name, flow)
    assert flows["payLookup(uint256)"]["target_kind"]["kind"] == "indeterminate", flows["payLookup(uint256)"]
