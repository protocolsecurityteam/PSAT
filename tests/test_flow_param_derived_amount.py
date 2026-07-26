"""Regression tests for the ``param_derived`` amount kind.

The shape is the ERC-4626 redemption / rebasing-wrapper unwrap: the caller
supplies an input, an EXTERNAL contract scales it, and the scaled result is what
leaves (``token.transfer(msg.sender, rate.convertToAssets(shares))``). It used to
classify ``indeterminate``, indistinguishable from "we traced nothing".

What the kind claims is deliberately narrow — the amount IS a call's return value
and a caller-supplied entry parameter was among that call's arguments. It is NOT
a bound (the callee's rate is unseen state that can move arbitrarily) and NOT
proof of caller control (we cannot see whether the callee honors its argument).
The tests below pin both the recall and those limits.

Same harness as ``tests/test_flow_lattice.py`` — a real solc compile driving the
production ``build_effects``. Every fixture is SYNTHETIC and minimal, and no rule
here keys on a callee name: ``convertToAssets`` is written only because some name
must appear in the source.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
    """The load-bearing one: the ERC-4626 / unwrap shape gets a name instead of
    collapsing into the same bucket as an untraced amount."""
    flow = flows["unwrap(uint256)"]
    assert flow["amount_kind"] == {"kind": "param_derived", "tier": "static_trace"}, flow
    assert flow["amount_param_index"] == 0, flow


def test_param_derived_index_names_the_converted_input_slot(flows):
    """The index is the slot of the caller input that FED the conversion — not
    slot 0 by luck, and not the amount's own slot (it has none)."""
    flow = flows["unwrapFor(address,uint256)"]
    assert flow["amount_kind"]["kind"] == "param_derived", flow
    assert flow["amount_param_index"] == 1, flow


def test_param_derived_nested_matches_inline_entry(flows):
    """Entry-vs-nested parity: an internal hop must not make the classification
    more specific than the identical operand shape written at the entry."""
    assert flows["unwrapVia(uint256)"]["amount_kind"] == flows["unwrap(uint256)"]["amount_kind"]
    assert flows["unwrapVia(uint256)"]["amount_param_index"] == flows["unwrap(uint256)"]["amount_param_index"]


def test_plain_param_amount_is_unchanged(flows):
    flow = flows["payout(uint256)"]
    assert flow["amount_kind"]["kind"] == "param", flow
    assert flow["amount_param_index"] == 0, flow


def test_call_without_a_caller_input_stays_indeterminate(flows):
    flow = flows["drain()"]
    assert flow["amount_kind"]["kind"] == "indeterminate", flow
    assert "amount_param_index" not in flow, flow


def test_conversion_of_storage_stays_indeterminate(flows):
    """A storage input is not a caller input; the kind says the CALLER supplied
    something, so a state-var argument must not earn it."""
    flow = flows["drainStored()"]
    assert flow["amount_kind"]["kind"] == "indeterminate", flow


def test_two_caller_inputs_keep_the_kind_but_publish_no_slot(flows):
    flow = flows["unwrapPair(uint256,uint256)"]
    assert flow["amount_kind"]["kind"] == "param_derived", flow
    assert "amount_param_index" not in flow, flow


def test_arithmetic_on_a_conversion_is_not_param_derived(flows):
    """``convertToAssets(shares) + 1`` is not the call's return value. The kind
    is a positive def-chain test precisely so a tainted value cannot borrow it."""
    flow = flows["unwrapMangled(uint256)"]
    assert flow["amount_kind"]["kind"] == "indeterminate", flow


def test_merge_with_storage_names_both_amounts(flows):
    """A conversion result on one branch, a storage bound on the other. Both are
    resolved, so the fold names them instead of reporting "unknown" — and neither
    may be promoted to stand for the whole."""
    flow = flows["unwrapUnion(uint256,bool)"]
    assert flow["amount_kind"]["kind"] == "one_of", flow
    assert {e["kind"] for e in flow["amount_kinds"]} == {"param_derived", "bounded_by_storage"}, flow
    # A disjunction is not a slot: neither branch's index may be published.
    assert "amount_param_index" not in flow, flow


def test_param_derived_never_reaches_a_destination(flows):
    """Amount-only. A destination read back from a call whose argument is a
    caller input is still ``indeterminate`` — the kind describes a quantity's
    provenance and says nothing about an address."""
    for name, flow in flows.items():
        assert flow["target_kind"]["kind"] != "param_derived", (name, flow)
    assert flows["payLookup(uint256)"]["target_kind"]["kind"] == "indeterminate", flows["payLookup(uint256)"]
