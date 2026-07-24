"""Regression tests for the ``flow.out`` destination/amount lattice (SDG §3).

Each test compiles a real Solidity fixture with Slither and drives the
production ``build_effects`` (and, for the passthrough test, ``build_claims``)
sequence — no fakes, only the solc compile is real. Precedent:
``tests/test_effects_facts.py``.

These fixtures are the guard for the two −12 theft-vs-routing false positives:
an immutable/fixed destination (operational routing) must classify distinctly
from a caller-chosen one (extraction), and any ambiguity must degrade to
``indeterminate`` rather than silently guessing a member of the union.
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

from services.static.claims import build_claims  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402


def _compile(tmp_path: Path, source: str, name: str):
    f = tmp_path / f"{name}.sol"
    f.write_text(textwrap.dedent(source).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == name)


def _out_flow(info, kind: str | None = None) -> Any:
    flows: list[Any] = [vf for vf in info["value_flows"] if vf["direction"] == "out"]
    if kind is not None:
        flows = [vf for vf in flows if vf["kind"] == kind]
    assert flows, f"no matching out-flow in {info['value_flows']}"
    return flows[0]


LATTICE_SRC = """
pragma solidity ^0.8.20;

interface ILP { function totalValueOutOfLp() external view returns (uint256); }
interface IERC20 { function transfer(address,uint256) external returns (bool); }

library Math { function min(uint256 a, uint256 b) internal pure returns (uint256){ return a < b ? a : b; } }

contract Lattice {
    ILP public immutable liquidityPool;
    address public immutable feeSink;
    address public treasury;               // has a setter -> storage_setter
    address public collector;              // no setter    -> storage_no_setter
    address public constant BURN = address(0xdead);
    uint256 public cap;

    constructor(ILP lp, address fs) { liquidityPool = lp; feeSink = fs; }

    function setTreasury(address t) external { treasury = t; }

    // Cast-through-immutable (the withdrawEther shape): dest is a TMP from
    // address(liquidityPool) -> immutable, static_trace. Amount is a Math.min
    // mix of balance and a view call -> indeterminate.
    function withdrawEther() external {
        uint256 amt = Math.min(address(this).balance, liquidityPool.totalValueOutOfLp());
        (bool ok,) = payable(address(liquidityPool)).call{value: amt}("");
        require(ok);
    }

    // Caller-supplied destination + caller-supplied amount = extraction.
    function payTo(address dest, uint256 amount) external {
        (bool ok,) = payable(dest).call{value: amount}("");
        require(ok);
    }

    // Direct immutable destination (no cast): ERC20 send with a state var arg0
    // -> immutable, dispositive_ast. msg.sender is a direct caller read.
    function feeToSink(address tok, uint256 amt) external {
        IERC20(tok).transfer(feeSink, amt);
    }

    function claim(address tok, uint256 amt) external {
        IERC20(tok).transfer(msg.sender, amt);
    }

    // storage_setter destination + storage amount.
    function payTreasury() external {
        (bool ok,) = payable(treasury).call{value: cap}("");
        require(ok);
    }

    // storage_no_setter destination (collector is never written outside ctor).
    function payCollector() external {
        (bool ok,) = payable(collector).call{value: 1 ether}("");
        require(ok);
    }

    // constant destination + msg.value amount.
    function toBurn() external payable {
        (bool ok,) = payable(BURN).call{value: msg.value}("");
        require(ok);
    }

    // Cross-branch MIX: caller param on one path, immutable on the other.
    // The union absorbs to TOP -> indeterminate. Never guess a member.
    function payMix(bool cond, address who, uint256 amt) external {
        if (cond) { (bool a,) = payable(who).call{value: amt}(""); require(a); }
        else { (bool b,) = payable(address(liquidityPool)).call{value: amt}(""); require(b); }
    }

    // Native transfer to an immutable destination + whole-balance amount.
    function sweep() external {
        payable(address(liquidityPool)).transfer(address(this).balance);
    }
}
"""


def test_cast_through_immutable_destination(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdrawEther()"])
    assert flow["target_kind"] == {"kind": "immutable", "tier": "static_trace"}
    # Math.min(balance, view_call) is not a single unambiguous origin.
    assert flow["amount_kind"] == {"kind": "indeterminate", "tier": "static_trace"}


def test_caller_param_destination_is_extraction(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payTo(address,uint256)"])
    assert flow["target_kind"]["kind"] == "param"
    assert flow["amount_kind"] == {"kind": "param", "tier": "dispositive_ast"}


def test_direct_immutable_is_dispositive(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["feeToSink(address,uint256)"])
    assert flow["target_kind"] == {"kind": "immutable", "tier": "dispositive_ast"}
    assert flow["amount_kind"] == {"kind": "param", "tier": "dispositive_ast"}


def test_msg_sender_destination(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["claim(address,uint256)"])
    assert flow["target_kind"] == {"kind": "msg_sender", "tier": "dispositive_ast"}


def test_storage_setter_vs_no_setter(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    setter = _out_flow(effects["functions"]["payTreasury()"])
    assert setter["target_kind"]["kind"] == "storage_setter"
    assert setter["amount_kind"] == {"kind": "bounded_by_storage", "tier": "dispositive_ast"}
    no_setter = _out_flow(effects["functions"]["payCollector()"])
    assert no_setter["target_kind"]["kind"] == "storage_no_setter"
    assert no_setter["amount_kind"] == {"kind": "fixed_constant", "tier": "dispositive_ast"}


def test_constant_destination_and_msg_value(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["toBurn()"])
    assert flow["target_kind"]["kind"] == "constant"
    assert flow["amount_kind"] == {"kind": "msg_value", "tier": "dispositive_ast"}


def test_cross_branch_mix_is_indeterminate(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payMix(bool,address,uint256)"])
    # param on one branch, immutable on the other -> never collapse to a member.
    assert flow["target_kind"] == {"kind": "indeterminate", "tier": "static_trace"}


def test_native_transfer_immutable_whole_balance(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["sweep()"], kind="native_transfer_send")
    assert flow["target_kind"]["kind"] == "immutable"
    assert flow["amount_kind"] == {"kind": "whole_balance", "tier": "static_trace"}


INDIRECTION_SRC = """
pragma solidity ^0.8.20;

interface ILP { function x() external view returns (uint256); }

contract Indirection {
    ILP public immutable liquidityPool;
    constructor(ILP lp) { liquidityPool = lp; }

    // Entry -> internal helper that reads the STATE var directly. A state var is
    // contract-global, so the classification survives the internal-call boundary.
    function withdrawEther() external { _withdrawEther(); }
    function _withdrawEther() internal {
        (bool ok,) = payable(address(liquidityPool)).call{value: address(this).balance}("");
        require(ok);
    }

    // Entry forwards a caller parameter into a helper. Inside the helper a
    // ``param`` origin is ambiguous (the entry could pass a fixed var OR a
    // caller address), so it must degrade to indeterminate, not claim theft.
    function payForward(address dest, uint256 amt) external { _pay(dest, amt); }
    function _pay(address d, uint256 a) internal {
        (bool ok,) = payable(d).call{value: a}("");
        require(ok);
    }
}
"""


def test_state_var_survives_internal_call(tmp_path):
    contract = _compile(tmp_path, INDIRECTION_SRC, "Indirection")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdrawEther()"])
    assert flow["target_kind"]["kind"] == "immutable"


def test_forwarded_param_is_indeterminate_in_callee(tmp_path):
    contract = _compile(tmp_path, INDIRECTION_SRC, "Indirection")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payForward(address,uint256)"])
    assert flow["target_kind"] == {"kind": "indeterminate", "tier": "static_trace"}
    assert flow["amount_kind"] == {"kind": "indeterminate", "tier": "static_trace"}


def test_lattice_reaches_the_claim_witness(tmp_path):
    """The classified fields survive projection into the ``flow.out`` claim
    witness the scorer/frontend read (matchers/flows.py)."""
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    claims = build_claims(contract, effects, {})["functions"]

    def flow_out_witness(sig):
        rows = [c for c in claims[sig] if c["claim_id"] == "flow.out"]
        assert rows, f"no flow.out claim on {sig}"
        return rows[0]["witness"]["flows"]

    theft = flow_out_witness("payTo(address,uint256)")
    assert any(e.get("target_kind", {}).get("kind") == "param" for e in theft)

    routing = flow_out_witness("withdrawEther()")
    assert any(e.get("target_kind") == {"kind": "immutable", "tier": "static_trace"} for e in routing)
