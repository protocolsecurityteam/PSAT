"""Interprocedural forwarded-destination/amount recovery (Part A fixes #1-#3).

The ``flow.out`` lattice walks value movement rooted at ONE external entry, so
the argument forwarded at each internal-call site along that single path is
unambiguous. These tests prove the recovery of a nested ``parameter``
destination/amount to the entry-rooted origin it was forwarded from — the
recall regression that collapsed 76/78 live destinations to ``indeterminate``
because every real ETH send lives one hop inside a helper/library.

Recovered:
  * an OZ ``Address.sendValue`` / ``functionCallWithValue`` library shape;
  * a multi-hop (3-hop) forwarded ``receiver`` chain -> ``param``;
  * a ``msg.sender`` / ``tx.origin`` / immutable / state-var forwarded origin;
  * the same for ``amount_kind``;
  * a mapping-element / storage-struct destination (``_requests[id].recipient``)
    -> ``storage_setter`` (redirectable base var), NEVER ``param``.

Held at the witness bar (stay ``indeterminate``):
  * a helper reached from two call sites with DIVERGENT forwarded origins.

Precedent: ``tests/test_flow_lattice.py`` (same compile-with-Slither harness).
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


def _out_flow(info, kind: str | None = None) -> Any:
    flows: list[Any] = [vf for vf in info["value_flows"] if vf["direction"] == "out"]
    if kind is not None:
        flows = [vf for vf in flows if vf["kind"] == kind]
    assert flows, f"no matching out-flow in {info['value_flows']}"
    return flows[0]


# --- OZ Address.sendValue / functionCallWithValue library shape ------------

_OZ_ADDRESS_SRC = """
pragma solidity ^0.8.20;

library Address {
    function sendValue(address payable recipient, uint256 amount) internal {
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "Address: send failed");
    }
    function functionCallWithValue(address target, bytes memory data, uint256 value)
        internal returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "Address: call failed");
        return ret;
    }
}

contract Vault {
    address public immutable treasury;
    constructor(address t) { treasury = t; }

    // Caller-chosen recipient forwarded through the library send site.
    function withdraw(address to, uint256 amt) external {
        Address.sendValue(payable(to), amt);
    }

    // Immutable recipient forwarded through the library — recovers to immutable.
    function payTreasury(uint256 amt) external {
        Address.sendValue(payable(treasury), amt);
    }

    // functionCallWithValue shape: caller destination + caller value.
    function forward(address to, bytes calldata data, uint256 value) external {
        Address.functionCallWithValue(to, data, value);
    }
}
"""


def test_oz_sendvalue_recovers_forwarded_param(tmp_path):
    contract = _compile(tmp_path, _OZ_ADDRESS_SRC, "Vault")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdraw(address,uint256)"])
    # ``to`` is the entry's caller-chosen param, forwarded (through a payable
    # cast) into the library's ``recipient.call{value: amount}`` site.
    assert flow["target_kind"] == {"kind": "param", "tier": "static_trace"}
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


def test_oz_sendvalue_recovers_forwarded_immutable(tmp_path):
    contract = _compile(tmp_path, _OZ_ADDRESS_SRC, "Vault")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payTreasury(uint256)"])
    # The immutable ``treasury`` forwarded into the library survives as immutable
    # (operational routing), distinct from the caller-chosen case above.
    assert flow["target_kind"]["kind"] == "immutable"
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


def test_oz_functioncallwithvalue_recovers(tmp_path):
    contract = _compile(tmp_path, _OZ_ADDRESS_SRC, "Vault")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["forward(address,bytes,uint256)"])
    assert flow["target_kind"]["kind"] == "param"
    assert flow["amount_kind"]["kind"] == "param"


# --- Multi-hop (3-hop) forwarded receiver chain ----------------------------

_MULTIHOP_SRC = """
pragma solidity ^0.8.20;
contract Redemption {
    // redeemEEth(receiver) -> _redeemEEth -> _redeem -> _processETHRedemption ->
    // receiver.call{value:}. The caller-chosen ``receiver`` is 3 hops deep.
    function redeemEEth(uint256 amount, address receiver) external {
        _redeemEEth(amount, receiver);
    }
    function _redeemEEth(uint256 amount, address receiver) internal {
        _redeem(amount, receiver);
    }
    function _redeem(uint256 ethAmount, address receiver) internal {
        _processETHRedemption(receiver, ethAmount);
    }
    function _processETHRedemption(address receiver, uint256 ethReceived) internal {
        (bool ok, ) = receiver.call{value: ethReceived}("");
        require(ok);
    }
}
"""


def test_three_hop_forwarded_receiver_recovers_to_param(tmp_path):
    contract = _compile(tmp_path, _MULTIHOP_SRC, "Redemption")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["redeemEEth(uint256,address)"])
    # ``receiver`` chains param->param->param across three internal calls.
    assert flow["target_kind"] == {"kind": "param", "tier": "static_trace"}
    # ``ethReceived`` is forwarded from ``amount`` (entry param) too.
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


# --- msg.sender / tx.origin forwarded into a helper ------------------------

_CALLER_FORWARD_SRC = """
pragma solidity ^0.8.20;
contract Caller {
    function withdraw(uint256 amt) external { _send(msg.sender, amt); }
    function withdrawToOrigin(uint256 amt) external { _send(tx.origin, amt); }
    function _send(address to, uint256 x) internal {
        (bool ok, ) = payable(to).call{value: x}("");
        require(ok);
    }
}
"""


def test_msg_sender_forwarded_into_helper(tmp_path):
    contract = _compile(tmp_path, _CALLER_FORWARD_SRC, "Caller")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdraw(uint256)"])
    assert flow["target_kind"] == {"kind": "msg_sender", "tier": "static_trace"}
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


def test_tx_origin_forwarded_into_helper(tmp_path):
    contract = _compile(tmp_path, _CALLER_FORWARD_SRC, "Caller")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdrawToOrigin(uint256)"])
    assert flow["target_kind"] == {"kind": "caller_controlled", "tier": "static_trace"}


# --- immutable / state-var forwarded destination + amount ------------------

_STATEVAR_FORWARD_SRC = """
pragma solidity ^0.8.20;
contract Routed {
    address public immutable sink;
    address public treasury;         // has a setter -> storage_setter
    uint256 public cap;              // has a setter -> bounded_by_storage
    constructor(address s) { sink = s; }
    function setTreasury(address t) external { treasury = t; }
    function setCap(uint256 c) external { cap = c; }

    // Immutable destination forwarded; amount forwarded from a state var.
    function drainToSink() external { _send(sink, cap); }
    // Storage-setter destination forwarded.
    function drainToTreasury(uint256 amt) external { _send(treasury, amt); }

    function _send(address to, uint256 x) internal {
        (bool ok, ) = payable(to).call{value: x}("");
        require(ok);
    }
}
"""


def test_immutable_destination_and_storage_amount_forwarded(tmp_path):
    contract = _compile(tmp_path, _STATEVAR_FORWARD_SRC, "Routed")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["drainToSink()"])
    assert flow["target_kind"]["kind"] == "immutable"
    # ``cap`` (a state var) forwarded as the amount -> bounded_by_storage.
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"


def test_storage_setter_destination_forwarded(tmp_path):
    contract = _compile(tmp_path, _STATEVAR_FORWARD_SRC, "Routed")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["drainToTreasury(uint256)"])
    assert flow["target_kind"]["kind"] == "storage_setter"
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


# --- Mapping-element / storage-struct destination (fix #3) -----------------

_MAPPING_ELEMENT_SRC = """
pragma solidity ^0.8.20;
contract Requests {
    struct Req { address recipient; uint256 amount; }
    mapping(uint256 => Req) public _requests;
    uint256 public nextId;

    // The mapping is written on the request-creation path -> a redirecting
    // writer of ``_requests`` exists, so its element destination is storage_setter.
    function request(address r, uint256 a) external returns (uint256 id) {
        id = nextId++;
        _requests[id] = Req(r, a);
    }

    // Destination is a struct field of a mapping element: base state-var mapping
    // + parameter key. Classified by the base var, never the key.
    function claim(uint256 id) external {
        Req storage rq = _requests[id];
        (bool ok, ) = payable(rq.recipient).call{value: rq.amount}("");
        require(ok);
    }

    // Same element destination, but reached one hop inside a helper.
    function claimVia(uint256 id) external { _claim(id); }
    function _claim(uint256 id) internal {
        (bool ok, ) = payable(_requests[id].recipient).call{value: _requests[id].amount}("");
        require(ok);
    }
}
"""


def test_mapping_element_destination_is_storage_setter(tmp_path):
    contract = _compile(tmp_path, _MAPPING_ELEMENT_SRC, "Requests")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["claim(uint256)"])
    kind = flow["target_kind"]["kind"]
    # The base mapping ``_requests`` is written on the request path -> redirectable.
    assert kind == "storage_setter", kind
    # NEVER a caller-directed ``param`` (would under-flag an attacker-influenceable
    # per-key destination), NEVER a false ``storage_no_setter`` / indeterminate.
    assert kind not in ("param", "storage_no_setter", "indeterminate")


def test_mapping_element_destination_via_helper_is_storage_setter(tmp_path):
    contract = _compile(tmp_path, _MAPPING_ELEMENT_SRC, "Requests")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["claimVia(uint256)"])
    assert flow["target_kind"]["kind"] == "storage_setter"


# --- Negative: divergent multi-caller binding stays indeterminate ----------

_DIVERGENT_SRC = """
pragma solidity ^0.8.20;
contract Divergent {
    address public immutable feeSink;
    constructor(address f) { feeSink = f; }

    // One entry reaches the shared helper from TWO call sites with DIFFERENT
    // destination origins: a caller param on one, an immutable on the other.
    // The single-entry walk re-walks the helper per binding and the cross-site
    // fold collapses the disagreement to indeterminate. The amount is ``amt`` on
    // both sites, so it stays recoverable.
    function router(address a, uint256 amt) external {
        _pay(a, amt);
        _pay(feeSink, amt);
    }
    function _pay(address d, uint256 x) internal {
        (bool ok, ) = payable(d).call{value: x}("");
        require(ok);
    }
}
"""


def test_divergent_multi_caller_destination_is_indeterminate(tmp_path):
    contract = _compile(tmp_path, _DIVERGENT_SRC, "Divergent")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["router(address,uint256)"])
    # param (site 1) vs immutable (site 2) -> never guess a member of the union.
    assert flow["target_kind"] == {"kind": "indeterminate", "tier": "static_trace"}
    # The amount is unambiguously the same forwarded param at both sites.
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


# --- Zero-value call is not a flow (OZ SafeERC20 / Address shape) -----------
# A ``.call{value: value}`` whose ``value`` is a provably-constant 0 (OZ's
# ``Address.functionCallWithValue(target, data, 0)``, the way SafeERC20 routes a
# token transfer) moves no ETH. It must NOT register as a value-out flow, or it
# folds with the function's real ETH send and collapses the recovered
# destination to ``indeterminate`` — the exact SafeERC20 pollution seen on the
# real EtherFiRedemptionManager.

_ZERO_VALUE_SRC = """
pragma solidity ^0.8.20;

library Address {
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }
    function functionCallWithValue(address target, bytes memory data, uint256 value)
        internal returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok);
        return ret;
    }
    function sendValue(address payable recipient, uint256 amount) internal {
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok);
    }
}

contract Mixed {
    address public immutable token;
    constructor(address t) { token = t; }

    // A real caller-directed ETH send AND a zero-value token call in one function.
    // Only the ETH send is a value-out flow; the destination must recover to param.
    function redeem(address receiver, uint256 amt, bytes calldata data) external {
        Address.functionCall(token, data);   // value:0 — not a flow
        Address.sendValue(payable(receiver), amt);  // real ETH send -> param
    }

    // A function whose ONLY call is the zero-value one: no value-out flow at all.
    function poke(bytes calldata data) external {
        Address.functionCall(token, data);
    }
}
"""


def test_zero_value_call_does_not_pollute_real_send(tmp_path):
    contract = _compile(tmp_path, _ZERO_VALUE_SRC, "Mixed")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["redeem(address,uint256,bytes)"])
    # The zero-value token call is excluded, so the real ETH send's caller
    # destination survives the fold instead of collapsing to indeterminate.
    assert flow["target_kind"] == {"kind": "param", "tier": "static_trace"}
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


def test_zero_value_only_function_has_no_value_flow(tmp_path):
    contract = _compile(tmp_path, _ZERO_VALUE_SRC, "Mixed")
    effects = build_effects(contract)
    outs = [vf for vf in effects["functions"]["poke(bytes)"]["value_flows"] if vf["direction"] == "out"]
    assert outs == [], outs


# --- Witness bar: a COMPUTED operand must never recover a member of a union ---
# The forwarded-param recovery drops the entrypoint-Phi echoes that sit beside a
# DIRECTLY-read nested parameter (they can only be the parameter's own binding
# from other call sites). But a ``computed`` operand (Binary/Member/…) attaches
# its wrapper alongside ALL operand sources, so it can carry a GENUINE co-origin
# with no Phi. Dropping it there would guess the ``param`` member of a real
# union and make the nested classification MORE specific than the byte-identical
# entry-level code. The invariant these guard: nested classification is never
# more specific than the same operand shape classified at the entry.

_COMPUTED_MIX_SRC = """
pragma solidity ^0.8.20;
contract Mix {
    address public owner;
    uint256 public rate;

    // dest = f(caller param, state var) -> genuine {parameter, state_variable}
    // union with a computed wrapper. Nested must match the entry twin.
    function payDestNested(address to) external { _sendDest(to); }
    function _sendDest(address to) internal {
        address dest = address(uint160(to) ^ uint160(owner));
        (bool ok, ) = dest.call{value: 1}("");
        require(ok);
    }
    function payDestEntry(address to) external {
        address dest = address(uint160(to) ^ uint160(owner));
        (bool ok, ) = dest.call{value: 1}("");
        require(ok);
    }

    // amount = caller param * storage rate -> genuine mix.
    function payAmtNested(address payable to, uint256 amt) external { _sendAmt(to, amt); }
    function _sendAmt(address payable to, uint256 amt) internal {
        (bool ok, ) = to.call{value: amt * rate}("");
        require(ok);
    }
    function payAmtEntry(address payable to, uint256 amt) external {
        (bool ok, ) = to.call{value: amt * rate}("");
        require(ok);
    }

    receive() external payable {}
}
"""


def test_computed_destination_mix_matches_entry_indeterminate(tmp_path):
    contract = _compile(tmp_path, _COMPUTED_MIX_SRC, "Mix")
    effects = build_effects(contract)
    nested = _out_flow(effects["functions"]["payDestNested(address)"])
    entry = _out_flow(effects["functions"]["payDestEntry(address)"])
    # A param^stateVar destination is a real union: never guess the param member.
    assert nested["target_kind"]["kind"] == "indeterminate"
    assert entry["target_kind"]["kind"] == "indeterminate"


def test_computed_amount_mix_matches_entry_indeterminate(tmp_path):
    contract = _compile(tmp_path, _COMPUTED_MIX_SRC, "Mix")
    effects = build_effects(contract)
    nested = _out_flow(effects["functions"]["payAmtNested(address,uint256)"])
    entry = _out_flow(effects["functions"]["payAmtEntry(address,uint256)"])
    # amt * rate mixes a caller param with a storage value -> indeterminate.
    assert nested["amount_kind"]["kind"] == "indeterminate"
    assert entry["amount_kind"]["kind"] == "indeterminate"


_STRUCT_MEMBER_SRC = """
pragma solidity ^0.8.20;
contract StructMember {
    struct Payout { address recipient; uint256 amount; }
    // A struct-member read off a caller-supplied struct param, one hop deep. The
    // Member op attaches a computed wrapper, but its ONLY non-computed source is
    // the forwarded param, so the computed-but-single-origin shape still recovers.
    function pay(Payout calldata p) external { _send(p); }
    function _send(Payout calldata p) internal {
        (bool ok, ) = p.recipient.call{value: p.amount}("");
        require(ok);
    }
    receive() external payable {}
}
"""


def test_computed_single_origin_struct_member_still_recovers(tmp_path):
    contract = _compile(tmp_path, _STRUCT_MEMBER_SRC, "StructMember")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["pay(StructMember.Payout)"])
    # recipient/amount are members of a forwarded caller struct -> caller-directed.
    assert flow["target_kind"] == {"kind": "param", "tier": "static_trace"}
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}
