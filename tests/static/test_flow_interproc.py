"""Interprocedural forwarded destination/amount recovery (Part A #1-#3). Real ETH sends live one hop inside a
helper, which collapsed 76/78 live destinations to ``indeterminate``. Divergent origins, merged element bases
and balance deltas must still stay ``indeterminate``. Same harness as ``test_flow_lattice.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

slither = pytest.importorskip("slither")

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.summaries import _extract_value_flows  # noqa: E402
from tests.support.slither_compile import _compile_named  # noqa: E402


def _out_flow(info, kind: str | None = None) -> Any:
    flows: list[Any] = [vf for vf in info["value_flows"] if vf["direction"] == "out"]
    if kind is not None:
        flows = [vf for vf in flows if vf["kind"] == kind]
    assert flows, f"no matching out-flow in {info['value_flows']}"
    return flows[0]


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


_STATIC_TRACE = "static_trace"


@pytest.mark.parametrize(
    ("src", "contract_name", "signature", "expected"),
    [
        pytest.param(
            _CALLER_FORWARD_SRC,
            "Caller",
            "withdraw(uint256)",
            {
                "target_kind": {"kind": "msg_sender", "tier": _STATIC_TRACE},
                "amount_kind": {"kind": "param", "tier": _STATIC_TRACE},
            },
            id="msg_sender",
        ),
        pytest.param(
            _CALLER_FORWARD_SRC,
            "Caller",
            "withdrawToOrigin(uint256)",
            {"target_kind": {"kind": "caller_controlled", "tier": _STATIC_TRACE}},
            id="tx_origin",
        ),
        pytest.param(
            _STATEVAR_FORWARD_SRC,
            "Routed",
            "drainToSink()",
            {"target_kind": {"kind": "immutable"}, "amount_kind": {"kind": "bounded_by_storage"}},
            id="immutable_destination_and_storage_amount",
        ),
        pytest.param(
            _STATEVAR_FORWARD_SRC,
            "Routed",
            "drainToTreasury(uint256)",
            {
                "target_kind": {"kind": "storage_setter"},
                "amount_kind": {"kind": "param", "tier": _STATIC_TRACE},
            },
            id="storage_setter_destination",
        ),
    ],
)
def test_forwarded_helper_origin_kinds(tmp_path, src, contract_name, signature, expected):
    effects = build_effects(_compile_named(tmp_path, src, contract_name))
    flow = _out_flow(effects["functions"][signature])
    for key, want in expected.items():
        assert {field: flow[key][field] for field in want} == want


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


def test_mapping_element_destination_via_helper_is_storage_setter(tmp_path):
    contract = _compile_named(tmp_path, _MAPPING_ELEMENT_SRC, "Requests")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["claimVia(uint256)"])
    assert flow["target_kind"]["kind"] == "storage_setter"


# A provably-zero ``.call{value: 0}`` (SafeERC20's route) would collapse the real send's destination to
# ``indeterminate`` (seen on EtherFiRedemptionManager).


# A ``computed`` operand can carry a genuine co-origin with no Phi, so it never recovers a union member; nested must not
# be more specific than entry.

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
    contract = _compile_named(tmp_path, _COMPUTED_MIX_SRC, "Mix")
    effects = build_effects(contract)
    nested = _out_flow(effects["functions"]["payDestNested(address)"])
    entry = _out_flow(effects["functions"]["payDestEntry(address)"])
    assert nested["target_kind"]["kind"] == "indeterminate"
    assert entry["target_kind"]["kind"] == "indeterminate"


def test_computed_amount_mix_matches_entry_indeterminate(tmp_path):
    contract = _compile_named(tmp_path, _COMPUTED_MIX_SRC, "Mix")
    effects = build_effects(contract)
    nested = _out_flow(effects["functions"]["payAmtNested(address,uint256)"])
    entry = _out_flow(effects["functions"]["payAmtEntry(address,uint256)"])
    assert nested["amount_kind"]["kind"] == "indeterminate"
    assert entry["amount_kind"]["kind"] == "indeterminate"


# EtherFiRedemptionManager's ``balance - prevBalance`` is a bounded delta, not ``whole_balance``.


# Lido ``claimWithdrawalsTo``: the argument resolver must drop sibling entries' ``msg.sender`` Phi echoes like the
# use-site classifiers do.


# TimelockController ``executeBatch``: an element classifies from its root base; a storage root can never become
# ``param``.

_ELEMENT_SRC = """
pragma solidity ^0.8.20;
contract Batch {
    mapping(uint256 => address) public payees;   // written -> storage_setter
    mapping(uint256 => address) public backups;
    function setPayee(uint256 i, address p) external { payees[i] = p; }
    function setBackup(uint256 i, address p) external { backups[i] = p; }

    // TimelockController.executeBatch shape: caller array elements read in a
    // loop and forwarded into a helper.
    function executeBatch(address[] calldata targets, uint256[] calldata values) external {
        for (uint256 i = 0; i < targets.length; ++i) {
            address target = targets[i];
            uint256 value = values[i];
            _execute(target, value);
        }
    }
    // Entry twin: the identical element operand classified at the entry itself.
    function executeBatchEntry(address[] calldata targets, uint256[] calldata values) external {
        for (uint256 i = 0; i < targets.length; ++i) {
            (bool ok, ) = targets[i].call{value: values[i]}(""); require(ok);
        }
    }

    // Storage-rooted element, at the entry and forwarded as an argument.
    function payStored(uint256 i, uint256 amt) external {
        (bool ok, ) = payees[i].call{value: amt}(""); require(ok);
    }
    function payStoredVia(uint256 i, uint256 amt) external { _execute(payees[i], amt); }

    // The BASE is merged across branches -> genuinely ambiguous element.
    function payMergedBase(bool c, uint256 i, uint256 amt) external {
        mapping(uint256 => address) storage m = c ? payees : backups;
        (bool ok, ) = m[i].call{value: amt}(""); require(ok);
    }

    function _execute(address target, uint256 value) internal {
        (bool ok, ) = target.call{value: value}(""); require(ok);
    }
}
"""


_STRUCT_MEMBER_ENTRY_SRC = """
pragma solidity ^0.8.20;
contract StructMemberEntry {
    struct Payout { address recipient; uint256 amount; }
    // PriorityWithdrawalQueue.claimWithdraw shape: the destination is a member
    // of a calldata STRUCT param, read at the entry and one hop deep.
    function payEntry(Payout calldata p) external {
        (bool ok, ) = p.recipient.call{value: p.amount}(""); require(ok);
    }
    function payNested(Payout calldata p) external { _send(p); }
    function _send(Payout calldata p) internal {
        (bool ok, ) = p.recipient.call{value: p.amount}(""); require(ok);
    }
    receive() external payable {}
}
"""


# ``target_param_index`` gives the fork prober an ABI slot; emitted only when every site agrees on one whole entry
# parameter.


def _index(info) -> Any:
    return _out_flow(info).get("target_param_index")


def test_param_index_absent_for_element_and_struct_member_destinations(tmp_path):
    """The flat positional encoder can't plant a sentinel inside a struct or array."""
    batch = build_effects(_compile_named(tmp_path, _ELEMENT_SRC, "Batch"))["functions"]
    array_elem = _out_flow(batch["executeBatch(address[],uint256[])"])
    assert array_elem["target_kind"]["kind"] == "param"
    assert array_elem.get("target_param_index") is None

    struct = build_effects(_compile_named(tmp_path, _STRUCT_MEMBER_ENTRY_SRC, "StructMemberEntry"))["functions"]
    for name in ("payEntry(StructMemberEntry.Payout)", "payNested(StructMemberEntry.Payout)"):
        member = _out_flow(struct[name])
        assert member["target_kind"]["kind"] == "param"
        assert member.get("target_param_index") is None


# The legacy eth_out flow hardcoded ``is_parameter=False``; it now names the recipient where visible and stays silent
# elsewhere.


def _eth_flows(contract, full_name: str) -> list[dict]:
    fn = next(f for f in contract.functions if f.full_name == full_name)
    return [flow for flow in _extract_value_flows(fn) if flow["direction"] == "eth_out"]


_LEGACY_ETH_SRC = """
pragma solidity ^0.8.20;
contract Legacy {
    address public treasury;
    function payParam(address payable to, uint256 amt) external {
        (bool ok, ) = to.call{value: amt}(""); require(ok);
    }
    function payTreasury(uint256 amt) external {
        (bool ok, ) = treasury.call{value: amt}(""); require(ok);
    }
    function payViaHelper(address to, uint256 amt) external { _send(to, amt); }
    function _send(address to, uint256 amt) internal {
        (bool ok, ) = to.call{value: amt}(""); require(ok);
    }
}
"""


def test_legacy_eth_flow_stays_silent_for_storage_and_nested_recipients(tmp_path):
    contract = _compile_named(tmp_path, _LEGACY_ETH_SRC, "Legacy")
    storage = _eth_flows(contract, "payTreasury(uint256)")[0]
    assert storage["token_var"] is None and storage["is_parameter"] is False
    # A callee formal isn't an entry slot; ``target_param_index`` resolves it interprocedurally.
    nested = _eth_flows(contract, "payViaHelper(address,uint256)")[0]
    assert nested["token_var"] is None and nested["is_parameter"] is False
