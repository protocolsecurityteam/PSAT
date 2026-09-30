"""The amount-record producer (W1) recovers which storage cell a payout is read from: canonical declaration,
member path, and origin + entry slot per key level. It resolves nothing about ownership. A record is published
only when every site named the same declaration; a refusal is an absent key, never an empty path. A key the
caller only derived names no slot, since two cells agreeing on a slot is how a guard gets read as gating a
record it never gated.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    _build_unit_ctx,
    _element_record_site,
    _element_walk,
    _member_name,
    build_effects,
)
from services.static.contract_analysis_pipeline.shared import _all_state_variables  # noqa: E402

_RECORD_KEYS = (
    "amount_record_variable",
    "amount_record_variables",
    "amount_record_member_path",
    "amount_record_key_kinds",
    "amount_record_key_param_indexes",
)

_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract Records {
    struct Bid { address bidder; uint256 amount; uint256 fee; }
    struct Req { uint256 shares; }
    struct Inner { uint256 amount; }
    struct Mid { Inner inner; }
    struct Outer { Mid mid; }
    struct Pair { Inner inner; }
    struct Cfg { uint256 fee; }

    mapping(uint256 => Bid) public bids;
    mapping(address => mapping(address => Req)) public withdrawRequests;
    mapping(address => uint256) internal _balances;
    mapping(uint256 => uint256) public simple;
    mapping(uint256 => Outer) public deep;
    mapping(uint256 => Pair) public pair;
    mapping(uint256 => mapping(uint256 => uint256)) public two;
    mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) public three;
    Cfg public cfg;
    uint256 public totalPot;
    IERC20 public token;

    // The owner-guarded record shape: the quantity is a member of a cell the
    // caller named by an entry parameter.
    function cancelBid(uint256 _bidId) external {
        require(bids[_bidId].bidder == msg.sender, "not yours");
        uint256 amt = bids[_bidId].amount;
        token.transfer(msg.sender, amt);
    }

    // The caller-keyed shape: the cell IS the caller's, two levels deep.
    function completeWithdraw(address asset) external {
        uint256 sh = withdrawRequests[msg.sender][asset].shares;
        token.transfer(msg.sender, sh);
    }

    // A scalar mapping — an EMPTY member path, which is a value and not an absence.
    function paySimple(uint256 id) external {
        token.transfer(msg.sender, simple[id]);
    }

    // Sibling of paySimple: storage-bounded, but no cell was selected at all.
    function payPot() external {
        token.transfer(msg.sender, totalPot);
    }

    // Sibling of cancelBid, one construct apart: the key is a cross-branch merge.
    function cancelBidMerged(uint256 a, uint256 b, bool flag) external {
        uint256 id = flag ? a : b;
        uint256 amt = bids[id].amount;
        token.transfer(msg.sender, amt);
    }

    // Sibling of cancelBid: the BASE is a merged storage pointer.
    function cancelBidPhiBase(uint256 a, uint256 b, bool flag) external {
        Bid storage bid = bids[a];
        if (flag) { bid = bids[b]; }
        token.transfer(msg.sender, bid.amount);
    }

    // Sibling of cancelBid: member depth 3, past the v1 bound.
    function payDeep(uint256 id) external {
        token.transfer(msg.sender, deep[id].mid.inner.amount);
    }

    // The redeem shape: the element's root is a memory array returned by a call.
    function redeem(uint256 shares) external {
        uint256[] memory amounts = previewRedeem(shares);
        token.transfer(msg.sender, amounts[0]);
    }

    function previewRedeem(uint256 shares) public pure returns (uint256[] memory out) {
        out = new uint256[](1);
        out[0] = shares * 2;
    }

    // The burn thread: the key is a callee formal bound to msg.sender at the
    // call site, so it resolves only through the walk's param bindings.
    function unwrapAll() external {
        _burnAndPay(msg.sender);
    }

    function _burnAndPay(address account) internal {
        uint256 amt = _balances[account];
        _balances[account] -= amt;
        token.transfer(account, amt);
    }

    // A narrowed key: the same ABI slot, a different cell for a large argument.
    function payTruncatedKey(uint256 id) external {
        token.transfer(msg.sender, bids[uint256(uint128(id))].amount);
    }

    // Its two-site form: one site keyed by the whole argument, one by a
    // narrowing of it. The slot alone cannot tell them apart.
    function paySpuriousAgreement(uint256 id) external {
        token.transfer(msg.sender, bids[id].amount);
        token.transfer(msg.sender, bids[uint256(uint128(id))].amount);
    }

    // Widening keeps resolving — the whole argument is still the key.
    function payWidenedKey(uint128 id) external {
        token.transfer(msg.sender, simple[uint256(id)]);
    }

    // As does an address-width hop.
    function payAddressKey(uint160 raw) external {
        token.transfer(msg.sender, _balances[address(raw)]);
    }

    // Caller-derived but not caller-named: no slot, so no ``param``.
    function payArithmeticKey(uint256 a, uint256 b) external {
        token.transfer(msg.sender, bids[a + b].amount);
    }

    // No key at all: a struct state variable is not a keyed record.
    function payCfg() external {
        token.transfer(msg.sender, cfg.fee);
    }

    // Three key levels, past the v1 bound.
    function payThree(uint256 a, uint256 b, uint256 c) external {
        token.transfer(msg.sender, three[a][b][c]);
    }

    // Two members, whose ORDER is the record's identity.
    function payPair(uint256 id) external {
        token.transfer(msg.sender, pair[id].inner.amount);
    }

    // Two levels, both entry parameters — and the same call with the arguments
    // swapped, which must not read as the same cell.
    function payTwo(uint256 a, uint256 b) external {
        token.transfer(msg.sender, two[a][b]);
    }

    function payTwoSwapped(uint256 a, uint256 b) external {
        token.transfer(msg.sender, two[b][a]);
    }

    // One flow key, two sites: same declaration, different member.
    function paySplit(uint256 id, address other) external {
        token.transfer(msg.sender, bids[id].amount);
        token.transfer(other, bids[id].fee);
    }

    // One flow key, two sites: same declaration and member, different slot.
    function payTwoBids(uint256 a, uint256 b) external {
        token.transfer(msg.sender, bids[a].amount);
        token.transfer(msg.sender, bids[b].amount);
    }

    // One flow key, one site with a record and one without.
    function payRecordAndPot(uint256 id) external {
        token.transfer(msg.sender, bids[id].amount);
        token.transfer(msg.sender, totalPot);
    }

    // One flow key whose amount does not fold to bounded_by_storage at all.
    function payRecordAndParam(uint256 id, uint256 amt) external {
        token.transfer(msg.sender, bids[id].amount);
        token.transfer(msg.sender, amt);
    }

    // The admin sweeps (A5/A6/A7): unbounded by construction, and the witness's
    // contribution to them is that its key is absent.
    function rescueTokens(IERC20 asset, uint256 amount) external {
        asset.transfer(msg.sender, amount);
    }

    function withdrawMax(uint256 amount) external {
        if (amount == type(uint256).max) {
            amount = token.balanceOf(address(this));
        }
        token.transfer(msg.sender, amount);
    }

    function rescueAll() external {
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}

contract VaultA {
    struct Bid { address bidder; uint256 amount; }
    mapping(uint256 => Bid) public bids;
    IERC20 public token;
    function payA(uint256 id) external { token.transfer(msg.sender, bids[id].amount); }
}

contract VaultB {
    struct Bid { address bidder; uint256 amount; }
    mapping(uint256 => Bid) public bids;
    IERC20 public token;
    function payB(uint256 id) external { token.transfer(msg.sender, bids[id].amount); }
}

// Two declarations of ``bids`` in one call graph, both paying on one flow key.
contract TwoDeclarations {
    VaultA public a;
    VaultB public b;
    function payBoth(uint256 id) external {
        a.payA(id);
        b.payB(id);
    }
}
"""


@pytest.fixture(scope="module")
def _unit(tmp_path_factory):
    f = tmp_path_factory.mktemp("amount_record") / "records.sol"
    f.write_text(textwrap.dedent(_SRC).strip() + "\n")
    return Slither(str(f))


def _contract(unit, name: str):
    return next(c for c in unit.contracts if c.name == name)


def _flow(unit, contract_name: str, signature: str) -> Any:
    flows = build_effects(_contract(unit, contract_name))["functions"][signature]["value_flows"]
    assert len(flows) == 1, flows
    return flows[0]


def _ctx_for(unit, contract_name: str, unit_name: str, **kwargs):
    """Built exactly as the flow walk builds it."""
    contract = _contract(unit, contract_name)
    code_unit = next(f for f in contract.functions if f.name == unit_name)
    state_vars = {getattr(v, "name", "") or "": v for v in _all_state_variables(contract)}
    return code_unit, _build_unit_ctx(
        code_unit, kwargs.pop("is_entry", True), state_vars, {}, set(), set(), False, **kwargs
    )


def _ir_lvalue(code_unit, predicate) -> Any:
    for node in code_unit.nodes:
        for ir in getattr(node, "irs_ssa", ()) or ():
            if predicate(ir):
                return getattr(ir, "lvalue", None)
    raise AssertionError("fixture no longer contains the IR shape under test")


def test_a_parameter_keyed_struct_member_names_its_declaration_member_and_slot(_unit):
    flow = _flow(_unit, "Records", "cancelBid(uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]


def test_a_caller_keyed_cell_records_msg_sender_at_the_level_that_selected_it(_unit):
    """Key origins are per level, in source order."""
    flow = _flow(_unit, "Records", "completeWithdraw(address)")
    assert flow["amount_record_variable"] == "Records.withdrawRequests"
    assert flow["amount_record_member_path"] == ["shares"]
    assert flow["amount_record_key_kinds"] == ["msg_sender", "param"]
    assert flow["amount_record_key_param_indexes"] == [None, 0]


def test_a_scalar_mapping_publishes_an_empty_member_path(_unit):
    """``payPot`` shows what an absent path means."""
    flow = _flow(_unit, "Records", "paySimple(uint256)")
    assert flow["amount_record_variable"] == "Records.simple"
    assert flow["amount_record_member_path"] == []
    assert flow["amount_record_key_kinds"] == ["param"]


@pytest.mark.parametrize(
    "signature,kind",
    [
        # Same kind, but no cell and nothing to join.
        pytest.param("payPot()", "bounded_by_storage", id="whole_variable"),
        # The base decides the kind, but the key is the cell's identity and a merge selects one of two.
        pytest.param("cancelBidMerged(uint256,uint256,bool)", "bounded_by_storage", id="merged_key"),
        # Three members is deeper than this pass names.
        pytest.param("payDeep(uint256)", "bounded_by_storage", id="member_nesting_past_v1"),
        # A memory-array element root; the reason token for the absence belongs to the join.
        pytest.param("redeem(uint256)", "indeterminate", id="memory_element_root"),
        # Published records are keyed records.
        pytest.param("payCfg()", "bounded_by_storage", id="keyless_struct_read"),
        # Refused whole rather than truncated.
        pytest.param("payThree(uint256,uint256,uint256)", "bounded_by_storage", id="three_key_levels"),
        # The record gate is the folded kind, never one site.
        pytest.param("payRecordAndParam(uint256,uint256)", "several", id="not_storage_bounded"),
    ],
)
def test_no_amount_record_published(_unit, signature, kind):
    flow = _flow(_unit, "Records", signature)
    assert flow["amount_kind"]["kind"] == kind
    for key in _RECORD_KEYS:
        assert key not in flow


def test_the_key_resolves_through_the_call_site_binding(_unit):
    """Without the threaded binding the caller's own balance reads as an unknown address's."""
    flow = _flow(_unit, "Records", "unwrapAll()")
    assert flow["amount_record_variable"] == "Records._balances"
    assert flow["amount_record_member_path"] == []
    assert flow["amount_record_key_kinds"] == ["msg_sender"]
    assert flow["amount_record_key_param_indexes"] == [None]


def test_the_same_key_without_a_binding_names_no_caller(_unit):
    code_unit, ctx = _ctx_for(_unit, "Records", "_burnAndPay", is_entry=False, param_bindings=None)
    element = _ir_lvalue(code_unit, lambda ir: type(ir).__name__ == "Index")
    site = _element_record_site(element, ctx)
    assert site is not None
    assert site["key_origins"] == (("indeterminate",),)


def test_a_merged_base_refuses_the_record(_unit):
    """The published flow also refuses on kind, so the site is asserted directly."""
    flow = _flow(_unit, "Records", "cancelBidPhiBase(uint256,uint256,bool)")
    assert flow["amount_kind"]["kind"] == "indeterminate"
    for key in _RECORD_KEYS:
        assert key not in flow

    code_unit, ctx = _ctx_for(_unit, "Records", "cancelBidPhiBase")
    element = _ir_lvalue(code_unit, lambda ir: type(ir).__name__ == "Member" and _member_name(ir) == "amount")
    roots = _element_walk(element, ctx)
    assert roots is not None and [root.merged_base for root in roots] == [True]
    assert _element_record_site(element, ctx) is None


def test_two_declarations_publish_the_plural_and_no_scalar(_unit):
    """A17: agreement on kind is not agreement on the cell."""
    flow = _flow(_unit, "TwoDeclarations", "payBoth(uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    assert flow["amount_record_variables"] == ["VaultA.bids", "VaultB.bids"]
    assert "amount_record_variable" not in flow
    assert "amount_record_member_path" not in flow
    assert "amount_record_key_kinds" not in flow
    assert "amount_record_key_param_indexes" not in flow


def test_each_vault_alone_names_its_own_declaration(_unit):
    flow = _flow(_unit, "VaultA", "payA(uint256)")
    assert flow["amount_record_variable"] == "VaultA.bids"
    assert "amount_record_variables" not in flow


def test_a_narrowed_key_withholds_the_slot_it_would_otherwise_name(_unit):
    """The cast selects a different cell for ``id >= 2**128``, so slot and ``param`` are withheld."""
    flow = _flow(_unit, "Records", "payTruncatedKey(uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert flow["amount_record_key_kinds"] == ["indeterminate"]
    assert flow["amount_record_key_param_indexes"] == [None]


def test_a_narrowed_and_a_whole_key_do_not_agree_on_a_slot(_unit):
    """Had both published slot 0, a guard proven to gate one would be read as gating the other."""
    flow = _flow(_unit, "Records", "paySpuriousAgreement(uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert "amount_record_key_kinds" not in flow
    assert "amount_record_key_param_indexes" not in flow


def test_a_widened_key_keeps_its_slot(_unit):
    flow = _flow(_unit, "Records", "payWidenedKey(uint128)")
    assert flow["amount_record_variable"] == "Records.simple"
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]


def test_an_address_width_key_conversion_keeps_its_slot(_unit):
    flow = _flow(_unit, "Records", "payAddressKey(uint160)")
    assert flow["amount_record_variable"] == "Records._balances"
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]


def test_a_caller_derived_key_is_not_a_caller_named_one(_unit):
    """``param`` would claim the caller named this cell."""
    flow = _flow(_unit, "Records", "payArithmeticKey(uint256,uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_key_kinds"] == ["indeterminate"]
    assert flow["amount_record_key_param_indexes"] == [None]


def test_a_two_member_path_keeps_its_source_order(_unit):
    """A reversed path would agree on the wrong record."""
    flow = _flow(_unit, "Records", "payPair(uint256)")
    assert flow["amount_record_variable"] == "Records.pair"
    assert flow["amount_record_member_path"] == ["inner", "amount"]


def test_two_key_levels_keep_their_order(_unit):
    assert _flow(_unit, "Records", "payTwo(uint256,uint256)")["amount_record_key_param_indexes"] == [0, 1]
    assert _flow(_unit, "Records", "payTwoSwapped(uint256,uint256)")["amount_record_key_param_indexes"] == [1, 0]


def test_sites_agreeing_on_the_declaration_but_not_the_member_withhold_the_path(_unit):
    flow = _flow(_unit, "Records", "paySplit(uint256,address)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]
    assert "amount_record_member_path" not in flow


def test_sites_agreeing_on_the_member_but_not_the_slot_withhold_the_slot(_unit):
    flow = _flow(_unit, "Records", "payTwoBids(uint256,uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert flow["amount_record_key_kinds"] == ["param"]
    assert "amount_record_key_param_indexes" not in flow


def test_one_site_without_a_record_suppresses_the_whole_fact(_unit):
    """A record from one site would name a cell half the flow's value never came from."""
    flow = _flow(_unit, "Records", "payRecordAndPot(uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    for key in _RECORD_KEYS:
        assert key not in flow


@pytest.mark.parametrize(
    "signature",
    ["rescueTokens(IERC20,uint256)", "withdrawMax(uint256)", "rescueAll()"],
)
def test_an_admin_sweep_names_no_record(_unit, signature):
    """A5/A6/A7 at the producer."""
    flow = _flow(_unit, "Records", signature)
    for key in _RECORD_KEYS:
        assert key not in flow
