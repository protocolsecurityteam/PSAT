"""The amount-record producer (W1): which storage cell a payout is read out of.

``amount_kind: bounded_by_storage`` says the quantity came out of storage and
nothing more — the variable, the struct member and the key that selected the
cell were all discarded at ``_origin_to_amount_kind``. This unit recovers them
as a separate, additive fact: ``amount_record_variable`` (canonical, so two
contracts each declaring ``bids`` cannot be read as one), the member path, and
the origin + entry slot of every key level.

It names a cell. It resolves nothing: whether the caller OWNS that cell is a
join against the guard side, and it is not made here.

The discipline the fixtures pin, each against a sibling differing in exactly one
construct:

* a record is published only when every contributing site named the SAME
  declaration — otherwise the honest plural and no scalar;
* one site that named no record at all suppresses the whole fact (a record
  assembled from the sites that happened to have one is not this flow's record);
* a merged key, a merged base, a memory/call-result root and depths past the
  v1 bounds all REFUSE, and a refusal is an absent key — never an empty path,
  which is a real value here (``simple[id]`` has one);
* a key the caller only DERIVED — narrowed by a cast, or arithmetic on two
  arguments — names no slot and is not called ``param``, because the guard side
  reads slots through this same helper and two different cells that agree on a
  slot are how a guard gets read as gating a record it never gated.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.static_analysis.effects import (  # noqa: E402
    _build_unit_ctx,
    _element_record_site,
    _element_walk,
    _member_name,
    build_effects,
)
from services.static.static_analysis.shared import _all_state_variables  # noqa: E402

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
    """A classification context for one unit, built exactly as the flow walk
    builds it — the second argument of every producer function under test."""
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


# --- what the record names --------------------------------------------------


def test_a_parameter_keyed_struct_member_names_its_declaration_member_and_slot(_unit):
    """``bids[_bidId].amount``: the canonical declaration, the member, and the
    ENTRY slot the key came from — the three facts a guard leaf must be shown to
    agree with before anything is proven about ownership."""
    flow = _flow(_unit, "Records", "cancelBid(uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]


def test_a_caller_keyed_cell_records_msg_sender_at_the_level_that_selected_it(_unit):
    """``withdrawRequests[msg.sender][asset].shares``: the key origins are per
    LEVEL and in source order, so a consumer can tell the caller-keyed level
    from the caller-named one instead of reading a single collapsed answer."""
    flow = _flow(_unit, "Records", "completeWithdraw(address)")
    assert flow["amount_record_variable"] == "Records.withdrawRequests"
    assert flow["amount_record_member_path"] == ["shares"]
    assert flow["amount_record_key_kinds"] == ["msg_sender", "param"]
    # msg.sender occupies no ABI slot; the second level does.
    assert flow["amount_record_key_param_indexes"] == [None, 0]


def test_a_scalar_mapping_publishes_an_empty_member_path(_unit):
    """``simple[id]`` selects a whole cell, so the member path is ``[]`` — a
    published value. Its sibling ``payPot`` shows what an ABSENT path means."""
    flow = _flow(_unit, "Records", "paySimple(uint256)")
    assert flow["amount_record_variable"] == "Records.simple"
    assert flow["amount_record_member_path"] == []
    assert flow["amount_record_key_kinds"] == ["param"]


def test_a_whole_variable_amount_is_storage_bounded_and_names_no_record(_unit):
    """The sibling of ``paySimple``: ``totalPot`` is read out of storage too, so
    the kind is identical — and there is no cell, no key, and nothing to join."""
    flow = _flow(_unit, "Records", "payPot()")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    for key in _RECORD_KEYS:
        assert key not in flow


# --- the binding thread (the burn shape) ------------------------------------


def test_the_key_resolves_through_the_call_site_binding(_unit):
    """``_burnAndPay(msg.sender)``: inside the callee the key is the formal
    ``account``, and only the binding the flow walk threads says whose cell that
    is. Without it the caller's own balance reads as an unknown address's."""
    flow = _flow(_unit, "Records", "unwrapAll()")
    assert flow["amount_record_variable"] == "Records._balances"
    assert flow["amount_record_member_path"] == []
    assert flow["amount_record_key_kinds"] == ["msg_sender"]
    assert flow["amount_record_key_param_indexes"] == [None]


def test_a_burn_decrement_resolves_its_key_the_same_way(_unit):
    """The ``_burn(msg.sender, amount)`` shape at the site itself: the element
    being DECREMENTED is ``_balances[account]``, and it names the caller's cell
    under the same binding — the record half of the burn variant, which the
    quantity join then has to agree with."""
    code_unit, ctx = _ctx_for(
        _unit,
        "Records",
        "_burnAndPay",
        is_entry=False,
        param_bindings={"account": ("msg_sender",)},
    )
    element = _ir_lvalue(code_unit, lambda ir: type(ir).__name__ == "Index")
    site = _element_record_site(element, ctx)
    assert site is not None
    assert (site["base_canonical"], site["member_path"], site["key_levels"]) == ("Records._balances", (), 1)
    assert site["key_origins"] == (("msg_sender",),)


def test_the_same_key_without_a_binding_names_no_caller(_unit):
    """The falsifier for the line above: the identical IR, walked with no
    binding for ``account``, resolves to ``indeterminate``. A formal parameter's
    name never stands in for the argument."""
    code_unit, ctx = _ctx_for(_unit, "Records", "_burnAndPay", is_entry=False, param_bindings=None)
    element = _ir_lvalue(code_unit, lambda ir: type(ir).__name__ == "Index")
    site = _element_record_site(element, ctx)
    assert site is not None
    assert site["key_origins"] == (("indeterminate",),)


# --- refusals, each against the sibling it differs from ---------------------


def test_a_merged_key_refuses_the_record_while_the_kind_stands(_unit):
    """``bids[flag ? a : b].amount``: the base decides the KIND, which is why
    the amount is still storage-bounded — but the key IS the cell's identity and
    a merge selects one of two. The record is withheld, not guessed."""
    flow = _flow(_unit, "Records", "cancelBidMerged(uint256,uint256,bool)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    for key in _RECORD_KEYS:
        assert key not in flow


def test_a_merged_base_refuses_the_record(_unit):
    """A storage pointer reassigned in a branch. The published flow refuses on
    the kind as well, so the site is asserted directly: the walk reports the
    root as a MERGE and the record site declines to read a base off it."""
    flow = _flow(_unit, "Records", "cancelBidPhiBase(uint256,uint256,bool)")
    assert flow["amount_kind"]["kind"] == "indeterminate"
    for key in _RECORD_KEYS:
        assert key not in flow

    code_unit, ctx = _ctx_for(_unit, "Records", "cancelBidPhiBase")
    element = _ir_lvalue(code_unit, lambda ir: type(ir).__name__ == "Member" and _member_name(ir) == "amount")
    roots = _element_walk(element, ctx)
    assert roots is not None and [root.merged_base for root in roots] == [True]
    assert _element_record_site(element, ctx) is None


def test_member_nesting_past_the_v1_bound_refuses(_unit):
    """``deep[id].mid.inner.amount`` — three members. The kind is unchanged; the
    record is not published, because the path a join would compare against a
    guard leaf is deeper than anything this pass is specified to name."""
    flow = _flow(_unit, "Records", "payDeep(uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    for key in _RECORD_KEYS:
        assert key not in flow


def test_a_memory_element_root_publishes_no_record(_unit):
    """The ``redeem`` shape: ``previewRedeem(shares)[0]`` is an element of a
    memory array returned by a call. The element root is not one this pass
    classifies from, so there is no record — the reason token for that absence
    belongs to the join, and inventing a record here would pre-empt it."""
    flow = _flow(_unit, "Records", "redeem(uint256)")
    assert flow["amount_kind"]["kind"] == "indeterminate"
    for key in _RECORD_KEYS:
        assert key not in flow


def test_two_declarations_publish_the_plural_and_no_scalar(_unit):
    """A17. Both vaults declare ``bids``, both pay on one flow key, and both
    sites fold to the same KIND — so agreement on the kind is not agreement on
    the cell. The canonical members are published and the scalar is not, because
    one of them is not the answer."""
    flow = _flow(_unit, "TwoDeclarations", "payBoth(uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    assert flow["amount_record_variables"] == ["VaultA.bids", "VaultB.bids"]
    assert "amount_record_variable" not in flow
    # The path and the keys belong to a record that was not identified.
    assert "amount_record_member_path" not in flow
    assert "amount_record_key_kinds" not in flow
    assert "amount_record_key_param_indexes" not in flow


def test_each_vault_alone_names_its_own_declaration(_unit):
    """The non-vacuity sibling of A17: analysed as its own entry, VaultA's flow
    does publish the scalar — so the plural above is the two-declaration fold and
    not a shape the producer simply never resolves."""
    flow = _flow(_unit, "VaultA", "payA(uint256)")
    assert flow["amount_record_variable"] == "VaultA.bids"
    assert "amount_record_variables" not in flow


# --- the key is the cell's identity, so a narrowed key names no slot ---------


def test_a_narrowed_key_withholds_the_slot_it_would_otherwise_name(_unit):
    """``bids[uint256(uint128(id))].amount``: the cast keeps resolving to slot 0
    — the argument IS what it was built from — while selecting a DIFFERENT cell
    for any ``id >= 2**128``. The record still names the declaration and the
    member; the slot and the ``param`` kind are withheld, because the argument
    was not, in whole, the key."""
    flow = _flow(_unit, "Records", "payTruncatedKey(uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert flow["amount_record_key_kinds"] == ["indeterminate"]
    assert flow["amount_record_key_param_indexes"] == [None]


def test_a_narrowed_and_a_whole_key_do_not_agree_on_a_slot(_unit):
    """The two-site form, and the reason the rule above is not cosmetic: one
    site reads ``bids[id]`` and the other ``bids[uint128(id)]``. Two cells. Had
    both published slot 0 they would AGREE — and a guard proven to gate one
    would be read as gating the other."""
    flow = _flow(_unit, "Records", "paySpuriousAgreement(uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert "amount_record_key_kinds" not in flow
    assert "amount_record_key_param_indexes" not in flow


def test_a_widened_key_keeps_its_slot(_unit):
    """The positive sibling: ``simple[uint256(id)]`` on a ``uint128`` argument
    widens, so every argument value keeps its own cell and the slot stands."""
    flow = _flow(_unit, "Records", "payWidenedKey(uint128)")
    assert flow["amount_record_variable"] == "Records.simple"
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]


def test_an_address_width_key_conversion_keeps_its_slot(_unit):
    """``_balances[address(raw)]`` on a ``uint160`` argument: same 160 bits,
    same cell per argument. A conversion is not by itself a loss."""
    flow = _flow(_unit, "Records", "payAddressKey(uint160)")
    assert flow["amount_record_variable"] == "Records._balances"
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]


def test_a_caller_derived_key_is_not_a_caller_named_one(_unit):
    """``bids[a + b]``: both operands are the caller's, and neither IS the key.
    ``param`` would say the caller named this cell, so the kind reads
    indeterminate — the same answer the missing slot gives."""
    flow = _flow(_unit, "Records", "payArithmeticKey(uint256,uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_key_kinds"] == ["indeterminate"]
    assert flow["amount_record_key_param_indexes"] == [None]


# --- shape and depth --------------------------------------------------------


def test_a_keyless_struct_read_is_not_a_record(_unit):
    """``cfg.fee`` selects no cell: there is no key to compare against a guard's
    and no ownership question this producer can pose. Published records are
    keyed records, so this one is absent rather than half-formed."""
    flow = _flow(_unit, "Records", "payCfg()")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    for key in _RECORD_KEYS:
        assert key not in flow


def test_three_key_levels_refuse(_unit):
    """``three[a][b][c]`` — past the v1 bound, refused whole rather than
    published truncated to the two levels a consumer is specified to read."""
    flow = _flow(_unit, "Records", "payThree(uint256,uint256,uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    for key in _RECORD_KEYS:
        assert key not in flow


def test_a_two_member_path_keeps_its_source_order(_unit):
    """``pair[id].inner.amount``: the path is read back out in source order, not
    in the reverse order the walk visits it. A join comparing paths against a
    guard's would agree on the wrong record if either side were reversed."""
    flow = _flow(_unit, "Records", "payPair(uint256)")
    assert flow["amount_record_variable"] == "Records.pair"
    assert flow["amount_record_member_path"] == ["inner", "amount"]


def test_two_key_levels_keep_their_order(_unit):
    """``two[a][b]`` and ``two[b][a]`` are different cells, and the only thing
    that says so is the ORDER of the slots. The levels are published first index
    level first, so the two do not read alike."""
    assert _flow(_unit, "Records", "payTwo(uint256,uint256)")["amount_record_key_param_indexes"] == [0, 1]
    assert _flow(_unit, "Records", "payTwoSwapped(uint256,uint256)")["amount_record_key_param_indexes"] == [1, 0]


# --- what one flow's sites must agree on ------------------------------------


def test_sites_agreeing_on_the_declaration_but_not_the_member_withhold_the_path(_unit):
    """``bids[id].amount`` and ``bids[id].fee`` on one flow key: the same cell,
    two quantities. The declaration and the key are the flow's answer; the
    member is not, and the first site's is not promoted to it."""
    flow = _flow(_unit, "Records", "paySplit(uint256,address)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]
    assert "amount_record_member_path" not in flow


def test_sites_agreeing_on_the_member_but_not_the_slot_withhold_the_slot(_unit):
    """``bids[a].amount`` and ``bids[b].amount``: same declaration, same member,
    two cells. The kinds still ride — both levels ARE entry arguments — while
    the slot, the thing they disagree on, does not."""
    flow = _flow(_unit, "Records", "payTwoBids(uint256,uint256)")
    assert flow["amount_record_variable"] == "Records.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert flow["amount_record_key_kinds"] == ["param"]
    assert "amount_record_key_param_indexes" not in flow


def test_one_site_without_a_record_suppresses_the_whole_fact(_unit):
    """``bids[id].amount`` and ``totalPot`` on one flow key both fold to
    storage-bounded. A record assembled from the site that happened to have one
    would name a cell half this flow's value never came out of."""
    flow = _flow(_unit, "Records", "payRecordAndPot(uint256)")
    assert flow["amount_kind"]["kind"] == "bounded_by_storage"
    for key in _RECORD_KEYS:
        assert key not in flow


def test_an_amount_that_is_not_storage_bounded_publishes_no_record(_unit):
    """A site DID name a record here — and the fold is ``several``, so the flow's
    quantity is not, as a whole, read out of that cell. The record gate is the
    folded kind, never the site that would have supported one."""
    flow = _flow(_unit, "Records", "payRecordAndParam(uint256,uint256)")
    assert flow["amount_kind"]["kind"] == "several"
    for key in _RECORD_KEYS:
        assert key not in flow


# --- the sweeps the witness must never reach --------------------------------


@pytest.mark.parametrize(
    "signature",
    ["rescueTokens(IERC20,uint256)", "withdrawMax(uint256)", "rescueAll()"],
)
def test_an_admin_sweep_names_no_record(_unit, signature):
    """A5/A6/A7 at the producer: a caller-supplied amount, a ``type(uint256).max``
    branch, and a whole-balance read. None is read out of a cell, so none carries
    a record — the witness's contribution to a sweep is that its key is absent."""
    flow = _flow(_unit, "Records", signature)
    for key in _RECORD_KEYS:
        assert key not in flow
