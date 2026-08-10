"""W2 — the ordering prover (``record_ordering.py``).

The unit that can over-claim, so every refusal path carries its own fixture and
every ``not_determined`` has a positive sibling differing in exactly ONE
construct: if a refusal could pass merely because the walk never reached the
code, the sibling proves it did.

Assertions are on the WHOLE verdict dict — ``{"state": "not_determined", ...}``
and a proof are both truthy, so ``is not None`` would assert nothing.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline import record_ordering as ro  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402

_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

library SafeTransferLib {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "T");
    }
}

contract Ordering {
    struct Bid { address bidder; uint256 amount; bool isActive; }

    mapping(uint256 => Bid) public bids;
    mapping(address => uint256) private _balances;
    uint256 public totalSupply;
    uint256 public cap;
    uint256 public used;
    IERC20 public token;
    address public oracle;

    modifier notifyOracle() {
        IERC20(oracle).transfer(msg.sender, 0);
        _;
    }

    // --- ordering, same unit ------------------------------------------------

    function goodClearThenPay(uint256 id) external {
        require(bids[id].bidder == msg.sender, "owner");
        uint256 amt = bids[id].amount;
        bids[id].amount = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    // A1 — the canonical DAO shape.
    function daoClearAfterPay() external {
        uint256 amt = _balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
        _balances[msg.sender] = 0;
    }

    function daoClearBeforePay() external {
        uint256 amt = _balances[msg.sender];
        _balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    // A2 — the decrement form.
    function decrementAfterCall(uint256 id, uint256 x) external {
        (bool ok, ) = msg.sender.call{value: x}("");
        require(ok, "f");
        bids[id].amount -= x;
    }

    function decrementBeforeCall(uint256 id, uint256 x) external {
        bids[id].amount -= x;
        (bool ok, ) = msg.sender.call{value: x}("");
        require(ok, "f");
    }

    // A3 — the token transfer IS the external call.
    function hookTokenClearAfter(uint256 id) external {
        uint256 amt = bids[id].amount;
        SafeTransferLib.safeTransfer(token, msg.sender, amt);
        bids[id].amount = 0;
    }

    function hookTokenClearBefore(uint256 id) external {
        uint256 amt = bids[id].amount;
        bids[id].amount = 0;
        SafeTransferLib.safeTransfer(token, msg.sender, amt);
    }

    // A4 — dominance, not reachability.
    function conditionalClear(uint256 id, bool flag) external {
        uint256 amt = bids[id].amount;
        if (flag) {
            bids[id].amount = 0;
        }
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    // A11 — a write we cannot see may be the one that matters.
    function assemblyClear(uint256 id) external {
        uint256 amt = bids[id].amount;
        assembly { sstore(0x10, 0) }
        bids[id].amount = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    // --- Transfer / Send: the ops no sink record sees ----------------------

    function transferBeforeClear(uint256 id) external {
        uint256 amt = bids[id].amount;
        payable(msg.sender).transfer(amt);
        bids[id].amount = 0;
    }

    function sendBeforeClear(uint256 id) external {
        uint256 amt = bids[id].amount;
        payable(msg.sender).send(amt);
        bids[id].amount = 0;
    }

    function clearBeforeTransfer(uint256 id) external {
        uint256 amt = bids[id].amount;
        bids[id].amount = 0;
        payable(msg.sender).transfer(amt);
    }

    // --- shapes that are not clearing writes -------------------------------

    function incrementThenPay(uint256 id, uint256 x) external {
        bids[id].amount += x;
        (bool ok, ) = msg.sender.call{value: x}("");
        require(ok, "f");
    }

    function callerValueThenPay(uint256 id, uint256 x) external {
        bids[id].amount = x;
        (bool ok, ) = msg.sender.call{value: x}("");
        require(ok, "f");
    }

    function structAssignThenPay(uint256 id, uint256 x) external {
        bids[id] = Bid(msg.sender, x, true);
        (bool ok, ) = msg.sender.call{value: x}("");
        require(ok, "f");
    }

    function deleteThenPay(uint256 id) external {
        uint256 amt = bids[id].amount;
        delete bids[id];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    // --- the F2-CLEARING flag-flip subclass --------------------------------

    function cancelBid(uint256 id) external {
        require(bids[id].isActive, "inactive");
        bids[id].isActive = false;
        uint256 amt = bids[id].amount;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    function cancelBidNoPredicate(uint256 id) external {
        bids[id].isActive = false;
        uint256 amt = bids[id].amount;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    function cancelBidConditionalPredicate(uint256 id, bool check) external {
        if (check) {
            require(bids[id].isActive, "inactive");
        }
        bids[id].isActive = false;
        uint256 amt = bids[id].amount;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    // --- loops --------------------------------------------------------------

    function cancelBidBatch(uint256 id, uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            uint256 amt = bids[id].amount;
            bids[id].amount = 0;
            (bool ok, ) = msg.sender.call{value: amt}("");
            require(ok, "f");
        }
    }

    function clearThenLoopPay(uint256 id, uint256 n) external {
        uint256 amt = bids[id].amount;
        bids[id].amount = 0;
        for (uint256 i = 0; i < n; i++) {
            (bool ok, ) = msg.sender.call{value: amt}("");
            require(ok, "f");
        }
    }

    // --- one-hop composition (the OZ _burn shape) ---------------------------

    function burnThenPay(uint256 amount) external {
        _burn(msg.sender, amount);
        token.transfer(msg.sender, amount);
    }

    function payThenBurn(uint256 amount) external {
        token.transfer(msg.sender, amount);
        _burn(msg.sender, amount);
    }

    function burnTwoHop(uint256 amount) external {
        _burnOuter(msg.sender, amount);
        token.transfer(msg.sender, amount);
    }

    function burnInsideCalleeAfterCall(uint256 amount) external {
        _payThenBurn(msg.sender, amount);
    }

    function burnInsideCalleeBeforeCall(uint256 amount) external {
        _burnThenPay(msg.sender, amount);
    }

    function _burn(address account, uint256 amount) internal {
        uint256 b = _balances[account];
        require(b >= amount, "x");
        _balances[account] = b - amount;
    }

    function _burnOuter(address account, uint256 amount) internal {
        _burn(account, amount);
    }

    function _payThenBurn(address account, uint256 amount) internal {
        token.transfer(account, amount);
        uint256 b = _balances[account];
        _balances[account] = b - amount;
    }

    function _burnThenPay(address account, uint256 amount) internal {
        uint256 b = _balances[account];
        _balances[account] = b - amount;
        token.transfer(account, amount);
    }

    function conditionalBurnThenPay(uint256 amount, bool flag) external {
        _maybeBurn(msg.sender, amount, flag);
        token.transfer(msg.sender, amount);
    }

    function _maybeBurn(address account, uint256 amount, bool flag) internal {
        if (flag) {
            uint256 b = _balances[account];
            _balances[account] = b - amount;
        }
    }

    // --- modifiers: the body runs AT the placeholder ------------------------

    modifier clearFirst(uint256 id) {
        bids[id].amount = 0;
        _;
    }

    modifier clearLast(uint256 id) {
        _;
        bids[id].amount = 0;
    }

    function payWithClearFirst(uint256 id, uint256 amt) external clearFirst(id) {
        token.transfer(msg.sender, amt);
    }

    function payWithClearLast(uint256 id, uint256 amt) external clearLast(id) {
        token.transfer(msg.sender, amt);
    }

    // --- an internal function pointer hides whatever it reaches -------------

    function _payer(uint256 amt) internal {
        token.transfer(msg.sender, amt);
    }

    function pointerCallAfterClear(uint256 id) external {
        function(uint256) internal fp = _payer;
        uint256 amt = bids[id].amount;
        fp(amt);
        bids[id].amount = 0;
        payable(msg.sender).transfer(amt);
    }

    // --- a helper invoked twice, cleared between -----------------------------

    function payTwiceClearBetween(uint256 id, uint256 amt) external {
        _pay(amt);
        bids[id].amount = 0;
        _pay(amt);
    }

    function payOnceAfterClear(uint256 id, uint256 amt) external {
        bids[id].amount = 0;
        _pay(amt);
    }

    function _pay(uint256 amt) internal {
        token.transfer(msg.sender, amt);
    }

    // --- other control transfers --------------------------------------------

    function clearThenSelfdestruct(uint256 id) external {
        bids[id].amount = 0;
        selfdestruct(payable(msg.sender));
    }

    function calleeSelfdestructBeforeClear(uint256 id) external {
        _boom();
        bids[id].amount = 0;
    }

    function _boom() internal {
        selfdestruct(payable(msg.sender));
    }

    function assemblyCallBeforeClear(uint256 id, address to) external {
        assembly {
            let ok := call(gas(), to, 0, 0, 0, 0, 0)
            pop(ok)
        }
        bids[id].amount = 0;
    }

    function tryCatchBeforeClear(uint256 id) external {
        try token.balanceOf(address(this)) returns (uint256 b) {
            b;
        } catch {}
        bids[id].amount = 0;
    }

    // A SolidityCall that transfers no control must not count as one.
    function ecrecoverThenClear(uint256 id, bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
        require(ecrecover(h, v, r, s) != address(0), "e");
        bids[id].amount = 0;
    }

    // --- same-node IR ordering ----------------------------------------------

    function callThenWriteSameNode(uint256 id) external {
        bids[id].amount -= token.balanceOf(address(this));
    }

    // --- a subtraction that is not a debit of this record --------------------

    function raiseThenPay(uint256 id) external {
        bids[id].amount = cap - used;
        token.transfer(msg.sender, 1);
    }

    // --- loops, again: a post-loop pair is not a per-iteration pair ----------

    function loopThenClearThenPay(uint256 id, uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            if (i > 2) break;
        }
        bids[id].amount = 0;
        token.transfer(msg.sender, 1);
    }

    // --- flag-flip falsifiers: the flip must FALSIFY the predicate -----------

    function flipWrongPolarity(uint256 id) external {
        require(!bids[id].isActive, "active");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipParamPredicate(uint256 id, bool want) external {
        require(bids[id].isActive == want, "x");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipOrAdmin(uint256 id) external {
        require(bids[id].isActive || msg.sender == oracle, "x");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipCompareStorage(uint256 id, uint256 other) external {
        require(bids[id].isActive == bids[other].isActive, "x");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipPredicateOtherElement(uint256 id, uint256 other) external {
        require(bids[other].isActive, "x");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipToTrue(uint256 id) external {
        require(bids[id].isActive, "x");
        bids[id].isActive = true;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipCustomErrorRevert(uint256 id) external {
        if (!bids[id].isActive) revert("inactive");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipDeepPredicate(uint256 id) external {
        require(bids[id].isActive && msg.sender != address(0), "x");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipEqualsTrue(uint256 id) external {
        require(bids[id].isActive == true, "x");
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    function flipAssert(uint256 id) external {
        assert(bids[id].isActive);
        bids[id].isActive = false;
        token.transfer(msg.sender, bids[id].amount);
    }

    // --- a modifier's external call runs before the body --------------------

    function guardedClearThenPay(uint256 id) external notifyOracle {
        uint256 amt = bids[id].amount;
        bids[id].amount = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "f");
    }

    // No external call at all: the rule holds vacuously, and soundly.
    function clearOnly(uint256 id) external {
        bids[id].amount = 0;
    }
}

// A body we cannot read is a call set we did not close.
abstract contract Hooked {
    mapping(address => uint256) internal _bal;

    function _hook(address account) internal virtual;

    function payWithHook() external {
        uint256 amt = _bal[msg.sender];
        _bal[msg.sender] = 0;
        _hook(msg.sender);
        payable(msg.sender).transfer(amt);
    }
}
"""


@pytest.fixture(scope="module")
def _unit(tmp_path_factory):
    path = tmp_path_factory.mktemp("record_ordering") / "ordering.sol"
    path.write_text(textwrap.dedent(_SRC).strip() + "\n")
    return Slither(str(path))


@pytest.fixture(scope="module")
def _effects(_unit):
    contract = next(c for c in _unit.contracts if c.name == "Ordering")
    return build_effects(contract)["functions"]


def _function(unit, name: str):
    contract = next(c for c in unit.contracts if c.name == "Ordering")
    return next(fn for fn in contract.functions if fn.name == name)


#: ``bids[<param slot>].amount`` — a struct member of a param-keyed element.
def _bid_amount(param_slot: int = 0) -> ro.RecordRef:
    return {
        "base_canonical": "Ordering.bids",
        "member_path": ["amount"],
        "key_kinds": ["param"],
        "key_param_indexes": [param_slot],
    }


#: ``_balances[msg.sender]`` — a caller-keyed scalar cell.
def _caller_balance() -> ro.RecordRef:
    return {
        "base_canonical": "Ordering._balances",
        "member_path": [],
        "key_kinds": ["msg_sender"],
        "key_param_indexes": [None],
    }


def _verdict(unit, effects, name: str, record: ro.RecordRef) -> dict[str, Any]:
    """The verdict, with ``assembly_state_access`` taken from the real
    ``EffectInfo`` so the wiring the pipeline uses is the wiring under test."""
    function = _function(unit, name)
    info = next(i for i in effects.values() if i["function"].startswith(f"{name}("))
    verdict = dict(ro.prove_record_ordering(function, record, assembly_state_access=info["assembly_state_access"]))
    if verdict["state"] == ro.NOT_DETERMINED:
        assert verdict["reason"] in ro.REFUSAL_REASONS, verdict
    return verdict


def _assert_refused(verdict: dict[str, Any], reason: str) -> None:
    assert verdict == {"state": ro.NOT_DETERMINED, "reason": reason}


def _assert_proven(verdict: dict[str, Any], shape: str, record: str, disclosures: list[str] | None = None) -> None:
    expected: dict[str, Any] = {
        "state": ro.PROVEN,
        "w2_basis": ro.W2_BASIS_CLEAR_DOMINATES_CALLS,
        "record": record,
        "clearing_shape": shape,
    }
    if disclosures is not None:
        expected["disclosures"] = disclosures
    assert verdict == expected


# ---------------------------------------------------------------------------
# The adversarial set (S1 §5.2 A1-A4, A11) and its positive siblings.
# ---------------------------------------------------------------------------


def test_good_clear_then_pay_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "goodClearThenPay", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_a1_dao_shape_clear_after_pay_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "daoClearAfterPay", _caller_balance()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_a1_sibling_clear_before_pay_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "daoClearBeforePay", _caller_balance()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering._balances",
    )


def test_a2_decrement_after_call_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "decrementAfterCall", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_a2_sibling_decrement_before_call_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "decrementBeforeCall", _bid_amount()),
        ro.SHAPE_DECREMENT,
        "Ordering.bids",
    )


def test_a3_hook_token_clear_after_refuses(_unit, _effects):
    # The safeTransfer is a LibraryCall wrapping a real token call: "not a
    # low-level call" is not an escape hatch.
    _assert_refused(
        _verdict(_unit, _effects, "hookTokenClearAfter", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_a3_sibling_hook_token_clear_before_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "hookTokenClearBefore", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_a4_conditional_clear_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "conditionalClear", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_a11_assembly_state_access_refuses(_unit, _effects):
    # The clearing write DOES dominate here; the assembly write is what refuses.
    _assert_refused(
        _verdict(_unit, _effects, "assemblyClear", _bid_amount()),
        ro.ASSEMBLY_STATE_ACCESS,
    )


def test_a11_flag_is_the_real_effect_info_fact(_effects):
    assembly = next(i for i in _effects.values() if i["function"].startswith("assemblyClear("))
    plain = next(i for i in _effects.values() if i["function"].startswith("goodClearThenPay("))
    assert assembly["assembly_state_access"] is True
    assert plain["assembly_state_access"] is False


def test_modifier_external_call_precedes_the_body(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "guardedClearThenPay", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_modifier_clearing_before_the_placeholder_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "payWithClearFirst", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_modifier_clearing_after_the_placeholder_refuses(_unit, _effects):
    # The DAO shape one indirection deep: the write node is son-less, but the
    # body — and its payout — already ran at the placeholder.
    _assert_refused(
        _verdict(_unit, _effects, "payWithClearLast", _bid_amount()),
        ro.CROSS_UNIT_ORDERING_UNPROVEN,
    )


def test_internal_function_pointer_refuses(_unit, _effects):
    # The pointer's body is chosen at runtime; the clear that follows it proves
    # nothing about what it already called.
    _assert_refused(
        _verdict(_unit, _effects, "pointerCallAfterClear", _bid_amount()),
        ro.CALL_ENUMERATION_INCOMPLETE,
    )


def test_pointer_fixture_really_carries_an_out_flow(_effects):
    # Without a live out-flow on this function the refusal above would be
    # protecting nothing.
    info = next(i for i in _effects.values() if i["function"].startswith("pointerCallAfterClear("))
    assert [f for f in info["value_flows"] if f["direction"] == "out"] != []


def test_helper_invoked_twice_keeps_both_positions(_unit, _effects):
    # The first `_pay` runs before the clear. Keying the walk on the callee's
    # name instead of on its call site would lose that position entirely.
    _assert_refused(
        _verdict(_unit, _effects, "payTwiceClearBetween", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_helper_invoked_once_after_the_clear_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "payOnceAfterClear", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


@pytest.mark.parametrize(
    "name",
    ["calleeSelfdestructBeforeClear", "assemblyCallBeforeClear", "tryCatchBeforeClear"],
)
def test_other_control_transfers_before_the_clear_refuse(_unit, _effects, name):
    _assert_refused(_verdict(_unit, _effects, name, _bid_amount()), ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS)


def test_selfdestruct_after_the_clear_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "clearThenSelfdestruct", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_non_control_solidity_call_is_not_an_external_call(_unit, _effects):
    # ecrecover precedes the clear; it transfers no control, so it must not
    # refuse — otherwise the enumerator's breadth would be indiscriminate.
    _assert_proven(
        _verdict(_unit, _effects, "ecrecoverThenClear", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_call_before_write_within_one_node_refuses(_unit, _effects):
    # Dominance is trivially satisfied inside a node; only the IR index tells
    # these two apart.
    _assert_refused(
        _verdict(_unit, _effects, "callThenWriteSameNode", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


# ---------------------------------------------------------------------------
# Transfer / Send — the ops the sink classifier does not produce at all.
# ---------------------------------------------------------------------------


def test_native_transfer_before_clear_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "transferBeforeClear", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_native_send_before_clear_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "sendBeforeClear", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_native_transfer_after_clear_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "clearBeforeTransfer", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_transfer_and_send_produce_no_sink_record(_effects):
    # The premise of the two refusals above: if the sink list DID carry these
    # ops, missing them would not have been a hole worth closing.
    info = next(i for i in _effects.values() if i["function"].startswith("transferBeforeClear("))
    assert [s for s in info["sinks"] if s["kind"] == "external_call"] == []


# ---------------------------------------------------------------------------
# Shapes that are not clearing writes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["incrementThenPay", "callerValueThenPay", "structAssignThenPay"],
)
def test_non_clearing_shapes_refuse(_unit, _effects, name):
    _assert_refused(_verdict(_unit, _effects, name, _bid_amount()), ro.NO_CLEARING_WRITE)


def test_delete_of_the_containing_element_is_a_clearing_write(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "deleteThenPay", _bid_amount()),
        ro.SHAPE_DELETE,
        "Ordering.bids",
    )


def test_subtraction_whose_minuend_is_not_the_record_refuses(_unit, _effects):
    # `amount = cap - used` subtracts, and may RAISE the record. A debit takes
    # the record's own prior value as its minuend.
    _assert_refused(_verdict(_unit, _effects, "raiseThenPay", _bid_amount()), ro.NO_CLEARING_WRITE)


def test_wrong_key_slot_finds_no_clearing_write(_unit, _effects):
    # ``goodClearThenPay`` clears ``bids[<slot 0>]``; a record keyed on a
    # different slot is a different cell and must not borrow the proof.
    _assert_refused(_verdict(_unit, _effects, "goodClearThenPay", _bid_amount(1)), ro.NO_CLEARING_WRITE)


def test_indeterminate_key_refuses_the_record(_unit, _effects):
    record: ro.RecordRef = {
        "base_canonical": "Ordering.bids",
        "member_path": ["amount"],
        "key_kinds": ["indeterminate"],
        "key_param_indexes": [None],
    }
    _assert_refused(_verdict(_unit, _effects, "goodClearThenPay", record), ro.RECORD_NOT_RESOLVABLE)


def test_absent_member_path_is_not_an_empty_member_path(_unit, _effects):
    # The producer's ABSENT list means its sites disagreed. Reading it as `[]`
    # would widen the record from `bids[id].amount` to the whole element, which
    # is what lets a sibling member's write clear it.
    record: ro.RecordRef = {
        "base_canonical": "Ordering.bids",
        "key_kinds": ["param"],
        "key_param_indexes": [0],
    }
    _assert_refused(_verdict(_unit, _effects, "cancelBid", record), ro.RECORD_NOT_RESOLVABLE)


def test_absent_key_kinds_refuses(_unit, _effects):
    record: ro.RecordRef = {"base_canonical": "Ordering.bids", "member_path": ["amount"]}
    _assert_refused(_verdict(_unit, _effects, "goodClearThenPay", record), ro.RECORD_NOT_RESOLVABLE)


# ---------------------------------------------------------------------------
# F2-CLEARING: the flag-flip subclass and its one-line reversibility.
# ---------------------------------------------------------------------------


def test_cancel_bid_flag_flip_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "cancelBid", _bid_amount()),
        ro.SHAPE_FLAG_FLIP,
        "Ordering.bids",
    )


def test_flag_flip_without_the_mandatory_predicate_refuses(_unit, _effects):
    _assert_refused(_verdict(_unit, _effects, "cancelBidNoPredicate", _bid_amount()), ro.NO_CLEARING_WRITE)


@pytest.mark.parametrize(
    "name",
    [
        # The flip must FALSIFY the predicate; mentioning the member is not the
        # same claim. Each of these leaves a second entry a way through.
        "flipWrongPolarity",
        "flipParamPredicate",
        "flipOrAdmin",
        "flipCompareStorage",
        "flipPredicateOtherElement",
        "flipToTrue",
        # A custom-error `if (...) revert` guard is a predicate this pass does
        # not read — refused, not refuted.
        "flipCustomErrorRevert",
    ],
)
def test_flag_flip_predicate_falsifiers_refuse(_unit, _effects, name):
    _assert_refused(_verdict(_unit, _effects, name, _bid_amount()), ro.NO_CLEARING_WRITE)


@pytest.mark.parametrize("name", ["flipDeepPredicate", "flipEqualsTrue", "flipAssert"])
def test_flag_flip_admissible_predicate_forms_prove(_unit, _effects, name):
    _assert_proven(_verdict(_unit, _effects, name, _bid_amount()), ro.SHAPE_FLAG_FLIP, "Ordering.bids")


def test_flag_flip_with_a_conditional_predicate_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "cancelBidConditionalPredicate", _bid_amount()),
        ro.NO_CLEARING_WRITE,
    )


def test_flag_flip_toggle_off_refuses_the_same_shape(_unit, _effects, monkeypatch):
    monkeypatch.setattr(ro, "FLAG_FLIP_CLEARING_ENABLED", False)
    _assert_refused(_verdict(_unit, _effects, "cancelBid", _bid_amount()), ro.NO_CLEARING_WRITE)


def test_flag_flip_toggle_does_not_touch_the_strict_shapes(_unit, _effects, monkeypatch):
    monkeypatch.setattr(ro, "FLAG_FLIP_CLEARING_ENABLED", False)
    _assert_proven(
        _verdict(_unit, _effects, "goodClearThenPay", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


# ---------------------------------------------------------------------------
# Loops — per-iteration ordering, published with its residual.
# ---------------------------------------------------------------------------


def test_loop_body_ordering_is_proven_with_the_cross_iteration_disclosure(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "cancelBidBatch", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
        [ro.DISCLOSURE_CROSS_ITERATION],
    )


def test_non_loop_proof_carries_no_disclosure_key(_unit, _effects):
    verdict = _verdict(_unit, _effects, "goodClearThenPay", _bid_amount())
    assert "disclosures" not in verdict


def test_post_loop_pair_carries_no_cross_iteration_disclosure(_unit, _effects):
    # Both sites are dominated by the loop header and neither is inside the
    # loop. Reading enclosure off dominance alone would attach a per-iteration
    # residual to a straight-line pair.
    verdict = _verdict(_unit, _effects, "loopThenClearThenPay", _bid_amount())
    _assert_proven(verdict, ro.SHAPE_ZERO_ASSIGNMENT, "Ordering.bids")
    assert "disclosures" not in verdict


def test_different_loop_nesting_refuses(_unit, _effects):
    # The write dominates the call; what it does not do is dominate it ONCE PER
    # PAYMENT, which is the claim a loop would need.
    _assert_refused(
        _verdict(_unit, _effects, "clearThenLoopPay", _bid_amount()),
        ro.LOOP_NESTING_MISMATCH,
    )


# ---------------------------------------------------------------------------
# One-hop composition.
# ---------------------------------------------------------------------------


def test_one_hop_burn_then_pay_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "burnThenPay", _caller_balance()),
        ro.SHAPE_ASSIGNED_DIFFERENCE,
        "Ordering._balances",
    )


def test_one_hop_pay_then_burn_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "payThenBurn", _caller_balance()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_call_inside_the_same_callee_before_the_burn_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "burnInsideCalleeAfterCall", _caller_balance()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


def test_call_inside_the_same_callee_after_the_burn_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "burnInsideCalleeBeforeCall", _caller_balance()),
        ro.SHAPE_ASSIGNED_DIFFERENCE,
        "Ordering._balances",
    )


def test_two_hop_composition_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "burnTwoHop", _caller_balance()),
        ro.CROSS_UNIT_ORDERING_UNPROVEN,
    )


def test_conditional_write_inside_the_callee_refuses(_unit, _effects):
    # Conjunct (i) of the composition: the write must be unconditional in the
    # callee, not merely present in it.
    _assert_refused(
        _verdict(_unit, _effects, "conditionalBurnThenPay", _caller_balance()),
        ro.CROSS_UNIT_ORDERING_UNPROVEN,
    )


# ---------------------------------------------------------------------------
# The published shape (the effects.py hookup).
# ---------------------------------------------------------------------------


def test_attachment_is_guarded_on_the_record_being_named(_unit):
    function = _function(_unit, "goodClearThenPay")
    record_keys: dict[str, Any] = {
        "amount_record_variable": "Ordering.bids",
        "amount_record_member_path": ["amount"],
        "amount_record_key_kinds": ["param"],
        "amount_record_key_param_indexes": [0],
    }
    flows: list[dict[str, Any]] = [
        {"kind": "low_level_value_call", "direction": "out"},
        {"kind": "low_level_value_call", "direction": "out", **record_keys},
        {"kind": "callee_erc20_selector", "direction": "in", **record_keys},
        {"kind": "callee_erc20_selector", "direction": "value_router", **record_keys},
    ]
    ro.attach_record_ordering(flows, function, assembly_state_access=False)
    assert "record_ordering" not in flows[0]
    _assert_proven(flows[1]["record_ordering"], ro.SHAPE_ZERO_ASSIGNMENT, "Ordering.bids")
    # An inbound or merely-routed move does not make this entry the payer, so
    # the ordering question is not the one being asked.
    assert "record_ordering" not in flows[2]
    assert "record_ordering" not in flows[3]


def test_function_with_no_external_call_is_vacuously_proven(_unit, _effects):
    # Stated so the vacuity is visible rather than incidental: with no control
    # transfer there is nothing for the write to race, and the consumer never
    # reaches this verdict without a value flow to hang it on.
    _assert_proven(
        _verdict(_unit, _effects, "clearOnly", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_unreadable_callee_body_refuses(_unit):
    contract = next(c for c in _unit.contracts if c.name == "Hooked")
    function = next(fn for fn in contract.functions if fn.name == "payWithHook")
    record: ro.RecordRef = {
        "base_canonical": "Hooked._bal",
        "member_path": [],
        "key_kinds": ["msg_sender"],
        "key_param_indexes": [None],
    }
    _assert_refused(
        dict(ro.prove_record_ordering(function, record, assembly_state_access=False)),
        ro.CALL_ENUMERATION_INCOMPLETE,
    )


def test_pipeline_orders_against_the_record_the_amount_producer_names(_effects):
    # With the amount producer naming records on these fixtures, the pipeline
    # attaches an ordering verdict to exactly the out-flows that carry a record
    # and to no others, and each verdict is the one the isolated prover earns.
    keyed = {
        fn: flow["record_ordering"]
        for fn, info in _effects.items()
        for flow in info["value_flows"]
        if "record_ordering" in flow
    }
    # An ordering key rides only where an amount record was named.
    for fn, info in _effects.items():
        for flow in info["value_flows"]:
            if "record_ordering" in flow:
                assert flow.get("amount_record_variable") is not None
                assert flow["direction"] == "out"
    # Spot the two poles of the composition through the whole pipeline.
    assert keyed["goodClearThenPay(uint256)"]["state"] == "proven_ordering"
    assert keyed["daoClearAfterPay()"]["state"] == "not_determined"
    assert (
        keyed["daoClearAfterPay()"]["reason"] == ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS
    )
