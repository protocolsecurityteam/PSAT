"""W2 ordering prover.

Every refusal has a fixture and every ``not_determined`` a positive sibling differing in one construct. Assertions
compare whole verdicts because a refusal and a proof are both truthy.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.contract_analysis_pipeline import record_ordering as ro
from services.static.contract_analysis_pipeline.effects import build_effects

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


def _bid_amount(param_slot: int = 0) -> ro.RecordRef:
    return {
        "base_canonical": "Ordering.bids",
        "member_path": ["amount"],
        "key_kinds": ["param"],
        "key_param_indexes": [param_slot],
    }


def _caller_balance() -> ro.RecordRef:
    return {
        "base_canonical": "Ordering._balances",
        "member_path": [],
        "key_kinds": ["msg_sender"],
        "key_param_indexes": [None],
    }


def _verdict(unit, effects, name: str, record: ro.RecordRef) -> dict[str, Any]:
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
# The adversarial ordering cases and their positive siblings.
# ---------------------------------------------------------------------------


def test_a11_assembly_state_access_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "assemblyClear", _bid_amount()),
        ro.ASSEMBLY_STATE_ACCESS,
    )


def test_modifier_clearing_before_the_placeholder_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "payWithClearFirst", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
    )


def test_internal_function_pointer_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "pointerCallAfterClear", _bid_amount()),
        ro.CALL_ENUMERATION_INCOMPLETE,
    )


@pytest.mark.parametrize(
    "name",
    ["calleeSelfdestructBeforeClear", "assemblyCallBeforeClear", "tryCatchBeforeClear"],
)
def test_other_control_transfers_before_the_clear_refuse(_unit, _effects, name):
    _assert_refused(_verdict(_unit, _effects, name, _bid_amount()), ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS)


def test_call_before_write_within_one_node_refuses(_unit, _effects):
    # Within a node only the IR index orders them.
    _assert_refused(
        _verdict(_unit, _effects, "callThenWriteSameNode", _bid_amount()),
        ro.CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
    )


@pytest.mark.parametrize(
    "name",
    ["incrementThenPay", "callerValueThenPay", "structAssignThenPay"],
)
def test_non_clearing_shapes_refuse(_unit, _effects, name):
    _assert_refused(_verdict(_unit, _effects, name, _bid_amount()), ro.NO_CLEARING_WRITE)


def test_subtraction_whose_minuend_is_not_the_record_refuses(_unit, _effects):
    # ``cap - used`` may raise the record; a debit's minuend is the record's own prior value.
    _assert_refused(_verdict(_unit, _effects, "raiseThenPay", _bid_amount()), ro.NO_CLEARING_WRITE)


def test_absent_member_path_is_not_an_empty_member_path(_unit, _effects):
    # Absent means the producer's sites disagreed; ``[]`` would widen the record to the whole element.
    record: ro.RecordRef = {
        "base_canonical": "Ordering.bids",
        "key_kinds": ["param"],
        "key_param_indexes": [0],
    }
    _assert_refused(_verdict(_unit, _effects, "cancelBid", record), ro.RECORD_NOT_RESOLVABLE)


@pytest.mark.parametrize(
    "name",
    [
        # Mentioning the member isn't falsifying the predicate.
        "flipWrongPolarity",
        "flipParamPredicate",
        "flipOrAdmin",
        "flipCompareStorage",
        "flipPredicateOtherElement",
        "flipToTrue",
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


def test_loop_body_ordering_is_proven_with_the_cross_iteration_disclosure(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "cancelBidBatch", _bid_amount()),
        ro.SHAPE_ZERO_ASSIGNMENT,
        "Ordering.bids",
        [ro.DISCLOSURE_CROSS_ITERATION],
    )


def test_different_loop_nesting_refuses(_unit, _effects):
    # The write dominates the call but not once per payment.
    _assert_refused(
        _verdict(_unit, _effects, "clearThenLoopPay", _bid_amount()),
        ro.LOOP_NESTING_MISMATCH,
    )


def test_one_hop_burn_then_pay_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "burnThenPay", _caller_balance()),
        ro.SHAPE_ASSIGNED_DIFFERENCE,
        "Ordering._balances",
    )


def test_call_inside_the_same_callee_after_the_burn_is_proven(_unit, _effects):
    _assert_proven(
        _verdict(_unit, _effects, "burnInsideCalleeBeforeCall", _caller_balance()),
        ro.SHAPE_ASSIGNED_DIFFERENCE,
        "Ordering._balances",
    )


def test_conditional_write_inside_the_callee_refuses(_unit, _effects):
    _assert_refused(
        _verdict(_unit, _effects, "conditionalBurnThenPay", _caller_balance()),
        ro.CROSS_UNIT_ORDERING_UNPROVEN,
    )


# ---------------------------------------------------------------------------
# The published shape (the effects package hookup).
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
    # An inbound or routed move doesn't make this entry the payer.
    assert "record_ordering" not in flows[2]
    assert "record_ordering" not in flows[3]


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
