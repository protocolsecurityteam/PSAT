"""The W1 ∧ W2 self-service join.

* **Unit** - hand-built :class:`ClaimContext`, stating every refusal reason and cross-plane
  reconciliation case against exact input, including ones no corpus contract reaches.
* **Producer integration** - an inline ``Slither`` contract through ``build_effects`` +
  ``build_predicate_tree`` + ``build_claims``, proving the join's two walks actually meet on
  the REAL producers (U1-U4); a unit test supplies both halves itself and cannot.

Every conjunct has a fixture removing exactly it (asserting ``not_determined``)
and a positive sibling; assertions are on the whole verdict dict, never ``is not None``.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import build_claims  # noqa: E402
from services.static.claims.context import ClaimContext  # noqa: E402
from services.static.claims.matchers import _facts  # noqa: E402
from services.static.claims.matchers import flows as flowmod  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.reentrancy_pause import (  # noqa: E402
    verified_guard_verdicts,
)

_UPGRADE = "self_service_bound_conditional_on_upgrade_authority"
_SIBLING = "self_service_sibling_function_residual_not_proven"
_BASE_DISCLOSURES = [_UPGRADE, _SIBLING]

_SIG = "pay(uint256)"


def _leaf(*, authority_role: str = "caller_authority", operands: list[dict], kind: str = "equality") -> dict:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": kind,
            "operator": "eq",
            "authority_role": authority_role,
            "operands": operands,
            "references_msg_sender": any(o.get("source") == "msg_sender" for o in operands),
            "parameter_indices": [],
            "expression": "",
            "basis": [],
        },
    }


def _and(*children: dict) -> dict:
    return {"op": "AND", "children": list(children)}


def _or(*children: dict) -> dict:
    return {"op": "OR", "children": list(children)}


def _element_op(base: str, member: list[str], key_index: int | None, *, param_index: int = 0) -> dict:
    return {
        "source": "parameter",
        "parameter_index": param_index,
        "parameter_name": "_bidId",
        "element_base_variable": base,
        "element_member_path": member,
        "element_key_param_index": key_index,
    }


_CALLER = {"source": "msg_sender"}


def _ownership_tree(base: str, key_index: int | None, *, mandatory: bool = True) -> dict:
    leaf = _leaf(operands=[_element_op(base, ["bidder"], key_index), _CALLER])
    if mandatory:
        return _and(leaf)
    return _or(leaf, _leaf(authority_role="business", operands=[{"source": "constant"}]))


def _flow(**kw: Any) -> dict:
    base: dict[str, Any] = {"direction": "out", "amount_kind": {"kind": "bounded_by_storage", "tier": "static_trace"}}
    base.update(kw)
    return base


def _ordering_proven(record: str, *, disclosures: list[str] | None = None) -> dict:
    w: dict[str, Any] = {
        "state": "proven_ordering",
        "w2_basis": "clear_dominates_calls",
        "record": record,
        "clearing_shape": "delete",
    }
    if disclosures:
        w["disclosures"] = disclosures
    return w


def _ctx(tree: Any, flow: dict) -> ClaimContext:
    effects = {
        "contract_name": "C",
        "functions": {_SIG: {"sinks": [], "value_flows": [flow], "parameter_names": ["_bidId"]}},
    }
    return ClaimContext(None, effects, {"trees": {_SIG: tree}})


def test_param_kind_without_index_refuses_never_kind_alone():
    flow = _flow(amount_record_variable="C.bids", amount_record_key_kinds=["param"])  # no key_param_indexes
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.bids", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "key_index_disagreement"}


def test_guard_without_msg_sender_operand_does_not_satisfy_w1():
    leaf = _leaf(operands=[_element_op("C.bids", ["bidder"], 0), {"source": "constant"}])
    flow = _flow(
        amount_record_variable="C.bids", amount_record_key_kinds=["param"], amount_record_key_param_indexes=[0]
    )
    verdict = _facts.amount_record_constraint(_ctx(_and(leaf), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "guard_not_mandatory"}


def test_w1_refusal_propagates_as_the_self_service_reason():
    flow = _flow(
        amount_record_variable="C.amounts",
        amount_record_key_kinds=["param"],
        amount_record_key_param_indexes=[0],
        record_ordering=_ordering_proven("C.amounts"),
    )
    verdict = _facts.self_service_payout(_ctx(_ownership_tree("C.owners", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "record_mismatch"}


def test_flow_entry_omits_the_keys_on_a_param_amount_and_rides_ss_r3():
    flow = {
        "direction": "out",
        "kind": "callee_erc20_selector",
        "selector": "0x",
        "from_is_self": True,
        "amount_kind": {"kind": "param", "tier": "static_trace"},
        "amount_param_index": 0,
    }
    entry = flowmod._flow_entry(_ctx(None, flow), _SIG, flow)
    assert "self_service_payout" not in entry
    assert "amount_record_constraint" not in entry
    assert entry["amount_constraint"]["state"] in {"unconstrained_proven", "constrained", "not_determined"}


_CORPUS_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}
contract Corpus {
    struct Bid { address bidder; uint256 amount; }
    mapping(uint256 => Bid) public bids;
    mapping(address => uint256) public balances;
    IERC20 public token;
    uint256 private _locked;
    modifier nonReentrant() { require(_locked == 0, "R"); _locked = 1; _; _locked = 0; }

    // P1: owner_guarded_record, zero-assign clearing, clear-before-pay.
    function cancelBid(uint256 _bidId) external {
        require(bids[_bidId].bidder == msg.sender, "no");
        uint256 amt = bids[_bidId].amount;
        bids[_bidId].amount = 0;
        token.transfer(msg.sender, amt);
    }
    // owner_guarded_record via delete.
    function cancelBidDelete(uint256 _bidId) external {
        require(bids[_bidId].bidder == msg.sender, "no");
        uint256 amt = bids[_bidId].amount;
        delete bids[_bidId];
        token.transfer(msg.sender, amt);
    }
    // keyed_by_caller, ordering-only (no guard, clear-before-pay).
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        token.transfer(msg.sender, amt);
    }
    // keyed_by_caller, clear-AFTER-pay but a real guard: proven via verified_guard.
    function withdrawGuarded() external nonReentrant {
        uint256 amt = balances[msg.sender];
        token.transfer(msg.sender, amt);
        balances[msg.sender] = 0;
    }
    // A1 (DAO shape): keyed_by_caller, clear-after-pay, NO guard applied.
    function badWithdraw() external {
        uint256 amt = balances[msg.sender];
        token.transfer(msg.sender, amt);
        balances[msg.sender] = 0;
    }
    // A5: admin sweep, param amount — no record at all.
    function rescueTokens(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
    // A7: whole-balance sweep — amount folds indeterminate.
    function sweepAll(address to) external {
        token.transfer(to, token.balanceOf(address(this)));
    }
}
"""


@pytest.fixture(scope="module")
def _corpus(tmp_path_factory):
    f = tmp_path_factory.mktemp("ssw") / "Corpus.sol"
    f.write_text(textwrap.dedent(_CORPUS_SRC).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == "Corpus")


def _flow_out_entries(contract: Any, sig: str) -> list[dict]:
    effects = build_effects(contract)
    trees = {
        "trees": {
            fn.full_name: build_predicate_tree(fn)
            for fn in contract.functions
            if fn.is_implemented and not fn.is_constructor
        }
    }
    artifact = build_claims(contract, effects, trees)
    out: list[dict] = []
    for claim in artifact["functions"].get(sig, []):
        if claim.get("claim_id") == "flow.out":
            out.extend(claim.get("witness", {}).get("flows", []))
    return out


def _self_service(contract: Any, sig: str) -> dict:
    entries = _flow_out_entries(contract, sig)
    assert entries, f"no flow.out entry for {sig}"
    return dict(entries[0].get("self_service_payout") or {"state": "__absent__"})


def test_producer_cancel_bid_proves_owner_guarded_and_ordering(_corpus):
    verdict = _self_service(_corpus, "cancelBid(uint256)")
    assert verdict == {
        "state": "proven_self_service",
        "w1_basis": "owner_guarded_record",
        "w2_basis": "clear_dominates_calls",
        "record": "Corpus.bids",
        "disclosures": _BASE_DISCLOSURES,
    }


def test_producer_cancel_bid_delete_proves(_corpus):
    assert _self_service(_corpus, "cancelBidDelete(uint256)")["state"] == "proven_self_service"


def test_producer_withdraw_proves_keyed_by_caller_on_ordering(_corpus):
    verdict = _self_service(_corpus, "withdraw()")
    assert verdict["state"] == "proven_self_service"
    assert verdict["w1_basis"] == "keyed_by_caller"
    assert verdict["w2_basis"] == "clear_dominates_calls"


def test_producer_verified_guard_and_ordering_are_both_earned(_corpus):
    """``withdraw`` needing no guard shows the ordering arm stands alone."""
    guarded = _self_service(_corpus, "withdrawGuarded()")
    assert guarded["state"] == "proven_self_service"
    assert guarded["w2_basis"] == "verified_guard"
    assert _self_service(_corpus, "withdraw()")["w2_basis"] == "clear_dominates_calls"


def test_producer_dao_shape_refuses(_corpus):
    assert _self_service(_corpus, "badWithdraw()") == {
        "state": "not_determined",
        "reason": "clearing_write_does_not_dominate_calls",
    }


def test_producer_contract_scoped_guard_licenses_no_unguarded_function(_corpus):
    verdict = _self_service(_corpus, "badWithdraw()")
    assert verdict["state"] == "not_determined"
    guard = verified_guard_verdicts(_corpus)["badWithdraw()"]
    assert guard["state"] == "not_determined"
    assert guard["reason"] == "guard_modifier_not_applied"


def test_producer_admin_sweep_param_leaves_the_key_absent(_corpus):
    entries = _flow_out_entries(_corpus, "rescueTokens(address,uint256)")
    assert entries
    assert all("self_service_payout" not in e for e in entries)


def test_producer_whole_balance_sweep_leaves_the_key_absent(_corpus):
    entries = _flow_out_entries(_corpus, "sweepAll(address)")
    assert entries
    assert all("self_service_payout" not in e for e in entries)


_BURN_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
interface IOracle { function convert(uint256 shares) external view returns (uint256); }
contract BurnPay {
    mapping(address => uint256) public shares;
    IERC20 public token;
    IOracle public oracle;
    // Provable sub-case: the paid amount IS read from the caller's own cell, so
    // it is keyed_by_caller — the only burn-of-caller-shares this join can earn.
    function redeemSame() external {
        uint256 amt = shares[msg.sender];
        shares[msg.sender] = 0;
        token.transfer(msg.sender, amt);
    }
    // A16: the paid amount is an oracle conversion of the burned quantity
    // (param_derived), so the amount is not read out of storage and the gate
    // never fires — the row stays fail-closed absent, never cleared.
    function redeemOracle(uint256 amt) external {
        shares[msg.sender] -= amt;
        token.transfer(msg.sender, oracle.convert(amt));
    }
}
"""


@pytest.fixture(scope="module")
def _burn(tmp_path_factory):
    f = tmp_path_factory.mktemp("ssw_burn") / "BurnPay.sol"
    f.write_text(textwrap.dedent(_BURN_SRC).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == "BurnPay")


def test_burn_same_value_proves_as_keyed_by_caller(_burn):
    """``burn_of_caller_shares`` needs a decrement fact no producer publishes."""
    verdict = _self_service(_burn, "redeemSame()")
    assert verdict["state"] == "proven_self_service"
    assert verdict["w1_basis"] == "keyed_by_caller"


def test_burn_then_oracle_pay_stays_fail_closed_absent(_burn):
    entries = _flow_out_entries(_burn, "redeemOracle(uint256)")
    assert entries
    assert all("self_service_payout" not in e for e in entries)
