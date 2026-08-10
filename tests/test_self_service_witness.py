"""The self-service payout join — ``_facts.amount_record_constraint`` (W1) and
``_facts.self_service_payout`` (W1 ∧ W2), plus the ``_flow_entry`` attachment.

Two harnesses, both driving production code:

* **Unit** — a hand-built :class:`ClaimContext` over synthetic predicate trees
  and flows. This is where every refusal reason and every cross-plane
  reconciliation case is stated against an exact input, including the ones no
  corpus contract reaches (``record_mismatch``, ``key_index_disagreement``,
  param-without-index, the lossy-key asymmetry, the two-declaration plural).
* **Producer integration** — an inline ``Slither`` contract run through
  ``build_effects`` + ``build_predicate_tree`` + ``build_claims``, so the join
  is fed by the REAL amount-record producer (U2), predicate-tree operand
  widening (U1), ordering prover (U3), and verified-guard arm (U4). This is what
  proves the two walks actually meet — a unit test alone cannot, because it
  supplies both halves itself.

Per SPEC §5.5 every conjunct has one fixture removing exactly it and asserting
``not_determined``, paired with a positive sibling differing in one construct;
assertions are on the whole verdict dict, never ``is not None``.
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


# ---------------------------------------------------------------------------
# Unit harness — hand-built predicate trees + flows
# ---------------------------------------------------------------------------


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
    """A mandatory (or, when ``mandatory=False``, OR-guarded) caller-authority
    leaf comparing ``base[key]``'s ownership member against ``msg.sender``."""
    leaf = _leaf(operands=[_element_op(base, ["bidder"], key_index), _CALLER])
    if mandatory:
        return _and(leaf)
    # Under an OR the leaf is reachable via an escape, so it is not mandatory.
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


def _ordering_refused(reason: str) -> dict:
    return {"state": "not_determined", "reason": reason}


def _ctx(tree: Any, flow: dict) -> ClaimContext:
    effects = {
        "contract_name": "C",
        "functions": {_SIG: {"sinks": [], "value_flows": [flow], "parameter_names": ["_bidId"]}},
    }
    return ClaimContext(None, effects, {"trees": {_SIG: tree}})


# --- W1: amount_record_constraint ------------------------------------------


def test_keyed_by_caller_is_constrained_without_a_guard():
    """A msg_sender key level proves the cell is the caller's; no guard leaf."""
    flow = _flow(
        amount_record_variable="C.balances",
        amount_record_key_kinds=["msg_sender"],
        amount_record_key_param_indexes=[None],
    )
    verdict = _facts.amount_record_constraint(_ctx(None, flow), _SIG, flow)
    assert verdict == {"state": "constrained", "basis": "keyed_by_caller", "record": "C.balances"}


def test_keyed_by_caller_survives_a_second_caller_chosen_level():
    """``withdrawRequests[msg.sender][asset]`` — the outer key is the caller's, so
    the whole subtree is theirs even though the caller picks ``asset``."""
    flow = _flow(
        amount_record_variable="C.withdrawRequests",
        amount_record_key_kinds=["msg_sender", "param"],
        amount_record_key_param_indexes=[None, 0],
    )
    verdict = _facts.amount_record_constraint(_ctx(None, flow), _SIG, flow)
    assert verdict == {"state": "constrained", "basis": "keyed_by_caller", "record": "C.withdrawRequests"}


def test_owner_guarded_record_joins_guard_and_amount_on_the_same_cell():
    flow = _flow(
        amount_record_variable="C.bids",
        amount_record_member_path=["amount"],
        amount_record_key_kinds=["param"],
        amount_record_key_param_indexes=[0],
    )
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.bids", 0), flow), _SIG, flow)
    assert verdict == {"state": "constrained", "basis": "owner_guarded_record", "record": "C.bids"}


def test_owner_guarded_record_compares_canonical_names_across_inheritance():
    """Both walks name the base off ``StateVariable.canonical_name`` (the
    declaring contract), so an inherited ``Base.pool`` joins to itself — the
    highest-probability silent-zero, asserted to JOIN, not vanish."""
    flow = _flow(
        amount_record_variable="Base.pool",
        amount_record_member_path=["amount"],
        amount_record_key_kinds=["param"],
        amount_record_key_param_indexes=[0],
    )
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("Base.pool", 0), flow), _SIG, flow)
    assert verdict == {"state": "constrained", "basis": "owner_guarded_record", "record": "Base.pool"}


def test_wrong_record_refuses_record_mismatch():
    """A8: the guard proves ownership of a DIFFERENT record than the amount reads."""
    flow = _flow(
        amount_record_variable="C.amounts", amount_record_key_kinds=["param"], amount_record_key_param_indexes=[0]
    )
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.owners", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "record_mismatch"}


def test_wrong_key_refuses_key_index_disagreement():
    """A9: same record, but the guard keys on a different entry slot than the pay."""
    flow = _flow(
        amount_record_variable="C.bids", amount_record_key_kinds=["param"], amount_record_key_param_indexes=[1]
    )
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.bids", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "key_index_disagreement"}


def test_non_mandatory_guard_refuses_guard_not_mandatory():
    """A10: the ownership check sits under an OR escape, so it is not mandatory."""
    flow = _flow(
        amount_record_variable="C.bids", amount_record_key_kinds=["param"], amount_record_key_param_indexes=[0]
    )
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.bids", 0, mandatory=False), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "guard_not_mandatory"}


def test_param_kind_without_index_refuses_never_kind_alone():
    """The amount side folds ``key_kinds`` and ``key_param_indexes`` separately,
    so ``param`` can survive a disagreement that strips the index. The join
    requires the index PRESENT and equal — never ``kind == param`` alone."""
    flow = _flow(amount_record_variable="C.bids", amount_record_key_kinds=["param"])  # no key_param_indexes
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.bids", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "key_index_disagreement"}


def test_lossy_key_asymmetry_refuses_on_the_amount_sides_indeterminate():
    """The guard side does not apply the amount side's lossy-narrowing check, so a
    guard on ``bids[uint128(id)]`` could stamp slot 0 while the amount side reads
    the key as indeterminate. The join refuses on that asymmetry rather than
    trusting the guard's slot — the amount side's ``None`` blocks the proof."""
    flow = _flow(
        amount_record_variable="C.bids",
        amount_record_key_kinds=["indeterminate"],
        amount_record_key_param_indexes=[None],
    )
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.bids", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "key_index_disagreement"}


def test_two_declarations_refuses_multiple_record_declarations():
    """A17: two contracts in the call graph each declare ``bids``, so the amount
    producer published the honest plural and no scalar."""
    flow = _flow(amount_record_variables=["Base.bids", "Impl.bids"])
    verdict = _facts.amount_record_constraint(_ctx(None, flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "multiple_record_declarations"}


def test_no_record_named_refuses_amount_root_not_classifiable():
    """The redeem shape: ``bounded_by_storage`` but the amount root was a memory
    array the walk could not classify, so it named no cell."""
    flow = _flow()  # no amount_record_* keys at all
    verdict = _facts.amount_record_constraint(_ctx(_ownership_tree("C.bids", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "amount_root_not_classifiable"}


def test_missing_tree_refuses_rather_than_reading_absence_as_no_guard():
    """No predicate tree is not proof of no guard; a non-keyed record refuses."""
    flow = _flow(
        amount_record_variable="C.bids", amount_record_key_kinds=["param"], amount_record_key_param_indexes=[0]
    )
    verdict = _facts.amount_record_constraint(_ctx(None, flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "guard_not_mandatory"}


def test_guard_without_msg_sender_operand_does_not_satisfy_w1():
    """Paired falsifier for conjunct 3: the same shape with the msg_sender operand
    removed proves nothing — an element read compared to a constant is no
    ownership proof."""
    leaf = _leaf(operands=[_element_op("C.bids", ["bidder"], 0), {"source": "constant"}])
    flow = _flow(
        amount_record_variable="C.bids", amount_record_key_kinds=["param"], amount_record_key_param_indexes=[0]
    )
    verdict = _facts.amount_record_constraint(_ctx(_and(leaf), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "guard_not_mandatory"}


# --- W1 ∧ W2: self_service_payout (W2 via ordering; no live contract) -------


def test_proven_keyed_by_caller_with_ordering():
    flow = _flow(
        amount_record_variable="C.balances",
        amount_record_key_kinds=["msg_sender"],
        amount_record_key_param_indexes=[None],
        record_ordering=_ordering_proven("C.balances"),
    )
    verdict = _facts.self_service_payout(_ctx(None, flow), _SIG, flow)
    assert verdict == {
        "state": "proven_self_service",
        "w1_basis": "keyed_by_caller",
        "w2_basis": "clear_dominates_calls",
        "record": "C.balances",
        "disclosures": _BASE_DISCLOSURES,
    }


def test_proven_owner_guarded_with_ordering():
    flow = _flow(
        amount_record_variable="C.bids",
        amount_record_member_path=["amount"],
        amount_record_key_kinds=["param"],
        amount_record_key_param_indexes=[0],
        record_ordering=_ordering_proven("C.bids"),
    )
    verdict = _facts.self_service_payout(_ctx(_ownership_tree("C.bids", 0), flow), _SIG, flow)
    assert verdict == {
        "state": "proven_self_service",
        "w1_basis": "owner_guarded_record",
        "w2_basis": "clear_dominates_calls",
        "record": "C.bids",
        "disclosures": _BASE_DISCLOSURES,
    }


def test_loop_ordering_carries_the_cross_iteration_disclosure():
    """P2: a per-iteration ordering proof rides ``cross_iteration_ordering_not_proven``
    beside the two universal disclosures."""
    flow = _flow(
        amount_record_variable="C.balances",
        amount_record_key_kinds=["msg_sender"],
        amount_record_key_param_indexes=[None],
        record_ordering=_ordering_proven("C.balances", disclosures=["cross_iteration_ordering_not_proven"]),
    )
    verdict = _facts.self_service_payout(_ctx(None, flow), _SIG, flow)
    assert verdict["disclosures"] == [_UPGRADE, _SIBLING, "cross_iteration_ordering_not_proven"]


def test_w1_refusal_propagates_as_the_self_service_reason():
    flow = _flow(
        amount_record_variable="C.amounts",
        amount_record_key_kinds=["param"],
        amount_record_key_param_indexes=[0],
        record_ordering=_ordering_proven("C.amounts"),
    )
    verdict = _facts.self_service_payout(_ctx(_ownership_tree("C.owners", 0), flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "record_mismatch"}


def test_ordering_refusal_wins_when_w1_holds():
    """A1 shape: W1 proven, ordering refuses — the ordering reason (WHY the code
    order is unsafe) is the self-service refusal reason."""
    flow = _flow(
        amount_record_variable="C.balances",
        amount_record_key_kinds=["msg_sender"],
        amount_record_key_param_indexes=[None],
        record_ordering=_ordering_refused("clearing_write_does_not_dominate_calls"),
    )
    verdict = _facts.self_service_payout(_ctx(None, flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "clearing_write_does_not_dominate_calls"}


def test_no_ordering_and_no_guard_refuses_function_not_analyzed():
    """Both W2 satisfiers silent (no ``record_ordering`` on the flow, no live
    contract for the guard arm) — the guard's explicit refusal is published."""
    flow = _flow(
        amount_record_variable="C.balances",
        amount_record_key_kinds=["msg_sender"],
        amount_record_key_param_indexes=[None],
    )
    verdict = _facts.self_service_payout(_ctx(None, flow), _SIG, flow)
    assert verdict == {"state": "not_determined", "reason": "function_not_analyzed"}


# --- _flow_entry gate + SS-R3 ride-along -----------------------------------


def test_flow_entry_attaches_only_on_a_storage_amount():
    flow = _flow(
        amount_record_variable="C.balances",
        amount_record_key_kinds=["msg_sender"],
        amount_record_key_param_indexes=[None],
        kind="native_transfer_send",
        selector=None,
        from_is_self=True,
        record_ordering=_ordering_proven("C.balances"),
    )
    entry = flowmod._flow_entry(_ctx(None, flow), _SIG, flow)
    assert entry["self_service_payout"]["state"] == "proven_self_service"
    assert entry["amount_record_constraint"] == {
        "state": "constrained",
        "basis": "keyed_by_caller",
        "record": "C.balances",
    }


def test_flow_entry_omits_the_keys_on_a_param_amount_and_rides_ss_r3():
    """A param amount is a different question: the self-service keys stay ABSENT
    (fail-closed), and SS-R3's ``amount_constraint`` rides instead."""
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


# ---------------------------------------------------------------------------
# Producer integration — the two walks actually meet on a real contract
# ---------------------------------------------------------------------------

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
    """P1 — the whole join, fed by all four producers, on a real contract."""
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
    """P3 — a guarded, clear-after-pay row proves via the verified guard; the
    ordering-only sibling with no guard proves via ordering. Both W2 bases are
    reachable, and the guard being unnecessary on ``withdraw`` is what shows the
    ordering arm survives a guard's removal."""
    guarded = _self_service(_corpus, "withdrawGuarded()")
    assert guarded["state"] == "proven_self_service"
    assert guarded["w2_basis"] == "verified_guard"
    assert _self_service(_corpus, "withdraw()")["w2_basis"] == "clear_dominates_calls"


def test_producer_dao_shape_refuses(_corpus):
    """A1 — pay then clear; the clearing write does not dominate the call."""
    assert _self_service(_corpus, "badWithdraw()") == {
        "state": "not_determined",
        "reason": "clearing_write_does_not_dominate_calls",
    }


def test_producer_contract_scoped_guard_licenses_no_unguarded_function(_corpus):
    """A12 — a real guard exists on the contract but ``badWithdraw`` does not
    apply it, and its ordering refuses, so the row is NOT cleared. The verified
    guard arm publishes ``guard_modifier_not_applied`` for it."""
    verdict = _self_service(_corpus, "badWithdraw()")
    assert verdict["state"] == "not_determined"
    guard = verified_guard_verdicts(_corpus)["badWithdraw()"]
    assert guard["state"] == "not_determined"
    assert guard["reason"] == "guard_modifier_not_applied"


def test_producer_admin_sweep_param_leaves_the_key_absent(_corpus):
    """A5 — a param-amount sweep names no record, so the gate never fires and the
    key stays absent (fail-closed). The discrimination pair with ``cancelBid``:
    the caller-owned shape proves, the sweep does not exist as a self-service
    question at all."""
    entries = _flow_out_entries(_corpus, "rescueTokens(address,uint256)")
    assert entries
    assert all("self_service_payout" not in e for e in entries)


def test_producer_whole_balance_sweep_leaves_the_key_absent(_corpus):
    """A7 — the amount folds indeterminate, so no record and no key."""
    entries = _flow_out_entries(_corpus, "sweepAll(address)")
    assert entries
    assert all("self_service_payout" not in e for e in entries)


# ---------------------------------------------------------------------------
# The burn variant — its provable sub-case and its fail-closed refusal
# ---------------------------------------------------------------------------

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
    """P4 (as the shipped producers realize it): a burn whose paid amount is read
    from the caller's own cell is keyed_by_caller — the distinct
    ``burn_of_caller_shares`` variant needs a decrement/SSA fact no producer
    publishes, so the only provable burn is this one."""
    verdict = _self_service(_burn, "redeemSame()")
    assert verdict["state"] == "proven_self_service"
    assert verdict["w1_basis"] == "keyed_by_caller"


def test_burn_then_oracle_pay_stays_fail_closed_absent(_burn):
    """A16 — the oracle-converted payout is param_derived, so the self-service
    key never attaches and the row is never cleared."""
    entries = _flow_out_entries(_burn, "redeemOracle(uint256)")
    assert entries
    assert all("self_service_payout" not in e for e in entries)
