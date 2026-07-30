"""A2 — the earned-negative gate, served beside the payload it gates.

An empty caller set is the strongest earned negative the resolver publishes.
The shipped consumers award it on ``membership_quality == "exact" and members ==
[]`` alone — a shape a provenance-less empty satisfies exactly as well as a
read-confirmed one. On the validated corpus 86 rows are ``restricted`` resting
solely on that branch, 86/86 with no height anywhere in the tree, and 4 of them
cannot be reconstructed at all.

The gate requires four things TOGETHER, each with an allow-list rather than a
presence check, because a presence check fails open for any future producer.
Every test below is a rejecting arm except the two that earn.
"""

from __future__ import annotations

from typing import Any

from services.policy.capability_surface import exact_empty_credit

BLOCK = 25643300
OTHER_BLOCK = 25619032


def _empty(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "finite_set",
        "members": [],
        "membership_quality": "exact",
        "confidence": "enumerable",
        "empty_reason": "owner_read_zero",
        "trace": [{"step": "live_getter_resolution", "selector": "0x8da5cb5b", "observed_at_block": BLOCK}],
    }
    base.update(over)
    return base


def test_a_fully_witnessed_empty_earns_and_carries_its_witness():
    assert exact_empty_credit(_empty()) == {
        "verdict": "earned",
        "missing": [],
        "block": BLOCK,
        "block_source": "trace.observed_at_block",
        "empty_reason": "owner_read_zero",
    }


def test_an_equal_heights_exact_as_of_is_an_admissible_observation_block():
    cap = _empty(
        trace=[{"step": "enumerable_role_store"}],
        empty_reason="slot_read_zero",
        exact_as_of=BLOCK,
    )
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "earned"
    assert credit["block_source"] == "exact_as_of"


# ---------------------------------------------------------------------------
# The observation block must not be laundered from the staleness floor
# ---------------------------------------------------------------------------


def test_last_indexed_block_is_not_an_observation_block():
    """The MIN over operands at DIFFERENT heights is a staleness floor. Reading
    it as "the set was empty at that block" is false — both fold families
    publish state-AT-h with revocations applied, so a member revoked from the
    later operand is absent from the published set while the true set at MIN
    still held it. Admitting it here would re-introduce through the consumer the
    exact claim the producer refuses."""
    cap = _empty(
        trace=[{"step": "enumerable_role_store"}],
        last_indexed_block=OTHER_BLOCK,
        exact_as_of="not_determined",
    )
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "not_determined"
    assert "observation_block" in credit["missing"]


def test_a_refused_exact_as_of_is_not_a_block():
    cap = _empty(trace=[{"step": "enumerable_role_store"}], exact_as_of="not_determined")
    assert exact_empty_credit(cap)["verdict"] == "not_determined"


# ---------------------------------------------------------------------------
# Coverage-proving step allow-list (presence is not a witness)
# ---------------------------------------------------------------------------


def test_an_unlisted_trace_step_does_not_prove_coverage():
    """A step name is not evidence. A future producer appending its own step,
    with a block and a reason, must not thereby mint an earned negative — the
    admissible producers are enumerated and each refuses to answer at all
    without proven coverage of what it read."""
    cap = _empty(trace=[{"step": "some_new_adapter", "observed_at_block": BLOCK}])
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "not_determined"
    assert "coverage_proving_step" in credit["missing"]


def test_a_trace_less_empty_is_not_determined():
    """The four unexplainable rows (ef 192, 797, 1151, 1613)."""
    cap = _empty(trace=[], empty_reason=None)
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "not_determined"
    assert set(credit["missing"]) == {"coverage_proving_step", "observation_block", "read_confirmed_empty_reason"}


def test_each_allow_listed_producer_is_accepted():
    for step in ("solmate_roles_authority", "enumerable_role_store", "live_getter_resolution", "live_slot_resolution"):
        cap = _empty(trace=[{"step": step, "observed_at_block": BLOCK}])
        assert exact_empty_credit(cap)["verdict"] == "earned", step


# ---------------------------------------------------------------------------
# empty_reason allow-list (never `is not None`)
# ---------------------------------------------------------------------------


def test_empty_by_design_never_earns_the_credit():
    """Its only surviving producer classifies the gate from the accessor's
    ``pending`` prefix and records ``basis: "accessor_name"``. A name may not
    license the strongest negative in the system — and the one persisted row
    carrying this reason got it from a DEFAULT ARGUMENT VALUE."""
    cap = _empty(empty_reason="empty_by_design")
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "not_determined"
    assert "read_confirmed_empty_reason" in credit["missing"]


def test_failure_reasons_never_earn_the_credit():
    for reason in ("unreadable_revert", "unreadable_empty", "not_read", "bad_input", None):
        cap = _empty(empty_reason=reason)
        assert exact_empty_credit(cap)["verdict"] == "not_determined", reason


def test_the_burn_reason_never_earns_the_credit():
    """``0x…dEaD`` being unspendable is a convention, not a read."""
    cap = _empty(empty_reason="owner_read_burn_address")
    assert exact_empty_credit(cap)["verdict"] == "not_determined"


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------


def test_a_lower_bound_or_partial_empty_can_never_earn():
    for over in ({"membership_quality": "lower_bound"}, {"confidence": "partial"}):
        credit = exact_empty_credit(_empty(**over))
        assert credit["verdict"] == "not_determined"
        assert "exact_enumerable" in credit["missing"]


# ---------------------------------------------------------------------------
# Shape guards
# ---------------------------------------------------------------------------


def test_a_populated_set_is_not_applicable():
    assert exact_empty_credit(_empty(members=["0x" + "11" * 20]))["verdict"] == "not_applicable"


def test_a_non_finite_set_is_not_applicable():
    assert exact_empty_credit({"kind": "AND", "children": []})["verdict"] == "not_applicable"


def test_a_missing_capability_is_not_determined():
    assert exact_empty_credit(None)["verdict"] == "not_determined"


def test_the_gate_never_returns_a_proven_absent_verdict():
    """It withholds a credit; it never asserts that a caller exists."""
    for cap in (_empty(), _empty(trace=[]), None, {"kind": "AND"}):
        assert exact_empty_credit(cap)["verdict"] in ("earned", "not_determined", "not_applicable")
