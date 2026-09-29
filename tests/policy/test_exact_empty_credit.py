"""A2 — the earned-negative gate, served beside the payload it gates.

An empty caller set is the strongest earned negative the resolver publishes, but the
shipped consumers award it on ``membership_quality == "exact" and members == []``
alone — which a provenance-less empty satisfies as well as a read-confirmed one
(86 ``restricted`` rows on the validated corpus rest solely on it). The gate requires
four things TOGETHER, each via allow-list (a presence check fails open for future
producers). Every test is a rejecting arm except the two that earn.
"""

from __future__ import annotations

from typing import Any

import pytest

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
    """The MIN over operands at DIFFERENT heights is a staleness floor, not "the set
    was empty at that block": both fold families publish state-AT-h with revocations
    applied, so a member revoked from the later operand is absent while the true set
    at MIN still held it. Admitting it would re-introduce the claim the producer refuses."""
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
    """A future producer appending its own step, with a block and a reason, must not
    mint an earned negative — admissible producers are enumerated and each refuses to
    answer without proven coverage."""
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


@pytest.mark.parametrize(
    "reason",
    [
        # Its only surviving producer classifies from the accessor's ``pending`` prefix
        # (``basis: "accessor_name"``). A name may not license the strongest negative — and
        # the one persisted row with this reason got it from a DEFAULT ARGUMENT VALUE.
        pytest.param("empty_by_design", id="empty_by_design"),
        # CRITICAL: failure reasons (and None) must never earn the credit.
        pytest.param("unreadable_revert", id="unreadable_revert"),
        pytest.param("unreadable_empty", id="unreadable_empty"),
        pytest.param("not_read", id="not_read"),
        pytest.param("bad_input", id="bad_input"),
        pytest.param(None, id="none"),
        # ``0x…dEaD`` being unspendable is a convention, not a read.
        pytest.param("owner_read_burn_address", id="burn_address"),
    ],
)
def test_unconfirmed_empty_reasons_never_earn_the_credit(reason):
    credit = exact_empty_credit(_empty(empty_reason=reason))
    assert credit["verdict"] == "not_determined"
    assert "read_confirmed_empty_reason" in credit["missing"]


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


@pytest.mark.parametrize(
    "cap,verdict",
    [
        pytest.param(_empty(members=["0x" + "11" * 20]), "not_applicable", id="populated_set"),
        pytest.param({"kind": "AND", "children": []}, "not_applicable", id="non_finite_set"),
        pytest.param(None, "not_determined", id="missing_capability"),
    ],
)
def test_shape_guards(cap, verdict):
    assert exact_empty_credit(cap)["verdict"] == verdict
