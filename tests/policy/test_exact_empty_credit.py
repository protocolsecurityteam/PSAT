"""A2: consumers awarded the strongest negative on ``exact`` + ``[]`` alone, which a provenance-less empty satisfies
(86 restricted rows rest on it). The gate needs four things together, each via allow-list.
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


def test_last_indexed_block_is_not_an_observation_block():
    """MIN over operands at different heights is a staleness floor; a member revoked from the later operand could
    still be in the set at MIN.
    """
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


def test_an_unlisted_trace_step_does_not_prove_coverage():
    """A future producer's own step must not mint an earned negative."""
    cap = _empty(trace=[{"step": "some_new_adapter", "observed_at_block": BLOCK}])
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "not_determined"
    assert "coverage_proving_step" in credit["missing"]


def test_a_trace_less_empty_is_not_determined():
    cap = _empty(trace=[], empty_reason=None)
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "not_determined"
    assert set(credit["missing"]) == {"coverage_proving_step", "observation_block", "read_confirmed_empty_reason"}


def test_each_allow_listed_producer_is_accepted():
    for step in ("solmate_roles_authority", "enumerable_role_store", "live_getter_resolution", "live_slot_resolution"):
        cap = _empty(trace=[{"step": step, "observed_at_block": BLOCK}])
        assert exact_empty_credit(cap)["verdict"] == "earned", step


@pytest.mark.parametrize(
    "reason",
    [
        # A name may not license the strongest negative, and the one persisted row got it from a default argument.
        pytest.param("empty_by_design", id="empty_by_design"),
        pytest.param("unreadable_revert", id="unreadable_revert"),
        pytest.param("unreadable_empty", id="unreadable_empty"),
        pytest.param("not_read", id="not_read"),
        pytest.param("bad_input", id="bad_input"),
        pytest.param(None, id="none"),
        # Unspendability is a convention, not a read.
        pytest.param("owner_read_burn_address", id="burn_address"),
    ],
)
def test_unconfirmed_empty_reasons_never_earn_the_credit(reason):
    credit = exact_empty_credit(_empty(empty_reason=reason))
    assert credit["verdict"] == "not_determined"
    assert "read_confirmed_empty_reason" in credit["missing"]


def test_a_lower_bound_or_partial_empty_can_never_earn():
    for over in ({"membership_quality": "lower_bound"}, {"confidence": "partial"}):
        credit = exact_empty_credit(_empty(**over))
        assert credit["verdict"] == "not_determined"
        assert "exact_enumerable" in credit["missing"]


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
