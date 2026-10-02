"""A2: consumers awarded the strongest negative on ``exact`` + ``[]`` alone, which a provenance-less empty satisfies
(86 restricted rows rest on it). The gate needs four things together, each via allow-list.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.policy.capability_surface import exact_empty_credit

BLOCK = 25643300


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


def test_an_equal_heights_exact_as_of_is_an_admissible_observation_block():
    cap = _empty(
        trace=[{"step": "enumerable_role_store"}],
        empty_reason="slot_read_zero",
        exact_as_of=BLOCK,
    )
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "earned"
    assert credit["block_source"] == "exact_as_of"


def test_a_refused_exact_as_of_is_not_a_block():
    cap = _empty(trace=[{"step": "enumerable_role_store"}], exact_as_of="not_determined")
    assert exact_empty_credit(cap)["verdict"] == "not_determined"


def test_a_trace_less_empty_is_not_determined():
    cap = _empty(trace=[], empty_reason=None)
    credit = exact_empty_credit(cap)
    assert credit["verdict"] == "not_determined"
    assert set(credit["missing"]) == {"coverage_proving_step", "observation_block", "read_confirmed_empty_reason"}


def test_each_allow_listed_producer_is_accepted():
    for step in ("solmate_roles_authority", "enumerable_role_store", "live_getter_resolution", "live_slot_resolution"):
        cap = _empty(trace=[{"step": step, "observed_at_block": BLOCK}])
        assert exact_empty_credit(cap)["verdict"] == "earned", step


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
