"""A3: the hoisted basis must never be attributed to members it did not resolve.

``details`` is stamped on EVERY member row of a finite_set while ``_intersect_finite`` /
``_union_finite`` CONCATENATE operand traces, so a merged set can carry one
``authority_getter_basis`` step beside members an event fold contributed; a naive hoist would
misattribute the basis to them. 0 corpus rows are merged today; these pin the guard for the first.

Second guard, vocabulary: the hoist reads PERSISTED capability dicts and 33 stored rows carry the
pre-split ``internal_accessor_convention``. One field must not carry two epochs, and an unmappable
label can't be ranked, so an unrecognised basis publishes nothing.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.policy.capability_surface import project_capability_surface

ADDR_A = "0x" + "aa" * 20
ADDR_B = "0x" + "bb" * 20


def _cap(members: list[str], trace: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "kind": "finite_set",
        "members": members,
        "membership_quality": "exact",
        "confidence": "enumerable",
        "trace": trace,
    }


def _details(cap: dict[str, Any]) -> list[dict[str, Any]]:
    return [row["details"] for row in project_capability_surface(cap).principal_rows]


BASIS_STEP = {"step": "authority_getter_basis", "basis": "deunderscore_convention", "selector": "0x0c340a24"}
CO_WITNESS = {"step": "live_getter_resolution", "selector": "0x0c340a24"}


def test_the_single_member_shape_hoists():
    """The realized shape (33/33 corpus rows): one member, one basis step, with
    ``live_getter_resolution`` as co-witness so the row doesn't rest on the convention alone."""
    details = _details(_cap([ADDR_A], [CO_WITNESS, BASIS_STEP]))
    assert details[0]["authority_basis"] == "deunderscore_convention"
    assert details[0]["accessor_slot_agreement"] == "not_determined"


def test_a_merged_multi_member_set_publishes_no_basis():
    """Two members, one basis step: the basis names how ONE was resolved; stamping both would
    attribute a name-matched binding to a row an event fold produced."""
    details = _details(_cap([ADDR_A, ADDR_B], [CO_WITNESS, BASIS_STEP]))
    assert len(details) == 2
    for row in details:
        assert "authority_basis" not in row
        assert "accessor_slot_agreement" not in row


_ABI_STEP = {"step": "authority_getter_basis", "basis": "abi_auto_getter", "selector": "0x8da5cb5b"}


@pytest.mark.parametrize(
    "trace",
    [
        # CRITICAL, fail-closed hoist guards. A fold contributed members beside the getter read,
        # so the basis no longer describes the set.
        pytest.param([BASIS_STEP, {"step": "enumerable_role_store"}], id="second-resolution-step-suppresses"),
        pytest.param([BASIS_STEP, _ABI_STEP], id="two-basis-steps-that-disagree"),
        # Fail-closed on the count, not the values: two steps mean two reads contributed and
        # which bound the member isn't recorded.
        pytest.param([BASIS_STEP, dict(BASIS_STEP)], id="two-identical-basis-steps"),
        # The 33 persisted rows carry ``internal_accessor_convention``, which conflated the ERC-7201
        # accessor match with the de-underscore convention. It is deliberately NOT mapped forward
        # (which helper fired isn't in the stored row): key absent = not_determined = weakest, the
        # honest reading of a pre-split row.
        pytest.param(
            [CO_WITNESS, {"step": "authority_getter_basis", "basis": "internal_accessor_convention"}],
            id="legacy-label-not-passed-through",
        ),
        pytest.param(
            [{"step": "authority_getter_basis", "basis": "some_future_arm"}], id="unknown-label-not-passed-through"
        ),
        pytest.param([{"step": "authority_getter_basis", "basis": 7}], id="non-string-basis"),
    ],
)
def test_hoist_is_suppressed_when_the_basis_is_not_attributable(trace):
    assert "authority_basis" not in _details(_cap([ADDR_A], trace))[0]


@pytest.mark.parametrize(
    "basis, step_extra, expected_residual",
    [
        # ``accessor_slot_agreement`` asks whether the matched ACCESSOR reads the same storage as
        # the canonical getter; with no accessor matched the question doesn't arise, so the key is
        # absent rather than a stated ``not_determined``.
        pytest.param("abi_auto_getter", {"selector": "0x8da5cb5b"}, {}, id="abi-forced-arm-states-no-slot-residual"),
        *[
            pytest.param(
                basis, {}, {"accessor_slot_agreement": "not_determined"}, id=f"name-matched-arm-{basis}-states-residual"
            )
            for basis in ("standard_namespaced_accessor", "deunderscore_convention", "slot_name_keyword")
        ],
    ],
)
def test_basis_arm_residual(basis, step_extra, expected_residual):
    step = {"step": "authority_getter_basis", "basis": basis, **step_extra}
    details = _details(_cap([ADDR_A], [step]))[0]
    assert details["authority_basis"] == basis
    assert {k: v for k, v in details.items() if k == "accessor_slot_agreement"} == expected_residual
