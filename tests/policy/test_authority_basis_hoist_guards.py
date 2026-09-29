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


def test_a_second_resolution_step_suppresses_the_hoist():
    """A fold contributed members beside the getter read, so the basis no longer describes the set."""
    details = _details(_cap([ADDR_A], [BASIS_STEP, {"step": "enumerable_role_store"}]))
    assert "authority_basis" not in details[0]


def test_two_basis_steps_that_disagree_publish_nothing():
    merged = [BASIS_STEP, {"step": "authority_getter_basis", "basis": "abi_auto_getter", "selector": "0x8da5cb5b"}]
    assert "authority_basis" not in _details(_cap([ADDR_A], merged))[0]


def test_two_identical_basis_steps_also_publish_nothing():
    """Fail-closed on the count, not the values: two steps mean two reads contributed and which
    bound the member isn't recorded."""
    assert "authority_basis" not in _details(_cap([ADDR_A], [BASIS_STEP, dict(BASIS_STEP)]))[0]


def test_the_legacy_label_is_not_passed_through():
    """The 33 persisted rows carry ``internal_accessor_convention``, which conflated the ERC-7201
    accessor match with the de-underscore convention. It is deliberately NOT mapped forward (which
    helper fired isn't in the stored row): key absent = not_determined = weakest, the honest
    reading of a pre-split row."""
    legacy = [CO_WITNESS, {"step": "authority_getter_basis", "basis": "internal_accessor_convention"}]
    assert "authority_basis" not in _details(_cap([ADDR_A], legacy))[0]


def test_an_unknown_label_is_not_passed_through():
    unknown = [{"step": "authority_getter_basis", "basis": "some_future_arm"}]
    assert "authority_basis" not in _details(_cap([ADDR_A], unknown))[0]


def test_a_non_string_basis_publishes_nothing():
    assert "authority_basis" not in _details(_cap([ADDR_A], [{"step": "authority_getter_basis", "basis": 7}]))[0]


def test_the_abi_forced_arm_states_no_slot_residual():
    """``accessor_slot_agreement`` asks whether the matched ACCESSOR reads the same storage as the
    canonical getter; with no accessor matched the question doesn't arise, so the key is absent
    rather than a stated ``not_determined``."""
    step = {"step": "authority_getter_basis", "basis": "abi_auto_getter", "selector": "0x8da5cb5b"}
    details = _details(_cap([ADDR_A], [step]))[0]
    assert details["authority_basis"] == "abi_auto_getter"
    assert "accessor_slot_agreement" not in details


def test_every_name_matched_arm_states_the_residual():
    for basis in ("standard_namespaced_accessor", "deunderscore_convention", "slot_name_keyword"):
        step = {"step": "authority_getter_basis", "basis": basis}
        details = _details(_cap([ADDR_A], [step]))[0]
        assert details["authority_basis"] == basis
        assert details["accessor_slot_agreement"] == "not_determined", basis
