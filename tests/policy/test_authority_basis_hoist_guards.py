"""A3 — the hoisted basis must never be attributed to members it did not resolve.

``details`` is stamped onto EVERY member row of a finite_set
(``_rows_for_finite_set``), while ``_intersect_finite`` / ``_union_finite``
CONCATENATE their operands' traces. So a merged set can carry one
``authority_getter_basis`` step beside members an event fold contributed, and a
naive hoist would publish "this principal rests on a de-underscore convention"
for rows resolved by something else entirely. 0 rows on the corpus are merged
today; these pin the guard for the first one that is.

The second guard is vocabulary: the hoist reads PERSISTED capability dicts, and
33 stored rows carry the pre-split ``internal_accessor_convention``. One field
must not carry two epochs, and a label the consumer cannot map is a label it
cannot rank — so an unrecognised basis publishes nothing.
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
    """The realized shape: 33/33 corpus rows are one member, one basis step, with
    ``live_getter_resolution`` as the co-witness that stops the row resting on
    the convention alone."""
    details = _details(_cap([ADDR_A], [CO_WITNESS, BASIS_STEP]))
    assert details[0]["authority_basis"] == "deunderscore_convention"
    assert details[0]["accessor_slot_agreement"] == "not_determined"


def test_a_merged_multi_member_set_publishes_no_basis():
    """Two members, one basis step — the basis names how ONE of them was
    resolved. Stamping it on both would attribute a name-matched binding to a
    row an event fold produced."""
    details = _details(_cap([ADDR_A, ADDR_B], [CO_WITNESS, BASIS_STEP]))
    assert len(details) == 2
    for row in details:
        assert "authority_basis" not in row
        assert "accessor_slot_agreement" not in row


def test_a_second_resolution_step_suppresses_the_hoist():
    """A fold contributed members alongside the getter read, so the basis no
    longer describes the whole set."""
    details = _details(_cap([ADDR_A], [BASIS_STEP, {"step": "enumerable_role_store"}]))
    assert "authority_basis" not in details[0]


def test_two_basis_steps_that_disagree_publish_nothing():
    merged = [BASIS_STEP, {"step": "authority_getter_basis", "basis": "abi_auto_getter", "selector": "0x8da5cb5b"}]
    assert "authority_basis" not in _details(_cap([ADDR_A], merged))[0]


def test_two_identical_basis_steps_also_publish_nothing():
    """Fail-closed on the count, not on the values: two steps mean two reads
    contributed, and which one bound the member is not recorded."""
    assert "authority_basis" not in _details(_cap([ADDR_A], [BASIS_STEP, dict(BASIS_STEP)]))[0]


def test_the_legacy_label_is_not_passed_through():
    """The 33 persisted rows carry ``internal_accessor_convention``, which
    conflated the ERC-7201 accessor match with the de-underscore convention. It
    is deliberately NOT mapped forward: the split is a fact about which helper
    fired, and that fact is not in the stored row. Key absent = not_determined =
    weakest, which is the honest reading of a row written before the split."""
    legacy = [CO_WITNESS, {"step": "authority_getter_basis", "basis": "internal_accessor_convention"}]
    assert "authority_basis" not in _details(_cap([ADDR_A], legacy))[0]


def test_an_unknown_label_is_not_passed_through():
    unknown = [{"step": "authority_getter_basis", "basis": "some_future_arm"}]
    assert "authority_basis" not in _details(_cap([ADDR_A], unknown))[0]


def test_a_non_string_basis_publishes_nothing():
    assert "authority_basis" not in _details(_cap([ADDR_A], [{"step": "authority_getter_basis", "basis": 7}]))[0]


def test_the_abi_forced_arm_states_no_slot_residual():
    """``accessor_slot_agreement`` answers "does the matched ACCESSOR read the
    same storage the canonical getter reads". With no accessor matched the
    question does not arise, so the key is absent rather than a stated
    ``not_determined``."""
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


def test_a_set_with_no_basis_step_is_unchanged():
    details = _details(_cap([ADDR_A], [CO_WITNESS]))[0]
    assert "authority_basis" not in details
    assert details["membership_quality"] == "exact"
