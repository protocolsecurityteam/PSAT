"""U1: each case changes one fact about the receiver read, and the refusal reason must move with it."""

from __future__ import annotations

from typing import Any

from services.scoring import planes as P
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    HOP1_SELECTOR,
    KEY_C,
    KEY_PROXY,
    KEY_T,
    KEY_V,
    _acl_plane,
    act_as_plane,
    fold,  # noqa: F401  (fold fixture, registered by import)
)

_LADDER_SITES = {(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)}


def _ladder(**over: Any) -> P.ActAsPlane:
    case: dict[str, Any] = {"call_sites": _LADDER_SITES}
    case.update(over)
    return act_as_plane(**case)


def test_u1_a_renounced_and_a_codeless_pointer_each_earn_their_own_negative():
    """``zero`` is renounced forever; ``eoa`` can become a contract via CREATE2, so it's a weaker proof."""
    read: dict[tuple[str, str], tuple[str, str, int | None]] = {(KEY_C, "vault"): (KEY_PROXY, "eth_call", 25_657_731)}
    cases = {
        "zero": P.ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS,
        "eoa": P.ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT,
        "safe": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
        "timelock": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
        "contract": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
        "unknown": P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
    }
    for kind, expected in cases.items():
        verdict = _ladder(reads=read, read_kinds={(KEY_C, "vault"): kind}).acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert verdict.outcome == expected, kind
        assert verdict.receiver_resolved_type == kind, kind
    unclassified = _ladder(reads=read).acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
    assert unclassified.outcome == P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
    assert unclassified.receiver_resolved_type == "not_determined"


def test_u1_the_parameter_bound_arm_reports_the_conjunct_that_actually_failed():
    """Parameter-bound makes the ACL shape admissible; it is never the refusal reason."""
    gate_cases = {
        "open": P.ACT_AS_CALL_SITE_IS_PUBLIC,
        "not_determined": P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED,
    }
    for openness, expected in gate_cases.items():
        plane = _acl_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("boringSolve", openness, "", True, CALLING_SELECTOR),)}
        )
        assert plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == expected, openness
    both = _acl_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("boringSolve", "not_determined", "", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", False, CALLING_SELECTOR),
            )
        }
    )
    assert both.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
    mixed = _acl_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("boringSolve", "not_determined", "", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", True, CALLING_SELECTOR),
            )
        }
    )
    admitted = mixed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
    assert admitted.witnessed and admitted.step is not None
    assert admitted.step.calling_function == "finishSolve"


def test_u1_delegation_is_required_at_hop_1_and_not_past_it():
    """B3: at hop 1 only an authority-delegated gate opens; past it the principal arrives as whoever the previous hop
    admitted, so a direct ``msg.sender ==`` intermediate is exactly the chain shape.
    """
    plane = act_as_plane(
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", False, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    )
    assert plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
    past = plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
    assert past.witnessed and past.step is not None
    # The relaxation is disclosed, not silently dropped.
    assert past.step.admitted_without_a_delegation_witness is True
    assert past.step.as_json()["admitted_without_a_delegation_witness"] is True
    assert "was NOT tested" not in past.step.as_json()["basis"]
    assert "no witness that" in past.step.as_json()["basis"]
    delegated = act_as_plane(
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    ).acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
    assert delegated.step is not None and delegated.step.admitted_without_a_delegation_witness is False
