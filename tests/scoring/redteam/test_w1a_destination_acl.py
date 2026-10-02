"""W1a: the AtomicSolverV3 -> Teller shape, where the callee is a parameter and the binding lives in the
destination's ACL.
"""

from __future__ import annotations

from services.scoring import planes as P
from services.scoring.schema import entity_key
from tests.support.scoring_builders import (
    ACL_ACCEPTED,
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    KEY_C,
    KEY_PROXY,
    KEY_V,
    VAULT,
    _acl_plane,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    act_as_plane,
    fold,  # noqa: F401  (fold fixture, registered by import)
)
from utils.scoring_status import VALUE_STATE_PROVEN_REACH


def test_w1a_a_parameter_bound_call_site_composes_on_the_destinations_own_acl(fold):
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(act_as=_acl_plane()),
    )
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["value_state"] == VALUE_STATE_PROVEN_REACH
    assert [c["entity"] for c in row["reach_composed_magnitudes"]] == [KEY_V]
    assert row["reach_composition_census"]["act_as_witnessed"] == 1


def test_w1a_an_acl_admitted_step_publishes_the_witness_shape_that_admitted_it(fold):
    """No abstraction above a witness, and no basis borrowed from one.

    An ACL-admitted step must not be rendered through the state-variable
    sentence (no state variable, no on-chain read). It names the shape, the
    ``function_principals`` row, the admitting roles and the membership quality,
    and leaves the receiver fields empty.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(act_as=_acl_plane()),
    )
    step = _gate_row(document)["reach_composed_magnitudes"][0]["act_as_chain"][0]
    assert step["witness_kind"] == P.ACT_AS_WITNESS_DESTINATION_ACL
    assert step["destination_acceptance"] == {
        "source": "function_principals",
        "function_principal_id": 14279,
        "destination_function": "bulkWithdraw",
        "accepting_roles": [12],
        "membership_quality": "exact",
    }
    assert (step["receiver_variable"], step["receiver_observed_via"], step["receiver_block"]) == (None, None, None)
    assert "on its own state variable" not in step["basis"]
    for fragment in ("function_principals row 14279", "role(s) [12]", "membership_quality 'exact'", "parameter-bound"):
        assert fragment in step["basis"], fragment
    other = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    other_step = _gate_row(other)["reach_composed_magnitudes"][0]["act_as_chain"][0]
    assert other_step["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert other_step["destination_acceptance"] is None
    assert "state variable 'vault'" in other_step["basis"]


def test_w1a_the_acl_admission_is_a_magnitude_witness_and_never_a_reach_one(fold):
    """Reach is decided by the closure walk; the ACL can only witness magnitude on already-reached entities."""
    without = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=act_as_plane()))
    with_acl = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=_acl_plane()))
    assert _gate_row(without)["reach_entities"] == _gate_row(with_acl)["reach_entities"]
    assert _gate_row(without)["value_at_stake_usd"] is None
    assert _gate_row(with_acl)["value_at_stake_usd"] == 1_000_000.0


def test_w1a_a_missing_or_unenumerated_acl_row_is_a_typed_refusal_not_a_pass():
    """Each variant removes one conjunct, and each shortfall is a different finding."""
    other_chain = entity_key("base", VAULT)
    variants = {
        "no_acl_at_all": (_acl_plane(destination_acl={}), P.ACT_AS_NO_DESTINATION_ACL),
        "acl_names_another_caller": (
            _acl_plane(destination_acl={(KEY_V, COMPOSED_SELECTOR): {KEY_PROXY: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # A same-address destination on another chain is a different contract.
        "acl_is_on_another_chain": (
            _acl_plane(destination_acl={(other_chain, COMPOSED_SELECTOR): {KEY_C: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        "acl_is_for_another_selector": (
            _acl_plane(destination_acl={(KEY_V, "0xdeadbeef"): {KEY_C: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # Not the same fact as the list never naming the caller.
        "acl_row_names_no_admitting_role": (
            _acl_plane(
                destination_acl={
                    (KEY_V, COMPOSED_SELECTOR): {KEY_C: P.DestinationAcceptance((), "exact", "bulkWithdraw", 14279)}
                }
            ),
            P.ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE,
        ),
        "membership_is_only_bounded_below": (
            _acl_plane(
                destination_acl={
                    (KEY_V, COMPOSED_SELECTOR): {
                        KEY_C: P.DestinationAcceptance((12,), "lower_bound", "bulkWithdraw", 14279)
                    }
                }
            ),
            P.ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE,
        ),
        # The second shape doesn't weaken the gate conjuncts, and parameter-binding is the shape's precondition, never
        # the shortfall.
        "call_site_needs_no_gate": (
            _acl_plane(call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "open", "", True, CALLING_SELECTOR),)}),
            P.ACT_AS_CALL_SITE_IS_PUBLIC,
        ),
        "gate_is_not_delegated": (
            _acl_plane(
                call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", False, CALLING_SELECTOR),)}
            ),
            P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED,
        ),
        # An undetermined gate is a coverage gap, never "needs no gate".
        "gate_openness_is_not_determined": (
            _acl_plane(
                call_sites={
                    (KEY_C, COMPOSED_SELECTOR): (("boringSolve", "not_determined", "", True, CALLING_SELECTOR),)
                }
            ),
            P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED,
        ),
        # An ACL row is a licence to call, not a witness of a call.
        "no_call_site": (_acl_plane(call_sites={}), P.ACT_AS_NO_CALL_SITE),
    }
    for name, (plane, expected) in variants.items():
        verdict = plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert not verdict.witnessed, name
        assert verdict.step is None, name
        assert verdict.outcome == expected, name


def test_w1a_a_state_variable_site_still_reports_its_own_sharper_shortfall():
    """Report the sharper refusal: how far the walk got."""
    plane = act_as_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", True, CALLING_SELECTOR),
            )
        },
        reads={(KEY_C, "vault"): (KEY_PROXY, "eth_call", 1)},
    )
    assert plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
    unread = act_as_plane(
        call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),)}
    )
    assert unread.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_NO_DESTINATION_ACL


def test_w1a_a_satisfied_state_variable_read_is_still_the_witness_that_admits(fold):
    """The state-variable witness is stronger, so it keeps priority."""
    both = _acl_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", True, CALLING_SELECTOR),
            )
        },
        reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
    )
    verdict = both.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
    assert verdict.witnessed
    assert verdict.step is not None
    assert verdict.step.witness_kind == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert verdict.step.acceptance is None

    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=both))
    step = _gate_row(document)["reach_composed_magnitudes"][0]["act_as_chain"][0]
    assert step["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert step["destination_acceptance"] is None
    assert (step["calling_function"], step["receiver_variable"]) == ("bulkWithdraw", "vault")
