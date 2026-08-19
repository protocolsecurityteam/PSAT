"""W1a — the destination-side ACL as the second act-as witness shape.

The corpus's own AtomicSolverV3 -> Teller shape: a restricted, authority-gated
function whose callee is a PARAMETER, so no storage of the caller can name the
destination and the binding lives in the destination's own ACL.

One of the twenty sections of the former ``test_scoring_redteam.py``.
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
    """The second witness shape, whole.

    The caller's compiled body calls the selector at an address its own caller
    supplies — the shape the state-variable witness is structurally unable to
    satisfy — and the destination's resolved access-control list names the
    caller as an accepted caller of that selector by an enumerated role. Neither
    fact alone witnesses the step; joined they do, and the magnitude composes.
    """
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
    """inv. 16: no abstraction above a witness, and no basis borrowed from one.

    An ACL-admitted step must not be rendered through the state-variable
    sentence — there is no state variable and no on-chain read of one. It names
    the shape, the ``function_principals`` row, the admitting roles and the
    membership quality, and leaves the receiver fields empty because nothing
    filled them.
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
    # ...and not through the sentence the other shape earns.
    assert "on its own state variable" not in step["basis"]
    for fragment in ("function_principals row 14279", "role(s) [12]", "membership_quality 'exact'", "parameter-bound"):
        assert fragment in step["basis"], fragment
    # The other shape keeps its own basis, unchanged and unconfusable with it.
    other = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    other_step = _gate_row(other)["reach_composed_magnitudes"][0]["act_as_chain"][0]
    assert other_step["witness_kind"] == P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    assert other_step["destination_acceptance"] is None
    assert "state variable 'vault'" in other_step["basis"]


def test_w1a_the_acl_admission_is_a_magnitude_witness_and_never_a_reach_one(fold):
    """The ACL says D accepts a call from N. It says nothing about who N reaches.

    Reach is decided by the closure walk, which never consults this plane; the
    admission may only turn a not_determined magnitude into a witnessed one on
    entities the row already reached.
    """
    without = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=act_as_plane()))
    with_acl = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=_acl_plane()))
    assert _gate_row(without)["reach_entities"] == _gate_row(with_acl)["reach_entities"]
    assert _gate_row(without)["value_at_stake_usd"] is None
    assert _gate_row(with_acl)["value_at_stake_usd"] == 1_000_000.0


def test_w1a_a_missing_or_unenumerated_acl_row_is_a_typed_refusal_not_a_pass():
    """Absence of the destination's acceptance is refused under its own reason.

    Each variant removes exactly one conjunct. A parameter-bound call site is
    promoted only when the destination's own list names this caller, for this
    selector, on this chain, by a ROLE, with the accepted set ENUMERATED. Each
    shortfall carries its own reason: "the list does not name this caller",
    "it names this caller and no role that admits it" and "it names a role and
    does not bound the accepted set" are three different findings, and a reader
    charged the wrong one is charged a claim the evidence does not support.
    """
    other_chain = entity_key("base", VAULT)
    variants = {
        # nothing on the destination side at all
        "no_acl_at_all": (_acl_plane(destination_acl={}), P.ACT_AS_NO_DESTINATION_ACL),
        # the destination accepts SOMEBODY, and not this caller
        "acl_names_another_caller": (
            _acl_plane(destination_acl={(KEY_V, COMPOSED_SELECTOR): {KEY_PROXY: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # the ACL is a fact about one deployment: a same-address destination on
        # another chain is a different contract and admits nothing here
        "acl_is_on_another_chain": (
            _acl_plane(destination_acl={(other_chain, COMPOSED_SELECTOR): {KEY_C: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # the destination accepts this caller for a DIFFERENT selector
        "acl_is_for_another_selector": (
            _acl_plane(destination_acl={(KEY_V, "0xdeadbeef"): {KEY_C: ACL_ACCEPTED}}),
            P.ACT_AS_NO_DESTINATION_ACL,
        ),
        # the row is there, and it expresses no role that admits this caller —
        # not the same fact as the destination's list never naming it
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
        # the gate conjuncts are not weakened by the second shape: a call site
        # that needs no gate, or whose gate is not delegated to an authority, is
        # never promoted by an ACL row — and each is refused under the conjunct
        # that ACTUALLY failed. The receiver being parameter-bound is the
        # PRECONDITION for this shape, so naming it as the shortfall would answer
        # a question nobody asked and hide the one that decided the verdict.
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
        # the third state of openness, which is neither of the other two: the
        # pipeline did not determine this function's gate. Publishing it as
        # "the call site needs no gate" would mint a proven-absent gate out of an
        # unread field, and publishing it as the receiver binding hides that the
        # only missing fact is a coverage gap.
        "gate_openness_is_not_determined": (
            _acl_plane(
                call_sites={
                    (KEY_C, COMPOSED_SELECTOR): (("boringSolve", "not_determined", "", True, CALLING_SELECTOR),)
                }
            ),
            P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED,
        ),
        # an ACL row alone is a licence to call, never a witness that the
        # caller's code calls anything
        "no_call_site": (_acl_plane(call_sites={}), P.ACT_AS_NO_CALL_SITE),
    }
    for name, (plane, expected) in variants.items():
        verdict = plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert not verdict.witnessed, name
        assert verdict.step is None, name
        assert verdict.outcome == expected, name


def test_w1a_a_state_variable_site_still_reports_its_own_sharper_shortfall():
    """One caller, two call sites, two shapes: report how far the walk GOT.

    A state-variable site that was read and holds somebody else got further than
    a parameter-bound site whose destination never named the caller, and the
    refusal a reader is charged must be the sharper one.
    """
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
    # With nothing to consult on either side, the parameter-bound site's own
    # reason is what the reader gets: the destination ACL WAS asked.
    unread = act_as_plane(
        call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),)}
    )
    assert unread.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_NO_DESTINATION_ACL


def test_w1a_a_satisfied_state_variable_read_is_still_the_witness_that_admits(fold):
    """Both shapes satisfied at once: the caller's own storage is what is read.

    The state-variable witness is the stronger fact — the caller's own storage
    names the destination, no arm of it depends on the destination's list — so
    it keeps priority, and the published step must be that one and not a second
    shape that also happened to hold. A step admitted on the caller's storage
    carries no ``destination_acceptance``: nothing consulted one.
    """
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
