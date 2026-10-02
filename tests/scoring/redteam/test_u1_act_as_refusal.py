"""U1: each case changes one fact about the receiver read, and the refusal reason must move with it."""

from __future__ import annotations

from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests.support import composition_admission_fixtures as CA
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    HOP1_ACCEPTED,
    HOP1_SELECTOR,
    KEY_C,
    KEY_PROXY,
    KEY_T,
    KEY_V,
    SAFE,
    _acl_plane,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _two_hop_case,
    act_as_plane,
    condition_plane,
    fold,  # noqa: F401  (fold fixture, registered by import)
    value_plane,
)
from utils import execution_record as EX

_LADDER_SITES = {(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)}


def _ladder(**over: Any) -> P.ActAsPlane:
    case: dict[str, Any] = {"call_sites": _LADDER_SITES}
    case.update(over)
    return act_as_plane(**case)


def test_u1_a_read_that_reverted_is_not_a_read_that_never_happened():
    """An ``eth_call_error`` row is a read that was issued and reverted, not a coverage gap."""
    never = _ladder()
    assert never.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_NOT_READ

    failed = _ladder(read_failures={(KEY_C, "vault"): ("eth_call_error", 25_657_731)})
    assert failed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_READ_FAILED

    # A failure record carries no address, so it cannot witness the destination.
    assert not failed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).witnessed

    other = _ladder(read_failures={(KEY_C, "authority"): ("eth_call_error", 1)})
    assert other.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_NOT_READ


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


def test_u1_a_label_at_the_pointer_never_refuses_a_read_that_holds_the_destination():
    """Branching on ``resolved_type`` would discard a stored read on the strength of a name."""
    for kind in ("contract", "safe", "timelock", "unknown", None):
        plane = _ladder(
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
            read_kinds={(KEY_C, "vault"): kind} if kind else {},
        )
        verdict = plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert verdict.witnessed, kind
        assert verdict.step is not None and verdict.step.receiver_variable == "vault"


def test_u1_an_undetermined_gate_openness_is_never_published_as_needing_no_gate():
    """Undetermined openness stays distinct from a proven open gate on both arms.

    ``the_call_site_needs_no_gate`` is a POSITIVE claim; minting it from an
    undetermined ``authority_openness`` publishes an unread field as a
    proven-absent gate. The state-variable arm gets its own reason, as the ACL
    arm does.
    """
    read: dict[tuple[str, str], tuple[str, str, int | None]] = {(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)}
    for openness, expected in (
        ("open", P.ACT_AS_CALL_SITE_IS_PUBLIC),
        ("not_determined", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
        ("", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
        ("public", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
    ):
        plane = act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", openness, "vault", True, CALLING_SELECTOR),)},
            reads=read,
        )
        assert plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == expected, openness


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


def test_u1_the_retired_sentinel_is_gone_and_every_reason_is_ranked():
    """``_rank_outcome`` indexes ``_ACT_AS_RANK`` bare, so an unregistered outcome raises at runtime."""
    assert not hasattr(P, "ACT_AS_RECEIVER_NOT_A_STATE_VARIABLE")
    ranked = P._ACT_AS_RANK
    for name in dir(P):
        if not name.startswith("ACT_AS_") or name.startswith("ACT_AS_WITNESS"):
            continue
        assert getattr(P, name) in ranked, name
    assert len(set(ranked.values())) == len(ranked)


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


def test_u1_the_openness_conjunct_is_kept_at_every_hop_and_it_is_attribution():
    """Attribution, not conservatism: an open function's value belongs to its own finding."""
    for openness, expected in (
        ("open", P.ACT_AS_CALL_SITE_IS_PUBLIC),
        ("not_determined", P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED),
    ):
        plane = act_as_plane(
            call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", openness, "vault", True, HOP1_SELECTOR),)},
            reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
        )
        verdict = plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
        assert verdict.outcome == expected, openness
        assert not verdict.witnessed, openness


def test_u1_case_a_two_hop_chain_composes_through_an_undelegated_intermediate(fold):
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", False, HOP1_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    first, second = entry["act_as_chain"]
    assert first["admitted_without_a_delegation_witness"] is False
    assert second["admitted_without_a_delegation_witness"] is True
    refused = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", False, CALLING_SELECTOR),)
                },
                reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
            )
        ),
    )
    census = _gate_row(refused)["reach_composition_census"]
    assert census["act_as_refused"] == {P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED: 1}
    assert census["act_as_witnessed"] == 0


def test_u1_case_an_open_intermediate_is_refused_past_hop_1_with_its_reason_named(fold):
    """The kept conjunct requires that the lever is not a sink.

    Opening an intermediate's calling function REMOVES this row's charge, so the
    refusal must be published with its reason, not left as silence a deployer
    could bank.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "open", "vault", True, HOP1_SELECTOR),),
                },
                reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
                destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
            )
        ),
    )
    row = _gate_row(document)
    assert [e["entity"] for e in row["reach_composed_magnitudes"]] == []
    assert row["reach_composition_census"]["act_as_refused"][P.ACT_AS_CALL_SITE_IS_PUBLIC] == 1


class _SeedsThatDisownOneMember(set):
    """The only way to put a caller with an empty ``chains`` entry on ``_compose``'s frontier: seeds are enumerated
    but hop 1 tests ``caller in seeds``.
    """

    def __init__(self, members, disowned):
        super().__init__(members)
        self._disowned = disowned

    def __contains__(self, item) -> bool:
        return item != self._disowned and super().__contains__(item)


def test_u1_an_empty_admitted_set_is_not_the_hop_1_question():
    """``_compose`` passes ``frozenset(entries)``, not ``...

    or None``: an empty admitted set must be a constraint nothing satisfies, or the seized gate is spent twice.
    """
    magnitude = FOLD._DestinationMagnitude(
        state="proven_exact",
        usd=5_000_000.0,
        function="exit",
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )
    plane = act_as_plane(
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    )
    admission = FOLD._AdmissionPlanes(CA.admits_every_principal(), P.RouterFlowPlane())
    composed, _census, refused, _withheld = FOLD._compose(
        _SeedsThatDisownOneMember({KEY_C, KEY_T}, KEY_T),
        [
            FOLD._WalkedHop(
                caller=KEY_T, destination=KEY_V, licensed=frozenset({P.LicensedFunction(COMPOSED_SELECTOR, "exit")})
            )
        ],
        plane,
        {(KEY_V, COMPOSED_SELECTOR): magnitude},
        value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
        condition_plane(),
        admission,
        {SAFE},
    )
    assert composed == {}
    assert refused == {P.ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION: 1}
    # The control: as a real seed it composes, so the refusal above is the empty constraint.
    as_seed, _census, _refused, _withheld_seed = FOLD._compose(
        {KEY_C, KEY_T},
        [
            FOLD._WalkedHop(
                caller=KEY_T, destination=KEY_V, licensed=frozenset({P.LicensedFunction(COMPOSED_SELECTOR, "exit")})
            )
        ],
        plane,
        {(KEY_V, COMPOSED_SELECTOR): magnitude},
        value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
        condition_plane(),
        admission,
        {SAFE},
    )
    assert as_seed[KEY_V].usd == 5_000_000.0
