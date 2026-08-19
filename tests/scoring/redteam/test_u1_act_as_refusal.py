"""U1 — the act-as refusal ladder: every reason names the conjunct that failed.

One caller, one selector, one state-variable-bound call site. Each case below
changes exactly one fact about the receiver read and asserts the reason moves
with it — a reason that fires on its neighbour's shape is a reason that
misstates the evidence.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests import composition_admission_fixtures as CA
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
    """The third state, and the two it must never be spelled as.

    A ``controller_values`` row observed via ``eth_call_error`` is the record of
    a read the pipeline ISSUED and that reverted. Publishing it as
    "never read on chain" asserts a coverage gap of the reader that the row
    itself disproves, and the two facts must reach the consumer apart.
    """
    never = _ladder()
    assert never.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_NOT_READ

    failed = _ladder(read_failures={(KEY_C, "vault"): ("eth_call_error", 25_657_731)})
    assert failed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_READ_FAILED

    # ...and a failure record NEVER satisfies the receiver test: it carries no
    # address, so it cannot witness that the variable holds the destination.
    assert not failed.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).witnessed

    # A failure recorded for ANOTHER variable does not answer for this one.
    other = _ladder(read_failures={(KEY_C, "authority"): ("eth_call_error", 1)})
    assert other.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_RECEIVER_NOT_READ


def test_u1_a_renounced_and_a_codeless_pointer_each_earn_their_own_negative():
    """Two proven-absent classes, kept apart from each other and from the rest.

    ``zero`` is a renounced pointer: the call lands at address(0), which holds no
    code and never can. ``eoa`` is an address proven codeless by an empty
    ``eth_getCode`` — a call there executes nothing today, and CREATE2 can make
    it a contract tomorrow, so it is NOT the same proof. Every other
    classification is a plain address comparison.
    """
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
        # ...and the refusal carries WHAT it held, so the census can report the
        # class rather than leave a reader to guess it.
        assert verdict.receiver_resolved_type == kind, kind
    # A row with no classification at all is a third state and not 'contract'.
    unclassified = _ladder(reads=read).acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
    assert unclassified.outcome == P.ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
    assert unclassified.receiver_resolved_type == "not_determined"


def test_u1_a_label_at_the_pointer_never_refuses_a_read_that_holds_the_destination():
    """The witness is the read and the address comparison, not the label.

    A pointer the resolver classified ``safe`` or ``timelock`` that holds D
    witnesses the step exactly as a ``contract`` one does. Branching admission on
    ``resolved_type`` asks what KIND of thing the address is — a question the
    act-as step never needed — and discards a stored read on the strength of a
    name.
    """
    for kind in ("contract", "safe", "timelock", "unknown", None):
        plane = _ladder(
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
            read_kinds={(KEY_C, "vault"): kind} if kind else {},
        )
        verdict = plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR)
        assert verdict.witnessed, kind
        assert verdict.step is not None and verdict.step.receiver_variable == "vault"


def test_u1_an_undetermined_gate_openness_is_never_published_as_needing_no_gate():
    """SCORER_DISCIPLINE_CONTRACT §2, at both arms of the plane.

    ``the_call_site_needs_no_gate`` is a POSITIVE claim — this function is open —
    and minting it from an ``authority_openness`` the pipeline did not determine
    publishes an unread field as a proven-absent gate. The third state gets its
    own reason on the state-variable arm exactly as it does on the ACL arm.
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
    """A precondition is not a shortfall.

    The receiver being parameter-bound is what makes the destination-ACL shape
    ADMISSIBLE; it is never the reason a step was refused. With the destination's
    ACL present and the gate the only gap, the reason must name the gate — and
    the ACL reasons stay available for the shortfalls that really are the
    destination's.
    """
    gate_cases = {
        "open": P.ACT_AS_CALL_SITE_IS_PUBLIC,
        "not_determined": P.ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED,
    }
    for openness, expected in gate_cases.items():
        plane = _acl_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("boringSolve", openness, "", True, CALLING_SELECTOR),)}
        )
        assert plane.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == expected, openness
    # Two parameter-bound sites, two different shortfalls: the sharpest is
    # published, and it is still a GATE reason rather than the binding.
    both = _acl_plane(
        call_sites={
            (KEY_C, COMPOSED_SELECTOR): (
                ("boringSolve", "not_determined", "", True, CALLING_SELECTOR),
                ("finishSolve", "restricted", "", False, CALLING_SELECTOR),
            )
        }
    )
    assert both.acts_as(KEY_C, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
    # ...and a site that clears every conjunct is admitted even when a sibling
    # site fails one, so a shortfall never masks a witness.
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
    """``_rank_outcome`` indexes ``_ACT_AS_RANK`` bare: an unregistered outcome
    raises at runtime, not at import. Every reason the plane can publish must be
    in the map, and the retired sentinel must be in neither."""
    assert not hasattr(P, "ACT_AS_RECEIVER_NOT_A_STATE_VARIABLE")
    ranked = P._ACT_AS_RANK
    for name in dir(P):
        if not name.startswith("ACT_AS_") or name.startswith("ACT_AS_WITNESS"):
            continue
        assert getattr(P, name) in ranked, name
    assert len(set(ranked.values())) == len(ranked)


def test_u1_delegation_is_required_at_hop_1_and_not_past_it():
    """B3: past the first hop the licence is the previous hop's admitted selector.

    At hop 1 the principal's leverage IS the seized authority pointer, so only an
    authority-delegated gate is opened by seizing it. Past hop 1 the principal
    has seized nothing on the intermediate and arrives as whoever the previous
    hop admitted — an intermediate gated by a direct ``msg.sender ==`` check is
    exactly the shape such a chain runs through, and refusing it discards a
    witnessed path over a mechanism the principal is not using.
    """
    plane = act_as_plane(
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", False, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    )
    # hop 1: the unconstrained question. The delegation witness is required and
    # this call site carries none.
    assert plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR).outcome == P.ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
    # hop >= 2: entered under the selector the previous hop admitted.
    past = plane.acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
    assert past.witnessed and past.step is not None
    # ...and the relaxation is DISCLOSED, on the step and in its basis, rather
    # than left as a conjunct that silently stopped being applied.
    assert past.step.admitted_without_a_delegation_witness is True
    assert past.step.as_json()["admitted_without_a_delegation_witness"] is True
    assert "was NOT tested" not in past.step.as_json()["basis"]
    assert "no witness that" in past.step.as_json()["basis"]
    # A step that DOES carry the delegation witness publishes false, so the
    # stored fact is recoverable from the published one at every hop.
    delegated = act_as_plane(
        call_sites={(KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),)},
        reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
    ).acts_as(KEY_T, KEY_V, COMPOSED_SELECTOR, via=frozenset({HOP1_SELECTOR}))
    assert delegated.step is not None and delegated.step.admitted_without_a_delegation_witness is False


def test_u1_the_openness_conjunct_is_kept_at_every_hop_and_it_is_attribution():
    """B3, the other half: an OPEN intermediate is refused past hop 1 too.

    Not because the rule is conservative — because it is attribution. A function
    anyone can call moves value that the seized gate did not confer, and charging
    those dollars to this row publishes as gate-conferred a capability the whole
    world already has. It belongs to that function's own finding.
    """
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
    """B3 end to end, on the whole fold: the dollars appear, once.

    The intermediate's calling function is restricted and its gate is a direct
    address check rather than an authority delegation. Hop 1 still requires the
    delegation witness and has it; hop 2 does not require it and does not have
    it, and the chain composes with the relaxation named on the step.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_two_hop_case(
            act_as=act_as_plane(
                call_sites={
                    (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                    # the intermediate: gated by msg.sender == solver, no canCall
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
    # ...and the same shape at hop 1 still refuses: the seized gate is what the
    # principal holds there, and only a delegated gate is opened by seizing it.
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
    """inv. 13's assertion for the kept conjunct: the lever is not a sink.

    Opening an intermediate's calling function REMOVES this row's charge, so the
    refusal must be published with the attribution reason named rather than left
    as silence a deployer could bank.
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
    # The vault's $5M is not charged to this row — the teller's own open
    # function is what moves it, and the seized gate conferred nothing there.
    assert [e["entity"] for e in row["reach_composed_magnitudes"]] == []
    # ...and the refusal is NAMED, with the conjunct that decided it.
    assert row["reach_composition_census"]["act_as_refused"][P.ACT_AS_CALL_SITE_IS_PUBLIC] == 1


class _SeedsThatDisownOneMember(set):
    """A ``seeds`` set that enumerates a node and denies membership in it.

    The only way to drive ``_compose``'s frontier to a caller whose ``chains``
    entry is EMPTY: the walk's own bookkeeping cannot produce one (a node enters
    the frontier only after an entry is recorded for it), so the state the
    changed line defends against is reachable only by breaking that bookkeeping
    from outside. ``chains`` and ``frontier`` are built by ENUMERATING seeds
    while the hop-1 test is ``caller in seeds`` — so a member the enumeration
    yields and the membership test denies lands on the frontier, non-seed, with
    no admitted functions.
    """

    def __init__(self, members, disowned):
        super().__init__(members)
        self._disowned = disowned

    def __contains__(self, item) -> bool:
        return item != self._disowned and super().__contains__(item)


def test_u1_an_empty_admitted_set_is_not_the_hop_1_question():
    """``fold._compose``'s fail-open, executed.

    ``_compose`` hands the plane ``frozenset(entries)`` — never
    ``frozenset(entries) or None``. A non-seed node with an EMPTY admitted set
    and a node at hop 1 are different questions, and spelling them identically
    hands the node the UNCONSTRAINED question: the via rule vanishes and the
    finding's seized gate is spent a second time, on a node no hop admitted a
    function of. Empty must reach the plane as a constraint nothing satisfies.
    """
    magnitude = FOLD._DestinationMagnitude(
        state="proven_exact",
        usd=5_000_000.0,
        function="exit",
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )
    plane = act_as_plane(
        # A call site that WOULD witness at hop 1 — so the old spelling composes
        # the vault's $5M here and the new one refuses it.
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
    # ...and the same node, genuinely a seed, gets the hop-1 question and the
    # $5M — so the refusal above is the empty CONSTRAINT and not a broken case.
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
