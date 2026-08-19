"""W4b — compositional gate-control magnitude (Phase 6).

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import FunctionSignal, PrincipalRef, Tri
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    KEY_C,
    KEY_PROXY,
    KEY_V,
    SAFE,
    VAULT,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _role_edge,
    _var_edge,
    act_as_plane,
    conferral_plane,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    pause_sig,
    proven,
    reaches,
    sig,
    value_plane,
)


def test_w4b_a_gate_composes_the_destination_functions_own_witness(fold):
    """Phase 6, whole. The dollars are the DESTINATION's witness, not the sheet.

    Three witnesses and the row publishes all three: the role licenses ``exit``
    at the vault, ``exit`` carries its own fork-proven ``flow.out`` magnitude,
    and a restricted authority-gated function of the seized node is witnessed
    calling that selector on a state variable read on-chain holding the vault.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    composed = row["reach_composed_magnitudes"]
    assert [c["entity"] for c in composed] == [KEY_V]
    assert composed[0]["flow_out_witness"] == {
        "state": "proven_exact",
        "usd": 1_000_000.0,
        "function": "exit",
        "entity": KEY_V,
    }
    step = composed[0]["act_as_chain"][0]
    assert (step["caller"], step["destination"], step["calling_function"]) == (KEY_C, KEY_V, "bulkWithdraw")
    assert step["receiver_observed_via"] == "eth_call" and step["receiver_block"] == 25_657_731
    # A composed call is COUNTED as composed, not as carrying no witness: the
    # census key existed and was never incremented, so the rows that composed
    # published a zero where the count belonged.
    census = row["magnitude_witness_census"]
    assert census["magnitude_composed"] == 1
    assert census["magnitude_not_witnessed"] == 0
    assert (
        census["magnitude_composed"] + census["magnitude_not_witnessed"] + census["magnitude_witnessed"]
        == census["instances"]
    )


def test_w4b_no_composed_magnitude_exceeds_the_destinations_own_bound(fold):
    """The anti-composition regression test.

    The destination's witness is the ceiling and the destination's sheet is the
    other ceiling; the published figure clears neither, whichever is lower.
    """
    for sheet, expected in ((5_000_000.0, 1_000_000.0), (250_000.0, 250_000.0)):
        document = fold(
            _composing_signals(),
            principals=_composing_principals(),
            **_composing_case(value=value_plane({KEY_V: {"usdc": sheet}}, contracts=(KEY_C,))),
        )
        row = _gate_row(document)
        composed = row["reach_composed_magnitudes"][0]
        assert composed["published_usd"] == expected
        assert composed["published_usd"] <= composed["flow_out_witness"]["usd"]
        assert composed["published_usd"] <= sheet
        assert row["value_at_stake_usd"] == expected


def test_b7_a_total_composed_from_extraction_ceilings_is_not_published_as_a_floor(fold):
    """The row header published BOTH directions of one bound.

    Every dollar of this row's value is a composed figure, and the row names
    which entities those are. The header said ``value_at_stake_is_floor`` and
    the band said ``">= "``, so the same row published a floor over a sum of
    ceilings — and the UI painted the badge. Ceilings do not become a floor by
    being summed, and the coverage gaps mean the total is not a ceiling on the
    row either.
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["entities_priced_from_a_composed_ceiling"] == [KEY_V]
    # The per-entry bound label and the caller-holding block are DELETED, not
    # corrected: one asserted a direction the entry never derived, the other was
    # one constant string false on 30% of what carried it.
    entry = row["reach_composed_magnitudes"][0]
    assert "principal_extraction_bound" not in entry
    assert "caller_holding_precondition" not in entry
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert row["value_at_stake_is_floor"] is False
    assert row["value_band"] == "$1M-$10M"
    basis = row["value_at_stake_basis"]
    assert "NEITHER" in basis and "CEILING" in basis
    # The basis POINTS at the per-entry disclosure rather than restating it.
    assert "reach_composed_magnitudes[]" in basis
    assert not basis.startswith(">=")


def test_b7_every_contribution_a_ceiling_with_no_coverage_gap_publishes_a_ceiling(fold):
    """The second arm, which the reference corpus never reaches.

    Aliasing the seized node onto the vault leaves the row ONE priced entity,
    whose whole figure is composed: no instance is undetermined and no entity
    holds an unpriced asset, so nothing is missing from the sum and the total
    bounds the principal from above. Implemented and asserted rather than left
    as a branch nobody has executed.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(
            value=value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C,), alias={KEY_C: KEY_V}),
        ),
    )
    row = _gate_row(document)
    assert row["undetermined_instances"] == []
    assert row["entities_holding_unpriced_assets"] == []
    assert row["entities_priced_from_a_composed_ceiling"] == [KEY_V]
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert row["value_at_stake_is_floor"] is False
    assert row["value_band"].startswith("<= ")
    assert row["value_at_stake_basis"].startswith("<= ")


def test_b7_a_row_mixing_a_ceiling_with_an_ungraded_figure_claims_neither_bound(fold):
    """The MIXED shape, end to end: one ceiling beside one figure of its own.

    A second call on the same row carries its own magnitude witness, so its
    entity is priced from that and never from composition. The row's total is
    then part extraction ceiling and part figure this fold does not grade for
    direction — an at-most over the sum would claim a bound the second half does
    not support, and the basis has to count which half is which rather than say
    "every one of them".
    """
    witnessed = sig(
        claim_id="authority.replace",
        function_name="setAuthorityAlso",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", 500_000.0).to_json()},
        **proven(0.75),
        **reaches(KEY_C),
    )
    document = fold(
        [*_composing_signals(), witnessed],
        principals=_composing_principals(),
        **_composing_case(
            value=value_plane({KEY_V: {"usdc": 5_000_000.0}, KEY_C: {"usdc": 3_000_000.0}}, contracts=(KEY_C,)),
        ),
    )
    row = _gate_row(document)
    assert set(row["value_by_entity"]) == {KEY_C, KEY_V}
    assert row["entities_priced_from_a_composed_ceiling"] == [KEY_V]
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert row["value_at_stake_is_floor"] is False
    assert not row["value_band"].startswith((">= ", "<= "))
    basis = row["value_at_stake_basis"]
    assert "1 of 2 entity(ies)" in basis
    assert "1 entity(ies) whose figure is not a proven ceiling and is graded in no direction" in basis


def _attributed(usd: float, **over: Any) -> FunctionSignal:
    """A ``flow.out`` instance whose figure came off the ATTRIBUTION path.

    ``proven_upper_bound`` is the constant-amount probe crediting a holder's
    whole priced balance — the live shape behind the reference corpus's rank-1
    finding, and no ceiling to :func:`_ceiling_bearing_basis`, which is exactly
    why its prose used to be written from coverage alone.
    """
    return flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_upper_bound", usd).to_json()},
        **proven(1.0),
        **reaches(KEY_C),
        **over,
    )


def _unwitnessed_elsewhere() -> FunctionSignal:
    """A sibling instance on the same row that answered no magnitude at all."""
    return flow_sig(
        function_name="g",
        selector="0xfeedface",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_V),
    )


def test_f1_an_attribution_derived_total_under_a_gap_names_the_refusal_not_a_floor(fold):
    """The live carrier: the basis said ">= proven floor" beside no floor.

    The string was built from the COVERAGE axis in :func:`_row_value`, where the
    attribution axis is not visible, so a row whose header refused the floor —
    ``bound_direction: not_determined``, ``is_floor: false`` — still published
    floor prose. Both axes are read where the direction is, and the refusal is
    COUNTED off the membership test it was made on rather than asserted.
    """
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    document = fold(
        [_attributed(5_000.0), _unwitnessed_elsewhere()],
        principals={1: facts(1, EOA, "eoa")},
        value=plane,
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 5_000.0
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert len(finding["undetermined_instances"]) == 1
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert finding["value_at_stake_is_floor"] is False
    basis = finding["value_at_stake_basis"]
    assert not basis.startswith(">= ")
    assert "proven floor" not in basis
    assert basis.startswith("bounded in NEITHER direction: 1 of 1 entity(ies)")
    # Named as what the membership test establishes and no further: a sheet
    # ceiling whose label was withheld reaches this arm too, so the population
    # is "not proven free of" an upper bound, never "is attribution-derived".
    assert "NOT proven free of an upper-bounding witness" in basis
    # Both halves of the coverage gap are still counted — the reason it is not
    # an at-most either — and neither is left for the reader to infer.
    assert "1 instance(s) not_determined" in basis
    assert "1 entity(ies) holding assets the priced sheet does not cover" in basis


def test_f1_a_floor_counts_the_partly_priced_entities_it_was_earned_on(fold):
    """The mirror face, which the reference corpus has no carrier for.

    ``_bound_direction``'s coverage axis reads undetermined instances AND partly
    priced entities; the floor string counted only the first. A floor earned on
    the second alone therefore had no floor prose at all, and one earned on both
    published a count that omitted half of what earned it.
    """
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    floor = flow_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 5_000_000.0).to_json()},
        **proven(1.0),
        **reaches(KEY_C),
    )
    finding = fold([floor], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["undetermined_instances"] == []
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert (
        finding["value_at_stake_basis"]
        == ">= proven floor over 1 entity(ies); 1 entity(ies) holding assets the priced sheet does not cover"
    )

    # And beside an unanswered instance, both populations appear — the count the
    # old string made of the instances alone is now the whole gap.
    both = fold([floor, _unwitnessed_elsewhere()], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert both["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert both["value_at_stake_basis"] == (
        ">= proven floor over 1 entity(ies); 1 instance(s) not_determined, "
        "1 entity(ies) holding assets the priced sheet does not cover"
    )


def test_b7_a_direction_is_published_only_where_one_was_proven():
    """Two claims and a fall-through, each earned separately.

    ``floor`` needs a coverage gap and NO composed figure; ``ceiling`` needs
    EVERY figure composed and nothing missing from the sum — a gap, a mixed
    contribution or a withheld hop each defeat it, and each for the same reason:
    what is absent from the total can only push the truth up, which an at-least
    survives and an at-most does not.
    """
    both, one = frozenset({KEY_C, KEY_V}), frozenset({KEY_V})
    direction = FOLD._bound_direction

    assert direction(1.0, both, frozenset(), True, False, both) == FOLD.BOUND_DIRECTION_FLOOR
    # A withheld hop is value the row reaches and the sum does not carry: it
    # cannot lower the truth, so the floor stands.
    assert direction(1.0, both, frozenset(), True, True, both) == FOLD.BOUND_DIRECTION_FLOOR
    assert direction(1.0, one, one, False, False, frozenset()) == FOLD.BOUND_DIRECTION_CEILING

    # Every way of failing the ceiling, one at a time.
    assert direction(1.0, one, one, True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, one, one, False, True, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # MIXED: one entity's figure is a ceiling and the other's is graded in no
    # direction, so their sum bounds the principal in neither.
    assert direction(1.0, both, one, False, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # Neither signal fired, which is not a proof that the sum is two-sided.
    assert direction(1.0, both, frozenset(), False, False, both) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # No total, no direction — and never a floor over a figure that is absent.
    assert direction(None, frozenset(), frozenset(), True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # F5: the coverage gap is NOT the whole question. An attribution-derived
    # contribution is itself a ceiling, so a gap over one earns no floor — and a
    # partial grade is as disqualifying as none, because the ungraded entity's
    # figure may be the ceiling.
    assert direction(1.0, both, frozenset(), True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, both, frozenset(), True, False, one) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # Only the two proven directions qualify the band.
    assert FOLD._BAND_PREFIX == {FOLD.BOUND_DIRECTION_FLOOR: ">= ", FOLD.BOUND_DIRECTION_CEILING: "<= "}


def test_w4b_an_unwitnessed_act_as_step_leaves_the_magnitude_not_determined(fold):
    """The binding rule. A licence says N MAY call D, never that P can make it.

    Each variant removes exactly one part of the act-as witness and each one is
    enough on its own to withhold the magnitude — including the live corpus
    shape, where the call site takes its callee as a PARAMETER so nothing
    witnesses which address it lands on.
    """
    variants = {
        # the corpus's own AtomicSolverV3 shape: receiver is not a state variable
        "receiver_not_a_state_variable": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 1)},
        ),
        "receiver_never_read": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)},
        ),
        "receiver_holds_another_address": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_PROXY, "eth_call", 1)},
        ),
        "call_site_is_public": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "open", "vault", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 1)},
        ),
        "gate_is_not_delegated_to_an_authority": act_as_plane(
            call_sites={
                (KEY_C, COMPOSED_SELECTOR): (("receiveFlashLoan", "restricted", "vault", False, CALLING_SELECTOR),)
            },
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 1)},
        ),
        "no_call_site_at_all": act_as_plane(),
    }
    for name, plane in variants.items():
        document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(act_as=plane))
        row = _gate_row(document)
        assert row["value_at_stake_usd"] is None, name
        assert row["value_state"] == "not_determined", name
        assert row["reach_composed_magnitudes"] == [], name
        assert row["reach_composition_census"]["act_as_refused"], name
        # ...and the reach itself is untouched: membership never depended on it.
        assert KEY_V in row["reach_entities"], name


def test_w4b_an_empty_licence_map_composes_nothing(fold):
    """A destination reached only through a state-variable hop names no function.

    There is no compositional source for it — nothing said WHICH of its
    functions the gate reaches — and an empty licence must never be read as
    "price the sheet".
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(
            closure=P.ControlClosure(edges=(_var_edge("owner"),)),
            conferral=conferral_plane(rewrites=("owner",)),
        ),
    )
    row = _gate_row(document)
    assert KEY_V in row["reach_entities"]
    assert row["reach_licensed_functions"] == {}
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None


def test_w4b_a_destination_with_no_flow_out_witness_composes_nothing(fold):
    """Composition REUSES a witness; where there is none there is nothing to reuse."""
    gate, _ = _composing_signals()
    unwitnessed = flow_sig(
        deployment_address=VAULT,
        contract_id=2,
        function_name="exit",
        selector=COMPOSED_SELECTOR,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        witness_tier="behavioral_observed",
        **proven(0.9),
        **reaches(KEY_V),
    )
    document = fold([gate, unwitnessed], principals=_composing_principals(), **_composing_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] is None
    assert row["reach_composed_magnitudes"] == []
    assert row["reach_composition_census"]["act_as_witnessed"] == 1
    assert row["reach_composition_census"]["destination_magnitude_witnessed"] == 0


def test_w4b_a_freeze_has_no_compositional_source_and_stays_floored(fold):
    """pause.set is untouched by Phase 6 (§7).

    Nothing composes into "how much a freeze immobilises": the destination
    witness Phase 6 reuses answers how much a CALL MOVES, which is a different
    quantity. Even with every act-as witness in place the freeze row publishes
    no magnitude.
    """
    freeze = pause_sig(
        function_name="pause",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.6),
        **reaches(KEY_C),
    )
    _, destination = _composing_signals()
    document = fold([freeze, destination], principals=_composing_principals(), **_composing_case())
    row = next(f for f in document.findings if f["capability"] == "pause.set")
    assert row["value_at_stake_usd"] is None
    assert row["value_state"] == "not_determined"
    assert row.get("reach_composed_magnitudes") == []


def test_w4b_a_composed_magnitude_answers_the_confidence_term(fold):
    """inv. 6: composing an answer may only raise the term, and only where real.

    The signal whose magnitude composed counts as answered; the unwitnessed
    freeze beside it does not, so the term rises by exactly one signal's worth
    and not to the ceiling.
    """
    signals = _composing_signals()
    without = fold(signals, principals=_composing_principals(), **_composing_case(act_as=act_as_plane()))
    with_ = fold(signals, principals=_composing_principals(), **_composing_case())
    detail_before = without.model_parameters["confidence_detail"]
    detail_after = with_.model_parameters["confidence_detail"]
    before = detail_before["reach_magnitude_signals"]
    after = detail_after["reach_magnitude_signals"]
    assert before["magnitude_witnessed"] == 1 and before.get("magnitude_composed", 0) == 0
    assert after["magnitude_witnessed"] == 2 and after["magnitude_composed"] == 1
    assert after["composed_by_capability"] == {"authority.replace": 1}
    assert detail_after["reach_magnitude_witnessed_pct"] >= detail_before["reach_magnitude_witnessed_pct"]


def test_w4b_case2_a_seed_that_cannot_act_composes_nothing_two_hops_out(fold):
    """§9.5 case 2, as the corpus actually answers it.

    The spec expected the timelock behind RolesAuthority ``0x4df6b733`` to regain
    a witnessed magnitude at Phase 6. It does not, and the shape is this one: the
    seized node is an AUTHORITY, its own outgoing hop names no licensed function,
    and the vault two hops out — which has a ``flow.out`` witness and a caller
    with a full act-as witness — is behind that break. A chain is as strong as
    its weakest step, so the magnitude stays not_determined for the timelock
    exactly as it does for the two EOAs the shipped document over-charged. That
    is §9.5 case 2's OTHER admissible outcome ("both sides fall to
    not_determined"), not its headline one, and this test pins which.
    """
    signals = _composing_signals()
    document = fold(
        signals,
        principals=_composing_principals(),
        **_composing_case(
            closure=P.ControlClosure(
                edges=(
                    # seed -> intermediate, a state-variable hop licensing nothing
                    _var_edge("authority", principal=KEY_C, anchor=KEY_PROXY),
                    # intermediate -> destination, fully licensed and fully act-as witnessed
                    _role_edge("roles 12", principal=KEY_PROXY, anchor=KEY_V),
                )
            ),
            conferral=conferral_plane(
                rewrites=("authority",),
                role_functions={(KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),)},
            ),
            act_as=act_as_plane(
                call_sites={
                    (KEY_PROXY, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)
                },
                reads={(KEY_PROXY, "vault"): (KEY_V, "eth_call", 1)},
            ),
        ),
    )
    row = _gate_row(document)
    assert {KEY_PROXY, KEY_V} <= set(row["reach_entities"])
    assert row["reach_licensed_functions"] == {KEY_V: [{"selector": COMPOSED_SELECTOR, "name": "exit"}]}
    assert row["reach_composed_magnitudes"] == []
    assert row["value_at_stake_usd"] is None
    # ...and the break is NAMED. A licensed hop the walk never offered is not an
    # act-as refusal at that hop — the question was never asked there — and
    # publishing it as an empty refusal map left the unit's most important
    # negative result readable only as silence.
    census = row["reach_composition_census"]
    assert census["licensed_hops"] == 1 and census["licensed_selectors"] == 0
    assert census["act_as_refused"] == {FOLD.ACT_AS_CALLER_UNREACHED: 1}
