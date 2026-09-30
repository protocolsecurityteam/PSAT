
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
    """Act-as composition, whole. The dollars are the DESTINATION's witness, not the sheet.

    Three witnesses, all published: the role licenses ``exit`` at the vault,
    ``exit`` carries its own fork-proven ``flow.out`` magnitude, and a restricted
    authority-gated function of the seized node calls that selector on a state
    variable read on-chain holding the vault.
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
    # The key existed but was never incremented.
    census = row["magnitude_witness_census"]
    assert census["magnitude_composed"] == 1
    assert census["magnitude_not_witnessed"] == 0
    assert (
        census["magnitude_composed"] + census["magnitude_not_witnessed"] + census["magnitude_witnessed"]
        == census["instances"]
    )


def test_w4b_no_composed_magnitude_exceeds_the_destinations_own_bound(fold):
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
    """The header published a floor over a sum of ceilings; with coverage gaps the total isn't a ceiling either."""
    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    row = _gate_row(document)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["entities_priced_from_a_composed_ceiling"] == [KEY_V]
    # Deleted: one asserted an underived direction, the other was a constant false on 30% of carriers.
    entry = row["reach_composed_magnitudes"][0]
    assert "principal_extraction_bound" not in entry
    assert "caller_holding_precondition" not in entry
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert row["value_at_stake_is_floor"] is False
    assert row["value_band"] == "$1M-$10M"
    basis = row["value_at_stake_basis"]
    assert "NEITHER" in basis and "CEILING" in basis
    assert "reach_composed_magnitudes[]" in basis
    assert not basis.startswith(">=")


def test_b7_every_contribution_a_ceiling_with_no_coverage_gap_publishes_a_ceiling(fold):
    """The reference corpus never reaches this arm."""
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
    """Part ceiling, part ungraded figure: an at-most would be unsupported."""
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
    """``proven_upper_bound`` credits a holder's whole priced balance but is no ceiling to
    :func:`_ceiling_bearing_basis`.
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
    """The string was built from the coverage axis where attribution isn't visible, so refused-floor rows still
    published floor prose.
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
    # A withheld sheet ceiling also reaches this arm, so it's "not proven free of", never "is attribution-derived".
    assert "NOT proven free of an upper-bounding witness" in basis
    assert "1 instance(s) not_determined" in basis
    assert "1 entity(ies) holding assets the priced sheet does not cover" in basis


def test_f1_a_floor_counts_the_partly_priced_entities_it_was_earned_on(fold):
    """The floor string counted only undetermined instances, not partly priced entities."""
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

    both = fold([floor, _unwitnessed_elsewhere()], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert both["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert both["value_at_stake_basis"] == (
        ">= proven floor over 1 entity(ies); 1 instance(s) not_determined, "
        "1 entity(ies) holding assets the priced sheet does not cover"
    )


def test_b7_a_direction_is_published_only_where_one_was_proven():
    """What's absent from the total can only push the truth up: an at-least survives, an at-most doesn't."""
    both, one = frozenset({KEY_C, KEY_V}), frozenset({KEY_V})
    direction = FOLD._bound_direction

    assert direction(1.0, both, frozenset(), True, False, both) == FOLD.BOUND_DIRECTION_FLOOR
    assert direction(1.0, both, frozenset(), True, True, both) == FOLD.BOUND_DIRECTION_FLOOR
    assert direction(1.0, one, one, False, False, frozenset()) == FOLD.BOUND_DIRECTION_CEILING

    assert direction(1.0, one, one, True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, one, one, False, True, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, both, one, False, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, both, frozenset(), False, False, both) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(None, frozenset(), frozenset(), True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # F5: an attribution-derived contribution is itself a ceiling, and a partial grade disqualifies like none.
    assert direction(1.0, both, frozenset(), True, False, frozenset()) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert direction(1.0, both, frozenset(), True, False, one) == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert FOLD._BAND_PREFIX == {FOLD.BOUND_DIRECTION_FLOOR: ">= ", FOLD.BOUND_DIRECTION_CEILING: "<= "}


def test_w4b_an_unwitnessed_act_as_step_leaves_the_magnitude_not_determined(fold):
    """A licence says N may call D, never that P can make it.

    Includes the live shape where the callee is a parameter.
    """
    variants = {
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
        assert KEY_V in row["reach_entities"], name


def test_w4b_an_empty_licence_map_composes_nothing(fold):
    """An empty licence must never read as "price the sheet"."""
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
    """Act-as composition leaves pause.set unchanged.

    The destination witness Phase 6 reuses answers how much a CALL MOVES, not how
    much a freeze immobilises, so even with every act-as witness the freeze row
    publishes no magnitude.
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
    """Composing an answer may only raise the term, and only where real.

    The composed signal counts as answered; the unwitnessed freeze beside it does
    not, so the term rises by exactly one signal's worth.
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
    """A seed without a licensed first hop cannot compose a downstream magnitude.

    The spec expected the timelock behind RolesAuthority ``0x4df6b733`` to regain
    a witnessed magnitude at Phase 6. It does not: the seized node is an
    AUTHORITY whose outgoing hop names no licensed function, and the vault two
    hops out is behind that break. A chain is as strong as its weakest step, so
    the magnitude stays not_determined, as for the two EOAs the shipped document
    over-charged. That is the OTHER admissible outcome ("both sides
    fall to not_determined"), and this test pins which.
    """
    signals = _composing_signals()
    document = fold(
        signals,
        principals=_composing_principals(),
        **_composing_case(
            closure=P.ControlClosure(
                edges=(
                    _var_edge("authority", principal=KEY_C, anchor=KEY_PROXY),
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
    # A hop never offered is not a refusal there; publishing an empty refusal map hid the unit's key negative.
    census = row["reach_composition_census"]
    assert census["licensed_hops"] == 1 and census["licensed_selectors"] == 0
    assert census["act_as_refused"] == {FOLD.ACT_AS_CALLER_UNREACHED: 1}
