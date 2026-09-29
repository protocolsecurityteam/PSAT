"""The two composed-entry surfaces §8 ruled on, and the disclosures beside them.

Each case is a *derivation* pinned by two carriers whose data differs, never one
carrier against a literal: a mutation that de-interpolates a derived string into
a constant has to fail here.
"""

from __future__ import annotations

import pathlib
from dataclasses import replace
from typing import Any

import pytest

from services.scoring import constants as K
from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests.support import composition_admission_fixtures as CA
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    KEY_C,
    KEY_V,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _tied_case,
    _tied_signals,
    facts,
    fold,  # noqa: F401  — the fold fixture
    value_plane,
)
from utils import execution_record as EX

_AUTHORS_THE_AMOUNT_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_CONSTRAINS_THE_TARGET_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param", "constrained"),)
_GATING_AUTHORITY = "0x" + "9" * 40
_VAULT_CONSULTS_AN_AUTHORITY = {("ethereum", KEY_V.partition("::")[2], COMPOSED_SELECTOR): (_GATING_AUTHORITY,)}

# The token §7.2 named and CAP-A §R2 retired. Kept as a literal here on purpose:
# it is the one string this module asserts the ABSENCE of, and a symbol would
# make the assertion vacuous the day the symbol is deleted.
RETIRED_CALLEE_TOKEN = "destination_callee_is_restricted_by_the_intermediate"

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _withheld(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("reach_composed_magnitudes_withheld") or [])


def _gate_only_document(fold, routes):
    """One withheld entry on the gate-only arm: no setter row, so the route alone decides."""
    return CA.composed_document(
        fold, deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY), routes=routes
    )


# CAP-A §R2 — the token names the field it is earned from


def test_the_second_typed_reason_names_the_constrained_target_and_not_a_callee(fold):
    """CAP-A §R2. The token is read off ``target_constraint``, which pins the
    destination call's counterparty ARGUMENT; no stored witness restricts the
    callee, so "the callee is restricted" asserted an unearned property."""
    entry = _withheld(_gate_row(_gate_only_document(fold, _CONSTRAINS_THE_TARGET_AT_C)))[0]
    classification = entry["route_classification"]

    assert classification["state"] == P.ROUTE_TARGET_CONSTRAINED
    assert entry["withheld_reason"] == P.ROUTE_TARGET_CONSTRAINED
    # The token IS the name of the field it is read from, in the same block.
    assert classification[classification["state"]] is True
    assert "callee" not in P.ROUTE_TARGET_CONSTRAINED


# B1-R R2-a — the gate-only arm fires on two tokens and its cause names which


def test_the_census_cause_names_the_route_token_and_not_only_the_arm(fold):
    """B1-R R2-a. ``ARM_GATE_ONLY`` is taken on either of two route tokens and
    the census gave both the AUTHORING cause. The documents differ only in the
    intermediate's flow witness, so a cause keyed on the arm alone fails here."""
    authored = _gate_row(_gate_only_document(fold, _AUTHORS_THE_AMOUNT_AT_C))
    constrained = _gate_row(_gate_only_document(fold, _CONSTRAINS_THE_TARGET_AT_C))

    # Same arm, same count — only the token differs.
    for row, token in ((authored, P.ROUTE_AMOUNT_AUTHORED), (constrained, P.ROUTE_TARGET_CONSTRAINED)):
        assert _withheld(row)[0]["arm_taken"] == FOLD.ARM_GATE_ONLY
        assert _withheld(row)[0]["withheld_reason"] == token
        assert row["reach_composition_census"]["composed_withheld_by_arm"] == {FOLD.ARM_GATE_ONLY: 1}

    authored_reading = authored["reach_composition_census"]["reading"]
    constrained_reading = constrained["reach_composition_census"]["reading"]
    assert authored_reading != constrained_reading
    assert "AUTHORING" in authored_reading and "AUTHORING" not in constrained_reading
    assert "PINNING" in constrained_reading and "PINNING" not in authored_reading
    # ...and the census points at the field that separates the two tokens rather
    # than at composed_withheld_by_arm, which does not.
    assert "composed_withheld_by_reason" in constrained_reading
    assert constrained["reach_composition_census"]["composed_withheld_by_reason"] == {P.ROUTE_TARGET_CONSTRAINED: 1}


def test_a_cause_is_registered_per_arm_and_route_token_with_no_fall_through():
    """No default sentence: an unregistered pair raises rather than reaching the
    document through a cause nobody wrote. The closing count is the registry's own
    size, so a frozen "three" cannot survive a fourth cause."""
    assert (FOLD.ARM_GATE_ONLY, P.ROUTE_AMOUNT_AUTHORED) in FOLD._WITHHELD_CAUSE_ORDER
    assert (FOLD.ARM_GATE_ONLY, P.ROUTE_TARGET_CONSTRAINED) in FOLD._WITHHELD_CAUSE_ORDER
    assert (FOLD.ARM_GATE_ONLY, None) not in FOLD._WITHHELD_CAUSE_ORDER
    with pytest.raises(KeyError):
        FOLD._withheld_cause((FOLD.ARM_GATE_ONLY, P.ROUTE_NOT_DETERMINED))
    with pytest.raises(KeyError):
        FOLD._withheld_cause((FOLD.ARM_REPUBLISHED_DIRECT, None))
    assert f"The {len(FOLD._WITHHELD_CAUSE_ORDER)} registered causes" in FOLD._withheld_cause_clause(
        (_a_withheld_record(),)
    )
    # The empty case counts nothing and claims nothing about the registry.
    assert "registered causes" not in FOLD._withheld_cause_clause(())


def _a_withheld_record() -> FOLD._WithheldComposition:
    return FOLD._WithheldComposition(
        entity=KEY_V,
        selector=COMPOSED_SELECTOR,
        function="exit",
        chain=(),
        execution=EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_NOT_PERSISTED),
        arm=FOLD.ARM_NOT_DETERMINED,
        reason=P.ROUTE_NO_FLOW_WITNESS,
        route=P.RouteClassification(P.ROUTE_NOT_DETERMINED, P.ROUTE_NO_FLOW_WITNESS, (), None, None),
        deletability=P.authority_deletability(P.DeletabilityPlane({}, {}, {}), [], KEY_V, COMPOSED_SELECTOR),
    )


# Ruling 6.2 M4 / §11.2 (k) — chosen_by names what decided THIS tie


def _tied_pair(**over: Any) -> FOLD._ComposedMagnitude:
    base = FOLD._ComposedMagnitude(
        entity=KEY_V,
        selector="0x11111111",
        function="exit",
        witness_state="proven_floor",
        witnessed_usd=1_000_000.0,
        usd=1_000_000.0,
        sheet_usd=None,
        chain=(),
        predicates=P.DestinationPredicates(P.PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0),
        execution=EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_NOT_PERSISTED),
    )
    return replace(base, tied_with=(replace(base, **over),))


def _tie(entry: FOLD._ComposedMagnitude) -> dict[str, Any]:
    """The published tie block. ``None`` there is the proven "one candidate",
    which no fixture here builds, so it is an error rather than a skip."""
    block = entry._tie_json()
    assert block is not None
    return block


def test_chosen_by_names_the_component_that_actually_decided_the_tie():
    """Ruling 6.2 M4. Reciting the whole ladder reads as though every component
    applied; three ties decided at three components publish three strings."""
    by_state = _tied_pair(witness_state="proven_upper_bound")
    by_selector = _tied_pair(selector="0x22222222")
    by_function = _tied_pair(function="manage")

    assert len({_tie(entry)["chosen_by"] for entry in (by_state, by_selector, by_function)}) == 3
    assert "the weakest witness state (component 2 of 6)" in _tie(by_state)["chosen_by"]
    assert "the lowest selector (component 3 of 6)" in _tie(by_selector)["chosen_by"]
    assert "the lowest destination function (component 4 of 6)" in _tie(by_function)["chosen_by"]
    # ...and each names only its own component as a decider, not the ladder.
    assert "the lowest selector (component 3 of 6) against" not in _tie(by_state)["chosen_by"]
    assert "the weakest witness state (component 2 of 6) against" not in _tie(by_selector)["chosen_by"]


@pytest.mark.parametrize(
    "rival,first,later",
    [
        ({"selector": "0x22222222", "function": "manage"}, 3, 4),
        ({"witness_state": "proven_upper_bound", "selector": "0x22222222"}, 2, 3),
        ({"witness_state": "proven_upper_bound", "selector": "0x22222222", "function": "manage"}, 2, 4),
    ],
    ids=["selector_then_function", "state_then_selector", "three_components"],
)
def test_chosen_by_names_the_FIRST_differing_component_and_not_a_later_one(rival, first, later):
    """B2-R SF-1. Other fixtures build a rival differing at exactly ONE
    component, where first and last coincide, so a rule returning the LAST
    differing component passed the module. These rivals differ at two (one at
    three)."""
    chosen_by = _tie(_tied_pair(**rival))["chosen_by"]

    def as_decider(index):
        return f"{FOLD._ORDER_COMPONENT_NAMES[index - 1]} (component {index} of 6) against"

    assert f"What decided it: {as_decider(first)} 1 candidate(s)" in chosen_by
    # The later component IS named — the ladder recital lists every one — but
    # never as a decider, because the components behind the first are not reached.
    assert as_decider(later) not in chosen_by
    assert FOLD._ORDER_COMPONENT_NAMES[later - 1] in chosen_by, "the recital still lists every component"
    # Exactly one component decided this tie, so exactly one is named as one.
    assert chosen_by.count(" against ") == 1


def test_chosen_by_counts_the_candidates_each_component_separated():
    winner = _tied_pair(selector="0x22222222")
    two_rivals = replace(
        winner,
        tied_with=(
            replace(winner, tied_with=(), selector="0x22222222"),
            replace(winner, tied_with=(), selector="0x33333333"),
        ),
    )
    one = _tie(winner)["chosen_by"]
    two = _tie(two_rivals)["chosen_by"]
    assert "against 1 candidate(s)" in one and "over the 2 candidates" in one
    assert "against 2 candidate(s)" in two and "over the 3 candidates" in two
    assert one != two


def test_a_tie_the_order_does_not_separate_publishes_that_and_names_no_decider():
    """The third state: two candidates equal under the whole key still differ in
    fields the key does not read, and naming a component there credits the rule
    with a choice the arrival order made."""
    unseparated = replace(
        _tied_pair(),
        tied_with=(
            replace(
                _tied_pair(),
                tied_with=(),
                execution=EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_FETCH_FAILED),
            ),
        ),
    )
    chosen_by = _tie(unseparated)["chosen_by"]
    assert "decides NOTHING here" in chosen_by
    assert "the order the candidates were built in and not on this rule" in chosen_by
    assert "component 1 of 6" not in chosen_by
    assert chosen_by != _tie(_tied_pair(selector="0x22222222"))["chosen_by"]


def test_chosen_by_glosses_the_chain_component_over_the_fields_a_step_publishes(fold):
    """§11.2 (k). The order's tail is every field ``ActAsStep.as_json``
    publishes, so the gloss is read off the steps in hand."""
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    tied = [
        entry
        for entry in (_gate_row(document).get("reach_composed_magnitudes") or [])
        if entry.get("composed_selector_tie")
    ]
    assert tied, "this fixture must compose a tie for the chain gloss to be read off a real step"
    chosen_by = tied[0]["composed_selector_tie"]["chosen_by"]
    step_fields = set(tied[0]["act_as_chain"][0])
    assert len(step_fields) > 5, "the gloss is only under-inclusive where the step publishes more than five"
    for field_name in step_fields:
        assert field_name in chosen_by


def test_the_chain_gloss_is_read_off_the_steps_and_not_written_into_the_sentence():
    chosen_by = _tie(_tied_pair(selector="0x22222222"))["chosen_by"]
    assert "no candidate here publishes a step at all" in chosen_by
    assert "receiver_variable" not in chosen_by


# CAP-A §B4 — the uncalibrated-arm register


def test_the_predicate_block_survives_and_claims_nothing_about_this_row(fold):
    """Ruling 6.1's KEEP, asserted as a property: the block is the only place a
    reader can check the composed ceiling against the destination's own body.
    M1 and M2 landed in B1 and A3 and are re-verified on the post-Phase-B document."""
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    entries = _gate_row(document).get("reach_composed_magnitudes") or []
    assert entries
    for entry in entries:
        block = entry["destination_predicates"]
        assert block["evaluated"] is False
        assert block["source"] == "effective_functions.conditions"
        reading = block["reading"]
        # M1: modal, so the sentence claims nothing about THIS row's list.
        assert "it may include the authorization guard" in reading
        assert "it includes the authorization guard" not in reading
        # M2: clause (4) and the block it cross-referenced are both gone, and the
        # promise counts the clauses that remain.
        assert "Three things about them" in reading
        assert "(1)" in reading and "(2)" in reading and "(3)" in reading and "(4)" not in reading
        assert "caller_holding_precondition" not in reading
        # The three-state read is intact: descriptions is null where nothing was
        # read and a list where something was, never an empty list standing in
        # for an extraction that never ran.
        assert (block["descriptions"] is None) == (block["state"] != P.PREDICATES_EXTRACTED)


# CAP-B ruling 1 — the migration block is DATED HISTORY, not a live claim


def test_the_frontend_golden_was_regenerated_for_the_current_model_version():
    """The residual staleness hole in the version-bump checklist, closed on the
    side that runs in CI.

    `site/src/test/fixtures/score_etherfi.json` is what the vitest suites assert
    against; a `MODEL_VERSION` bump that skips regenerating it leaves those tests
    pinned to the PREVIOUS model, still internally consistent and green. Asserting
    the stamp here makes the omission fail in the Python suite, where the bump is
    made."""
    import json

    golden = json.loads((ROOT / "site" / "src" / "test" / "fixtures" / "score_etherfi.json").read_text())
    assert golden["model_version"] == K.MODEL_VERSION, (
        f"the frontend golden is stamped {golden['model_version']!r} but MODEL_VERSION is "
        f"{K.MODEL_VERSION!r} — regenerate site/src/test/fixtures/score_etherfi.json "
        f"(see its README for the shape and the minified one-line write)"
    )


# --------------------------------------------------------------------------
# U1-F4 — a magnitude trimmed to an incomplete sheet says the sheet is incomplete
# --------------------------------------------------------------------------

# The destination's witness is $1M (``_composing_signals``), so a sheet below it
# is what caps the entry and the trim is live.
_TRIMMING_SHEET = 250_000.0


def _trimmed_entry(fold, per_asset_state):
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(
            value=value_plane(
                {KEY_V: {"usdc": _TRIMMING_SHEET}},
                per_asset_state={KEY_V: per_asset_state},
                contracts=(KEY_C,),
            )
        ),
    )
    return _gate_row(document)["reach_composed_magnitudes"][0]


def test_a_magnitude_trimmed_to_an_incomplete_sheet_publishes_that_it_is_incomplete(fold):
    """U1-F4. ``min(witness, sheet)`` against a sheet nobody proved whole.

    The figure is $250k where the destination's witness says $1M, and the entry
    said the sheet capped it and stopped. But the sheet carries an unpriced
    asset, so it is a FLOOR, not an at-most, and a min against a floor is a
    smaller number on an unestablished bound. The dollars stand; the entry may no
    longer call them a ceiling in silence.
    """
    entry = _trimmed_entry(fold, {"usdc": P.ASSET_PRICED, "other": P.ASSET_UNPRICED})

    assert entry["bounded_by"] == FOLD._BOUNDED_BY_SHEET
    assert entry["published_usd"] == _TRIMMING_SHEET
    assert entry["destination_sheet_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # The basis ENUMERATES the conjunct that failed, off the destination's own
    # coverage, through the same derivation the per-entity ceiling records use —
    # so a reader is pointed at a field that says something rather than at three
    # candidate causes, two of which read empty here.
    basis = entry["destination_sheet_bound_direction_basis"]
    assert "assets_not_priced" in basis
    assert "asset_list_proven_whole" not in basis
    # And the entry's own sentence carries the caveat rather than leaving the
    # typed field to be joined by somebody who thought to look.
    assert FOLD._TRIMMED_TO_AN_UNPROVEN_CEILING in entry["reading"]


def test_a_trim_onto_a_fully_covered_sheet_claims_the_ceiling_it_earned(fold):
    """The negative path: every asset at the destination is priced, so the sheet
    IS an at-most and the entry says so uncaveated; a disclosure that fired on
    every trim would say nothing about any."""
    entry = _trimmed_entry(fold, {"usdc": P.ASSET_PRICED})

    assert entry["bounded_by"] == FOLD._BOUNDED_BY_SHEET
    assert entry["destination_sheet_bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert "every asset observed at this entity" in entry["destination_sheet_bound_direction_basis"]
    assert FOLD._TRIMMED_TO_AN_UNPROVEN_CEILING not in entry["reading"]


def test_an_entry_no_sheet_bounded_publishes_no_direction_at_all(fold):
    """``null`` is the third state, and it is not "not_determined".

    With no sheet there is no direction to publish and no completeness to refuse;
    ``sheet_not_determined`` carries the fact, and a refusal here would conflate
    "no sheet" with "a sheet that proves no at-most".
    """
    document = fold(_composing_signals(), principals=_composing_principals(), **_composing_case(value=value_plane()))
    entry = _gate_row(document)["reach_composed_magnitudes"][0]

    assert entry["sheet_not_determined"] is True
    assert entry["destination_sheet_bound_direction"] is None
    assert entry["destination_sheet_bound_direction_basis"] is None
    assert FOLD._TRIMMED_TO_AN_UNPROVEN_CEILING not in entry["reading"]


def test_an_entry_built_without_a_plane_cannot_claim_a_ceiling_it_never_read(fold):
    """Fail-closed on the third state of the completeness question itself.

    ``sheet_is_proven_complete`` is ``None`` where nobody read the destination's
    coverage (every hand-built entry). That is no completeness proof, so the
    direction is not_determined, never ``ceiling``. The two coverage fields are
    one answer and may not be published apart.
    """
    entry = FOLD._ComposedMagnitude(
        entity=KEY_V,
        selector=COMPOSED_SELECTOR,
        function="exit",
        witness_state="proven_floor",
        witnessed_usd=1_000_000.0,
        usd=_TRIMMING_SHEET,
        sheet_usd=_TRIMMING_SHEET,
        chain=(),
        predicates=P.DestinationPredicates(P.PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0),
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )
    assert entry.sheet_bound_direction == FOLD.BOUND_DIRECTION_NOT_DETERMINED

    with pytest.raises(ValueError):
        replace(entry, sheet_is_proven_complete=True)

    # And the sentence stays OFF, because the field it exists to point at is
    # null here. A reading that told a reader to consult an enumeration of the
    # conjuncts this sheet fails, beside a null enumeration, is the
    # authored-string defect one level up from the one it was written to fix —
    # the typed direction above carries the refusal on its own.
    published = entry.as_json()
    assert published["destination_sheet_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert published["destination_sheet_bound_direction_basis"] is None
    assert FOLD._TRIMMED_TO_AN_UNPROVEN_CEILING not in published["reading"]
    # The general rule behind that, over every field the sentence names: it is
    # published only where every field it points at is.
    for field in ("destination_sheet_bound_direction", "destination_sheet_bound_direction_basis"):
        assert field in FOLD._TRIMMED_TO_AN_UNPROVEN_CEILING
        if FOLD._TRIMMED_TO_AN_UNPROVEN_CEILING in published["reading"]:
            assert published[field] is not None


# --------------------------------------------------------------------------
# U-B2 — the shared pot is counted ONCE and both doors onto it stay visible
# --------------------------------------------------------------------------

# A second admin address, holding no setter at the vault, so the two powers over
# one pot take DIFFERENT arms of the composition rule.
_SECOND_ADMIN = "0x" + "4" * 40


def _two_powers_over_one_pot(fold):
    """Two admin capabilities at one seized node, both reaching one destination.

    The owner's ruling concerns this exact reference-corpus shape:
    ``authority.replace`` and ``ownership.transfer`` at one unit, both licensing
    the same selector at the same vault, with a BYTE-IDENTICAL composed figure:
    one pot, two doors. The pot is counted once; the second door may not
    disappear to achieve that.

    Only the ``authority.replace`` principal holds a setter at the destination,
    so its figure is republished and the other's withheld.
    """
    ownership = replace(
        _composing_signals()[0],
        claim_id="ownership.transfer",
        function_name="transferOwnership",
        selector="0xf2fde38b",
        principal_refs=(PrincipalRef(3, "ethereum", _SECOND_ADMIN),),
    )
    return fold(
        [*_composing_signals(), ownership],
        principals={**_composing_principals(), 3: facts(3, _SECOND_ADMIN, "eoa")},
        **_composing_case(
            deletability=CA.deletability_plane(host=((KEY_V, EOA, "setAuthority"),)),
        ),
    )


def _row_for(document, capability: str) -> dict[str, Any]:
    """The published row for a capability, findings or subsumed; a subsumed row
    is published in full and is not a row that vanished."""
    published = (*document.findings, *(document.provenance.get("subsumed_rows") or ()))
    rows = [row for row in published if row["capability"] == capability]
    assert len(rows) == 1, f"{capability}: expected one published row, got {len(rows)}"
    return rows[0]


def test_the_shared_pot_is_priced_once_and_both_admin_powers_stay_attributed(fold):
    """R2/U-B2, the owner's ruling and its condition, in one document.

    THE RULING: composition stays withheld for the second power, so the pot is
    charged once. THE CONDITION: both powers remain visibly attributed on the
    unit, because "we decided not to charge you twice" and "we never saw the
    second door" are different documents and only one is true.
    """
    document = _two_powers_over_one_pot(fold)
    replace_row = _row_for(document, "authority.replace")
    ownership_row = _row_for(document, "ownership.transfer")

    # Both doors published, each attributed to its OWN principal — the pair is
    # what makes them two powers rather than one row read twice.
    assert replace_row["example_functions"] == ["setAuthority"]
    assert ownership_row["example_functions"] == ["transferOwnership"]
    assert replace_row["principal_unit"] != ownership_row["principal_unit"]

    # The pot is priced ONCE: exactly one of the two rows carries the composed
    # figure at the vault.
    priced = [row["capability"] for row in (replace_row, ownership_row) if row["reach_composed_magnitudes"]]
    assert priced == ["authority.replace"]
    assert [entry["entity"] for entry in replace_row["reach_composed_magnitudes"]] == [KEY_V]

    # And the second power's dollars are WITHHELD, not absent: the entry names
    # the same entity and the same selector, publishes no figure, and carries
    # the typed reason the rule refused it.
    withheld = _withheld(ownership_row)
    assert [(entry["entity"], entry["selector"]) for entry in withheld] == [(KEY_V, COMPOSED_SELECTOR)]
    assert withheld[0]["published_usd"] is None
    assert withheld[0]["arm_taken"] == FOLD.ARM_NOT_DETERMINED
    assert withheld[0]["withheld_reason"]
    assert ownership_row["reach_composed_magnitudes"] == []


def test_the_withheld_door_is_counted_in_its_rows_own_census(fold):
    """A refusal nobody counted reads the same as a rule nobody ran.

    The row's census must say a candidate reached the admission rule and was
    refused, or a reader aggregating censuses sees a unit with one power.
    """
    census = _row_for(_two_powers_over_one_pot(fold), "ownership.transfer")["reach_composition_census"]

    assert census["composed_selected"] == 1
    assert census["composed"] == 0
    assert census["composed_withheld"] == 1
    assert census["composed_withheld_by_arm"] == {FOLD.ARM_NOT_DETERMINED: 1}


def test_the_composed_figure_is_the_same_under_either_power(fold):
    """Why counting it once is the right answer rather than a convenient one.

    The second charge is refused because it is the SAME dollars (the destination's
    witness at the same selector from the same seized node). Pinned by measuring:
    figures that differed would be two pots and the ruling would not apply.
    """
    both = _two_powers_over_one_pot(fold)
    replace_only = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(deletability=CA.deletability_plane(host=((KEY_V, EOA, "setAuthority"),))),
    )
    ownership_admitted = fold(
        [
            *_composing_signals()[1:],
            replace(
                _composing_signals()[0],
                claim_id="ownership.transfer",
                function_name="transferOwnership",
                selector="0xf2fde38b",
            ),
        ],
        principals=_composing_principals(),
        **_composing_case(deletability=CA.deletability_plane(host=((KEY_V, EOA, "setAuthority"),))),
    )

    charged = _row_for(both, "authority.replace")["reach_composed_magnitudes"][0]["published_usd"]
    assert charged == _gate_row(replace_only)["reach_composed_magnitudes"][0]["published_usd"]
    admitted = _row_for(ownership_admitted, "ownership.transfer")["reach_composed_magnitudes"][0]
    assert charged == admitted["published_usd"]
