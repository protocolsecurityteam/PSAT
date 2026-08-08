"""§14 case 8 — no constant data-claim.

A published string that DESCRIBES what a field means may be a constant; one that
makes a CLAIM ABOUT THE DATA must be derived from the carrier's own data,
because a constant one can be — and on this document was — false for the row
carrying it. Every test below is the same shape: two carriers whose data differs
must publish different strings, which is the property a constant cannot have.
The end of the module walks a whole folded document and asserts that no
narration names a concept the document no longer publishes, over findings and
subsumed rows alike (case 7's parity clause).
"""

from __future__ import annotations

from typing import Any

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests import composition_admission_fixtures as CA
from tests.test_scoring_redteam import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    KEY_C,
    KEY_V,
    _composing_signals,
    fold,  # noqa: F401  — the fold fixture, reused rather than forked
    proven,
    reaches,
    sig,
)
from utils import execution_record as EX

_AUTHORS_THE_AMOUNT_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_DELETES_THE_VAULT_AUTHORITY = ((KEY_V, EOA, "setAuthority"),)

# Builders. Each returns the smallest carrier that can hold the string.

_NO_PREDICATE_TEXT = P.DestinationPredicates(
    state="column_holds_no_array",
    function_id=None,
    function_name=None,
    descriptions=None,
    entries_stored=None,
    functions_matching=0,
)


def _predicates(*descriptions: str) -> P.DestinationPredicates:
    return P.DestinationPredicates(
        state="extracted",
        function_id=1,
        function_name="exit",
        descriptions=tuple(descriptions),
        entries_stored=len(descriptions),
        functions_matching=1,
    )


def _recorded() -> EX.ProvingExecution:
    return EX.ProvingExecution(
        state=EX.EXECUTION_RECORDED,
        transcript_ptr="job::artifact",
        effect_verdict_id=7,
        caller="0x" + "a" * 40,
        target="0x" + "b" * 40,
        selector=COMPOSED_SELECTOR,
    )


def _composed(
    *,
    witnessed_usd: float,
    sheet_usd: float | None,
    entity: str = KEY_V,
    predicates: P.DestinationPredicates | None = None,
) -> FOLD._ComposedMagnitude:
    return FOLD._ComposedMagnitude(
        entity=entity,
        selector=COMPOSED_SELECTOR,
        function="exit",
        witness_state="proven_floor",
        witnessed_usd=witnessed_usd,
        usd=(witnessed_usd if sheet_usd is None else min(witnessed_usd, sheet_usd)),
        sheet_usd=sheet_usd,
        chain=(),
        predicates=(
            predicates if predicates is not None else _predicates("require(bool)(isAuthorized(msg.sender,msg.sig))")
        ),
        execution=_recorded(),
    )


def _route(state: str) -> P.RouteClassification:
    if state == P.ROUTE_AMOUNT_AUTHORED:
        return P.RouteClassification(
            state=state,
            reason=None,
            flows=(
                P.RouterFlow(
                    sink_id="exit:sink1",
                    destination_selector=COMPOSED_SELECTOR,
                    amount_kind="param_derived",
                    target_constraint_state="unconstrained_proven",
                    target_constraint_guard=None,
                ),
            ),
            amount_authored=True,
            target_constrained=False,
        )
    return P.RouteClassification(
        state=P.ROUTE_NOT_DETERMINED,
        reason=P.ROUTE_NEITHER_CONJUNCT,
        flows=(),
        amount_authored=False,
        target_constrained=False,
    )


def _verdict(state: str) -> P.DeletabilityVerdict:
    if state == P.DELETABILITY_DELETABLE:
        return P.DeletabilityVerdict(
            state=state,
            destination_key=KEY_V,
            selector=COMPOSED_SELECTOR,
            principal_addresses=(EOA,),
            arm="host",
            basis=P.SetterPrincipal(
                function_principal_id=1,
                chain="ethereum",
                contract_address=KEY_V.partition("::")[2],
                function_name="setAuthority",
                selector="0x7a9e5e4b",
                principal_address=EOA,
                membership_quality="exact",
            ),
        )
    return P.DeletabilityVerdict(
        state=P.DELETABILITY_PROVEN_NOT_DELETABLE,
        destination_key=KEY_V,
        selector=COMPOSED_SELECTOR,
        principal_addresses=(EOA,),
        reason=P.DELETABILITY_NO_SETTER_ROW,
    )


def _withheld_entry(arm: str, *, deletability: str = P.DELETABILITY_PROVEN_NOT_DELETABLE) -> FOLD._WithheldComposition:
    route = _route(P.ROUTE_AMOUNT_AUTHORED if arm == FOLD.ARM_GATE_ONLY else P.ROUTE_NOT_DETERMINED)
    reason = route.state if arm == FOLD.ARM_GATE_ONLY else (route.reason or EX.REASON_FETCH_FAILED)
    if arm == FOLD.ARM_WITHHELD:
        reason = EX.REASON_FETCH_FAILED
    return FOLD._WithheldComposition(
        entity=KEY_V,
        selector=COMPOSED_SELECTOR,
        function="exit",
        chain=(),
        execution=(
            _recorded()
            if arm != FOLD.ARM_WITHHELD
            else EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_FETCH_FAILED)
        ),
        arm=arm,
        reason=reason,
        route=route,
        deletability=_verdict(deletability),
    )


def _tied_findings(shared: bool) -> list[dict[str, Any]]:
    """Two rows that tie on the sort key, holding entities in common or not."""
    return [
        {
            "raw_points": 10.0,
            "capability": "authority.replace",
            "principal_unit": "ethereum::0x" + "1" * 40,
            "value_by_entity": {"ethereum::0xaaa": 1.0},
        },
        {
            "raw_points": 10.0,
            "capability": "authority.replace",
            "principal_unit": "ethereum::0x" + "2" * 40,
            "value_by_entity": {"ethereum::0xaaa" if shared else "ethereum::0xbbb": 2.0},
        },
    ]


# exposure_order_tie.reading — the split the order made, or the earned empty


def test_the_order_tie_reading_differs_between_rows_that_share_an_entity_and_rows_that_do_not():
    """The old constant asserted a share and a split on a row sharing nothing,
    which was every carrier in the document."""
    shared = _tied_findings(shared=True)
    alone = _tied_findings(shared=False)
    FOLD._disclose_order_ties(shared)
    FOLD._disclose_order_ties(alone)
    shared_reading = shared[0]["exposure_order_tie"]["reading"]
    alone_reading = alone[0]["exposure_order_tie"]["reading"]

    # The mutation: a constant string makes these equal.
    assert shared_reading != alone_reading

    assert shared[0]["exposure_order_tie"]["shared_entities"] == ["ethereum::0xaaa"]
    assert alone[0]["exposure_order_tie"]["shared_entities"] == []
    # The claim is made only where the data carries it, and the count is the
    # row's own rather than a word standing in for it.
    assert "1 entity(ies) it holds in common" in shared_reading
    assert "split among them is order-determined" in shared_reading
    # Where nothing is shared the row publishes the EARNED empty.
    assert "no exposure budget was split by the order here" in alone_reading
    assert "split among them" not in alone_reading


def test_the_order_tie_reading_scales_with_the_number_of_shared_entities():
    """Three carriers, three strings: a sentence naming a count cannot be written
    once."""
    readings = [FOLD._order_tie_reading(list(names), 1) for names in ([], ["a"], ["a", "b"])]
    assert len(set(readings)) == 3


def test_the_order_tie_reading_says_which_side_of_the_split_this_row_is_on():
    """B1-R S2. The first row in a tie group has no tied row AHEAD of it and is
    charged FIRST, so "the earlier row consumes the budget first" is false of
    exactly the carrier ``position_in_tie`` identifies one field away."""
    first = FOLD._order_tie_reading(["a"], 0)
    second = FOLD._order_tie_reading(["a"], 1)
    third = FOLD._order_tie_reading(["a"], 2)

    # The mutation: dropping position_in_tie from the derivation makes these equal.
    assert len({first, second, third}) == 3

    assert "FIRST in the tie (position_in_tie 0)" in first
    assert "consumes that shared exposure budget before any row tied with it" in first
    assert "this row is charged what is left" not in first
    assert "row(s) ahead" not in first

    assert "the 1 row(s) ahead of this one in the tie (position_in_tie 1)" in second
    assert "the 2 row(s) ahead of this one in the tie (position_in_tie 2)" in third
    for later in (second, third):
        assert "this row is charged what is left of it" in later
        assert "FIRST in the tie" not in later


def test_a_real_tie_group_publishes_the_position_it_also_prints():
    """The block publishes ``position_in_tie`` beside the sentence; they must
    agree on the same carrier, through the real emission site."""
    group = _tied_findings(shared=True)
    FOLD._disclose_order_ties(group)
    for index, finding in enumerate(group):
        block = finding["exposure_order_tie"]
        assert block["position_in_tie"] == index
        assert block["reading"] == FOLD._order_tie_reading(block["shared_entities"], index)


# reach_composed_magnitudes[].reading — which ceiling actually bound the figure


def test_the_composed_reading_names_the_ceiling_that_actually_bound_the_figure():
    """V0-b's #8/#35. The constant said the dollars are "not the destination's
    balance sheet" while ``bounded_by`` said ``destination sheet`` on six of the
    twenty-eight kept entries — the document contradicting itself in two adjacent
    keys."""
    by_witness = _composed(witnessed_usd=100.0, sheet_usd=900.0).as_json()
    by_sheet = _composed(witnessed_usd=900.0, sheet_usd=100.0).as_json()

    assert by_witness["reading"] != by_sheet["reading"]

    assert by_witness["bounded_by"] == "flow.out witness"
    assert by_sheet["bounded_by"] == "destination sheet"
    # The published figure and the sentence agree about where it came from.
    assert by_sheet["published_usd"] == by_sheet["destination_sheet_usd"] == 100.0
    assert "BALANCE SHEET" in by_sheet["reading"]
    assert "not the destination's balance sheet" not in by_sheet["reading"]
    assert "flow.out witness" in by_witness["reading"]


def test_a_composed_entry_with_no_sheet_at_all_reads_as_bound_by_its_witness():
    """``sheet_not_determined`` is a third state, and its sentence may not claim
    a sheet was compared and lost."""
    entry = _composed(witnessed_usd=100.0, sheet_usd=None).as_json()
    assert entry["sheet_not_determined"] is True
    assert entry["bounded_by"] == "flow.out witness"
    assert entry["destination_sheet_usd"] is None
    assert "sheet_not_determined" in entry["reading"]


# reach_composed_magnitudes_withheld[].reading — the arm that withheld it


def test_the_withheld_reading_is_derived_from_the_arm_that_withheld_the_figure():
    """The constant's two clauses are FALSE on the transport-fault arm: nothing
    was proven there, and ``_admit_composed`` computes the deletability verdict
    BEFORE the fault branch, so that entry can publish ``deletable`` beside the
    refusal."""
    readings = {arm: _withheld_entry(arm).as_json()["reading"] for arm in FOLD._WITHHELD_ARM_READINGS}
    assert len(set(readings.values())) == 3

    fault = readings[FOLD.ARM_WITHHELD]
    assert "could not be READ at all" in fault
    assert "What was proven is the call recorded" not in fault
    # The two clauses that were false on this arm are gone from it.
    assert "call the probe made directly to the destination" not in fault
    assert "Neither answered in favour of the figure" not in fault

    gate_only = readings[FOLD.ARM_GATE_ONLY]
    assert "The MAGNITUDE does not survive it" in gate_only
    undetermined = readings[FOLD.ARM_NOT_DETERMINED]
    assert "no typed finding" in undetermined
    assert "no fourth arm that publishes" in undetermined


def test_a_faulted_entry_that_the_join_licensed_does_not_read_as_a_join_refusal():
    """The exercised carrier: a fault beside a proven deletability licence."""
    entry = _withheld_entry(FOLD.ARM_WITHHELD, deletability=P.DELETABILITY_DELETABLE).as_json()
    assert entry["authority_deletability"]["state"] == P.DELETABILITY_DELETABLE
    assert entry["published_usd"] is None
    reading = entry["reading"]
    assert "does NOT release it" in reading
    assert "Neither answered in favour" not in reading


def test_an_unregistered_withholding_arm_cannot_reach_a_published_reading():
    """No default sentence: an arm nobody wrote a reading for raises rather than
    borrowing another arm's claim."""
    with pytest.raises(ValueError, match="no withheld reading is registered"):
        _withheld_entry(FOLD.ARM_REPUBLISHED_DIRECT)


# value_at_stake_basis — the concept the document no longer publishes


def _basis(
    composed: dict[str, FOLD._ComposedMagnitude],
    ceiling: frozenset[str],
    sheet: frozenset[str] = frozenset(),
) -> str:
    """The basis for a ceiling-bearing row, composed entries by default.

    ``sheet`` is the writer's OTHER kind and is empty here on purpose: these
    cases pin the composed clause's counting, and a sheet ceiling counts a
    different population against a different question.
    """
    return FOLD._ceiling_bearing_basis(
        FOLD.BOUND_DIRECTION_NOT_DETERMINED,
        {key: 1.0 for key in ceiling | sheet},
        ceiling,
        sheet,
        [{"instance": 1}],
        [],
        [],
        [],
        [],
        {},
        composed,
    )


def _mixed_ceiling(with_text: int, without_text: int) -> tuple[dict[str, Any], frozenset[str]]:
    """A ceiling-bearing row of ``with_text + without_text`` composed entries,
    only the first group of which publishes extracted predicate text."""
    composed: dict[str, Any] = {}
    for index in range(with_text + without_text):
        key = f"ethereum::0x{index:040x}"
        composed[key] = _composed(
            witnessed_usd=1.0,
            sheet_usd=None,
            entity=key,
            predicates=None if index < with_text else _NO_PREDICATE_TEXT,
        )
    return composed, frozenset(composed)


def test_the_ceiling_basis_counts_the_condition_texts_it_names():
    """A3 deleted ``caller_holding_precondition``; the basis kept saying "the
    precondition can put the true extraction below it" — a definite reference to
    a field the document does not contain. What replaces it is counted."""
    with_text = _basis(*_mixed_ceiling(1, 0))
    without_text = _basis(*_mixed_ceiling(0, 1))

    assert with_text != without_text

    assert "precondition" not in with_text
    assert "precondition" not in without_text
    assert "travel with 1 of those 1 figure(s)" in with_text
    assert "no condition text was extracted" in without_text


def test_the_ceiling_basis_count_moves_with_the_row_and_is_not_a_frozen_pair():
    """B1-R S1. The one-entity carrier above pins the BRANCH and never the COUNT:
    freezing the interpolation to "1 of those 1 figure(s)" left the suite green
    while the document published that literal on rows carrying 11 and 2 figures.
    These carriers have M > 1 and N != M — the live shapes (11/11 and 2/2) plus a
    mixed one no corpus row has — so a frozen pair fails."""
    eleven = _basis(*_mixed_ceiling(11, 0))
    two = _basis(*_mixed_ceiling(2, 0))
    mixed = _basis(*_mixed_ceiling(2, 3))
    one = _basis(*_mixed_ceiling(1, 0))

    # The mutation: any frozen count collapses at least two of these.
    assert len({eleven, two, mixed, one}) == 4

    assert "travel with 11 of those 11 figure(s)" in eleven
    assert "travel with 2 of those 2 figure(s)" in two
    # N < M: numerator and denominator are read from different fields and a
    # single count standing in for both would hide the shortfall.
    assert "travel with 2 of those 5 figure(s)" in mixed
    assert "travel with 1 of those 1 figure(s)" in one
    assert "travel with 5 of those 5 figure(s)" not in mixed


def test_the_two_ceiling_kinds_are_counted_apart_and_neither_borrows_the_others_clause():
    """A row can carry a composed extraction ceiling and a sheet ceiling at once.

    The two are proven by different evidence and narrowed by different evidence —
    a destination function's own stored conditions against which of a node's
    assets replaced code can actually reach — so one clause written over both
    would be a claim about the row that is false of whichever half it was not
    written for. Each kind counts its OWN population, and a row carrying only one
    of them reads exactly as it did before the other existed.
    """
    composed, ceiling = _mixed_ceiling(2, 0)
    sheet = frozenset({"ethereum::0x" + "f" * 40, "ethereum::0x" + "e" * 40, "ethereum::0x" + "d" * 40})
    both = _basis(composed, ceiling, sheet)

    # Counted apart, and neither count is the row's total of five.
    assert "2 priced from a composed extraction CEILING" in both
    assert "3 priced from a SHEET CEILING" in both
    assert "5 of 5 entity(ies)" in both
    # The composed clause counts composed entries only; the sheet clause counts
    # sheet entries only. A shared denominator would be the frozen-pair defect
    # one axis over.
    assert "travel with 2 of those 2 figure(s)" in both
    assert "each of the 3 sheet figure(s)" in both
    assert "travel with 2 of those 5 figure(s)" not in both

    # A single-kind row is untouched by the existence of the other.
    assert "SHEET CEILING" not in _basis(composed, ceiling)
    assert "composed extraction CEILING" not in _basis({}, frozenset(), sheet)


# act_as_composition.census.reading — the corpus count in a literal


def _rollup(exclusive: dict[str, float], composed_entities: list[str]) -> str:
    findings = [{"reach_composition_census": {}, "subsumed_exclusive_value_by_entity": exclusive}]
    subsumed = [
        {
            "reach_composition_census": {},
            "reach_composed_magnitudes": [{"entity": key, "published_usd": 1.0} for key in composed_entities],
        }
    ]
    return FOLD._composition_totals(findings, subsumed)["reading"]


def test_the_rollup_reading_counts_the_subsumed_entities_that_charge_a_top_row():
    """ "one composed subsumed entity does so here" was a measurement of one
    corpus baked into a literal."""
    none = _rollup({}, [])
    one = _rollup({"ethereum::0xaaa": 1.0}, ["ethereum::0xaaa"])
    two = _rollup({"ethereum::0xaaa": 1.0, "ethereum::0xbbb": 1.0}, ["ethereum::0xaaa", "ethereum::0xbbb"])

    assert len({none, one, two}) == 3

    assert "1 composed subsumed entity(ies) do so here" in one
    assert "2 composed subsumed entity(ies) do so here" in two
    # The empty case is an earned negative, not silence.
    assert "no composed subsumed entity does so here" in none
    assert "honest shape of this corpus" not in none + one + two


# The deleted concepts, asserted over a whole folded document


def _authored_strings(node: Any, path: str = "") -> list[tuple[str, str]]:
    """Every authored string in the published document, by ruling 7's scope."""
    keys = ("reading", "note", "basis", "chosen_by", "bound_kind", "fact", "value_at_stake_basis", "licensing")
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in keys and isinstance(value, str):
                out.append((f"{path}.{key}", value))
            else:
                out.extend(_authored_strings(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for item in node:
            out.extend(_authored_strings(item, f"{path}[]"))
    return out


# A cross-reference is a claim that the field exists, and every one of these
# names something this document does not publish or a measurement its author
# never made.
_DEAD_CONCEPTS = (
    "caller_holding_precondition",
    "principal_extraction_bound",
    "the precondition can put",
    "the 87 contracts",
    "the 13 callers",
    "no finding walks it",
    "is not_determined wherever populated",
    "one composed subsumed entity does so here",
    # Retired by the code-control ceiling. It was true of every capability class
    # when it was written and is now false of exactly one: at the node whose CODE
    # a principal can replace, that node's own sheet is the answer, because the
    # code that would have stood in the way is the code being replaced. The
    # replacement sentence states which class it holds for and which it does not,
    # so the unqualified form must never come back.
    "balance sheet is never the answer",
)


def _published_strings(document) -> list[tuple[str, str]]:
    return _authored_strings(
        {
            "findings": document.findings,
            "warnings": document.warnings,
            "model_parameters": document.model_parameters,
            "provenance": document.provenance,
        }
    )


@pytest.fixture()
def republishing_document(fold):  # noqa: F811
    return CA.composed_document(
        fold,
        deletability=CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
        routes=_AUTHORS_THE_AMOUNT_AT_C,
    )


def test_no_published_narration_names_a_concept_the_document_does_not_publish(republishing_document):
    strings = _published_strings(republishing_document)
    assert strings, "the walk found no authored string — the scope is wrong, not the document"
    for path, value in strings:
        for dead in _DEAD_CONCEPTS:
            assert dead not in value, f"{path} still names {dead!r}"


def test_the_predicate_reading_claims_no_guard_it_did_not_check(republishing_document):
    """Ruling 6.1 M1. "it INCLUDES the authorization guard" is an indicative
    existential about this row's extracted list; the fold never checks it."""
    readings = [
        value
        for path, value in _published_strings(republishing_document)
        if path.endswith("destination_predicates.reading")
    ]
    assert readings
    for reading in readings:
        assert "it includes the authorization guard" not in reading
        assert "it may include the authorization guard" in reading
        # The enumeration matches what is enumerated.
        assert "Three things about them" in reading
        assert reading.count("(1)") == reading.count("(2)") == reading.count("(3)") == 1
        assert "(4)" not in reading


# The registries themselves, and case 7's subsumed parity


def test_every_registered_arm_and_ceiling_carries_its_own_sentence():
    """A registry whose entries collapse to one string is a constant wearing a
    dict; both maps are keyed on a closed vocabulary."""
    assert set(FOLD._WITHHELD_ARM_READINGS) == {FOLD.ARM_WITHHELD, FOLD.ARM_GATE_ONLY, FOLD.ARM_NOT_DETERMINED}
    assert len(set(FOLD._WITHHELD_ARM_READINGS.values())) == len(FOLD._WITHHELD_ARM_READINGS)
    assert set(FOLD._COMPOSED_SOURCE_READINGS) == {"flow.out witness", "destination sheet"}
    assert len(set(FOLD._COMPOSED_SOURCE_READINGS.values())) == len(FOLD._COMPOSED_SOURCE_READINGS)
    # The arm the rule takes when it PUBLISHES has no sentence; reaching for it raises.
    assert FOLD.ARM_REPUBLISHED_DIRECT not in FOLD._WITHHELD_ARM_READINGS


@pytest.mark.parametrize(
    "deletability,key",
    [
        (CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY), "reach_composed_magnitudes"),
        (CA.deletability_plane(), "reach_composed_magnitudes_withheld"),
    ],
    ids=["republished", "withheld"],
)
def test_case7_the_derived_readings_hold_on_a_subsumed_row_too(fold, deletability, key):  # noqa: F811
    """§14 case 7 applied to case 8: ``_ComposedMagnitude.as_json`` and
    ``_WithheldComposition.as_json`` have no findings/subsumed branch, and this
    asserts the consequence on the population three earlier passes never
    measured."""
    weaker = sig(
        claim_id="ownership.transfer",
        function_name="transferOwnership",
        selector="0xf2fde38b",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
    )
    document = CA.composed_document(
        fold,
        signals=[*_composing_signals(), weaker],
        deletability=deletability,
        routes=_AUTHORS_THE_AMOUNT_AT_C,
    )
    subsumed = list(document.provenance.get("subsumed_rows") or [])
    assert subsumed, "the case must exercise a subsumed row, not two findings"
    entries = [entry for row in subsumed for entry in (row.get(key) or [])]
    assert entries, f"the subsumed row published no {key}"
    for entry in entries:
        reading = entry["reading"]
        if key == "reach_composed_magnitudes":
            # Derived from this entry's own bounded_by, on a subsumed row too.
            assert reading.startswith(FOLD._COMPOSED_SOURCE_READINGS[entry["bounded_by"]] + ". ")
        else:
            assert reading == (
                FOLD._WITHHELD_OPENING + FOLD._WITHHELD_ARM_READINGS[entry["arm_taken"]] + FOLD._WITHHELD_CLOSING
            )
        for dead in _DEAD_CONCEPTS:
            assert dead not in reading


# reach_composition_census.reading — B1-N1's two clauses, one level up


def test_the_census_account_of_composed_withheld_is_derived_from_the_arms_that_fired():
    """B1-R S3. The census explained ``composed_withheld`` with a single cause,
    which is B1-N1's two clauses aggregated: both fail on the transport-fault arm
    (reached before the join is consulted, and able to publish ``deletable``
    beside its refusal) and the first fails on the unclassified arm too."""
    none = FOLD._withheld_cause_clause(())
    gate_only = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_GATE_ONLY),))
    fault = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_WITHHELD, deletability=P.DELETABILITY_DELETABLE),))
    undetermined = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_NOT_DETERMINED),))
    both = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_GATE_ONLY), _withheld_entry(FOLD.ARM_WITHHELD)))

    # The mutation: one authored cause for the counter collapses all of these.
    assert len({none, gate_only, fault, undetermined, both}) == 5

    for clause in (none, gate_only, fault, undetermined, both):
        assert "not the route the proof took" not in clause
        assert "nothing proved this principal could have issued the proven call" not in clause

    assert "composed_withheld is 0 here" in none
    assert "count of nothing and not a claim that the rule was not asked" in none
    assert "1 to a route witnessed AUTHORING" in gate_only
    assert "could not be READ at all" in fault
    assert "does not release the figure" in fault
    assert "earned no typed finding in either direction" in undetermined
    # Two arms on one row are counted apart, never merged into one cause.
    assert "1 to a route witnessed AUTHORING" in both and "could not be READ at all" in both


def test_every_withholding_arm_has_a_census_cause_and_they_are_distinct():
    """Keyed on ``(arm, route token)`` since B2: the gate-only arm fires on two
    tokens and each carries its own cause, so the registry is larger than the arm
    set and the distinctness has to hold over the pairs."""
    arms = {arm for arm, _ in FOLD._WITHHELD_CAUSE_ORDER}
    assert arms == set(FOLD._WITHHELD_ARM_READINGS)
    causes = [FOLD._withheld_cause(key) for key in FOLD._WITHHELD_CAUSE_ORDER]
    assert len(set(causes)) == len(causes)
    assert FOLD.ARM_REPUBLISHED_DIRECT not in arms


def test_the_freeze_ladder_note_states_the_duration_gate_it_actually_carries(monkeypatch):
    """B1-R S4/R2-N2. "no duration term" is false beside the ``auto_expiry`` rung
    in the same dict. Asserting ``str(K.FREEZE_AUTO_EXPIRY) in note`` against the
    shipped values is a tautology, so the thresholds are moved and the note
    re-read: only a live interpolation survives."""
    from services.scoring import constants as K

    note = K.model_parameters()["freeze_ladder"]["note"]
    assert str(K.FREEZE_AUTO_EXPIRY) in note
    assert str(K.FREEZE_AUTO_EXPIRY_MAX_SECONDS) in note
    assert "GATE on one rung and a term in none" in note
    assert "no duration term" not in note
    assert "is not_determined wherever populated" not in note

    shipped_rung, shipped_seconds = K.FREEZE_AUTO_EXPIRY, K.FREEZE_AUTO_EXPIRY_MAX_SECONDS
    monkeypatch.setattr(K, "FREEZE_AUTO_EXPIRY", 0.99)
    monkeypatch.setattr(K, "FREEZE_AUTO_EXPIRY_MAX_SECONDS", 7 * 86400)
    moved = K.model_parameters()["freeze_ladder"]["note"]
    assert moved != note
    assert "0.99" in moved and str(7 * 86400) in moved
    # ...and the shipped values are gone, so a literal matching today cannot pass.
    assert str(shipped_rung) not in moved and str(shipped_seconds) not in moved
