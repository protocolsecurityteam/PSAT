"""no constant data-claim.

A published string that DESCRIBES what a field means may be a constant; one that
makes a CLAIM ABOUT THE DATA must be derived from the carrier's own data (a
constant one was, on this document, false for its row). Each test pins that with
two carriers whose data differs and must publish different strings. The end of
the module walks a whole folded document, over findings and subsumed rows alike
(case 7's parity clause), asserting no narration names a retired concept.
"""

from __future__ import annotations

from typing import Any

import pytest

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
    SCANNED,
    _cc_row,
    _composing_signals,
    facts,
    fold,  # noqa: F401  — the fold fixture, reused rather than forked
    proven,
    reaches,
    sig,
    value_plane,
)
from utils import execution_record as EX

_AUTHORS_THE_AMOUNT_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_DELETES_THE_VAULT_AUTHORITY = ((KEY_V, EOA, "setAuthority"),)


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


def test_the_order_tie_reading_differs_between_rows_that_share_an_entity_and_rows_that_do_not():
    shared = _tied_findings(shared=True)
    alone = _tied_findings(shared=False)
    FOLD._disclose_order_ties(shared)
    FOLD._disclose_order_ties(alone)
    shared_reading = shared[0]["exposure_order_tie"]["reading"]
    alone_reading = alone[0]["exposure_order_tie"]["reading"]

    assert shared_reading != alone_reading

    assert shared[0]["exposure_order_tie"]["shared_entities"] == ["ethereum::0xaaa"]
    assert alone[0]["exposure_order_tie"]["shared_entities"] == []
    assert "1 entity(ies) it holds in common" in shared_reading
    assert "split among them is order-determined" in shared_reading
    assert "no exposure budget was split by the order here" in alone_reading
    assert "split among them" not in alone_reading


def test_the_order_tie_reading_scales_with_the_number_of_shared_entities():
    readings = [FOLD._order_tie_reading(list(names), 1) for names in ([], ["a"], ["a", "b"])]
    assert len(set(readings)) == 3


def test_the_order_tie_reading_says_which_side_of_the_split_this_row_is_on():
    """B1-R S2: "the earlier row consumes the budget first" is false of the carrier ``position_in_tie`` identifies."""
    first = FOLD._order_tie_reading(["a"], 0)
    second = FOLD._order_tie_reading(["a"], 1)
    third = FOLD._order_tie_reading(["a"], 2)

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
    group = _tied_findings(shared=True)
    FOLD._disclose_order_ties(group)
    for index, finding in enumerate(group):
        block = finding["exposure_order_tie"]
        assert block["position_in_tie"] == index
        assert block["reading"] == FOLD._order_tie_reading(block["shared_entities"], index)


def test_the_composed_reading_names_the_ceiling_that_actually_bound_the_figure():
    """V0-b #8/#35: the constant contradicted ``bounded_by`` on 6 of 28 kept entries."""
    by_witness = _composed(witnessed_usd=100.0, sheet_usd=900.0).as_json()
    by_sheet = _composed(witnessed_usd=900.0, sheet_usd=100.0).as_json()

    assert by_witness["reading"] != by_sheet["reading"]

    assert by_witness["bounded_by"] == "flow.out witness"
    assert by_sheet["bounded_by"] == "destination sheet"
    assert by_sheet["published_usd"] == by_sheet["destination_sheet_usd"] == 100.0
    assert "BALANCE SHEET" in by_sheet["reading"]
    assert "not the destination's balance sheet" not in by_sheet["reading"]
    assert "flow.out witness" in by_witness["reading"]


def test_a_composed_entry_with_no_sheet_at_all_reads_as_bound_by_its_witness():
    entry = _composed(witnessed_usd=100.0, sheet_usd=None).as_json()
    assert entry["sheet_not_determined"] is True
    assert entry["bounded_by"] == "flow.out witness"
    assert entry["destination_sheet_usd"] is None
    assert "sheet_not_determined" in entry["reading"]


def test_the_withheld_reading_is_derived_from_the_arm_that_withheld_the_figure():
    """``_admit_composed`` computes deletability before the fault branch, so the constant's clauses were false on the
    fault arm.
    """
    readings = {arm: _withheld_entry(arm).as_json()["reading"] for arm in FOLD._WITHHELD_ARM_READINGS}
    assert len(set(readings.values())) == 3

    fault = readings[FOLD.ARM_WITHHELD]
    assert "could not be READ at all" in fault
    assert "What was proven is the call recorded" not in fault
    assert "call the probe made directly to the destination" not in fault
    assert "Neither answered in favour of the figure" not in fault

    gate_only = readings[FOLD.ARM_GATE_ONLY]
    assert "The MAGNITUDE does not survive it" in gate_only
    undetermined = readings[FOLD.ARM_NOT_DETERMINED]
    assert "no typed finding" in undetermined
    assert "no fourth arm that publishes" in undetermined


def test_a_faulted_entry_that_the_join_licensed_does_not_read_as_a_join_refusal():
    entry = _withheld_entry(FOLD.ARM_WITHHELD, deletability=P.DELETABILITY_DELETABLE).as_json()
    assert entry["authority_deletability"]["state"] == P.DELETABILITY_DELETABLE
    assert entry["published_usd"] is None
    reading = entry["reading"]
    assert "does NOT release it" in reading
    assert "Neither answered in favour" not in reading


def test_an_unregistered_withholding_arm_cannot_reach_a_published_reading():
    with pytest.raises(ValueError, match="no withheld reading is registered"):
        _withheld_entry(FOLD.ARM_REPUBLISHED_DIRECT)


def _basis(
    composed: dict[str, FOLD._ComposedMagnitude],
    ceiling: frozenset[str],
    sheet: frozenset[str] = frozenset(),
) -> str:
    """``sheet`` is empty on purpose: a sheet ceiling counts a different population."""
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
        P.ValuePlane(),
    )


def _mixed_ceiling(with_text: int, without_text: int) -> tuple[dict[str, Any], frozenset[str]]:
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
    """A3 deleted ``caller_holding_precondition`` but the basis kept referencing it."""
    with_text = _basis(*_mixed_ceiling(1, 0))
    without_text = _basis(*_mixed_ceiling(0, 1))

    assert with_text != without_text

    assert "precondition" not in with_text
    assert "precondition" not in without_text
    assert "travel with 1 of those 1 figure(s)" in with_text
    assert "no condition text was extracted" in without_text


def test_the_ceiling_basis_count_moves_with_the_row_and_is_not_a_frozen_pair():
    """B1-R S1: a frozen "1 of those 1" stayed green while rows carried 11 and 2, so these carriers have M > 1 and N
    != M.
    """
    eleven = _basis(*_mixed_ceiling(11, 0))
    two = _basis(*_mixed_ceiling(2, 0))
    mixed = _basis(*_mixed_ceiling(2, 3))
    one = _basis(*_mixed_ceiling(1, 0))

    assert len({eleven, two, mixed, one}) == 4

    assert "travel with 11 of those 11 figure(s)" in eleven
    assert "travel with 2 of those 2 figure(s)" in two
    assert "travel with 2 of those 5 figure(s)" in mixed
    assert "travel with 1 of those 1 figure(s)" in one
    assert "travel with 5 of those 5 figure(s)" not in mixed


def test_the_two_ceiling_kinds_are_counted_apart_and_neither_borrows_the_others_clause():
    """The two kinds are proven by different evidence, so one clause over both would be false of one half."""
    composed, ceiling = _mixed_ceiling(2, 0)
    sheet = frozenset({"ethereum::0x" + "f" * 40, "ethereum::0x" + "e" * 40, "ethereum::0x" + "d" * 40})
    both = _basis(composed, ceiling, sheet)

    assert "2 priced from a composed extraction CEILING" in both
    assert "3 priced from a SHEET CEILING" in both
    assert "5 of 5 entity(ies)" in both
    # A shared denominator would be the frozen-pair defect one axis over.
    assert "travel with 2 of those 2 figure(s)" in both
    assert "each of the 3 sheet figure(s)" in both
    assert "travel with 2 of those 5 figure(s)" not in both

    assert "SHEET CEILING" not in _basis(composed, ceiling)
    assert "composed extraction CEILING" not in _basis({}, frozenset(), sheet)


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
    none = _rollup({}, [])
    one = _rollup({"ethereum::0xaaa": 1.0}, ["ethereum::0xaaa"])
    two = _rollup({"ethereum::0xaaa": 1.0, "ethereum::0xbbb": 1.0}, ["ethereum::0xaaa", "ethereum::0xbbb"])

    assert len({none, one, two}) == 3

    assert "1 composed subsumed entity(ies) do so here" in one
    assert "2 composed subsumed entity(ies) do so here" in two
    assert "no composed subsumed entity does so here" in none
    assert "honest shape of this corpus" not in none + one + two


def _authored_strings(node: Any, path: str = "") -> list[tuple[str, str]]:
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


# Each names something this document does not publish.
_DEAD_CONCEPTS = (
    "caller_holding_precondition",
    "principal_extraction_bound",
    "the precondition can put",
    "the 87 contracts",
    "the 13 callers",
    "no finding walks it",
    "is not_determined wherever populated",
    "one composed subsumed entity does so here",
    # False since the code-control ceiling: at a node whose code can be replaced, its sheet is the answer.
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
def republishing_document(fold):
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


@pytest.mark.parametrize(
    "deletability,key",
    [
        (CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY), "reach_composed_magnitudes"),
        (CA.deletability_plane(), "reach_composed_magnitudes_withheld"),
    ],
    ids=["republished", "withheld"],
)
def test_case7_the_derived_readings_hold_on_a_subsumed_row_too(fold, deletability, key):
    """``_ComposedMagnitude.as_json`` and
    ``_WithheldComposition.as_json`` have no findings/subsumed branch; asserts
    the consequence on the population earlier passes never measured."""
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
            assert reading.startswith(FOLD._COMPOSED_SOURCE_READINGS[entry["bounded_by"]] + ". ")
        else:
            assert reading == (
                FOLD._WITHHELD_OPENING + FOLD._WITHHELD_ARM_READINGS[entry["arm_taken"]] + FOLD._WITHHELD_CLOSING
            )
        for dead in _DEAD_CONCEPTS:
            assert dead not in reading


def test_the_census_account_of_composed_withheld_is_derived_from_the_arms_that_fired():
    """B1-R S3: both B1-N1 clauses fail on the transport-fault arm and one on the unclassified arm."""
    none = FOLD._withheld_cause_clause(())
    gate_only = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_GATE_ONLY),))
    fault = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_WITHHELD, deletability=P.DELETABILITY_DELETABLE),))
    undetermined = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_NOT_DETERMINED),))
    both = FOLD._withheld_cause_clause((_withheld_entry(FOLD.ARM_GATE_ONLY), _withheld_entry(FOLD.ARM_WITHHELD)))

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
    assert "1 to a route witnessed AUTHORING" in both and "could not be READ at all" in both


def test_the_credit_path_reading_counts_the_paths_that_actually_answered():
    """Zero is named too, or a reader can't tell a path that didn't fire from one the model lacks."""
    none = FOLD._credit_path_reading({})
    mixed = FOLD._credit_path_reading(
        {
            FOLD.CREDIT_PATH_OWN: 55,
            FOLD.CREDIT_PATH_COMPOSED: 40,
            FOLD.CREDIT_PATH_SHEET_CEILING: 21,
        }
    )
    moved = FOLD._credit_path_reading(
        {
            FOLD.CREDIT_PATH_OWN: 55,
            FOLD.CREDIT_PATH_COMPOSED: 40,
            FOLD.CREDIT_PATH_SHEET_CEILING: 22,
        }
    )
    assert len({none, mixed, moved}) == 3
    assert "55 from" in mixed and "40 from" in mixed and "21 from" in mixed
    assert none.count("0 from") == 3
    for clause in FOLD._CREDIT_PATH_CLAUSES.values():
        assert clause in none and clause in mixed
    assert len(set(FOLD._CREDIT_PATH_CLAUSES.values())) == len(FOLD._CREDIT_PATH_CLAUSES)


def test_the_mixed_witness_cause_names_the_answer_that_put_an_entity_in_the_population():
    """There are two fold answers now, so the sentence carries both counts."""
    empty = FOLD._mixed_witness_cause(0, 0, 0, 0)
    plain = FOLD._mixed_witness_cause(5, 0, 0, 0)
    composed = FOLD._mixed_witness_cause(5, 3, 0, 2)
    ceiling = FOLD._mixed_witness_cause(5, 0, 3, 2)
    both = FOLD._mixed_witness_cause(26, 3, 8, 6)
    assert len({empty, plain, composed, ceiling, both}) == 5
    assert "measured zero" in empty
    assert "None of the 5 entity(ies)" in plain
    assert "26 entity(ies)" in both and "3 carry a COMPOSED" in both and "8 a SHEET CEILING" in both
    assert "6 of them carry no call witness of their own at all" in both


def _ceiling_row(entity: str, usd: float, capability: str = "upgrade.implementation") -> dict[str, Any]:
    return {
        "reach_sheet_ceiling_magnitudes": [
            {
                "entity": entity,
                "capability": capability,
                "published_usd": usd,
                "ceiling_reason": P.CEILING_ADMITTED,
                "bound_direction": FOLD.BOUND_DIRECTION_NOT_DETERMINED,
            }
        ]
    }


def test_the_sheet_ceiling_rollup_reading_counts_what_the_rows_published():
    empty = FOLD._sheet_ceiling_totals([], [], {})
    one = FOLD._sheet_ceiling_totals([_ceiling_row("ethereum::0xaaa", 5.0)], [], {"upgrade.implementation": 1})
    refusing = FOLD._sheet_ceiling_totals(
        [
            {
                **_ceiling_row("ethereum::0xaaa", 5.0),
                "undetermined_instances": [
                    {
                        "entity": "ethereum::0xbbb",
                        "function": "f",
                        "why": f"{FOLD.SHEET_CEILING_REFUSED_PREFIX}no_rows)",
                    }
                ],
            }
        ],
        [],
        {"upgrade.implementation": 1},
    )
    assert len({empty["reading"], one["reading"], refusing["reading"]}) == 3
    assert empty["entities_priced_from_a_sheet_ceiling"] == 0
    assert "measured zero and not a silence" in empty["reading"]
    assert refusing["calls_refused_by_reason"]["no_rows"] == 1
    assert "1 code-control call(s)" in refusing["reading"]
    other = FOLD._sheet_ceiling_totals(
        [{**_ceiling_row("ethereum::0xaaa", 5.0), "undetermined_instances": [{"why": "entity_value_not_determined"}]}],
        [],
        {},
    )
    assert set(other["calls_refused_by_reason"].values()) == {0}


def test_the_rollup_publishes_a_named_zero_for_every_token_in_a_closed_vocabulary():
    """An absent token reads the same as "not in the model".

    The vocabularies derive from the plane's tuples so a new reason can't go uncounted.
    """
    empty = FOLD._sheet_ceiling_totals([], [], {})
    assert set(empty["calls_refused_by_reason"]) == set(FOLD.CEILING_REFUSAL_REASONS)
    assert set(empty["entities_by_ceiling_reason"]) == set(P.CEILING_ADMITTING_REASONS)
    assert set(empty["entities_by_bound_direction"]) == set(FOLD.SHEET_CEILING_BOUND_DIRECTIONS)
    assert set(empty["calls_refused_by_reason"].values()) == {0}
    assert set(empty["entities_by_ceiling_reason"].values()) == {0}
    assert set(FOLD.CEILING_REFUSAL_REASONS) | set(P.CEILING_ADMITTING_REASONS) == set(P.CEILING_REASONS)
    assert not set(FOLD.CEILING_REFUSAL_REASONS) & set(P.CEILING_ADMITTING_REASONS)
    assert FOLD.BOUND_DIRECTION_FLOOR not in FOLD.SHEET_CEILING_BOUND_DIRECTIONS
    # A census smaller than its own carriers is worse than a sparse one.
    stray = FOLD._named_zeros({"unregistered": {"a", "b"}}, FOLD.CEILING_REFUSAL_REASONS)
    assert stray["unregistered"] == 2
    assert set(FOLD.CEILING_REFUSAL_REASONS) <= set(stray)


def test_the_rollup_reading_says_whether_the_capability_buckets_sum_to_the_population():
    """Dollars are deduped per entity but capability buckets are not."""
    one_each = FOLD._sheet_ceiling_totals(
        [_ceiling_row("ethereum::0xaaa", 5.0), _ceiling_row("ethereum::0xbbb", 7.0, "exec.arbitrary")], [], {}
    )
    shared = FOLD._sheet_ceiling_totals(
        [_ceiling_row("ethereum::0xaaa", 5.0), _ceiling_row("ethereum::0xaaa", 5.0, "exec.arbitrary")], [], {}
    )
    assert one_each["entities_in_more_than_one_capability"] == 0
    assert shared["entities_in_more_than_one_capability"] == 1
    assert shared["entities_priced_from_a_sheet_ceiling"] == 1
    assert sum(shared["entities_by_capability"].values()) == 2
    assert shared["ceiling_usd_over_distinct_entities"] == 5.0
    assert one_each["reading"] != shared["reading"]
    assert "sums past the distinct-entity count" in shared["reading"]
    assert "arithmetic coincidence of this corpus" in one_each["reading"]


def test_the_rollup_counts_one_sheet_once_and_names_a_disagreement_rather_than_absorbing_it():
    """A disagreement means per-key reconciliation let two figures stand, so it's counted."""
    agreeing = FOLD._sheet_ceiling_totals(
        [_ceiling_row("ethereum::0xaaa", 5.0), _ceiling_row("ethereum::0xaaa", 5.0)], [], {}
    )
    assert agreeing["entities_priced_from_a_sheet_ceiling"] == 1
    assert agreeing["ceiling_usd_over_distinct_entities"] == 5.0
    assert agreeing["rows_publishing_a_sheet_ceiling"] == {"findings": 2, "subsumed_rows": 0}
    assert agreeing["entities_publishing_more_than_one_figure"] == []
    assert "double-counts nothing" in agreeing["reading"]

    disagreeing = FOLD._sheet_ceiling_totals(
        [_ceiling_row("ethereum::0xaaa", 5.0), _ceiling_row("ethereum::0xaaa", 9.0)], [], {}
    )
    assert disagreeing["entities_publishing_more_than_one_figure"] == ["ethereum::0xaaa"]
    assert disagreeing["ceiling_usd_over_distinct_entities"] == 9.0
    assert "publish more than one figure" in disagreeing["reading"]

    subsumed = FOLD._sheet_ceiling_totals(
        [_ceiling_row("ethereum::0xaaa", 5.0)], [_ceiling_row("ethereum::0xaaa", 5.0)], {}
    )
    assert subsumed["rows_publishing_a_sheet_ceiling"] == {"findings": 1, "subsumed_rows": 1}
    assert subsumed["ceiling_usd_over_distinct_entities"] == 5.0


# These shipped with zero corpus carriers, so a sentence calling a proven-zero reading "priced" rode green.


def _proven_empty_ceiling_row(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"native": 0.0}},
        per_asset_state={KEY_C: {"native": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    return _cc_row(document)["reach_sheet_ceiling_magnitudes"][0], plane


def test_a_proven_empty_ceiling_reads_its_own_admission_and_not_the_priced_one(fold):
    entry, _ = _proven_empty_ceiling_row(fold)
    assert entry["ceiling_reason"] == P.CEILING_PROVEN_EMPTY
    assert entry["sheet_state"] == P.SHEET_PROVEN_EMPTY
    assert entry["reading"] == FOLD._CEILING_SOURCE_READINGS[(P.CEILING_PROVEN_EMPTY, True)] + FOLD._CEILING_CLOSING
    assert entry["reading"] != FOLD._CEILING_SOURCE_READINGS[(P.CEILING_ADMITTED, True)] + FOLD._CEILING_CLOSING
    assert "priced holdings" not in entry["reading"]


def test_the_direction_basis_on_a_proven_empty_row_states_what_was_observed(fold):
    entry, _ = _proven_empty_ceiling_row(fold)
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["bound_direction_basis"] == FOLD._SHEET_CEILING_DIRECTION_BASIS[True]
    assert entry["per_asset"] == [{"asset": "native", "usd": 0.0, "state": P.ASSET_PROVEN_ZERO}]
    assert entry["assets_not_priced"] == [] and entry["unpriced_positions"] == 0


def test_the_completeness_block_on_a_ceiling_row_is_the_carriers_own_record(fold):
    """#171: basis strings are the producer's ``asset_set_basis`` copied, with account arithmetic so two folded
    accounts can't read as fully scanned on one.
    """
    entry, plane = _proven_empty_ceiling_row(fold)
    published = entry["asset_set_completeness"]
    assert published == plane.asset_set_proven_complete[KEY_C]
    assert published["basis"] == SCANNED["basis"]
    assert published["source"] == "chain_log_sweep"
    assert published["accounts_scanned"] == published["accounts_folded"]
    priced = value_plane({KEY_C: {"usdc": 5.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    admitted = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=priced))
    assert admitted["reach_sheet_ceiling_magnitudes"][0]["asset_set_completeness"] is None


DELIVERED = {
    "shape": "fan_out_all",
    "fan_out_threshold_k": 25,
    "min_fan_out": 199,
    "delivery_count": 3,
    "scanned_from_block": 0,
    "measured_through_block": 21_000_000,
    "accounts": ["0x" + "c" * 40],
    "basis": ["delivery receipts read over blocks 0-21000000; every delivery fanned out to >= 25 recipients"],
}


def _airdrop_determined_ceiling_row(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(per_asset_state={KEY_C: {"junk": P.ASSET_AIRDROP_DELIVERED}})
    plane.asset_disposition = {KEY_C: {"junk": dict(DELIVERED)}}
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    return _cc_row(document)["reach_sheet_ceiling_magnitudes"][0], plane


def test_a_disposed_ceiling_publishes_only_what_its_carrier_record_proves(fold):
    """#171 end to end: every claim comes from the copied delivery evidence, and nothing restates delivery shape as
    worth.
    """
    entry, plane = _airdrop_determined_ceiling_row(fold)
    carrier = plane.asset_disposition[KEY_C]["junk"]

    # A mass distribution is not "nothing ever arrived".
    assert entry["sheet_state"] == P.SHEET_AIRDROP_DETERMINED
    assert entry["ceiling_reason"] == P.CEILING_AIRDROP_DETERMINED
    assert entry["sheet_state"] != P.SHEET_PROVEN_EMPTY
    assert entry["ceiling_reason"] != P.CEILING_PROVEN_EMPTY
    assert entry["sheet_usd"] == 0.0

    # The asset list isn't proven whole, so it takes the partial arm.
    complete = entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert complete is False
    stem = FOLD._CEILING_SOURCE_READINGS[(P.CEILING_AIRDROP_DETERMINED, False)]
    assert entry["reading"].startswith(stem)
    assert entry["reading"].endswith(FOLD._CEILING_CLOSING)
    assert entry["asset_set_completeness"] is None

    assert carrier["fan_out_threshold_k"] == 25
    assert carrier["min_fan_out"] >= carrier["fan_out_threshold_k"]
    assert carrier["delivery_count"] == 3
    assert (carrier["scanned_from_block"], carrier["measured_through_block"]) == (0, 21_000_000)
    assert carrier["basis"] == DELIVERED["basis"]
    assert "junk" in (plane.asset_disposition.get(plane.canonical(KEY_C)) or {})

    # This half shipped missing: the carrier was assembled and no narration read it.
    published_carrier = entry["asset_disposition"]
    assert published_carrier["assets"] == 1
    assert published_carrier["fan_out_threshold_k"] == carrier["fan_out_threshold_k"]
    assert published_carrier["min_fan_out"] == carrier["min_fan_out"]
    assert published_carrier["delivery_count"] == carrier["delivery_count"]
    assert published_carrier["accounts"] == carrier["accounts"]
    assert published_carrier["basis"] == sorted(carrier["basis"])
    assert (published_carrier["scanned_from_block"], published_carrier["measured_through_block"]) == (0, 21_000_000)

    for figure in (
        str(carrier["delivery_count"]),
        str(carrier["min_fan_out"]),
        str(carrier["fan_out_threshold_k"]),
        f"{carrier['scanned_from_block']}-{carrier['measured_through_block']}",
    ):
        assert figure in entry["reading"], figure

    assert entry["assets_priced"] == 0
    assert "STILL HELD" in entry["reading"]
    assert "never what they are worth, which is not_determined here" in entry["reading"]

    assert entry["per_asset"] == [{"asset": "junk", "usd": None, "state": P.ASSET_AIRDROP_DELIVERED}]
    assert entry["assets_disposed"] == ["junk"]

    # "spam"/"worthless" would be false of the real tokens measured into this state.
    published = set(entry)
    for concept in ("assets_not_priced", "assets_disposed", "unpriced_positions", "per_asset", "asset_disposition"):
        if concept in entry["reading"]:
            assert concept in published, concept
    for banned in ("spam", "scam", "worthless", "junk token"):
        assert banned not in entry["reading"].lower()


def _priced_but_partly_unpriced_ceiling_row(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "other": P.ASSET_UNPRICED}},
    )
    return _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))["reach_sheet_ceiling_magnitudes"][
        0
    ]


def _priced_sheet_with_a_disposed_row(fold):
    """The live $575M proxy: an admitted ceiling failing only on the list conjunct."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "junk": P.ASSET_AIRDROP_DELIVERED}},
    )
    plane.asset_disposition = {KEY_C: {"junk": dict(DELIVERED)}}
    return _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))["reach_sheet_ceiling_magnitudes"][
        0
    ]


def test_the_reading_and_the_direction_publish_ONE_derived_shortfall(fold):
    """Written twice by hand, the reading kept naming ``assets_not_priced`` on carriers where it's empty."""
    admitted = _priced_sheet_with_a_disposed_row(fold)
    assert admitted["ceiling_reason"] == P.CEILING_ADMITTED
    assert admitted["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert admitted["assets_not_priced"] == [] and admitted["unpriced_positions"] == 0
    assert admitted["asset_list_proven_whole"] is False

    shortfall = FOLD._coverage_shortfall(admitted)
    assert shortfall and "asset_list_proven_whole" in shortfall
    assert admitted["bound_direction_basis"].endswith(shortfall)
    assert FOLD._CEILING_COVERAGE_SHORTFALL_PREFIX + shortfall in admitted["reading"]
    assert "assets_not_priced" not in admitted["reading"]
    assert "assets_not_priced" not in admitted["bound_direction_basis"]
    assert "the entity holds more than it" in admitted["reading"]

    unpriced = _priced_but_partly_unpriced_ceiling_row(fold)
    assert "assets_not_priced" in unpriced["reading"]
    assert "asset_list_proven_whole" not in unpriced["reading"]
    assert unpriced["reading"] != admitted["reading"]

    priced = value_plane({KEY_C: {"usdc": 5.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    whole = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=priced))[
        "reach_sheet_ceiling_magnitudes"
    ][0]
    assert whole["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert FOLD._CEILING_COVERAGE_SHORTFALL_PREFIX not in whole["reading"]


def test_the_refused_direction_names_the_conjunct_that_actually_failed(fold):
    """``complete`` is three conjuncts but the shipped sentence named two; a $575M proxy refused on the third."""
    disposed, _ = _airdrop_determined_ceiling_row(fold)
    assert disposed["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert disposed["assets_not_priced"] == [] and disposed["unpriced_positions"] == 0
    assert disposed["asset_list_proven_whole"] is False
    assert "asset_list_proven_whole" in disposed["bound_direction_basis"]
    assert "assets_not_priced" not in disposed["bound_direction_basis"]
    assert "unpriced_positions" not in disposed["bound_direction_basis"]

    unpriced = _priced_but_partly_unpriced_ceiling_row(fold)
    assert unpriced["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert unpriced["assets_not_priced"] == ["other"] and unpriced["asset_list_proven_whole"] is True
    assert "assets_not_priced" in unpriced["bound_direction_basis"]
    assert "asset_list_proven_whole" not in unpriced["bound_direction_basis"]

    assert disposed["bound_direction_basis"] != unpriced["bound_direction_basis"]
    for entry in (disposed, unpriced):
        for concept in ("assets_not_priced", "unpriced_positions", "asset_list_proven_whole"):
            if concept in entry["bound_direction_basis"]:
                assert concept in entry, concept


def test_a_ceiling_row_stops_counting_a_disposed_asset_as_a_priced_one(fold):
    """A disposed reading is in neither term of ``observed - not_priced``, so an all-airdrop sheet published 140 of
    140 priced beside $0.
    """
    disposed, _ = _airdrop_determined_ceiling_row(fold)
    assert disposed["assets_observed"] == 1
    assert disposed["assets_disposed"] == ["junk"]
    assert disposed["assets_priced"] == 0
    assert disposed["assets_observed"] == disposed["assets_priced"] + len(disposed["assets_not_priced"]) + len(
        disposed["assets_disposed"]
    )

    unpriced = _priced_but_partly_unpriced_ceiling_row(fold)
    assert unpriced["assets_disposed"] == [] and unpriced["assets_priced"] == 1
