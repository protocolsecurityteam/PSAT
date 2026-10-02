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

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    KEY_C,
    KEY_V,
    SCANNED,
    _cc_row,
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


def test_a_composed_entry_with_no_sheet_at_all_reads_as_bound_by_its_witness():
    entry = _composed(witnessed_usd=100.0, sheet_usd=None).as_json()
    assert entry["sheet_not_determined"] is True
    assert entry["bounded_by"] == "flow.out witness"
    assert entry["destination_sheet_usd"] is None
    assert "sheet_not_determined" in entry["reading"]


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
