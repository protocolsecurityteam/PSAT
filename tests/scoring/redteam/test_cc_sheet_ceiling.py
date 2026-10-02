"""Code-control sheet ceiling (CC1-CC7): replacing a node's code removes it from between the principal and what it
holds, so the node's own priced sheet bounds the move from above.
"""

from __future__ import annotations

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests.support.scoring_builders import (
    EOA,
    IMPL,
    KEY_C,
    KEY_IMPL,
    KEY_PROXY,
    KEY_V,
    OWNERS,
    SAFE,
    VAULT,
    _cc_row,
    bounded_by_sheet,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)
from utils import execution_record as EX
from utils.scoring_status import VALUE_STATE_PROVEN_REACH


def test_cc1_code_control_over_a_priced_node_is_priced_at_that_nodes_own_sheet(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    finding = _cc_row(document)
    assert finding["value_at_stake_usd"] == 5_000_000.0
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert finding["value_by_entity"] == {KEY_C: 5_000_000.0}
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    # Split, never widened.
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["reach_composed_magnitudes"] == []
    # The b7 conjunction is satisfied from the sheet source.
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert finding["value_at_stake_is_floor"] is False
    assert finding["value_band"] == "<= $1M-$10M"
    assert finding["value_at_stake_basis"].startswith("<= ")
    assert "SHEET CEILING" in finding["value_at_stake_basis"]

    entry = finding["reach_sheet_ceiling_magnitudes"][0]
    assert entry["entity"] == KEY_C
    assert entry["published_usd"] == entry["sheet_usd"] == 5_000_000.0
    assert entry["sheet_state"] == P.SHEET_PRICED
    assert entry["ceiling_reason"] == P.CEILING_ADMITTED
    # The reference corpus has no full-coverage carrier.
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["assets_observed"] == entry["assets_priced"] == 1
    assert entry["assets_not_priced"] == []
    assert entry["unpriced_positions"] == 0
    assert entry["per_asset"] == [{"asset": "usdc", "usd": 5_000_000.0, "state": P.ASSET_PRICED}]
    assert "every asset observed at this entity carries a determined reading" in entry["bound_direction_basis"]
    assert finding["reach_sheet_ceiling_magnitudes_withheld"] == []
    # #170: a balance observation has no execution to name, and the reason must not be a fault.
    execution = entry[EX.PROVING_EXECUTION_KEY]
    assert execution["state"] == EX.EXECUTION_NOT_DETERMINED
    assert execution["reason"] == EX.REASON_NOT_PROVEN_BY_A_CALL
    assert EX.REASON_NOT_PROVEN_BY_A_CALL in EX.NOT_DETERMINED_REASONS
    assert EX.REASON_NOT_PROVEN_BY_A_CALL not in EX.FAULT_REASONS
    # The structural census walks proving_execution keys, so the registration is load-bearing.
    assert FOLD._execution_fault_census(document.findings, document.provenance["subsumed_rows"]) is None
    census = finding["magnitude_witness_census"]
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["magnitude_not_witnessed"] == 0
    assert census["magnitude_composed"] == 0


def test_cc4_a_shared_implementation_earns_no_ceiling(fold):
    """``_entity_contribution`` refuses a shared-implementation key before every branch, so ``alias_ambiguous`` has
    no published carrier.
    """
    plane = value_plane({KEY_IMPL: {"usdc": 9_000_000.0}}, contracts=(KEY_PROXY,))
    plane.alias_ambiguous = {KEY_IMPL}
    signal = sig(
        deployment_address=IMPL,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_IMPL),
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] is None
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert [row["why"] for row in finding["undetermined_instances"]] == [
        "shared_implementation_folds_onto_no_proxy(not_determined)"
    ]
    assert P.ceiling_for(plane, KEY_IMPL) == (None, P.CEILING_ALIAS_AMBIGUOUS)


def test_cc7_a_sheet_ceiling_charges_the_exposure_budget_nothing(fold):
    """Ceilings are risk-weighted upper bounds, never expected loss.

    A ceiling in the numerator (1) inflates ``exposure_usd`` off bounds, so the coverage
    disclosure would claim near-total coverage on their strength, and (2) SPENDS the entity's
    budget, trimming a later row that measured a real extraction there.

    Here the flow.out row measures a real $2M at the shared entity; the ceiling row reaches it
    too and must leave the budget untouched.
    """
    ceiling_row = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    measured = flow_sig(
        function_name="withdraw",
        selector="0x11112222",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        gates=bounded_by_sheet(2_000_000.0),
        **proven(0.9),
        **reaches(KEY_C),
    )
    document = fold(
        [ceiling_row, measured],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    upgrade = _cc_row(document)
    flow = _cc_row(document, "flow.out")
    assert upgrade["value_at_stake_usd"] == 5_000_000.0
    assert upgrade["exposure_usd"] is None
    assert upgrade["exposure_entities_charged"] == []
    assert flow["exposure_usd"] == pytest.approx(2_000_000.0 * flow["severity_proven"] * flow["weakness"])
    gaps = {(g["principal_unit"], g["capability"]): g for g in document.provenance["exposure_gaps"]}
    ceiling_gap = gaps[(upgrade["principal_unit"], "upgrade.implementation")]
    assert ceiling_gap["ceiling_entities_excluded_from_exposure"] == [KEY_C]
    assert ceiling_gap["budget_exhausted_entities"] == []
    assert ceiling_gap["budget_partially_exhausted_entities"] == []
    assert "ceiling_entities_excluded_from_exposure" in ceiling_gap["reading"]
    coverage = document.provenance["exposure_coverage"]
    assert coverage["findings_with_exposure_not_determined"] >= 1
    assert coverage["perimeter_usd_charged"] == pytest.approx(5_000_000.0)


def test_cc7_a_subsumed_rows_sheet_ceiling_leaks_into_the_budget_in_neither_direction(fold):
    """Subsumption leaks both ways with a sheet ceiling, on one principal unit.
    IN: a subsumed row's ceiling at an entity the top row doesn't price would be charged, because the exposure
    skip reads the top row's ceiling list.
    OUT: the top row's ceiling marks the key occupied, discarding a subsumed row's witnessed value there.
    """
    top = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    witnessed_at_c = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        selector="0x11112222",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(400_000.0),
        **proven(0.5),
        **reaches(KEY_C),
    )
    ceiling_at_v = sig(
        claim_id="exec.arbitrary",
        function_name="execute",
        selector="0x33334444",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.4),
        **reaches(KEY_V),
    )
    document = fold(
        [top, witnessed_at_c, ceiling_at_v],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}, KEY_V: {"usdc": 900_000.0}}),
    )
    finding = _cc_row(document)
    assert finding["capability"] == "upgrade.implementation"
    assert [r["capability"] for r in finding["subsumed_capabilities"]] == ["authority.replace", "exec.arbitrary"]

    exclusive = finding["subsumed_exclusive_value_by_entity"]
    assert KEY_C in exclusive and exclusive[KEY_C]["usd"] == 400_000.0
    assert KEY_V in exclusive
    assert finding["subsumed_exclusive_sheet_ceiling_entities"] == [KEY_V]

    assert finding["exposure_usd"] == pytest.approx(400_000.0 * exclusive[KEY_C]["fraction"])
    assert finding["exposure_entities_charged"] == [KEY_C]
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if (g["principal_unit"], g["capability"]) == (finding["principal_unit"], "upgrade.implementation")
    )
    assert gap["ceiling_entities_excluded_from_exposure"] == [KEY_V]
    assert gap["budget_exhausted_entities"] == [] and gap["budget_partially_exhausted_entities"] == []
