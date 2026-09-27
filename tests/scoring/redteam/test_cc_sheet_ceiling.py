"""Observed own holdings remain useful for code-control findings."""

from __future__ import annotations

import pytest

from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_V,
    SCANNED,
    _cc_row,
    facts,
    fold,  # noqa: F401 -- pytest fixture
    proven,
    reaches,
    sig,
    value_plane,
)


@pytest.mark.parametrize("capability", ["upgrade.implementation", "exec.arbitrary", "delegatecall.execute"])
@pytest.mark.parametrize("dollars", [0.0, 0.001, 5_000_000.0])
def test_code_control_values_own_observed_holdings_with_explicit_scope(fold, capability, dollars):
    plane = value_plane(
        {KEY_C: {"token": dollars}},
        per_asset_state={KEY_C: {"token": P.ASSET_PROVEN_ZERO if dollars == 0 else P.ASSET_PRICED}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    plane.fresh_entities.add(KEY_C)
    signal = sig(
        claim_id=capability,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = _cc_row(document, capability)
    assert finding["severity_proven"] is not None
    assert finding["raw_points"] > 0
    assert finding["reach_entities"] == [KEY_C]
    assert finding["value_at_stake_usd"] == dollars
    assert finding["value_band"] != "not_determined"
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    record = finding["reach_sheet_ceiling_magnitudes"][0]
    assert record["value_scope"] == "observed_own_holdings"
    assert record["observation_fresh"] is True
    assert record["bound_direction"] == "ceiling"
    assert finding["exposure_usd"] is None
    assert plane.total(KEY_C) == dollars
    assert document.model_parameters["confidence_detail"]["reach_magnitude_signals"]["magnitude_sheet_ceiling"] == 1


def test_downstream_membership_survives_without_a_wallet_ceiling(fold):
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
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"token": 1_000_000.0}, KEY_V: {"token": 900_000_000.0}}),
    )
    row = _cc_row(document)
    assert set(row["reach_entities"]) == {KEY_C, KEY_V}
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert row["value_by_entity"] == {KEY_C: 1_000_000.0}
    assert {item["entity"] for item in row["undetermined_instances"]} == {KEY_V}


@pytest.mark.parametrize("gap", ["unscanned", "unpriced", "stale", "truncated", "typed_receipt"])
def test_partial_observations_value_control_without_claiming_complete_magnitude(fold, gap):
    plane = value_plane(
        {KEY_C: {"token": 2_000_000.0}},
        per_asset_state={KEY_C: {"token": P.ASSET_PRICED}},
        asset_set_proven_complete={KEY_C: SCANNED},
        fresh_entities={KEY_C},
    )
    if gap == "unscanned":
        plane.asset_set_proven_complete.clear()
    elif gap == "unpriced":
        plane.per_asset_state[KEY_C]["other"] = P.ASSET_UNPRICED
    elif gap == "stale":
        plane.fresh_entities.clear()
    elif gap == "truncated":
        plane.asset_set_truncated.add(KEY_C)
    else:
        plane.typed_receipts_unresolved[KEY_C] = [{"token": "receipt"}]
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    doc = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    row = _cc_row(doc)
    assert row["value_at_stake_usd"] == 2_000_000.0
    assert row["value_at_stake_bound_direction"] == "not_determined"
    record = row["reach_sheet_ceiling_magnitudes"][0]
    assert record["value_scope"] == "observed_own_holdings"
    assert record["bound_direction"] == "not_determined"
    assert record["observation_fresh"] is (gap != "stale")
    assert row["exposure_usd"] is None
    assert "observed own holdings" in row["value_at_stake_basis"]
    assert "lack a complete fresh inventory" in row["value_at_stake_basis"]
    assert "bound from above what replacing" not in row["value_at_stake_basis"]
    assert "Partial or stale records do not bound current holdings" in doc.provenance["sheet_ceilings"]["reading"]
    assert doc.model_parameters["confidence_detail"]["reach_magnitude_signals"]["magnitude_sheet_ceiling"] == 0


def test_gate_control_does_not_inherit_code_control_valuation(fold):
    signal = sig(
        claim_id="authority.replace",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    doc = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=value_plane({KEY_C: {"token": 2_000_000.0}}))
    assert doc.findings[0]["value_at_stake_usd"] is None
    assert not doc.findings[0]["reach_sheet_ceiling_magnitudes"]
