"""Present holdings do not cap a capability with unbounded future scope.

Retires CC1-CC7's assumption that upgrading code can move at most today's
wallet. Preserve the findings and observed context; require actual capability
scope before publishing a dollar ceiling, including when holdings are zero.
"""

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


@pytest.mark.parametrize("capability", ["upgrade.implementation", "exec.arbitrary", "authority.replace"])
@pytest.mark.parametrize("dollars", [0.0, 0.001, 5_000_000.0])
def test_present_holdings_never_cap_unscoped_control(fold, capability, dollars):
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
    assert finding["value_at_stake_usd"] is None
    assert finding["value_band"] == "not_determined"
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert finding["reach_sheet_ceiling_magnitudes"] == []
    assert plane.total(KEY_C) == dollars
    assert document.model_parameters["confidence_detail"]["reach_magnitude_signals"]["magnitude_sheet_ceiling"] == 0


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
    assert row["value_at_stake_usd"] is None
    assert row["value_by_entity"] == {}
    assert {item["entity"] for item in row["undetermined_instances"]} == {KEY_C, KEY_V}
