"""Legacy delivery evidence must no longer exclude holdings or determine zero."""

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests.support.scoring_builders import EOA, facts, fold, magnitude, proven, reaches, sig  # noqa: F401

KEY = "ethereum::0x" + "a" * 40
TOKEN = "0x" + "1" * 40


def test_legacy_disposition_is_an_unpriced_observation():
    plane = P.ValuePlane(
        per_asset_state={KEY: {TOKEN: P.ASSET_AIRDROP_DELIVERED}},
    )
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert plane.total(KEY) is None
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)
    assert not FOLD._asset_coverage(plane, KEY)["complete"]


def test_legacy_disposition_beside_priced_value_preserves_value_but_cannot_cap():
    plane = P.ValuePlane(
        per_asset={KEY: {"native": 50.0}},
        per_asset_state={KEY: {"native": P.ASSET_PRICED, TOKEN: P.ASSET_AIRDROP_DELIVERED}},
    )
    assert plane.total(KEY) == 50
    assert plane.trimming_total(KEY) is None
    assert P.ceiling_for(plane, KEY)[0] is None


def test_legacy_disposition_beside_zero_does_not_prove_empty():
    plane = P.ValuePlane(
        per_asset={KEY: {"native": 0.0}},
        per_asset_state={KEY: {"native": P.ASSET_PROVEN_ZERO, TOKEN: P.ASSET_AIRDROP_DELIVERED}},
        asset_set_proven_complete={KEY: {"source": "legacy_scan"}},
        fresh_entities={KEY},
    )
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert plane.total(KEY) is None


def test_security_finding_survives_delivery_retirement(fold):
    signal = sig(
        deployment_address=KEY.split("::")[1],
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY),
    )
    legacy = P.ValuePlane(per_asset_state={KEY: {TOKEN: P.ASSET_AIRDROP_DELIVERED}}, contract_entities={KEY})
    current = P.ValuePlane(per_asset_state={KEY: {TOKEN: P.ASSET_UNPRICED}}, contract_entities={KEY})
    before = fold([signal], value=legacy, principals={1: facts(1, EOA, "eoa")})
    after = fold([signal], value=current, principals={1: facts(1, EOA, "eoa")})
    assert len(before.findings) == len(after.findings) == 1
    assert before.grade_lambda == after.grade_lambda
    assert before.confidence_pct == after.confidence_pct
    assert after.findings[0].get("value_at_stake_usd") is None
