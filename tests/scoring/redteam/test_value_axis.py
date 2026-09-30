
from __future__ import annotations

from services.scoring.schema import PrincipalRef, Tri, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_IMPL,
    KEY_PROXY,
    KEY_V,
    OWNERS,
    PROXY,
    SAFE,
    VAULT,
    C,
    bounded_by_sheet,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)
from utils.scoring_status import VALUE_BOUND_EXACT


def test_f1_a_native_only_flow_is_still_bounded_by_its_witness(fold):
    plane = value_plane({KEY_C: {"native": 1_000_000_000.0}})
    signal = flow_sig(
        function_name="sweepETH",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={
            "reach_magnitude_usd": Tri.proven("proven_exact", 10.0).to_json(),
            "asset_class": Tri.proven("proven", "native_only").to_json(),
        },
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_EXACT),
    )
    finding = fold([signal], value=plane).findings[0]
    assert finding["value_at_stake_usd"] == 10.0
    assert finding["value_band"] == "<$100k"


def test_f1_a_native_only_flow_with_no_native_row_is_not_determined(fold):
    signal = flow_sig(
        function_name="sweepETH",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"asset_class": Tri.proven("proven", "native_only").to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C),
    )
    finding = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}})).findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["undetermined_instances"][0]["why"].startswith("native_only_flow")


def test_f4_an_unpriced_entity_is_never_exposure_zero(fold):
    priced = sig(
        function_name="upgradeToA",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    unpriced = sig(
        function_name="upgradeToB",
        deployment_address=VAULT,
        contract_id=2,
        selector="0xfeedface",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_V),
    )
    document = fold(
        [priced, unpriced],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    by_unit = {f["principal_unit"]: f for f in document.findings}
    assert by_unit[entity_key("ethereum", EOA)]["exposure_usd"] is not None
    assert by_unit[entity_key("ethereum", SAFE)]["exposure_usd"] is None
    assert document.provenance["exposure_gaps"]


def test_f11_a_withheld_grade_publishes_no_derived_figure(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=value_plane({}))
    served = document.document()

    assert served["grade_state"] == "not_determined"
    assert served["confidence_pct"] is None
    assert "pct" not in served["model_parameters"]["confidence_detail"]
    for finding in served["findings"]:
        assert "net_points_lambda" not in finding
        assert "exposure_usd" not in finding
    withheld = document.provenance["grade_withheld"]
    assert withheld["grade_lambda_computed"] is not None
    assert withheld["per_finding"]


def test_f10_the_transitive_branch_reads_the_signals_value_state(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
    )  # value_state stays not_determined
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 900_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["value_state"] == "not_determined"
    assert finding["undetermined_instances"]


def test_v3_the_transitive_branch_discloses_unpriced_closure_entities(fold):
    """Gate control never prices from the sheet; code control's exception is pinned in ``test_cc3_*``."""
    signal = sig(
        claim_id="authority.replace",
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
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])
    assert finding["value_at_stake_usd"] is None
    assert finding["value_band"] == "not_determined"
    assert finding["value_at_stake_is_floor"] is False
    named = {row["entity"] for row in finding["undetermined_instances"]}
    assert named == {KEY_C, KEY_V}
    priced_gap = next(row for row in finding["undetermined_instances"] if row["entity"] == KEY_C)
    assert priced_gap["why"].startswith("reach_magnitude_not_witnessed")
    assert finding["magnitude_witness_census"]["magnitude_not_witnessed"] == 1


def test_v4_exposure_caps_on_the_entity_contribution_not_the_row_total(fold):
    signals = [
        flow_sig(
            function_name=f"withdraw{index}",
            deployment_address=address,
            contract_id=index + 1,
            selector=f"0x0000001{index}",
            authority_openness="open",
            principal_state="none_required",
            witness_tier="behavioral_observed",
            gates={"reach_magnitude_usd": Tri.proven("proven_exact", 100.0).to_json()},
            **proven(0.9, ("caller_arbitrary_proven",)),
            **reaches(entity_key("ethereum", address), bound=VALUE_BOUND_EXACT),
        )
        for index, address in enumerate((C, VAULT))
    ]
    document = fold(
        signals,
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 200.0
    assert finding["value_by_entity"] == {KEY_C: 100.0, KEY_V: 100.0}
    assert finding["exposure_usd"] <= 200.0


def test_p0_a_proxy_and_its_implementation_are_one_priced_entity(fold):
    """Keying contributions on raw keys published value and exposure at exactly 2x."""
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(100_000_000.0),
        **proven(1.0),
        **reaches(KEY_IMPL, KEY_PROXY),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_PROXY: {"usdc": 100_000_000.0}}, alias={KEY_IMPL: KEY_PROXY}),
    )
    finding = document.findings[0]
    assert finding["reach_entities"] == [KEY_PROXY]
    assert finding["value_by_entity"] == {KEY_PROXY: 100_000_000.0}
    assert finding["value_at_stake_usd"] == 100_000_000.0
    assert finding["exposure_entities_charged"] == [KEY_PROXY]
    fraction = finding["severity_proven"] * finding["weakness"]
    assert finding["exposure_usd"] == round(fraction * 100_000_000.0, 2)
    # Double-charging the pair drove the grade negative.
    assert document.grade_exposure == round(100.0 * (1.0 - fraction), 3)


def test_host_entities_name_the_deployments_not_the_reach(fold):
    """A transitive row's reach set can omit an unpriced host."""
    signal = sig(
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_V),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_V: {"usdc": 1_000.0}}),
    )
    finding = document.findings[0]
    assert finding["host_entities"] == [KEY_C]
    assert finding["reach_entities"] == [KEY_V]
    assert finding["n_entities"] == 1
