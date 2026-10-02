from __future__ import annotations

from services.scoring.schema import PrincipalRef, Tri
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_V,
    C,
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
