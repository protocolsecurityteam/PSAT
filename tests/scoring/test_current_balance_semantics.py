"""Collection changes retain the established monetary scoring policy."""

from types import SimpleNamespace

from services.aggregations.tvl import snapshot_payload
from services.scoring import planes as P
from services.scoring.distill.flow_reach import _flow_reach
from services.scoring.fold.contributions import _sheet_ceiling
from services.scoring.schema import signal_from_row, signal_to_row_kwargs
from tests.support.scoring_builders import magnitude, proven, reaches, sig

KEY = "ethereum::0x" + "1" * 40


def test_current_holdings_keep_existing_code_control_and_trimming_rules():
    value = P.ValuePlane(
        per_asset={KEY: {"native": 2_000_000.0}},
        per_asset_state={KEY: {"native": P.ASSET_PRICED}},
    )
    # Collection provenance must not introduce a new freshness/completeness gate.
    assert P.ceiling_for(value, KEY) == (2_000_000, P.CEILING_ADMITTED)
    assert value.trimming_total(KEY) == 2_000_000
    instance = SimpleNamespace(
        signal=SimpleNamespace(
            claim_id="upgrade.implementation",
            chain="ethereum",
            deployment_address=KEY.split("::")[1],
        )
    )
    usd, reason = _sheet_ceiling(instance, KEY, value)
    assert usd == 2_000_000
    assert "code_control_sheet_ceiling" in reason


def test_stored_transfer_valuation_survives_redistillation_and_row_loading():
    reach = _flow_reach(
        {
            "observed_reach_value_usd": 1_000_000,
            "reach_determined": True,
            "observed_reach_holders": [KEY.split("::")[1]],
        },
        SimpleNamespace(chain="ethereum"),
        KEY,
    )
    assert reach.state == "proven_reach"
    assert reach.magnitude.value == 1_000_000
    original = sig(
        value_basis="observed_reach_value_usd(fork-proven)",
        gates=magnitude(1_000_000),
        **proven(1.0),
        **{k: v for k, v in reaches(KEY).items() if k != "value_basis"},
    )
    restored = signal_from_row(SimpleNamespace(**signal_to_row_kwargs(original)))
    assert restored.gate_inputs == original.gate_inputs
    assert restored.value_basis == original.value_basis
    assert restored.witness_notes == original.witness_notes


def test_tvl_serialization_preserves_measured_zero_and_unknown_coverage():
    result = snapshot_payload(SimpleNamespace(total_usd=0, defillama_tvl=0))
    assert result["total_usd"] == result["defillama_tvl"] == 0
    assert result["holdings_partial"] is None
    assert result["holdings_observed_at"] is None
    assert snapshot_payload(None)["total_usd"] is None
