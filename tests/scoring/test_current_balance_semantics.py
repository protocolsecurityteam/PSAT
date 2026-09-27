"""Regression checks for current holdings, delivery retirement and scoped bounds."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from services.aggregations.tvl import snapshot_payload
from services.scoring import planes as P
from services.scoring.fold.ceilings import _asset_coverage
from services.scoring.fold.contributions import _sheet_ceiling
from services.scoring.planes.value import _asset_reading, _observation_fresh

KEY = "ethereum::0x" + "1" * 40


def plane():
    return P.ValuePlane(
        per_asset={KEY: {"native": 100.0}},
        per_asset_state={KEY: {"native": P.ASSET_PRICED}},
        fresh_entities={KEY},
    )


def test_indexed_priced_subset_is_context_not_a_hard_bound():
    value = plane()
    assert value.total(KEY) == 100
    assert P.ceiling_for(value, KEY) == (None, "asset_set_not_proven_complete")
    assert _asset_coverage(value, KEY)["complete"] is False
    assert value.trimming_total(KEY) is None


def test_complete_current_sheet_values_own_code_control_scope():
    value = plane()
    value.asset_set_proven_complete[KEY] = {"source": "explicit_test_witness"}
    assert P.ceiling_for(value, KEY) == (100, P.CEILING_ADMITTED)
    instance = SimpleNamespace(
        signal=SimpleNamespace(
            claim_id="upgrade.implementation", chain="ethereum", deployment_address=KEY.split("::")[1]
        )
    )
    usd, reason = _sheet_ceiling(instance, KEY, value)
    assert usd == 100
    assert "code_control_sheet_ceiling" in reason
    assert value.trimming_total(KEY) is None
    assert value.trimming_total(KEY, current_holdings_only=True) == 100


def test_stale_or_partly_priced_complete_sheet_cannot_cap_value():
    value = plane()
    value.asset_set_proven_complete[KEY] = {"source": "explicit_test_witness"}
    value.fresh_entities.clear()
    assert P.ceiling_for(value, KEY) == (None, "observation_not_fresh")
    value.fresh_entities.add(KEY)
    value.per_asset_state[KEY]["relevant_unpriced"] = P.ASSET_UNPRICED
    assert P.ceiling_for(value, KEY) == (None, P.CEILING_UNPRICED)


def test_legacy_delivery_classification_cannot_zero_held_assets():
    value = P.ValuePlane(per_asset_state={KEY: {"token": P.ASSET_AIRDROP_DELIVERED}})
    assert value.sheet_state(KEY) == P.SHEET_UNPRICED
    assert value.total(KEY) is None
    assert P.ceiling_for(value, KEY) == (None, P.CEILING_UNPRICED)


@pytest.mark.parametrize(
    "raw,usd,state",
    [
        ("0", None, P.ASSET_PROVEN_ZERO),
        ("1", None, P.ASSET_UNPRICED),
        ("1", 0, P.ASSET_BELOW_RESOLUTION),
        ("0.000000000000000000000000000000000000001", 0, P.ASSET_BELOW_RESOLUTION),
    ],
)
def test_missing_quote_is_not_zero_and_raw_underflow_cannot_prove_zero(raw, usd, state):
    assert _asset_reading(SimpleNamespace(raw_balance=raw, usd_value=usd))[1] == state


def test_write_time_is_not_an_observation_time():
    now = datetime.now(timezone.utc)
    assert not _observation_fresh(SimpleNamespace(fetched_at=now))
    assert not _observation_fresh(SimpleNamespace(observed_at=now - timedelta(days=1)))
    assert not _observation_fresh(SimpleNamespace(observed_at=now + timedelta(days=1)))
    assert _observation_fresh(SimpleNamespace(observed_at=now))


def test_tvl_serialization_preserves_measured_zero_and_separate_scope():
    result = snapshot_payload(SimpleNamespace(total_usd=0, defillama_tvl=0, external_slug="series"))
    assert result["total_usd"] == result["defillama_tvl"] == 0
    assert result["holdings_partial"] is None
    assert result["external_source"] == "DefiLlama"
    assert result["external_slug"] == "series"
    assert result["holdings_observed_at"] is None
    assert snapshot_payload(None)["total_usd"] is None


@pytest.mark.parametrize(
    "old_key", ["observed_reach_value_usd", "observed_reach_floor_usd", "observed_reach_priced_usd"]
)
def test_legacy_wallet_scalars_cannot_be_redistilled_into_a_call_magnitude(old_key):
    from services.scoring.distill.flow_reach import _flow_reach

    observed = {old_key: 1000000, "reach_determined": True, "observed_reach_holders": ["0x" + "1" * 40]}
    reach = _flow_reach(observed, SimpleNamespace(chain="ethereum"), KEY)
    assert reach.state == "proven_reach"
    assert reach.bound == "floor"
    assert reach.magnitude.state == "not_determined"


def test_pricing_failure_keeps_witnessed_holder_reach():
    from services.scoring.distill.flow_reach import _flow_reach

    reach = _flow_reach(
        {
            "reach_determined": False,
            "observed_reach_holders": ["0x" + "1" * 40],
            "observed_reach_unvalued_pairs": [{"holder": "0x" + "1" * 40, "asset": "token"}],
        },
        SimpleNamespace(chain="ethereum"),
        KEY,
    )
    assert reach.state == "proven_reach"
    assert reach.entity_keys == (KEY,)
    assert reach.magnitude.state == "not_determined"


def test_legacy_zero_wallet_scalar_cannot_prove_no_reach():
    from services.scoring.distill.flow_reach import _flow_reach

    reach = _flow_reach(
        {"reach_determined": True, "observed_reach_value_usd": 0}, SimpleNamespace(chain="ethereum"), KEY
    )
    assert reach.state == "not_determined"


def test_persisted_legacy_signal_magnitude_is_withheld_before_reconciliation():
    from services.scoring.schema import signal_from_row, signal_to_row_kwargs
    from tests.support.scoring_builders import magnitude, proven, reaches, sig

    original = sig(
        value_basis="observed_reach_value_usd(fork-proven)",
        gates=magnitude(1000000),
        **proven(1.0),
        **{k: v for k, v in reaches(KEY).items() if k != "value_basis"},
    )
    stored = SimpleNamespace(**signal_to_row_kwargs(original))
    current = signal_from_row(stored)
    assert current.gate_inputs["reach_magnitude_usd"]["state"] == "not_determined"
    assert current.value_state == "proven_reach"
    assert "legacy_holdings_magnitude_withheld" in current.witness_notes
