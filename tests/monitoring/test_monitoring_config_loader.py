"""Persisted monitoring JSON is validated once at its read boundary."""

from __future__ import annotations

import pytest

from services.monitoring.config import MonitoringConfigError, load_monitoring_config


def test_load_monitoring_config_accepts_current_shape_without_dropping_extensions() -> None:
    raw = {
        "tracked_topics": [
            {
                "topic0": "0x" + "ab" * 32,
                "signature": "Changed(address)",
                "witness_tier": "self_describing",
                "writer_openness": "restricted",
            }
        ],
        "watch_roles": True,
        "operator_extension": {"enabled": True},
    }

    loaded = load_monitoring_config(raw)

    assert loaded is raw
    assert raw["operator_extension"] == {"enabled": True}


def test_load_monitoring_config_normalizes_absent_config() -> None:
    assert load_monitoring_config(None) == {}


@pytest.mark.parametrize(
    "raw",
    [
        [],
        {"tracked_topics": "not-a-list"},
        {"tracked_topics": ["not-an-object"]},
        {"tracked_topics": [{"signature": "MissingTopic(address)"}]},
        {"tracked_topics": [{"topic0": "0x1234"}]},
        {"tracked_topics": [{"topic0": "0x" + "zz" * 32}]},
        {"tracked_topics": [{"topic0": "0x" + "ab" * 32, "witness_tier": "guess"}]},
    ],
)
def test_load_monitoring_config_rejects_malformed_stored_json(raw: object) -> None:
    with pytest.raises(MonitoringConfigError, match="monitoring_config failed schema validation"):
        load_monitoring_config(raw)
