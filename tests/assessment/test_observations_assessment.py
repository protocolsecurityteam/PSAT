"""Controller read success and failure remain separate from claims."""

from __future__ import annotations

from services.assessment import add_observations, build_static_assessment
from services.assessment.runtime import controller_observations


def _base():
    return build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash=None,
        static_facts={
            "controller_tracking": [
                {
                    "controller_id": "state:owner",
                    "source": "state_variable",
                    "read_spec": {"strategy": "getter", "target": "owner()"},
                }
            ]
        },
        effects={"schema_version": "semantic", "functions": {}},
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )


def test_successful_controller_read_is_evidence() -> None:
    assessment = add_observations(
        _base(),
        {
            "schema_version": "1",
            "controller_values": {
                "state:owner": {
                    "value": "0x2222222222222222222222222222222222222222",
                    "resolved_type": "safe",
                    "block_number": 100,
                    "observed_via": "eth_call",
                    "details": {},
                }
            },
        },
    )
    receipt = assessment["analyses"][-1]
    assert receipt["status"] == "completed"
    assert len(receipt["evidence"]) == 1
    assert assessment["evidence"][receipt["evidence"][0]]["method"] == "rpc"


def test_failed_controller_read_is_only_a_diagnostic() -> None:
    base = _base()
    before = set(base["claims"])
    assessment = add_observations(
        base,
        {
            "schema_version": "1",
            "controller_values": {
                "state:owner": {
                    "value": None,
                    "resolved_type": "unknown",
                    "block_number": 100,
                    "observed_via": "eth_call_error",
                    "details": {"error": "timeout"},
                }
            },
        },
    )
    assert set(assessment["claims"]) == before
    receipt = assessment["analyses"][-1]
    assert receipt["status"] == "failed"
    assert receipt["diagnostics"][0]["code"] == "ControllerReadFailed"


def test_failed_refresh_retracts_the_previous_controller_observation() -> None:
    successful = add_observations(
        _base(),
        {
            "schema_version": "1",
            "controller_values": {
                "state:owner": {
                    "value": "0x2222222222222222222222222222222222222222",
                    "resolved_type": "safe",
                    "block_number": 100,
                    "observed_via": "eth_call",
                    "details": {},
                }
            },
        },
    )
    failed = add_observations(
        successful,
        {
            "schema_version": "1",
            "controller_values": {
                "state:owner": {
                    "value": None,
                    "resolved_type": "unknown",
                    "block_number": 101,
                    "observed_via": "eth_call_error",
                    "details": {"error": "timeout"},
                }
            },
        },
    )

    assert controller_observations(failed)["controller_values"] == {}
    assert not any(evidence["producer"] == "resolution.observation" for evidence in failed["evidence"].values())
