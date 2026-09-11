from __future__ import annotations

from typing import cast

from schemas.static_facts import StaticFacts
from services.assessment import (
    add_observations,
    add_resolution,
    contract_subject,
    control_graph,
    controller_observations,
    observation_plan,
)
from services.resolution.observation_plan import build_observation_plan
from tests.support.policy_builders import TARGET_ADDRESS, _assessment, _minimal_snapshot, _minimal_static_facts


def test_runtime_inputs_are_transient_assessment_projections() -> None:
    facts = _minimal_static_facts()
    facts["controller_tracking"] = [
        {
            "controller_id": "state_variable:owner",
            "label": "owner",
            "source": "owner",
            "kind": "state_variable",
            "read_spec": {"strategy": "getter_call", "target": "owner", "type": "address"},
            "confidence": "exact",
            "tracking_mode": "event_plus_state",
            "writer_functions": [
                {
                    "function": "transferOwnership(address)",
                    "contract": "TestContract",
                    "visibility": "external",
                    "writes": ["owner"],
                    "associated_events": [],
                    "evidence": [],
                }
            ],
            "associated_events": [],
            "polling_sources": ["owner"],
            "notes": [],
            "authority_provenance": "caller_gate",
        }
    ]
    assessment = _assessment(static_facts=facts)
    plan = observation_plan(assessment)

    assert plan["contract_address"] == TARGET_ADDRESS
    assert plan["tracked_controllers"][0]["controller_id"] == "state_variable:owner"
    assert plan["tracked_controllers"][0].get("authority_provenance") == "caller_gate"
    assert contract_subject(assessment)["subject"]["name"] == "TestContract"


def test_root_and_recursive_plans_exclude_non_address_string_fields() -> None:
    facts = _minimal_static_facts()
    facts["controller_tracking"] = [
        {
            "controller_id": "external_contract:_name",
            "label": "_name",
            "source": "_name",
            "kind": "external_contract",
            "confidence": "exact",
            "tracking_mode": "state_only",
            "read_spec": {"strategy": "getter_call", "target": "name", "type": "string", "type_kind": "primitive"},
            "writer_functions": [],
            "associated_events": [],
            "polling_sources": [],
            "notes": [],
        }
    ]
    root_plan = observation_plan(_assessment(static_facts=facts))
    assert root_plan == build_observation_plan(cast(StaticFacts, facts))
    assert root_plan["tracked_controllers"] == []


def test_observations_and_graph_project_from_evidence() -> None:
    facts = _minimal_static_facts()
    snapshot = _minimal_snapshot(
        {
            "state_variable:owner": {
                "value": "0x2222222222222222222222222222222222222222",
                "resolved_type": "eoa",
            }
        }
    )
    assessment = _assessment(static_facts=facts, snapshot=snapshot)
    projected_snapshot = controller_observations(assessment)
    assert projected_snapshot["controller_values"]["state_variable:owner"]["resolved_type"] == "eoa"

    graph = {
        "schema_version": "1",
        "root_contract_address": TARGET_ADDRESS,
        "max_depth": 1,
        "nodes": [
            {
                "id": f"address:{TARGET_ADDRESS}",
                "address": TARGET_ADDRESS,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "TestContract",
                "contract_name": "TestContract",
                "depth": 0,
                "analysis_state": "analyzed",
                "details": {},
                "artifacts": {},
            }
        ],
        "edges": [],
    }
    assessment = add_resolution(assessment, graph, chain_id=1)
    projected_graph = control_graph(assessment)
    assert projected_graph["nodes"][0]["label"] == "TestContract"
    assert projected_graph["nodes"][0]["analysis_state"] == "analyzed"


def test_failed_observation_is_analysis_not_projected_state() -> None:
    facts = _minimal_static_facts()
    facts["controller_tracking"] = [
        {
            "controller_id": "state_variable:owner",
            "label": "owner",
            "source": "owner",
            "kind": "state_variable",
            "read_spec": {"strategy": "getter_call", "target": "owner"},
            "confidence": "exact",
            "tracking_mode": "state_only",
            "writer_functions": [],
            "associated_events": [],
            "polling_sources": [],
            "notes": [],
        }
    ]
    assessment = _assessment(static_facts=facts)
    failed = add_observations(
        assessment,
        {
            "schema_version": "1",
            "block_number": 10,
            "controller_values": {
                "state_variable:owner": {
                    "value": None,
                    "resolved_type": "unknown",
                    "observed_via": "eth_call_error",
                    "details": {},
                }
            },
        },
    )

    assert controller_observations(failed)["controller_values"] == {}
    receipt = next(item for item in failed["analyses"] if item["detector"] == "observe.controllers")
    assert receipt["status"] == "failed"
    assert receipt["diagnostics"][0]["code"] == "ControllerReadFailed"
