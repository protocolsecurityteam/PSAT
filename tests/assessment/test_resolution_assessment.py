"""Resolution facts become entities, evidence, and directed authority claims."""

from __future__ import annotations

from pydantic import TypeAdapter

from db.models import CONTROL_EDGE_RELATIONS
from schemas.assessment import Assessment
from services.assessment import add_resolution, build_static_assessment
from services.assessment.resolution import AUTHORITY_RELATIONS


def _base() -> Assessment:
    return build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        analysis={"controller_tracking": []},
        effects={
            "schema_version": "semantic-2",
            "claims_schema_version": "claims/1",
            "functions": {},
            "claim_analyses": {},
            "claim_diagnostics": [],
        },
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )


def test_authority_vocabulary_matches_the_graph_writer() -> None:
    assert AUTHORITY_RELATIONS == CONTROL_EDGE_RELATIONS


def test_resolution_separates_authority_from_dependency_edges() -> None:
    graph = {
        "schema_version": "2",
        "nodes": [
            {
                "id": "vault",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "analysis_state": "analyzed",
                "details": {},
            },
            {
                "id": "safe",
                "address": "0x2222222222222222222222222222222222222222",
                "node_type": "principal",
                "resolved_type": "safe",
                "analysis_state": "not_analyzable",
                "details": {"threshold": 2},
            },
            {
                "id": "oracle",
                "address": "0x3333333333333333333333333333333333333333",
                "node_type": "contract",
                "resolved_type": "contract",
                "analysis_state": "analyzed",
                "details": {},
            },
        ],
        "edges": [
            {
                "from_id": "vault",
                "to_id": "safe",
                "relation": "controller_value",
                "source_controller_id": "owner",
                "notes": [],
            },
            {
                "from_id": "vault",
                "to_id": "oracle",
                "relation": "external_call_target",
                "source_controller_id": None,
                "notes": [],
            },
        ],
    }

    assessment = add_resolution(_base(), graph, chain_id=1)
    TypeAdapter(Assessment).validate_python(assessment)

    assert len(assessment["authority_edges"]) == 1
    assert len(assessment["dependency_edges"]) == 1
    authority = assessment["authority_edges"][0]
    accounts = assessment["accounts"]
    entities = assessment["entities"]
    assert accounts[entities[authority["authority_id"]]["account_id"]]["address"] == (
        "0x2222222222222222222222222222222222222222"
    )
    assert accounts[entities[authority["target_id"]]["account_id"]]["address"] == (
        "0x1111111111111111111111111111111111111111"
    )
    assert assessment["analyses"][-1]["status"] == "completed"


def test_proxy_deployment_scope_does_not_mutate_static_claim_identity() -> None:
    # Add one static claim so the scope/id invariant is observable.
    base_with_claim = build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        analysis={"controller_tracking": []},
        effects={
            "schema_version": "semantic-2",
            "claims_schema_version": "claims/1",
            "functions": {
                "pause()": {
                    "selector": "0x8456cb59",
                    "state_changing": True,
                    "state_writes": [],
                    "effect_targets": [],
                    "claims": [
                        {
                            "claim_id": "pause.set",
                            "tier": "idiom_structural",
                            "witness": {"flags": [{"var": "paused", "member": None}]},
                        }
                    ],
                }
            },
            "claim_analyses": {},
            "claim_diagnostics": [],
        },
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    static_claim = next(iter(base_with_claim["claims"].values()))
    static_account_id = static_claim["scope"]["account_id"]

    resolved = add_resolution(
        base_with_claim,
        {
            "schema_version": "2",
            "root_contract_address": "0x9999999999999999999999999999999999999999",
            "nodes": [],
            "edges": [],
        },
        chain_id=1,
    )
    assert resolved["scope"]["account_id"] != static_account_id
    assert resolved["claims"][static_claim["id"]]["scope"]["account_id"] == static_account_id
