"""Resolution facts become entities, evidence, and directed authority claims."""

from __future__ import annotations

from pydantic import TypeAdapter

from db.models import CONTROL_EDGE_RELATIONS
from schemas.assessment import Assessment
from services.assessment import add_resolution, build_static_assessment, control_graph
from services.assessment.resolution import AUTHORITY_RELATIONS


def _base() -> Assessment:
    return build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts={"controller_tracking": []},
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

    authority_claims = [
        claim for claim in assessment["claims"].values() if claim["proposition"]["kind"] == "authority_relationship"
    ]
    assert len(authority_claims) == 1
    authority = authority_claims[0]["proposition"]
    authority_value = authority.get("authority")
    assert authority_value is not None
    assert authority_value.get("entity") == "1:0x2222222222222222222222222222222222222222"
    assert authority.get("target") == "1:0x1111111111111111111111111111111111111111"
    assert [edge["relation"] for edge in control_graph(assessment)["edges"]] == [
        "controller_value",
        "external_call_target",
    ]
    assert assessment["analyses"][-1]["status"] == "completed"


def test_proxy_deployment_scope_does_not_mutate_static_claim_identity() -> None:
    # Add one static claim so the scope/id invariant is observable.
    base_with_claim = build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts={"controller_tracking": []},
        effects={
            "schema_version": "semantic-2",
            "claims_schema_version": "claims/1",
            "functions": {
                "pause()": {
                    "selector": "0x8456cb59",
                    "state_changing": True,
                    "state_writes": [],
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
    static_claim_key = next(iter(base_with_claim["claims"]))

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
    assert resolved["contract"]["address"] == "0x1111111111111111111111111111111111111111"
    assert resolved["contract"]["deployment_address"] == "0x9999999999999999999999999999999999999999"
    assert static_claim_key in resolved["claims"]


def test_resolution_refresh_retracts_removed_edges_and_evidence() -> None:
    graph = {
        "schema_version": "2",
        "root_contract_address": "0x1111111111111111111111111111111111111111",
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
                "details": {},
            },
        ],
        "edges": [{"from_id": "vault", "to_id": "safe", "relation": "controller_value", "notes": []}],
    }
    with_edge = add_resolution(_base(), graph, chain_id=1)
    without_edge = add_resolution(
        with_edge,
        {**graph, "nodes": graph["nodes"][:1], "edges": []},
        chain_id=1,
    )

    assert control_graph(without_edge)["edges"] == []
    assert not any(
        claim["proposition"]["kind"] == "authority_relationship" for claim in without_edge["claims"].values()
    )
    assert "0x2222222222222222222222222222222222222222" not in {
        entity["address"] for entity in without_edge["entities"].values()
    }
