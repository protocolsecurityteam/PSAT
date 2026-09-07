"""Principal indexes can be reproduced without making observations again."""

import copy

from services.assessment.principals import (
    GRAPH_PRODUCER,
    PRODUCER,
    add_principal_graph_nodes,
    add_principal_observations,
)
from services.assessment.runtime import control_graph
from services.policy.principal_index import build_principal_index, observe_principals
from tests.support.policy_builders import TARGET_ADDRESS, principal_assessment

PRINCIPAL = "0x" + "ab" * 20


def base():
    return principal_assessment(
        {
            "contract_address": TARGET_ADDRESS,
            "contract_name": "Vault",
            "functions": [
                {
                    "function": "manage()",
                    "capability_expr": {
                        "kind": "finite_set",
                        "members": [PRINCIPAL],
                        "membership_quality": "exact",
                    },
                    "authority_roles": [
                        {"role": 1, "principals": [{"address": PRINCIPAL, "resolved_type": "unknown", "details": {}}]}
                    ],
                }
            ],
        }
    )


def test_observe_then_project_without_rpc(monkeypatch):
    import services.policy.principal_index as principals

    monkeypatch.setattr(
        principals,
        "classify_resolved_address_with_status",
        lambda *_a, **_kw: ("safe", {"threshold": 2, "owners": [PRINCIPAL]}, True),
    )
    assessment = observe_principals(base(), rpc_url="http://rpc.invalid")
    assert any(evidence["producer"] == PRODUCER for evidence in assessment["evidence"].values())
    assert any(claim["rule"] == "policy.principal_classification/v1" for claim in assessment["claims"].values())

    def forbidden(*_a, **_kw):
        raise AssertionError("Projection made a new observation")

    monkeypatch.setattr(principals, "classify_resolved_address_with_status", forbidden)
    before = copy.deepcopy(assessment)
    rows = build_principal_index(assessment)
    assert rows[0]["resolved_type"] == "safe"
    assert rows[0]["details"]["threshold"] == 2
    assert assessment == before


def test_failed_refresh_retracts_classification_and_records_diagnostics(monkeypatch):
    import services.policy.principal_index as principals

    assessment = add_principal_observations(
        base(), [{"address": PRINCIPAL, "resolved_type": "safe", "complete": True, "details": {"threshold": 2}}]
    )
    old = {key for key, value in assessment["claims"].items() if value["rule"] == "policy.principal_classification/v1"}

    def fail(*_a, **_kw):
        raise RuntimeError("RPC unavailable")

    monkeypatch.setattr(principals, "classify_resolved_address_with_status", fail)
    refreshed = observe_principals(assessment, rpc_url="http://rpc.invalid")
    assert not old.intersection(refreshed["claims"])
    receipt = next(item for item in refreshed["analyses"] if item["detector"] == PRODUCER)
    assert receipt["status"] == "failed"
    assert receipt["diagnostics"][0]["message"] == "RPC unavailable"
    assert build_principal_index(refreshed)[0]["resolved_type"] == "unknown"
    assert refreshed["entities"][f"1:{PRINCIPAL}"]["tags"] == []


def test_unfinished_controller_walk_keeps_classification_but_marks_partial():
    assessment = add_principal_observations(
        base(),
        [
            {
                "address": PRINCIPAL,
                "resolved_type": "contract",
                "complete": True,
                "details": {"terminal_principal": {"status": "unknown_unfetched", "terminal": False}},
            }
        ],
    )
    receipt = next(item for item in assessment["analyses"] if item["detector"] == PRODUCER)
    assert receipt["status"] == "partial"
    assert receipt["claims"]
    assert receipt["targets_completed"] == 0
    assert receipt["omissions"][0]["reason"] == "terminal_principal:unknown_unfetched"


def test_function_principal_graph_is_rebuilt_from_assessment_only():
    assessment = add_principal_graph_nodes(
        base(),
        [
            {
                "id": f"address:{PRINCIPAL}",
                "address": PRINCIPAL,
                "node_type": "principal",
                "resolved_type": "eoa",
                "label": None,
                "contract_name": None,
                "depth": 1,
                "analysis_state": None,
                "details": {
                    "control_graph_basis": "fp_materialization",
                    "fp_function_count": 1,
                    "fp_origins": ["semantic"],
                    "fp_principal_types": ["finite_set"],
                },
                "artifacts": {},
            }
        ],
    )

    graph = control_graph(assessment)
    assert graph["nodes"][0]["address"] == PRINCIPAL
    assert graph["edges"] == [
        {
            "from_id": f"address:{TARGET_ADDRESS}",
            "to_id": f"address:{PRINCIPAL}",
            "relation": "capability_principal",
            "label": "capability_principal",
            "source_controller_id": None,
            "notes": ["functions=1"],
        }
    ]
    receipt = next(row for row in assessment["analyses"] if row["detector"] == GRAPH_PRODUCER)
    assert receipt["status"] == "completed"
    assert receipt["claims"]
