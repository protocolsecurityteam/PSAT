"""Typed artifact loader contracts (``db.queue.typed``).

The loaders are the stage-to-stage wire's validation gate; these tests pin
their three contracts: a schema-complete document round-trips, a shape
violation raises ``ArtifactSchemaError`` naming the artifact and the
offending fields, and a non-dict body is rejected outright. A missing row
stays ``None`` (absent), never an error.
"""

from __future__ import annotations

import pytest

from db.queue.typed import (
    ArtifactSchemaError,
    load_assessment,
    load_contract_analysis,
    load_control_snapshot,
    load_control_tracking_plan,
    load_effective_permissions,
    load_principal_labels,
    load_resolved_control_graph,
)
from tests.support.policy_builders import (
    _graph_with_nodes,
    _minimal_contract_analysis,
    _minimal_snapshot,
    _tracking_plan,
)


def _reader(artifacts: dict) -> object:
    return lambda session, job_id, name: artifacts.get(name)


def test_absent_artifact_returns_none() -> None:
    read = _reader({})
    assert load_contract_analysis(read, None, "job") is None
    assert load_assessment(read, None, "job") is None
    assert load_control_snapshot(read, None, "job") is None
    assert load_resolved_control_graph(read, None, "job") is None


def test_schema_complete_documents_pass() -> None:
    read = _reader(
        {
            "contract_analysis": _minimal_contract_analysis(),
            "control_snapshot": _minimal_snapshot(),
            "control_tracking_plan": _tracking_plan(),
            "resolved_control_graph": _graph_with_nodes([]),
        }
    )
    assert load_contract_analysis(read, None, "job") is not None
    assert load_control_snapshot(read, None, "job") is not None
    assert load_control_tracking_plan(read, None, "job") is not None
    assert load_resolved_control_graph(read, None, "job") is not None


def test_partial_document_fails_closed_naming_artifact_and_fields() -> None:
    read = _reader({"contract_analysis": {"contract_address": "0x1"}})
    with pytest.raises(ArtifactSchemaError) as excinfo:
        load_contract_analysis(read, None, "job")
    assert excinfo.value.artifact_name == "contract_analysis"
    assert any("schema_version" in p for p in excinfo.value.problems)


def test_non_dict_body_is_rejected() -> None:
    read = _reader({"control_tracking_plan": "not a dict"})
    with pytest.raises(ArtifactSchemaError, match="expected a JSON object"):
        load_control_tracking_plan(read, None, "job")


def test_unknown_keys_survive_validation() -> None:
    """Validation is a gate, not a filter: keys the schema doesn't know
    about (a future producer's additions) must round-trip untouched."""
    doc = _minimal_contract_analysis()
    doc["future_field"] = {"nested": 1}
    out = load_contract_analysis(_reader({"contract_analysis": doc}), None, "job")
    assert out is doc


def test_effective_permissions_and_principal_labels_validate() -> None:
    ep = {
        "schema_version": "1",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "TestContract",
        "authority_contract": None,
        "principal_resolution": {"status": "no_authority", "reason": "none"},
        "artifacts": {},
        "functions": [],
    }
    pl = {
        "schema_version": "1",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "TestContract",
        "principals": [
            {
                "address": "0x2222222222222222222222222222222222222222",
                "resolved_type": "safe",
                "details": {},
                "display_name": "Admin Safe",
                "labels": [],
                "confidence": "high",
                "graph_context": [],
                "controller_context": [],
                "permissions": [],
            }
        ],
    }
    read = _reader({"effective_permissions": ep, "principal_labels": pl})
    assert load_effective_permissions(read, None, "job") is not None
    assert load_principal_labels(read, None, "job") is not None

    # An out-of-vocabulary resolved_type must fail, not coerce silently.
    bad = dict(pl)
    bad["principals"] = [{**pl["principals"][0], "resolved_type": "not_a_type"}]
    with pytest.raises(ArtifactSchemaError):
        load_principal_labels(_reader({"principal_labels": bad}), None, "job")


def test_assessment_validates_as_the_canonical_wire() -> None:
    account_id = "account:1"
    contract_id = "contract:1"
    scope = {
        "contract_id": contract_id,
        "account_id": account_id,
        "code_hash": None,
        "source_hash": "0xsource",
    }
    assessment = {
        "schema_version": "assessment/1",
        "scope": scope,
        "accounts": {
            account_id: {
                "id": account_id,
                "chain_id": 1,
                "address": "0x1111111111111111111111111111111111111111",
            }
        },
        "contract": {
            "id": contract_id,
            "account_id": account_id,
            "name": "Vault",
            "code_hash": None,
            "source_hash": "0xsource",
        },
        "functions": {},
        "controllers": {},
        "entities": {},
        "authority_edges": [],
        "dependency_edges": [],
        "claims": {},
        "evidence": {},
        "analyses": [],
    }
    assert load_assessment(_reader({"assessment": assessment}), None, "job") is assessment

    malformed = {**assessment, "evidence": []}
    with pytest.raises(ArtifactSchemaError, match="evidence"):
        load_assessment(_reader({"assessment": malformed}), None, "job")

    dangling = {
        **assessment,
        "analyses": [
            {
                "detector": "static.facts",
                "version": "1",
                "status": "completed",
                "coverage": {"targets_total": 0, "targets_completed": 0, "omissions": []},
                "diagnostics": [],
                "claim_ids": [],
                "evidence_ids": ["evidence:missing"],
            }
        ],
    }
    with pytest.raises(ArtifactSchemaError, match="evidence:missing is missing"):
        load_assessment(_reader({"assessment": dangling}), None, "job")
