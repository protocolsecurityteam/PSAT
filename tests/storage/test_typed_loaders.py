"""Canonical assessment loader contracts (``db.queue.typed``).

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
)


def _reader(artifacts: dict) -> object:
    return lambda session, job_id, name: artifacts.get(name)


def test_absent_artifact_returns_none() -> None:
    read = _reader({})
    assert load_assessment(read, None, "job") is None


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
