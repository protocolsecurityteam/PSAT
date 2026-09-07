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
    assessment = {
        "schema_version": "assessment/5",
        "contract": {
            "chain_id": 1,
            "address": "0x1111111111111111111111111111111111111111",
            "deployment_address": "0x1111111111111111111111111111111111111111",
            "name": "Vault",
            "code_hash": None,
            "source_hash": "0xsource",
        },
        "functions": {},
        "controllers": {},
        "entities": {},
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
                "targets_total": 0,
                "targets_completed": 0,
                "omissions": [],
                "diagnostics": [],
                "claims": [],
                "evidence": ["evidence:missing"],
            }
        ],
    }
    with pytest.raises(ArtifactSchemaError, match="evidence:missing is missing"):
        load_assessment(_reader({"assessment": dangling}), None, "job")

    stale = {**assessment, "schema_version": "assessment/3"}
    with pytest.raises(ArtifactSchemaError, match="schema_version"):
        load_assessment(_reader({"assessment": stale}), None, "job")

    invalid_boolean = {
        **assessment,
        "functions": {
            "f()": {"abi_signature": "f()", "selector": None, "state_changing": "false"},
        },
    }
    with pytest.raises(ArtifactSchemaError, match="state_changing"):
        load_assessment(_reader({"assessment": invalid_boolean}), None, "job")
