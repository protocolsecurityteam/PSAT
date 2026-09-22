"""Canonical row-shaped Assessment read boundary."""

from __future__ import annotations

import pytest

from db.queue.typed import ArtifactSchemaError, load_assessment


def _reader(artifacts: dict) -> object:
    return lambda session, job_id, name: artifacts.get(name)


def _assessment() -> dict:
    return {
        "view": {},
        "subjects": [{"id": "subject:1", "recorded_at": "2026-01-01T00:00:00Z", "kind": "address", "identity": {}}],
        "evidence": [
            {
                "id": "evidence:1",
                "recorded_at": "2026-01-01T00:00:00Z",
                "subject": "subject:1",
                "kind": "artifact",
                "source": {},
                "payload": "payload:1",
                "obtained_at": "2026-01-01T00:00:00Z",
                "chain_id": None,
                "block_number": None,
                "block_hash": None,
                "transaction_hash": None,
                "transaction_index": None,
                "log_index": None,
            }
        ],
        "claims": [],
        "analyses": [],
        "corrections": [],
        "contexts": [],
        "implementations": [],
        "payloads": [
            {
                "id": "payload:1",
                "recorded_at": "2026-01-01T00:00:00Z",
                "media_type": "application/json",
                "byte_length": 2,
            }
        ],
    }


def test_absent_artifact_returns_none() -> None:
    assert load_assessment(_reader({}), None, "job") is None


def test_assessment_validates_as_canonical_rows() -> None:
    assessment = _assessment()
    assert load_assessment(_reader({"assessment": assessment}), None, "job") is assessment

    malformed = {**assessment, "evidence": {}}
    with pytest.raises(ArtifactSchemaError, match="evidence"):
        load_assessment(_reader({"assessment": malformed}), None, "job")

    dangling = _assessment()
    dangling["evidence"][0]["payload"] = "payload:missing"
    with pytest.raises(ArtifactSchemaError, match="payload is missing"):
        load_assessment(_reader({"assessment": dangling}), None, "job")

    duplicate = _assessment()
    duplicate["subjects"].append(duplicate["subjects"][0])
    with pytest.raises(ArtifactSchemaError, match="duplicate identity"):
        load_assessment(_reader({"assessment": duplicate}), None, "job")

    stale = {**assessment, "schema_version": "assessment/5"}
    with pytest.raises(ArtifactSchemaError, match="schema_version"):
        load_assessment(_reader({"assessment": stale}), None, "job")

    invalid_boolean = _assessment()
    invalid_boolean["payloads"][0]["byte_length"] = "2"
    with pytest.raises(ArtifactSchemaError, match="byte_length"):
        load_assessment(_reader({"assessment": invalid_boolean}), None, "job")
