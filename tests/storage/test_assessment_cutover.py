"""The offline cutover must preserve exact payloads and remain retryable."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from db import contract_materializations as cm
from db.assessment import load_assessment, store_assessment_section
from db.models import Artifact, ContractMaterialization
from db.queue import create_job, store_artifact
from scripts.consolidate_assessments import consolidate_job
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _legacy(session, job_id, name, data):
    # Deliberately seed the old storage layout without using the guarded writer.
    row = Artifact(job_id=job_id, name=name, data=data)
    session.add(row)
    session.commit()
    return row


def test_cutover_copies_exact_sections_and_nested_results(db_session):
    job = create_job(db_session, {"address": "0x" + "a" * 40})
    payloads = {
        "contract_analysis": {"subject": {"name": "Original"}, "analysis_status": {"errors": []}},
        "predicate_trees": {"error": "original degraded result"},
        "effects": {},
        "principal_labels": {"principals": [{"address": "0x123", "labels": ["owner"]}]},
    }
    for name, data in payloads.items():
        _legacy(db_session, job.id, name, data)
    snapshot = {"controllers": [{"id": "owner", "value": "0x123"}]}
    _legacy(db_session, job.id, "recursive.0x123.snapshot", snapshot)
    assert consolidate_job(db_session, job.id, dry_run=True) == 5
    assert load_assessment(db_session, job.id) is None
    assert consolidate_job(db_session, job.id) == 5
    expected = {
        "schema_version": "assessment/1",
        **payloads,
        "recursive": {"0x123": {"schema_version": "assessment/1", "control_snapshot": snapshot}},
    }
    assert load_assessment(db_session, job.id) == expected
    assert list(db_session.execute(select(Artifact.name).where(Artifact.job_id == job.id)).scalars()) == ["assessment"]
    assert consolidate_job(db_session, job.id) == 0


def test_cutover_keeps_legacy_rows_when_existing_section_conflicts(db_session):
    job = create_job(db_session, {"address": "0x" + "b" * 40})
    _legacy(db_session, job.id, "effects", {"functions": {"old()": {}}})
    store_assessment_section(db_session, job.id, "effects", {"functions": {"new()": {}}})
    with pytest.raises(ValueError, match="conflicts"):
        consolidate_job(db_session, job.id)
    db_session.rollback()
    assert db_session.execute(
        select(Artifact.id).where(Artifact.job_id == job.id, Artifact.name == "effects")
    ).scalar_one()
    assert (load_assessment(db_session, job.id) or {}).get("effects") == {"functions": {"new()": {}}}


@pytest.mark.parametrize("name", ["contract_analysis", "effects", "principal_labels", "recursive.0x123.snapshot"])
def test_writer_rejects_parallel_analytical_documents(db_session, name):
    job = create_job(db_session, {"address": "0x" + "c" * 40})
    with pytest.raises(ValueError, match="Assessment section"):
        store_artifact(db_session, job.id, name, data={})


def test_cutover_unreadable_body_retains_every_legacy_row(db_session, monkeypatch):
    job = create_job(db_session, {"address": "0x" + "d" * 40})
    first = _legacy(db_session, job.id, "effects", {"functions": {}})
    second = _legacy(db_session, job.id, "principal_labels", {"principals": []})

    def unreadable(_row):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr("scripts.consolidate_assessments._artifact_row_to_value", unreadable)
    with pytest.raises(RuntimeError, match="storage unavailable"):
        consolidate_job(db_session, job.id)
    db_session.rollback()
    assert set(db_session.execute(select(Artifact.id).where(Artifact.job_id == job.id)).scalars()) == {
        first.id,
        second.id,
    }
    assert load_assessment(db_session, job.id) is None


def test_cutover_retry_after_assessment_copy_deletes_verified_legacy_rows(db_session):
    job = create_job(db_session, {"address": "0x" + "e" * 40})
    effects = {"schema_version": "semantic-2", "functions": {"f()": {"claims": []}}}
    _legacy(db_session, job.id, "effects", effects)
    store_assessment_section(db_session, job.id, "effects", effects)

    # This is the durable state after a prior attempt copied the Assessment but
    # stopped before deleting the legacy row. A retry verifies equality and
    # completes cleanup without changing the copied payload.
    assert consolidate_job(db_session, job.id) == 1
    assert load_assessment(db_session, job.id) == {
        "schema_version": "assessment/1",
        "effects": effects,
    }
    assert list(db_session.execute(select(Artifact.name).where(Artifact.job_id == job.id)).scalars()) == ["assessment"]


def test_cutover_reads_storage_backed_legacy_body_exactly(db_session, storage_bucket):
    from db.storage import artifact_key, serialize_artifact

    job = create_job(db_session, {"address": "0x" + "f" * 40})
    payload = {"schema_version": "semantic-2", "error": "degraded", "opaque": [None, {"x": 1}]}
    key = artifact_key(job.id, "effects")
    body, content_type = serialize_artifact(payload, None)
    storage_bucket.put(key, body, content_type)
    db_session.add(
        Artifact(
            job_id=job.id,
            name="effects",
            storage_key=key,
            stored_object_size_bytes=len(body),
            content_type=content_type,
        )
    )
    db_session.commit()

    assert consolidate_job(db_session, job.id) == 1
    assert (load_assessment(db_session, job.id) or {}).get("effects") == payload
    # Cutover intentionally retains the old object as rollback backup even
    # after its legacy database row has been removed.
    assert storage_bucket.get(key) == body


def test_cutover_hydrates_recursive_static_sections_and_advances_verified_job_era(db_session):
    child_address = "0x" + "1" * 40
    job = create_job(db_session, {"address": "0x" + "2" * 40, "chain": "ethereum"})
    job.analysis_schema_version = 6
    static_sections = {
        "contract_analysis": {"subject": {"address": job.address}},
        "control_tracking_plan": {"contract_address": job.address},
        "predicate_trees": {"trees": {}},
        "effects": {"functions": {}},
    }
    for name, payload in static_sections.items():
        _legacy(db_session, job.id, name, payload)
    snapshot = {"controller_values": {}}
    _legacy(db_session, job.id, f"recursive.{child_address}.snapshot", snapshot)
    cached_sections = {
        "schema_version": "assessment/1",
        "contract_analysis": {"subject": {"address": child_address}},
        "control_tracking_plan": {"contract_address": child_address},
        "predicate_trees": {"trees": {"owner()": {"op": "LEAF"}}},
    }
    db_session.add(
        ContractMaterialization(
            chain=cm.chain_cache_token("ethereum"),
            bytecode_keccak="0x" + "3" * 64,
            address=child_address,
            contract_name="Child",
            assessment=cached_sections,
            analysis_schema_version=7,
            status="ready",
        )
    )
    db_session.commit()

    assert consolidate_job(db_session, job.id) == 5
    assessment = load_assessment(db_session, job.id)
    assert assessment is not None
    recursive = assessment.get("recursive")
    assert recursive is not None
    child = recursive[child_address]
    assert child.get("control_snapshot") == snapshot
    for name in ("contract_analysis", "control_tracking_plan", "predicate_trees"):
        assert child.get(name) == cached_sections[name]
    assert "effects" not in child  # version-6 materializations never stored it
    db_session.refresh(job)
    assert job.analysis_schema_version == 7


def test_cutover_rejects_unconverted_ready_v6_recursive_materialization(db_session):
    child_address = "0x" + "4" * 40
    job = create_job(db_session, {"address": "0x" + "5" * 40, "chain": "ethereum"})
    legacy = _legacy(db_session, job.id, f"recursive.{child_address}.snapshot", {"controller_values": {}})
    db_session.add(
        ContractMaterialization(
            chain=cm.chain_cache_token("ethereum"),
            bytecode_keccak="0x" + "6" * 64,
            address=child_address,
            contract_name="Unconverted",
            analysis={"subject": {"address": child_address}},
            tracking_plan={"contract_address": child_address},
            analysis_schema_version=6,
            status="ready",
        )
    )
    db_session.commit()

    with pytest.raises(RuntimeError, match="consolidate_materializations"):
        consolidate_job(db_session, job.id)
    db_session.rollback()
    assert db_session.get(Artifact, legacy.id) is not None
    assert load_assessment(db_session, job.id) is None
