from __future__ import annotations

import json
from typing import Any, cast

import pytest

from db import contract_materializations as cm
from db.assessment import load_assessment, store_assessment
from db.models import ContractMaterialization
from db.queue import create_job
from db.storage import JSON_CONTENT_TYPE, StorageError
from schemas.assessment import Assessment
from scripts.consolidate_materializations import consolidate_materialization, consolidate_materializations
from tests.conftest import requires_postgres

ADDR = "0x" + "a1" * 20
KECCAK = "0x" + "11" * 32
ANALYSIS = {"subject": {"address": ADDR, "name": "Vault"}, "functions": []}
PLAN = {"contract_address": ADDR, "tracked_controllers": []}
TREES = {"schema_version": "semantic", "trees": {}}


@pytest.fixture(autouse=True)
def _clean_materializations(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield
    db_session.rollback()
    db_session.query(ContractMaterialization).delete()
    db_session.commit()


class _Storage:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail_get: set[str] = set()

    def put(self, key: str, body: bytes, content_type: str, metadata=None) -> None:
        assert content_type == JSON_CONTENT_TYPE
        self.objects[key] = body

    def get(self, key: str) -> bytes:
        if key in self.fail_get:
            raise StorageError("unreadable")
        return self.objects[key]


def _row(*, version: int = 6, **overrides: Any) -> ContractMaterialization:
    values: dict[str, Any] = {
        "chain": "1",
        "bytecode_keccak": KECCAK,
        "address": ADDR,
        "status": "ready",
        "analysis_schema_version": version,
        "analysis": ANALYSIS,
        "tracking_plan": PLAN,
        "predicate_trees": TREES,
    }
    values.update(overrides)
    return ContractMaterialization(**values)


@requires_postgres
def test_inline_v6_converts_losslessly_and_is_restartable(db_session, monkeypatch):
    monkeypatch.setattr("scripts.consolidate_materializations.get_storage_client", lambda: None)
    row = _row()
    db_session.add(row)
    db_session.commit()

    assert consolidate_materialization(db_session, row) == "converted"
    db_session.refresh(row)
    assert row.analysis_schema_version == cm.ANALYSIS_SCHEMA_VERSION
    assert cm.hydrate_analysis(row) == ANALYSIS
    assert cm.hydrate_tracking_plan(row) == PLAN
    assert cm.hydrate_predicate_trees(row) == TREES
    # Backups are retained for rollback/forensics.
    assert row.analysis == ANALYSIS and row.tracking_plan == PLAN and row.predicate_trees == TREES
    assert consolidate_materialization(db_session, row) == "skipped"


@requires_postgres
def test_blob_v6_reads_legacy_blobs_and_verifies_new_blob(db_session, monkeypatch):
    storage = _Storage()
    keys = {
        "analysis": "legacy/analysis.json",
        "tracking_plan": "legacy/tracking.json",
        "predicate_trees": "legacy/trees.json",
    }
    for name, payload in (("analysis", ANALYSIS), ("tracking_plan", PLAN), ("predicate_trees", TREES)):
        storage.objects[keys[name]] = json.dumps(payload).encode()
    row = _row(
        analysis=None,
        tracking_plan=None,
        predicate_trees=None,
        analysis_blob_key=keys["analysis"],
        tracking_plan_blob_key=keys["tracking_plan"],
        predicate_trees_blob_key=keys["predicate_trees"],
    )
    db_session.add(row)
    db_session.commit()
    monkeypatch.setattr("db.contract_materializations.get_storage_client", lambda: storage)
    monkeypatch.setattr("scripts.consolidate_materializations.get_storage_client", lambda: storage)

    assert consolidate_materialization(db_session, row) == "converted"
    db_session.refresh(row)
    assert row.assessment is None and row.assessment_blob_key in storage.objects
    assert row.analysis_blob_key == keys["analysis"]
    assert cm.hydrate_tracking_plan(row) == PLAN


@requires_postgres
def test_unreadable_legacy_body_aborts_without_stamp(db_session, monkeypatch):
    storage = _Storage()
    key = "legacy/analysis.json"
    storage.fail_get.add(key)
    row = _row(analysis=None, analysis_blob_key=key)
    db_session.add(row)
    db_session.commit()
    monkeypatch.setattr("db.contract_materializations.get_storage_client", lambda: storage)

    with pytest.raises(StorageError):
        consolidate_materialization(db_session, row)
    db_session.rollback()
    db_session.refresh(row)
    assert row.analysis_schema_version == 6
    assert row.assessment is None


@requires_postgres
def test_conflicting_existing_assessment_aborts_without_stamp(db_session, monkeypatch):
    monkeypatch.setattr("scripts.consolidate_materializations.get_storage_client", lambda: None)
    row = _row(
        assessment={
            "schema_version": "assessment/1",
            "contract_analysis": {"subject": {"address": ADDR, "name": "Different"}},
            "control_tracking_plan": PLAN,
        }
    )
    db_session.add(row)
    db_session.commit()

    with pytest.raises(ValueError, match="conflicts"):
        consolidate_materialization(db_session, row)
    db_session.rollback()
    db_session.refresh(row)
    assert row.analysis_schema_version == 6


@requires_postgres
def test_matching_existing_assessment_resumes_and_stamps(db_session, monkeypatch):
    monkeypatch.setattr("scripts.consolidate_materializations.get_storage_client", lambda: None)
    expected = {
        "schema_version": "assessment/1",
        "contract_analysis": ANALYSIS,
        "control_tracking_plan": PLAN,
        "predicate_trees": TREES,
    }
    row = _row(assessment=expected)
    db_session.add(row)
    db_session.commit()

    assert consolidate_materialization(db_session, row) == "already_converted"
    db_session.refresh(row)
    assert row.analysis_schema_version == 7
    assert row.assessment == expected


@requires_postgres
def test_converter_refuses_a_future_runtime_era(db_session, monkeypatch):
    row = _row()
    db_session.add(row)
    db_session.commit()
    monkeypatch.setattr(cm, "ANALYSIS_SCHEMA_VERSION", 8)

    with pytest.raises(RuntimeError, match="supports only analyzer era 6->7"):
        consolidate_materialization(db_session, row)
    db_session.rollback()
    db_session.refresh(row)
    assert row.analysis_schema_version == 6 and row.assessment is None


@requires_postgres
def test_bulk_dry_run_skips_older_rows_and_changes_nothing(db_session, monkeypatch):
    monkeypatch.setattr("scripts.consolidate_materializations.get_storage_client", lambda: None)
    current = _row()
    older = _row(
        version=5,
        bytecode_keccak="0x" + "22" * 32,
        address="0x" + "b2" * 20,
    )
    db_session.add_all([current, older])
    db_session.commit()

    assert consolidate_materializations(db_session, dry_run=True) == {
        "converted": 0,
        "already_converted": 0,
        "dry_run": 1,
        "skipped": 0,
    }
    db_session.expire_all()
    assert current.analysis_schema_version == 6 and current.assessment is None
    assert older.analysis_schema_version == 5 and older.assessment is None


@requires_postgres
def test_recursive_job_runtime_survives_static_materialization_cutover(db_session, monkeypatch):
    """Job runtime state and the converted reusable static bundle remain intact."""
    monkeypatch.setattr("scripts.consolidate_materializations.get_storage_client", lambda: None)
    job = create_job(db_session, {"address": ADDR})
    child = {
        "schema_version": "assessment/1",
        "control_snapshot": {"contract_address": ADDR, "controller_values": {"owner": "0x1"}},
        "effective_permissions": {"contract_address": ADDR, "functions": []},
    }
    store_assessment(
        db_session,
        job.id,
        cast(Assessment, {"schema_version": "assessment/1", "recursive": {ADDR: child}}),
    )
    row = _row()
    db_session.add(row)
    db_session.commit()

    assert consolidate_materialization(db_session, row) == "converted"
    persisted = load_assessment(db_session, job.id)
    assert persisted is not None and persisted.get("recursive", {})[ADDR] == child
    assert cm.hydrate_analysis(row) == ANALYSIS
    assert cm.hydrate_tracking_plan(row) == PLAN
