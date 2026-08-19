"""Tests for db.queue operations — requires a running PostgreSQL instance.

These tests are integration tests. Run with:
    docker compose up postgres -d
    TEST_DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test uv run pytest tests/test_queue.py -v

Tests are skipped if no PostgreSQL connection is available.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@pytest.fixture()
def db_session():
    """Create tables, yield a session, then clean up test data (keep schema intact)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Artifact, Base, Job, SourceFile

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        # Clean up test rows, but leave tables intact
        session.rollback()
        session.query(SourceFile).delete()
        session.query(Artifact).delete()
        session.query(Job).delete()
        session.commit()
        session.close()
        engine.dispose()


@requires_postgres
def test_create_and_get_job(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import create_job

    job = create_job(db_session, {"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "name": "test"})
    assert job.id is not None
    assert job.status == JobStatus.queued
    assert job.stage == JobStage.discovery
    assert job.address == "0xdAC17F958D2ee523a2206206994597C13D831ec7"


@requires_postgres
def test_claim_and_advance_job(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import advance_job, claim_job, create_job

    create_job(db_session, {"address": "0x0000000000000000000000000000000000000001"})

    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None
    assert claimed.status == JobStatus.processing
    assert claimed.worker_id == "test-worker"

    # No more jobs to claim
    assert claim_job(db_session, JobStage.discovery, "test-worker-2") is None

    # Advance to next stage
    advance_job(db_session, claimed.id, JobStage.static)
    db_session.refresh(claimed)
    assert claimed.stage == JobStage.static
    assert claimed.status == JobStatus.queued


@requires_postgres
def test_fail_job(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import claim_job, create_job, fail_job

    create_job(db_session, {"address": "0x0000000000000000000000000000000000000002"})
    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None

    fail_job(db_session, claimed.id, "something went wrong")
    db_session.refresh(claimed)
    assert claimed.status == JobStatus.failed
    assert claimed.error == "something went wrong"


@requires_postgres
def test_complete_job(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import claim_job, complete_job, create_job

    create_job(db_session, {"address": "0x0000000000000000000000000000000000000003"})
    claimed = claim_job(db_session, JobStage.discovery, "test-worker")
    assert claimed is not None

    complete_job(db_session, claimed.id)
    db_session.refresh(claimed)
    assert claimed.status == JobStatus.completed
    assert claimed.stage == JobStage.done


@requires_postgres
def test_store_and_get_artifact(db_session):
    from db.queue import create_job, get_artifact, store_artifact

    job = create_job(db_session, {"address": "0x0000000000000000000000000000000000000004"})

    store_artifact(db_session, job.id, "contract_analysis", data={"summary": {"model": "ownable"}})
    store_artifact(db_session, job.id, "analysis_report", text_data="This is a report")

    json_artifact = get_artifact(db_session, job.id, "contract_analysis")
    assert isinstance(json_artifact, dict)
    assert json_artifact["summary"]["model"] == "ownable"

    text_artifact = get_artifact(db_session, job.id, "analysis_report")
    assert text_artifact == "This is a report"

    assert get_artifact(db_session, job.id, "missing") is None


@requires_postgres
def test_artifact_upsert(db_session):
    from db.queue import create_job, get_artifact, store_artifact

    job = create_job(db_session, {"address": "0x0000000000000000000000000000000000000005"})

    store_artifact(db_session, job.id, "snapshot", data={"v": 1})
    artifact = get_artifact(db_session, job.id, "snapshot")
    assert isinstance(artifact, dict)
    assert artifact["v"] == 1

    # Upsert should replace
    store_artifact(db_session, job.id, "snapshot", data={"v": 2})
    artifact = get_artifact(db_session, job.id, "snapshot")
    assert isinstance(artifact, dict)
    assert artifact["v"] == 2


@requires_postgres
def test_store_and_get_source_files(db_session):
    from db.queue import create_job, get_source_files, store_source_files

    job = create_job(db_session, {"address": "0x0000000000000000000000000000000000000006"})

    files = {
        "src/Token.sol": "pragma solidity ^0.8.0;\ncontract Token {}",
        "src/Utils.sol": "pragma solidity ^0.8.0;\nlibrary Utils {}",
    }
    store_source_files(db_session, job.id, files)

    retrieved = get_source_files(db_session, job.id)
    assert len(retrieved) == 2
    assert "src/Token.sol" in retrieved
    assert "contract Token {}" in retrieved["src/Token.sol"]


@requires_postgres
def test_get_all_artifacts(db_session):
    from db.queue import create_job, get_all_artifacts, store_artifact

    job = create_job(db_session, {"address": "0x0000000000000000000000000000000000000007"})

    store_artifact(db_session, job.id, "analysis", data={"key": "value"})
    store_artifact(db_session, job.id, "report", text_data="text content")

    all_artifacts = get_all_artifacts(db_session, job.id)
    assert "analysis" in all_artifacts
    assert "report" in all_artifacts
    assert all_artifacts["analysis"]["key"] == "value"
    assert all_artifacts["report"] == "text content"
