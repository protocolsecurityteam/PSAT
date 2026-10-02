"""Skips without a reachable TEST_DATABASE_URL."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from tests.cache_helpers import requires_postgres


@requires_postgres
def test_post_analyze_without_header_mints_trace_id(db_session, api_client):
    from db.models import Job

    address = "0x" + "a" * 40
    response = api_client.post("/api/analyze", json={"address": address})
    assert response.status_code == 200, response.text

    echoed = response.headers.get("X-PSAT-Trace-Id")
    assert echoed, "server must echo X-PSAT-Trace-Id even when client did not supply one"
    assert len(echoed) == 16  # uuid4().hex[:16]

    job_id = uuid.UUID(response.json()["job_id"])
    job = db_session.execute(select(Job).where(Job.id == job_id)).scalar_one()
    assert job.trace_id == echoed


@requires_postgres
def test_create_job_without_bind_mints_fresh_id(db_session):
    """Legacy callers skipping API ingress must not write NULL trace ids."""
    from db.models import Job, JobStage
    from db.queue import create_job

    job = create_job(
        db_session,
        {"company": "fixture-protocol", "name": "fixture-orphan"},
        initial_stage=JobStage.discovery,
    )

    persisted = db_session.execute(select(Job).where(Job.id == job.id)).scalar_one()
    assert persisted.trace_id is not None
    assert len(persisted.trace_id) == 16
