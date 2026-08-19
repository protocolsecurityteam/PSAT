"""Integration tests: ``trace_id`` end-to-end across HTTP → DB → child jobs.

Skips when ``TEST_DATABASE_URL`` is unset or unreachable (matches the
pattern in ``tests/cache_helpers.requires_postgres`` so the offline CI
can still run the rest of the suite).

What this pins:

1. ``POST /api/analyze`` without ``X-PSAT-Trace-Id`` → response carries
   the header → ``Job.trace_id`` matches the echoed value (the API
   minted it and persisted it).
2. ``POST /api/analyze`` *with* a client-supplied ``X-PSAT-Trace-Id`` →
   that exact value lands on ``Job.trace_id`` and is echoed back.
3. ``db.queue.create_job`` invoked with a parent's bound trace context
   stamps the child's ``trace_id`` to the parent's, modelling the
   discovery worker's DApp/DefiLlama sibling spawn path.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.cache_helpers import requires_postgres  # noqa: E402


@requires_postgres
def test_post_analyze_without_header_mints_trace_id(db_session, api_client):
    """Round-trip the no-header path: server mints, echoes, and persists."""
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
def test_post_analyze_with_client_header_uses_supplied_trace_id(db_session, api_client):
    """A client-supplied trace_id flows through to the persisted Job row."""
    from db.models import Job

    supplied = "client12345678ab"
    address = "0x" + "b" * 40
    response = api_client.post(
        "/api/analyze",
        json={"address": address},
        headers={"X-PSAT-Trace-Id": supplied},
    )
    assert response.status_code == 200, response.text
    assert response.headers.get("X-PSAT-Trace-Id") == supplied

    job_id = uuid.UUID(response.json()["job_id"])
    job = db_session.execute(select(Job).where(Job.id == job_id)).scalar_one()
    assert job.trace_id == supplied


@requires_postgres
def test_create_job_inherits_bound_trace_id(db_session):
    """A child job created inside a parent's bind block inherits the parent's id.

    Exercises the discovery worker's sibling-spawn pattern: the worker
    binds via ``BaseWorker._execute_job`` and then ``create_job(...)`` is
    called for every DApp/DefiLlama sibling. This test fakes the bind
    directly because spawning a real worker would require RPC plumbing.
    """
    from db.models import Job, JobStage
    from db.queue import create_job
    from utils.logging import bind_trace_context

    parent_trace = "parent-trace-9876"
    with bind_trace_context(trace_id=parent_trace):
        child = create_job(
            db_session,
            {
                "company": "fixture-protocol",
                "name": "fixture-child",
                "rpc_url": "https://rpc.example",
            },
            initial_stage=JobStage.discovery,
        )

    persisted = db_session.execute(select(Job).where(Job.id == child.id)).scalar_one()
    assert persisted.trace_id == parent_trace


@requires_postgres
def test_create_job_without_bind_mints_fresh_id(db_session):
    """A create_job call outside any bind still gets a non-null trace_id.

    Stops legacy callers (e.g. cron jobs that skip the API ingress) from
    silently writing rows with NULL trace_id, which would defeat
    correlation later.
    """
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
