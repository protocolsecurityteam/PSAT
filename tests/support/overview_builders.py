"""Row builders for the company-overview / analysis-detail aggregation tests.

Protocol → Job → Contract is the spine every one of those payloads is read off,
and three test modules used to carry their own copy of it. One definition here;
the addresses are UUID-derived so two modules seeding "the same" contract never
collide on ``uq_contract_address_chain``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import Contract, Job, JobStage, JobStatus, Protocol


def _addr(seed: str) -> str:
    """Deterministic-but-test-unique 0x address keyed by ``seed``.

    The conftest db_session fixture cleans up Protocol but not Contract or
    Job rows (they have ON DELETE SET NULL). Hardcoding addresses across
    tests collides on uq_contract_address_chain — UUID-derive instead.
    """
    return "0x" + (uuid.uuid4().hex + seed.encode().hex())[:40]


def _add_protocol(session, name: str) -> Protocol:
    p = Protocol(name=name)
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


def _add_job(
    session,
    *,
    address: str,
    name: str | None = None,
    company: str | None = None,
    protocol_id: int | None = None,
    status: JobStatus = JobStatus.completed,
    request: dict | None = None,
    is_proxy: bool = False,
) -> Job:
    job = Job(
        id=uuid.uuid4(),
        address=address,
        company=company,
        protocol_id=protocol_id,
        name=name or address,
        status=status,
        stage=JobStage.done,
        request=request or {"address": address},
        is_proxy=is_proxy,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return job


def _add_contract(
    session,
    *,
    address: str,
    job: Job,
    protocol_id: int | None = None,
    chain: str | None = "ethereum",
    is_proxy: bool = False,
    implementation: str | None = None,
    contract_name: str | None = None,
) -> Contract:
    c = Contract(
        address=address,
        job_id=job.id,
        protocol_id=protocol_id,
        chain=chain,
        contract_name=contract_name or address,
        is_proxy=is_proxy,
        implementation=implementation,
    )
    session.add(c)
    session.commit()
    session.refresh(c)
    return c
