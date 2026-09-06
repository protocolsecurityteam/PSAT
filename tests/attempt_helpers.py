"""Explicit claims for tests that invoke worker stages outside the run loop."""

import uuid

from sqlalchemy.orm import Session

from db.attempts import JobAttempt, bind_job_attempt
from db.models import Job, JobStatus


def prepare_attempt(session, job):
    if not isinstance(session, Session):
        session.info = {}
    try:
        identity = uuid.UUID(str(job.id))
    except (ValueError, AttributeError):
        identity = None
    if not isinstance(job, Job) and isinstance(session, Session) and identity is not None:
        persisted = session.get(Job, identity)
        if persisted is not None:
            attempt = prepare_attempt(session, persisted)
            job.lease_id = persisted.lease_id
            setattr(job, "_heartbeat_lease_id", job.lease_id)
            return attempt
    if not isinstance(job, Job):
        if getattr(job, "lease_id", None) is None:
            job.lease_id = uuid.uuid4()
        setattr(job, "_heartbeat_lease_id", job.lease_id)
        return None
    assert isinstance(session, Session)
    if job.status != JobStatus.processing or job.lease_id is None:
        job.status = JobStatus.processing
        job.lease_id = uuid.uuid4()
        session.commit()
    setattr(job, "_heartbeat_lease_id", job.lease_id)
    return JobAttempt(job.id, job.lease_id)


def claimed_call(method, session, job, *args, **kwargs):
    """Run a stage/helper under real attempt authority, then restore test scope."""
    attempt = prepare_attempt(session, job)
    if attempt is None:
        return method(session, job, *args, **kwargs)
    try:
        if method.__name__ == "_execute_job":
            return method(session, job, *args, **kwargs)
        with bind_job_attempt(attempt):
            return method(session, job, *args, **kwargs)
    finally:
        session.info.pop("job_attempt", None)


def lease_for(session, job_id):
    job = session.get(Job, job_id)
    assert job is not None
    attempt = prepare_attempt(session, job)
    assert attempt is not None
    return attempt.lease_id


def proxy_parent(session):
    from db.queue import create_job

    session.info.pop("job_attempt", None)
    job = create_job(session, {})
    attempt = prepare_attempt(session, job)
    session.info["job_attempt"] = attempt
    return job
