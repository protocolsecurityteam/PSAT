"""Re-running a job's policy stage when an input it read from another job changed after it ran.

A producer marks the job stale; the reconciliation drain re-queues the job's policy once the job has completed, and
the stages after policy follow. A policy run clears its own mark before reading those inputs, so a mark set after the
read always forces another run, and one set before it is satisfied by this run.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from db.models import Contract, IndexerWork, Job, JobStage, JobStatus
from services.resolution.indexer_work import WorkPending, mark_dirty

STALE_POLICY_KIND = "stale_policy"


def mark_policy_stale(session: Session, job_id: Any) -> None:
    """Doesn't commit."""
    mark_dirty(session, STALE_POLICY_KIND, str(job_id))


def clear_policy_stale(session: Session, job_id: Any) -> None:
    """Doesn't commit; the caller commits before reading the inputs the mark stands for."""
    session.execute(delete(IndexerWork).where(IndexerWork.kind == STALE_POLICY_KIND, IndexerWork.key == str(job_id)))


def refresh_stale_policy(session: Session, job_id: Any) -> int:
    """Re-queue a stale job's policy stage; returns 1 when re-queued, 0 when there is nothing to re-run. Raises
    ``WorkPending`` while the job is still in flight or another job holds its address. Doesn't commit.
    """
    from services.resolution.deferred_reconciler import _address_has_active_job, _requeue_policy
    from utils.chains import supported_chain_ids

    job = session.execute(
        select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if job is None or job.status == JobStatus.failed_terminal:
        return 0
    # Policy writes only to the job's own contract rows; a superseded job has none to refresh.
    if session.execute(select(Contract.id).where(Contract.job_id == job.id).limit(1)).first() is None:
        return 0
    if job.status != JobStatus.completed or job.stage != JobStage.done:
        raise WorkPending("stale job is not completed")
    chain_id = job.chain_id
    if chain_id is None or chain_id not in supported_chain_ids():
        raise WorkPending("stale job has no enabled chain")
    if _address_has_active_job(session, job.address, chain_id=chain_id, exclude_job_id=job.id):
        raise WorkPending("another analysis owns this address")
    _requeue_policy(job, "Re-running policy: an input read from another contract changed")
    session.flush()
    return 1
