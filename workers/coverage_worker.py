"""Coverage worker — links each analyzed Contract to its protocol's audits.

Claim waits until no audit in the protocol is mid-flight in text -> scope extraction. Text-extraction failures don't
block (their scope status stays NULL forever). After ``_STUCK_COVERAGE_TIMEOUT`` a job is claimed anyway with a warning,
so one wedged PDF can't hang the protocol. ``protocol_id=NULL`` jobs pass immediately (``NULL = NULL`` is UNKNOWN, so
NOT EXISTS holds).
"""

from __future__ import annotations

import logging
import os
import uuid

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStage, JobStatus
from services.worker_workload import custom_claim_statement
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.coverage_worker")

_STUCK_COVERAGE_TIMEOUT = int(os.getenv("PSAT_COVERAGE_STUCK_TIMEOUT", "3600"))


class CoverageWorker(BaseWorker):
    stage = JobStage.coverage
    next_stage = JobStage.done
    poll_interval = 5.0

    def _claim_job(self, session: Session) -> Job | None:
        """Normal claim wins; the stuck-job path only runs when readiness holds every job back."""
        return self._claim_next_job(session) or self._claim_stuck_job(session)

    def _claim_next_job(self, session: Session) -> Job | None:
        """Claim a coverage job whose protocol's audits have settled."""
        from services.worker_lifecycle import claim_allowed

        if not claim_allowed(session):
            return None
        claim_id = session.execute(
            custom_claim_statement("coverage", stuck=False),
        ).scalar_one_or_none()
        if claim_id is None:
            return None
        job = session.get(Job, claim_id)
        if job is None:
            return None
        from db.queue import DEFAULT_JOB_LEASE_TTL_S
        from services.worker_lifecycle import note_claim

        note_claim(session)
        job.lease_id = uuid.uuid4()
        session.execute(
            text("UPDATE jobs SET lease_expires_at=now()+(:ttl * interval '1 second') WHERE id=:id"),
            {"ttl": DEFAULT_JOB_LEASE_TTL_S, "id": job.id},
        )
        job.status = JobStatus.processing
        job.worker_id = self.worker_id
        session.commit()
        session.refresh(job)
        return job

    def _claim_stuck_job(self, session: Session) -> Job | None:
        from services.worker_lifecycle import claim_allowed

        if not claim_allowed(session):
            return None
        claim_id = session.execute(
            custom_claim_statement("coverage", stuck=True),
            {"timeout": _STUCK_COVERAGE_TIMEOUT},
        ).scalar_one_or_none()
        if claim_id is None:
            return None
        job = session.get(Job, claim_id)
        if job is None:
            return None
        logger.warning(
            "Worker %s: claiming stuck coverage job %s (address=%s) past %ss timeout — "
            "protocol %s has unresolved audit(s)",
            self.worker_id,
            job.id,
            job.address or "?",
            _STUCK_COVERAGE_TIMEOUT,
            job.protocol_id,
        )
        from db.queue import DEFAULT_JOB_LEASE_TTL_S
        from services.worker_lifecycle import note_claim

        note_claim(session)
        job.lease_id = uuid.uuid4()
        session.execute(
            text("UPDATE jobs SET lease_expires_at=now()+(:ttl * interval '1 second') WHERE id=:id"),
            {"ttl": DEFAULT_JOB_LEASE_TTL_S, "id": job.id},
        )
        job.status = JobStatus.processing
        job.worker_id = self.worker_id
        session.commit()
        session.refresh(job)
        return job

    def process(self, session: Session, job: Job) -> None:
        """Refresh coverage for this job's Contract with verification deferred.

        Rows land ``equivalence_status='pending'`` for ``workers.coverage_verify``; inline verify fanned out Etherscan
        bursts that 429'd the global window for every worker.
        """
        from services.audits.coverage import upsert_coverage_for_contract

        contract = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        if contract is None:
            # Cached path may have skipped the Contract write; nothing to refresh.
            logger.info(
                "Coverage stage: job %s has no Contract row — skipping refresh, advancing to done",
                job.id,
            )
            return

        self.update_detail(session, job, "Refreshing audit coverage")
        with log_timed_phase(logger, "coverage_upsert"):
            inserted = upsert_coverage_for_contract(
                session,
                contract.id,
                verify_source_equivalence=False,
            )
        session.commit()
        # Coverage is a scored axis; marked after commit so the mark never references rolled-back rows.
        if contract.protocol_id is not None:
            from services.scoring.dirty import SCORE_DIRTY_COVERAGE, mark_protocol_score_dirty

            if mark_protocol_score_dirty(session, contract.protocol_id, SCORE_DIRTY_COVERAGE):
                try:
                    session.commit()
                except Exception as exc:
                    # The mark swallows its own failure, so its commit must too; a lost mark delays a real invalidation,
                    # hence a degradation not just a log.
                    session.rollback()
                    record_degraded(phase="score_dirty_mark", exc=exc, context={"protocol_id": contract.protocol_id})
                    logger.warning(
                        "Coverage stage: protocol score dirty-mark commit failed for protocol %s",
                        contract.protocol_id,
                        exc_info=True,
                    )
        record_stage_metric("coverage_rows", inserted)
        self.update_detail(session, job, f"Audit coverage refreshed: {inserted} row(s)")
        logger.info(
            "Coverage stage complete for job %s (contract %s): %d coverage row(s) — verification deferred",
            job.id,
            contract.id,
            inserted,
        )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    CoverageWorker().run_loop()


if __name__ == "__main__":
    main()
