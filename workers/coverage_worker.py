"""Coverage worker — end-of-pipeline source-equivalence-aware coverage refresh.

Runs after ``PolicyWorker`` for every analyzed contract. Links each Contract
to its protocol's audits (via ``services.audits.coverage``) with the
expensive ``verify_source_equivalence=True`` pass enabled, so proof-grade
``reviewed_commit`` matches land automatically instead of requiring an
admin ``refresh_coverage`` call.

Two races are solved by the readiness predicate in ``_claim_next_job``:

    Timeline A: address pipeline (discovery → static → resolution → policy
                → coverage → done)
    Timeline B: audit pipeline (text_extraction → scope_extraction)

Coverage for a protocol's contracts must wait until every audit in that
protocol has either succeeded, failed, or been explicitly skipped. A
claim fires only when NO audit in the protocol is mid-flight. An audit
with ``text_extraction_status=NULL`` (never attempted) or ``'processing'``
counts as mid-flight; text-extraction failures (status='failed') don't
block because ``scope_extraction_status`` stays NULL forever for those
rows, which the predicate below explicitly handles by only blocking on
scope when text extraction ``succeeded``.

Stuck-audit escape hatch: once a job has sat at ``stage=coverage,
status=queued`` for longer than ``_STUCK_COVERAGE_TIMEOUT`` (default 1h),
we claim it anyway and log a warning. Better to produce coverage (even
just temporal) than to leave the job hanging forever because one audit's
PDF extraction wedged.

Jobs with ``protocol_id=NULL`` (direct address submissions without a
parent company) bypass the readiness wait naturally — ``NULL = NULL``
evaluates to UNKNOWN, so the NOT EXISTS subquery returns true and claim
succeeds immediately.

The full claim/run scaffolding (stale recovery, advance-vs-complete,
error isolation) lives in ``BaseWorker``. This worker plugs into the
``_claim_job`` hook with its two-phase pattern and defines its own
``process`` — that's the entire deviation from the default pipeline
worker shape.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from db.models import AuditContractCoverage, Contract, Job, JobStage, JobStatus
from db.queue import store_artifact
from services.artifacts import AUDIT_ARTIFACT, make_job_contract, make_job_stage_context, make_stage_artifact
from utils.logging import log_timed_phase, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.coverage_worker")

# How long a coverage job can sit in 'queued' before we bypass the
# readiness predicate and run it anyway. An hour is long enough for a
# stuck audit PDF extraction to unstick on its own (or be manually
# reset) without leaving analysis users waiting indefinitely.
_STUCK_COVERAGE_TIMEOUT = int(os.getenv("PSAT_COVERAGE_STUCK_TIMEOUT", "3600"))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _coverage_row_payload(row: AuditContractCoverage) -> dict[str, object]:
    return {
        "audit_report_id": row.audit_report_id,
        "contract_id": row.contract_id,
        "protocol_id": row.protocol_id,
        "matched_name": row.matched_name,
        "match_type": row.match_type,
        "match_confidence": row.match_confidence,
        "covered_from_block": row.covered_from_block,
        "covered_to_block": row.covered_to_block,
        "bytecode_keccak_at_match": row.bytecode_keccak_at_match,
        "verified_at": _iso(row.verified_at),
        "equivalence_status": row.equivalence_status,
        "equivalence_reason": row.equivalence_reason,
        "equivalence_checked_at": _iso(row.equivalence_checked_at),
        "proof_kind": row.proof_kind,
        "matched_commit_sha": row.matched_commit_sha,
    }


def _store_audit_artifact(
    session: Session,
    job: Job,
    contract: Contract | None,
    coverage_matches: list[dict[str, object]],
) -> None:
    contract_payload = make_job_contract(session, job, contract)
    store_artifact(
        session,
        job.id,
        AUDIT_ARTIFACT,
        data=make_stage_artifact(
            kind=AUDIT_ARTIFACT,
            stage=JobStage.coverage.value,
            schema_version="1.0",
            context=make_job_stage_context(job, stage=JobStage.coverage.value, schema_version="1.0"),
            data={
                "contract": contract_payload,
                "coverage_matches": coverage_matches,
            },
            contract=contract_payload,
        ),
    )


class CoverageWorker(BaseWorker):
    """Drains the ``coverage`` stage with a readiness-gated two-phase claim."""

    stage = JobStage.coverage
    next_stage = JobStage.done
    poll_interval = 5.0

    # -- Claim ------------------------------------------------------------

    def _claim_job(self, session: Session) -> Job | None:
        """Primary readiness-gated claim OR stuck-job fallback.

        The ``or`` short-circuits so a normal-path claim always wins
        when available. Only when the readiness predicate is holding
        every job back do we escalate to the stuck-job path — this
        bounds how long a single wedged audit can block downstream
        coverage without hiding the wedge from ops (every stuck claim
        logs a warning).
        """
        return self._claim_next_job(session) or self._claim_stuck_job(session)

    def _claim_next_job(self, session: Session) -> Job | None:
        """Claim a coverage job whose protocol's audit side has settled.

        Readiness predicate: NO audit in the same protocol is still
        moving through the text → scope pipeline. An audit whose text
        extraction failed (status='failed') leaves scope_extraction_status
        NULL forever — that's "settled" for our purposes, not "blocked",
        which is why the inner AND only guards on scope when text
        extraction ``succeeded``.
        """
        claim_id = session.execute(
            text(
                """
                SELECT j.id
                FROM jobs j
                WHERE j.stage = 'coverage' AND j.status = 'queued'
                  AND NOT EXISTS (
                    SELECT 1 FROM audit_reports ar
                    WHERE ar.protocol_id = j.protocol_id
                      AND (
                        ar.text_extraction_status IS NULL
                        OR ar.text_extraction_status = 'processing'
                        OR (ar.text_extraction_status = 'success'
                            AND (ar.scope_extraction_status IS NULL
                                 OR ar.scope_extraction_status = 'processing'))
                      )
                  )
                ORDER BY j.updated_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """
            )
        ).scalar_one_or_none()
        if claim_id is None:
            return None
        job = session.get(Job, claim_id)
        if job is None:
            return None
        job.status = JobStatus.processing
        job.worker_id = self.worker_id
        session.commit()
        session.refresh(job)
        return job

    def _claim_stuck_job(self, session: Session) -> Job | None:
        """Bypass readiness and claim a job that's been queued too long.

        The audit pipeline may be permanently wedged on one bad PDF;
        don't punish every contract in the protocol for it. Logs a
        warning so the wedge is visible in operational dashboards.
        """
        claim_id = session.execute(
            text(
                """
                SELECT j.id
                FROM jobs j
                WHERE j.stage = 'coverage' AND j.status = 'queued'
                  AND j.updated_at < (NOW() - (:timeout * INTERVAL '1 second'))
                ORDER BY j.updated_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """
            ),
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
        job.status = JobStatus.processing
        job.worker_id = self.worker_id
        session.commit()
        session.refresh(job)
        return job

    # -- Process ----------------------------------------------------------

    def process(self, session: Session, job: Job) -> None:
        """Refresh coverage for this job's Contract — fast path, defer verify.

        Finds the Contract via the job_id link the discovery worker set,
        then delegates to ``upsert_coverage_for_contract`` with
        ``verify_source_equivalence=False``. The match side is symmetric
        to the audit-side refresh triggered from the scope worker — we
        fetch all audits whose scope mentions the contract name and
        write one coverage row per match.

        Source-equivalence verification (the Etherscan + GitHub HTTP
        pass) is deferred to ``workers.coverage_verify``: a coverage
        rebuild here lands rows with ``equivalence_status='pending'``,
        and the dedicated verify worker drains them at a steady rate.
        Holding verify inline used to fan out 4-way Etherscan bursts per
        coverage job, which 429'd the global rate-limit window and
        cascaded into every other Etherscan-using worker on the box.
        """
        from services.audits.coverage import upsert_coverage_for_contract

        contract = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        if contract is None:
            # Address-only jobs where discovery/static skipped the Contract
            # write (cached path reassigned it) can land here. Nothing to
            # refresh; let the next-stage advance carry the job to done.
            logger.info(
                "Coverage stage: job %s has no Contract row — skipping refresh, advancing to done",
                job.id,
            )
            _store_audit_artifact(session, job, None, [])
            return

        self.update_detail(session, job, "Refreshing audit coverage")
        with log_timed_phase(logger, "coverage_upsert"):
            inserted = upsert_coverage_for_contract(
                session,
                contract.id,
                verify_source_equivalence=False,
            )
        session.commit()
        coverage_matches = [
            _coverage_row_payload(row)
            for row in session.execute(
                select(AuditContractCoverage)
                .where(
                    AuditContractCoverage.contract_id == contract.id,
                    AuditContractCoverage.protocol_id == contract.protocol_id,
                )
                .order_by(AuditContractCoverage.audit_report_id.asc())
            )
            .scalars()
            .all()
        ]
        _store_audit_artifact(session, job, contract, coverage_matches)
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
