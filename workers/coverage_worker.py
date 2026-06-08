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

Jobs with ``protocol_id=NULL`` (direct address submissions without a
parent company) bypass the readiness wait naturally — ``NULL = NULL``
evaluates to UNKNOWN, so the NOT EXISTS subquery returns true and claim
succeeds immediately.

The full claim/run scaffolding (stale recovery, advance-vs-complete,
error isolation) lives in ``BaseWorker``. This worker plugs into the
``_claim_job`` hook with a readiness predicate and defines its own
``process``.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from db.models import AuditContractCoverage, Contract, Job, JobStage, JobStatus
from db.queue import store_artifact
from services.artifacts import AUDIT_ARTIFACT, make_job_contract, make_job_stage_context, make_stage_artifact
from utils.logging import log_timed_phase, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.coverage_worker")


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
    """Drains the ``coverage`` stage with a readiness-gated claim."""

    stage = JobStage.coverage
    next_stage = JobStage.done
    poll_interval = 5.0

    # -- Claim ------------------------------------------------------------

    def _claim_job(self, session: Session) -> Job | None:
        """Claim only when the protocol audit side has settled."""
        return self._claim_next_job(session)

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

    # -- Process ----------------------------------------------------------

    def process(self, session: Session, job: Job) -> None:
        """Refresh coverage for this job's Contract — fast path, defer verify.

        Finds the canonical Contract via the job's ``(chain_id, address)``,
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
        from db.queue import require_contract_for_job
        from services.audits.coverage import upsert_coverage_for_contract

        contract = require_contract_for_job(session, job, context=f"coverage refresh for {job.id}")

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
