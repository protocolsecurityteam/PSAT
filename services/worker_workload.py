"""Cheap queue readiness census. No RPC, analysis imports, or provider calls.

Custom-stage predicates are also used by the consumers, so readiness cannot
silently diverge. Indexer/score queues are deliberately owned by the monitor.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

# Preserve the custom consumers' existing readiness/timeout semantics, including
# their historical lack of a next_attempt/dependency predicate.
COVERAGE_READY = """(
    NOT EXISTS (
        SELECT 1 FROM audit_reports ar WHERE ar.protocol_id=j.protocol_id AND (
            ar.text_extraction_status IS NULL OR ar.text_extraction_status='processing'
            OR (ar.text_extraction_status='success'
                AND (ar.scope_extraction_status IS NULL OR ar.scope_extraction_status='processing'))
        )
    )
)"""
SELECTION_READY = """(
    NOT EXISTS (
        SELECT 1 FROM jobs sib WHERE sib.stage IN ('dapp_crawl','defillama_scan')
        AND sib.request->>'root_job_id'=j.id::text AND sib.status IN ('queued','processing')
    )
)"""
NORMAL_READY = """(
    (j.next_attempt_at IS NULL OR j.next_attempt_at <= now()) AND NOT EXISTS (
        SELECT 1 FROM job_dependencies d WHERE d.depender_job_id=j.id AND d.status='pending'
    )
)"""


@dataclass(frozen=True)
class Workload:
    ready: tuple[str, ...]
    active: bool

    @property
    def busy(self) -> bool:
        return bool(self.ready) or self.active


def snapshot(session: Session) -> Workload:
    """EXISTS probes stop at the first match; no scans of artifact bodies.

    Processing rows keep a running fleet alive through lease recovery. They also
    wake a stopped fleet: recovery sweeps belong to consumers. Browser processing
    is excluded; a dependent becomes visible when its normal readiness changes.
    """
    params = {
        "coverage_timeout": int(os.getenv("PSAT_COVERAGE_STUCK_TIMEOUT", "3600")),
        "selection_timeout": int(os.getenv("PSAT_SELECTION_STUCK_TIMEOUT", "3600")),
        "job_stale": int(os.getenv("PSAT_STALE_JOB_TIMEOUT", "600")),
        "text_stale": int(os.getenv("PSAT_AUDIT_TEXT_STALE_TIMEOUT", "600")),
        "scope_stale": int(os.getenv("PSAT_AUDIT_SCOPE_STALE_TIMEOUT", "900")),
        "verify_stale": int(os.getenv("PSAT_COVERAGE_VERIFY_STALE_TIMEOUT", "600")),
    }
    row = (
        session.execute(
            text(f"""
            SELECT
            EXISTS(SELECT 1 FROM jobs j WHERE j.status='queued' AND (
                (j.stage='coverage' AND ({COVERAGE_READY}
                    OR j.updated_at < now()-(:coverage_timeout * interval '1 second'))) OR
                (j.stage='selection' AND ({SELECTION_READY}
                    OR j.updated_at < now()-(:selection_timeout * interval '1 second'))) OR
                (j.stage IN ('discovery','static','resolution','policy','effects','defillama_scan')
                    AND {NORMAL_READY})
            )) AS jobs,
            EXISTS(SELECT 1 FROM audit_reports WHERE text_extraction_status IS NULL) AS audit_text,
            EXISTS(SELECT 1 FROM audit_reports
                WHERE text_extraction_status='success' AND scope_extraction_status IS NULL) AS audit_scope,
            EXISTS(SELECT 1 FROM audit_contract_coverage acc JOIN contracts c ON c.id=acc.contract_id
                WHERE acc.equivalence_status='pending' AND c.is_proxy=FALSE) AS coverage_verify,
            EXISTS(SELECT 1 FROM monitoring_enrollment_queue WHERE dirty_at<=now()
                AND (lease_expires_at IS NULL OR lease_expires_at<=now())) AS enrollment,
            (EXISTS(SELECT 1 FROM jobs WHERE status='processing' AND stage NOT IN ('dapp_crawl','done')
                AND (lease_expires_at<=now() OR updated_at<now()-(:job_stale * interval '1 second')))
             OR EXISTS(SELECT 1 FROM audit_reports WHERE
                (text_extraction_status='processing'
                    AND text_extraction_started_at<now()-(:text_stale * interval '1 second'))
                OR (scope_extraction_status='processing'
                    AND scope_extraction_started_at<now()-(:scope_stale * interval '1 second')))
             OR EXISTS(SELECT 1 FROM audit_contract_coverage WHERE equivalence_status='verifying'
                AND equivalence_checked_at<now()-(:verify_stale * interval '1 second'))) AS recovery,
            (EXISTS(SELECT 1 FROM jobs WHERE status='processing' AND stage NOT IN ('dapp_crawl','done'))
             OR EXISTS(SELECT 1 FROM audit_reports
                WHERE text_extraction_status='processing' OR scope_extraction_status='processing')
             OR EXISTS(SELECT 1 FROM audit_contract_coverage WHERE equivalence_status='verifying')
             OR EXISTS(SELECT 1 FROM monitoring_enrollment_queue WHERE lease_expires_at>now())) AS active
        """),
            params,
        )
        .mappings()
        .one()
    )
    return Workload(tuple(k for k, v in row.items() if k != "active" and v), bool(row["active"]))


def custom_claim_statement(stage: str, *, stuck: bool = False):
    """Keep ready-first ordering and the existing stuck fallback unchanged."""
    predicate = {"coverage": COVERAGE_READY, "selection": SELECTION_READY}[stage]
    if stuck:
        predicate = "j.updated_at < now() - (:timeout * interval '1 second')"
    return text(f"""
        SELECT j.id FROM jobs j WHERE j.stage='{stage}' AND j.status='queued'
        AND {predicate} ORDER BY j.updated_at ASC FOR UPDATE SKIP LOCKED LIMIT 1
    """)
