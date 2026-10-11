"""Extracts the in-scope contract list from audit PDF text.

Content-hash cache: a sibling AuditReport with the same ``text_sha256`` that is already scoped is cloned instead of
paying for another LLM call (the common Solodit copy + GitHub copy of one PDF).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from sqlalchemy import select, text, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select, Update

from db.models import AuditReport, SessionLocal
from db.queue import HEARTBEAT_AUDIT_SCOPE
from services.audits import ScopeExtractionOutcome, process_audit_scope
from utils.logging import log_timed_phase
from workers.audit_row_worker import AuditRowWorker

logger = logging.getLogger("workers.audit_scope_extraction")


_BATCH_SIZE = int(os.getenv("PSAT_AUDIT_SCOPE_BATCH_SIZE", "4"))
_MAX_CONCURRENT = int(os.getenv("PSAT_AUDIT_SCOPE_CONCURRENCY", "8"))
_IDLE_POLL_INTERVAL = float(os.getenv("PSAT_AUDIT_SCOPE_POLL_INTERVAL", "15.0"))

# An LLM call can take 60s+ and the worker reads a large object first.
_STALE_PROCESSING_SECONDS = int(os.getenv("PSAT_AUDIT_SCOPE_STALE_TIMEOUT", "900"))


class _CacheCopyOutcome:
    """Returned by ``_process_row`` on a content-hash cache hit."""

    __slots__ = ("sibling_id",)

    def __init__(self, sibling_id: int) -> None:
        self.sibling_id = sibling_id


_ProcessResult = ScopeExtractionOutcome | _CacheCopyOutcome


class AuditScopeExtractionWorker(AuditRowWorker):
    worker_name = "AuditScopeExtraction"
    heartbeat_process = HEARTBEAT_AUDIT_SCOPE
    batch_size = _BATCH_SIZE
    max_concurrent = _MAX_CONCURRENT
    idle_poll_interval = _IDLE_POLL_INTERVAL
    stale_processing_seconds = _STALE_PROCESSING_SECONDS
    thread_name_prefix = "audit-scope"
    log = logger

    def _pending_rows_query(self) -> Select:
        """Newest-first so a freshly discovered audit isn't blocked behind a backlog."""
        return (
            select(AuditReport)
            .where(
                AuditReport.text_extraction_status == "success",
                AuditReport.scope_extraction_status.is_(None),
            )
            .order_by(
                AuditReport.text_extracted_at.desc().nullslast(),
                AuditReport.id.asc(),
            )
            .limit(self.batch_size)
            .with_for_update(skip_locked=True)
        )

    def _mark_processing(self, row: AuditReport, now: datetime) -> None:
        row.scope_extraction_status = "processing"
        row.scope_extraction_worker = self.worker_id
        row.scope_extraction_started_at = now
        row.scope_extraction_error = None

    def _stale_recovery_query(self, cutoff: datetime) -> Update:
        return (
            update(AuditReport)
            .where(
                AuditReport.scope_extraction_status == "processing",
                AuditReport.scope_extraction_started_at < cutoff,
            )
            .values(
                scope_extraction_status=None,
                scope_extraction_worker=None,
                scope_extraction_started_at=None,
            )
            .returning(AuditReport.id)
        )

    def _find_cache_sibling(self, session: Session, audit_id: int, text_sha256: str | None) -> int | None:
        if not text_sha256:
            return None
        row = session.execute(
            text(
                "SELECT id FROM audit_reports "
                "WHERE text_sha256 = :sha AND id != :self_id "
                "AND scope_extraction_status = 'success' "
                "AND scope_contracts IS NOT NULL "
                "ORDER BY scope_extracted_at DESC NULLS LAST, id ASC "
                "LIMIT 1"
            ),
            {"sha": text_sha256, "self_id": audit_id},
        ).scalar_one_or_none()
        return int(row) if row is not None else None

    def _process_row(self, audit: AuditReport) -> tuple[int, _ProcessResult]:
        session = SessionLocal()
        try:
            sibling_id = self._find_cache_sibling(session, audit.id, audit.text_sha256)
        finally:
            session.close()

        if sibling_id is not None:
            logger.info(
                "Worker %s: audit %s — cache hit via sibling %s (sha=%s)",
                self.worker_id,
                audit.id,
                sibling_id,
                (audit.text_sha256 or "")[:16],
            )
            return audit.id, _CacheCopyOutcome(sibling_id)

        if not audit.text_storage_key:
            return audit.id, ScopeExtractionOutcome(
                status="failed",
                error="audit has text_extraction_status=success but no text_storage_key",
            )

        with log_timed_phase(logger, "audit_scope_extract", record_metric=False, audit_id=audit.id):
            outcome = process_audit_scope(
                audit_report_id=audit.id,
                text_storage_key=audit.text_storage_key,
                text_sha256=audit.text_sha256,
                audit_title=audit.title or "",
                auditor=audit.auditor or "",
            )
        return audit.id, outcome

    def _persist_outcome(self, audit_id: int, result: _ProcessResult) -> None:
        now = datetime.now(timezone.utc)
        session = SessionLocal()
        try:
            audit = session.get(AuditReport, audit_id)
            if audit is None:
                logger.warning("Scope audit %s disappeared before persist", audit_id)
                return

            if isinstance(result, _CacheCopyOutcome):
                sibling = session.get(AuditReport, result.sibling_id)
                if sibling is None:
                    # Sibling deleted since lookup; reset to pending so the next pass extracts fresh.
                    logger.warning(
                        "Cache sibling %s gone; resetting audit %s to NULL",
                        result.sibling_id,
                        audit_id,
                    )
                    audit.scope_extraction_status = None
                    audit.scope_extraction_worker = None
                    audit.scope_extraction_started_at = None
                    audit.scope_extraction_error = None
                    session.commit()
                    return
                audit.scope_extraction_status = "success"
                audit.scope_extraction_error = None
                audit.scope_extraction_worker = None
                audit.scope_extracted_at = now
                audit.scope_storage_key = sibling.scope_storage_key
                audit.scope_contracts = list(sibling.scope_contracts or [])
                if sibling.reviewed_commits:
                    audit.reviewed_commits = list(sibling.reviewed_commits)
                if sibling.referenced_repos:
                    audit.referenced_repos = list(sibling.referenced_repos)
                if sibling.scope_entries:
                    audit.scope_entries = list(sibling.scope_entries)
                if sibling.classified_commits:
                    audit.classified_commits = list(sibling.classified_commits)
                self._maybe_backfill_date(audit, sibling.date)
                self._refresh_coverage(session, audit_id)
                session.commit()
                logger.info(
                    "Audit %s → cache-copy from %s (%d contracts)",
                    audit_id,
                    result.sibling_id,
                    len(audit.scope_contracts or []),
                )
                return

            outcome = result
            audit.scope_extraction_status = outcome.status
            audit.scope_extraction_error = outcome.error
            audit.scope_extraction_worker = None
            if outcome.status == "success":
                audit.scope_extracted_at = now
                audit.scope_storage_key = outcome.storage_key
                audit.scope_contracts = list(outcome.contracts)
                if outcome.reviewed_commits:
                    audit.reviewed_commits = list(outcome.reviewed_commits)
                audit.referenced_repos = list(outcome.referenced_repos) if outcome.referenced_repos else None
                # Always write: an empty list is a valid state and must clobber a stale prior extract.
                audit.scope_entries = list(outcome.scope_entries) if outcome.scope_entries else None
                audit.classified_commits = list(outcome.classified_commits) if outcome.classified_commits else None
                self._maybe_backfill_date(audit, outcome.extracted_date)
                self._refresh_coverage(session, audit_id)
            session.commit()
        except OperationalError:
            session.rollback()
            raise
        except Exception as exc:
            session.rollback()
            logger.warning(
                "Failed to persist scope outcome for audit %s: %s",
                audit_id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
        finally:
            session.close()

    def _log_outcome(self, audit_id: int, result: _ProcessResult) -> None:
        """The cache-copy path already logged inside ``_persist_outcome``."""
        if isinstance(result, _CacheCopyOutcome):
            return
        self.log.info(
            "Audit %s → %s (method=%s, contracts=%d)%s",
            audit_id,
            result.status,
            result.method,
            len(result.contracts),
            f" [{result.error}]" if result.error else "",
        )

    @staticmethod
    def _refresh_coverage(session: Session, audit_id: int) -> None:
        """Rebuild ``audit_contract_coverage`` for this audit inside the caller's transaction, guarded so a coverage
        bug never blocks recording the extraction. Verification is deferred to ``CoverageVerifyWorker`` (rows land
        ``pending``); inline verify caused Etherscan bursts that stalled other workers.
        """
        from services.audits.coverage import upsert_coverage_for_audit

        try:
            inserted = upsert_coverage_for_audit(session, audit_id, verify_source_equivalence=False)
            logger.info(
                "Audit %s → coverage refreshed (%d row(s)) — verification deferred",
                audit_id,
                inserted,
            )
        except OperationalError:
            # The transaction is aborted, so the scope write can't commit either; the whole persist is retried.
            raise
        except Exception as exc:
            logger.warning(
                "Failed to refresh coverage for audit %s — scope persist still proceeds: %s",
                audit_id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

    @staticmethod
    def _maybe_backfill_date(audit: AuditReport, candidate: str | None) -> None:
        """Discovery-time dates come from filename parsing, so nulls and ``YYYY-MM-00`` are common; prefer the
        title-page date.
        """
        if not candidate:
            return
        existing = audit.date or ""
        if not existing or existing.endswith("-00") or len(existing) < 10:
            audit.date = candidate


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    AuditScopeExtractionWorker().run_loop()


if __name__ == "__main__":
    main()
