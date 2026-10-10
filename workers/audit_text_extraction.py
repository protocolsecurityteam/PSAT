"""Downloads audit PDFs, extracts text, stores it in object storage.

``text_extraction_status``: NULL eligible, processing, success, failed (terminal; reset to NULL manually to retry),
skipped (image-only, >50MB, not extractable).
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import Select, Update

from db.models import AuditReport, SessionLocal
from db.queue import HEARTBEAT_AUDIT_TEXT
from services.audits import ExtractionOutcome, process_audit_report
from utils.logging import log_timed_phase
from workers.audit_row_worker import AuditRowWorker

logger = logging.getLogger("workers.audit_text_extraction")


_BATCH_SIZE = int(os.getenv("PSAT_AUDIT_TEXT_BATCH_SIZE", "8"))

# pypdf is GIL-bound but downloads dominate.
_MAX_CONCURRENT = int(os.getenv("PSAT_AUDIT_TEXT_CONCURRENCY", "8"))

_IDLE_POLL_INTERVAL = float(os.getenv("PSAT_AUDIT_TEXT_POLL_INTERVAL", "10.0"))

# Auditor portfolios rate-limit aggressively.
_PER_HOST_CONCURRENCY = int(os.getenv("PSAT_AUDIT_TEXT_HOST_CONCURRENCY", "3"))

_STALE_PROCESSING_SECONDS = int(os.getenv("PSAT_AUDIT_TEXT_STALE_TIMEOUT", "600"))


class AuditTextExtractionWorker(AuditRowWorker):
    worker_name = "AuditTextExtraction"
    heartbeat_process = HEARTBEAT_AUDIT_TEXT
    batch_size = _BATCH_SIZE
    max_concurrent = _MAX_CONCURRENT
    idle_poll_interval = _IDLE_POLL_INTERVAL
    stale_processing_seconds = _STALE_PROCESSING_SECONDS
    thread_name_prefix = "audit-text"
    log = logger

    def __init__(self) -> None:
        super().__init__()
        # Spearbit / Cantina portfolio pages 429 above a few concurrent requests.
        self._host_semaphores: dict[str, threading.Semaphore] = {}
        self._host_semaphores_lock = threading.Lock()
        self._http_session = requests.Session()

    def _pending_rows_query(self) -> Select:
        return (
            select(AuditReport)
            .where(AuditReport.text_extraction_status.is_(None))
            .order_by(AuditReport.discovered_at.desc().nullslast(), AuditReport.id.asc())
            .limit(self.batch_size)
            .with_for_update(skip_locked=True)
        )

    def _mark_processing(self, row: AuditReport, now: datetime) -> None:
        row.text_extraction_status = "processing"
        row.text_extraction_worker = self.worker_id
        row.text_extraction_started_at = now
        row.text_extraction_error = None

    def _stale_recovery_query(self, cutoff: datetime) -> Update:
        return (
            update(AuditReport)
            .where(
                AuditReport.text_extraction_status == "processing",
                AuditReport.text_extraction_started_at < cutoff,
            )
            .values(
                text_extraction_status=None,
                text_extraction_worker=None,
                text_extraction_started_at=None,
            )
            .returning(AuditReport.id)
        )

    def _host_semaphore(self, url: str) -> threading.Semaphore:
        host = urlparse(url).netloc.lower() or "_unknown"
        with self._host_semaphores_lock:
            sem = self._host_semaphores.get(host)
            if sem is None:
                sem = threading.Semaphore(_PER_HOST_CONCURRENCY)
                self._host_semaphores[host] = sem
        return sem

    def _process_row(self, audit: AuditReport) -> tuple[int, ExtractionOutcome]:
        url = audit.pdf_url or audit.url
        if not url:
            return audit.id, ExtractionOutcome(status="failed", error="no URL on audit row")

        host_sem = self._host_semaphore(url)
        with host_sem:
            with log_timed_phase(logger, "audit_text_extract", record_metric=False, audit_id=audit.id):
                outcome = process_audit_report(
                    audit_report_id=audit.id,
                    url=url,
                    session=self._http_session,
                )
        return audit.id, outcome

    def _persist_outcome(self, audit_id: int, result: ExtractionOutcome) -> None:
        now = datetime.now(timezone.utc)
        session = SessionLocal()
        try:
            audit = session.get(AuditReport, audit_id)
            if audit is None:
                logger.warning("Audit %s disappeared before outcome could be saved", audit_id)
                return
            audit.text_extraction_status = result.status
            audit.text_extraction_error = result.error
            audit.text_extraction_worker = None
            if result.status == "success":
                audit.text_storage_key = result.storage_key
                audit.text_size_bytes = result.text_size_bytes
                audit.text_sha256 = result.text_sha256
                audit.text_extracted_at = now
            session.commit()
        except OperationalError:
            session.rollback()
            raise
        except Exception as exc:
            session.rollback()
            logger.warning(
                "Failed to persist outcome for audit %s: %s",
                audit_id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
        finally:
            session.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    AuditTextExtractionWorker().run_loop()


if __name__ == "__main__":
    main()
