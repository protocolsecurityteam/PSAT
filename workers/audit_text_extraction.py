"""Worker that downloads audit PDFs, extracts text, and stores the result.

State model on ``audit_reports``:

    NULL            — never attempted. Eligible for claim.
    "processing"    — a worker holds this row. Gets recovered if stale.
    "success"       — text is in object storage at ``text_storage_key``.
    "failed"        — terminal failure; ``text_extraction_error`` has details.
                      (Manual DB op can reset to NULL to retry.)
    "skipped"       — image-only PDF, >50MB, or otherwise not extractable.

Shared scaffolding (signal handling, batch claim, stale recovery, thread
pool, run loop) lives in ``workers.audit_row_worker.AuditRowWorker``.
This file holds only the text-phase specifics: the eligibility query,
per-host rate limiting for auditor CDNs, the PDF download + extract
call, and the result persistence.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from sqlalchemy import select, update
from sqlalchemy.sql import Select, Update

from db.models import AuditReport, SessionLocal
from db.queue import HEARTBEAT_AUDIT_TEXT
from services.audits import ExtractionOutcome, process_audit_report
from workers.audit_row_worker import AuditRowWorker

logger = logging.getLogger("workers.audit_text_extraction")


# --- Tunables (env-overridable for ops) ----------------------------------

# Rows claimed per poll. The thread pool processes all of them in
# parallel, so keep this in proportion to MAX_CONCURRENT.
_BATCH_SIZE = int(os.getenv("PSAT_AUDIT_TEXT_BATCH_SIZE", "8"))

# Thread-pool size. pypdf parse is GIL-bounded, but downloads dominate —
# 8 threads cover ~4 concurrent downloads on average (rest are waiting on
# DB / storage I/O).
_MAX_CONCURRENT = int(os.getenv("PSAT_AUDIT_TEXT_CONCURRENCY", "8"))

_IDLE_POLL_INTERVAL = float(os.getenv("PSAT_AUDIT_TEXT_POLL_INTERVAL", "10.0"))

# Max in-flight requests per host. Most auditor portfolios rate-limit
# aggressively; GitHub's raw CDN tolerates far more but 3 is plenty for
# the volume we're doing.
_PER_HOST_CONCURRENCY = int(os.getenv("PSAT_AUDIT_TEXT_HOST_CONCURRENCY", "3"))

_STALE_PROCESSING_SECONDS = int(os.getenv("PSAT_AUDIT_TEXT_STALE_TIMEOUT", "600"))


class AuditTextExtractionWorker(AuditRowWorker):
    """Drain rows where text extraction has not yet been attempted."""

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
        # Per-host semaphores gate concurrent downloads from any one
        # auditor's CDN — Spearbit / Cantina portfolio pages rate-limit
        # at a few concurrent requests and will 429 at higher.
        self._host_semaphores: dict[str, threading.Semaphore] = {}
        self._host_semaphores_lock = threading.Lock()
        # One shared requests.Session so keep-alive connections pay off
        # across calls to the same host.
        self._http_session = requests.Session()

    # -- Claim predicates -------------------------------------------------

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

    # -- Per-host rate limiting ------------------------------------------

    def _host_semaphore(self, url: str) -> threading.Semaphore:
        """Return (and lazily create) the semaphore gating concurrent calls
        to the URL's host. One semaphore per unique netloc."""
        host = urlparse(url).netloc.lower() or "_unknown"
        with self._host_semaphores_lock:
            sem = self._host_semaphores.get(host)
            if sem is None:
                sem = threading.Semaphore(_PER_HOST_CONCURRENCY)
                self._host_semaphores[host] = sem
        return sem

    # -- Per-row work -----------------------------------------------------

    def _process_row(self, audit: AuditReport) -> tuple[int, ExtractionOutcome]:
        """Download + extract for one claimed row; respects per-host limits."""
        url = audit.pdf_url or audit.url
        if not url:
            return audit.id, ExtractionOutcome(status="failed", error="no URL on audit row")

        host_sem = self._host_semaphore(url)
        with host_sem:
            outcome = process_audit_report(
                audit_report_id=audit.id,
                url=url,
                session=self._http_session,
            )
        return audit.id, outcome

    def _persist_outcome(self, audit_id: int, outcome: ExtractionOutcome) -> None:
        """Write the extraction outcome back to the row in its own session."""
        now = datetime.now(timezone.utc)
        session = SessionLocal()
        try:
            audit = session.get(AuditReport, audit_id)
            if audit is None:
                logger.warning("Audit %s disappeared before outcome could be saved", audit_id)
                return
            audit.text_extraction_status = outcome.status
            audit.text_extraction_error = outcome.error
            audit.text_extraction_worker = None
            if outcome.status == "success":
                audit.text_storage_key = outcome.storage_key
                audit.text_size_bytes = outcome.text_size_bytes
                audit.text_sha256 = outcome.text_sha256
                audit.text_extracted_at = now
            session.commit()
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
