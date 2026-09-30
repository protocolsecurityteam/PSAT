"""Base for workers draining a column state machine on ``audit_reports``.

Not a ``BaseWorker`` subclass: that drives the ``jobs`` queue; this drives per-row status columns. Kept separate so they
can't drift into each other.
"""

from __future__ import annotations

import contextvars
import logging
import os
import signal
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.sql import Select, Update

from db.models import AuditReport, SessionLocal
from db.queue import record_heartbeat
from utils.logging import configure_logging
from utils.memory import (
    cgroup_memory_current_bytes,
    cgroup_memory_max_bytes,
    count_sibling_python_procs,
    current_rss_bytes,
    mb,
)

logger = logging.getLogger("workers.audit_row_worker")


class AuditRowWorker:
    worker_name: str = "AuditRow"

    # ``db.queue.HEARTBEAT_*`` name; None means the worker doesn't beat.
    heartbeat_process: str | None = None

    batch_size: int = 4
    max_concurrent: int = 4
    idle_poll_interval: float = 10.0

    stale_processing_seconds: int = 600
    stale_recovery_every_n_polls: int = 20

    thread_name_prefix: str = "audit-row"

    log: logging.Logger = logger

    def __init__(self) -> None:
        configure_logging()
        self.worker_id = f"{self.worker_name}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum: int, _frame: object) -> None:
        self.log.info(
            "Worker %s received signal %s, shutting down",
            self.worker_id,
            signum,
        )
        self._running = False

    def _pending_rows_query(self) -> Select:
        raise NotImplementedError

    def _mark_processing(self, row: AuditReport, now: datetime) -> None:
        raise NotImplementedError

    def _stale_recovery_query(self, cutoff: datetime) -> Update:
        raise NotImplementedError

    def _process_row(self, audit: AuditReport) -> tuple[int, Any]:
        """Runs on a worker thread and must never raise; return a failure-shaped outcome instead."""
        raise NotImplementedError

    def _persist_outcome(self, audit_id: int, result: Any) -> None:
        """Uses its own session so one row's failure never poisons another's commit."""
        raise NotImplementedError

    def _log_outcome(self, audit_id: int, result: Any) -> None:
        status = getattr(result, "status", "?")
        error = getattr(result, "error", None)
        self.log.info(
            "Audit %s → %s%s",
            audit_id,
            status,
            f" ({error})" if error else "",
        )

    def _claim_batch(self, session: Session) -> list[AuditReport]:
        """Claim up to ``batch_size`` rows with SKIP LOCKED; rows are expunged so worker threads can read them."""
        from services.worker_lifecycle import claim_allowed, note_claim

        if not claim_allowed(session):
            return []

        rows = list(session.execute(self._pending_rows_query()).scalars().all())
        if not rows:
            return []

        note_claim(session)
        now = datetime.now(timezone.utc)
        for row in rows:
            self._mark_processing(row, now)
        session.commit()
        for row in rows:
            session.expunge(row)
        return rows

    def _recover_stale_rows(self, session: Session) -> None:
        """Reset rows stuck in 'processing' past ``stale_processing_seconds``; the prior claimer is assumed dead."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.stale_processing_seconds)
        result = session.execute(self._stale_recovery_query(cutoff))
        ids = [row.id for row in result]
        if ids:
            self.log.warning(
                "Worker %s: reset %d stale row(s) back to pending: %s",
                self.worker_id,
                len(ids),
                ids,
            )
            session.commit()
        else:
            session.rollback()

    def run_loop(self) -> None:
        self.log.info(
            "%s worker %s starting (batch=%d, pool=%d, idle=%ss, stale=%ss)",
            self.worker_name,
            self.worker_id,
            self.batch_size,
            self.max_concurrent,
            self.idle_poll_interval,
            self.stale_processing_seconds,
        )

        # Mirrors BaseWorker's [BOOT] line so OOM-attribution scrapes parse it.
        boot_rss = current_rss_bytes()
        self.log.info(
            "[BOOT] worker=%s pid=%d phase=%s rss_mb=%s cgroup_used_mb=%s/%s python_siblings=%d pool=%d",
            self.worker_id,
            os.getpid(),
            self.worker_name,
            mb(boot_rss),
            mb(cgroup_memory_current_bytes()),
            mb(cgroup_memory_max_bytes()),
            count_sibling_python_procs(),
            self.max_concurrent,
        )

        executor = ThreadPoolExecutor(
            max_workers=self.max_concurrent,
            thread_name_prefix=self.thread_name_prefix,
        )

        # Delta vs boot over the worker lifetime: a leaking worker drifts monotonically.
        rss_at_boot = boot_rss
        batch_counter = 0
        poll_counter = 0
        try:
            while self._running:
                poll_counter += 1

                session = SessionLocal()
                try:
                    if poll_counter % self.stale_recovery_every_n_polls == 0:
                        self._recover_stale_rows(session)
                    claimed = self._claim_batch(session)
                finally:
                    session.close()

                if self.heartbeat_process:
                    # Fires before the batch (and on idle) so this counts rows claimed this pass.
                    record_heartbeat(
                        self.heartbeat_process,
                        status="running" if claimed else "idle",
                        detail={"claimed_last_pass": len(claimed)},
                    )
                if not claimed:
                    time.sleep(self.idle_poll_interval)
                    continue

                self.log.info(
                    "Worker %s claimed %d audit(s)",
                    self.worker_id,
                    len(claimed),
                )

                # ``Context.run`` cannot be entered concurrently, so each future needs its own context copy.
                futures = {}
                for row in claimed:
                    ctx = contextvars.copy_context()
                    futures[executor.submit(ctx.run, self._process_row, row)] = row.id
                for future in as_completed(futures):
                    try:
                        audit_id, result = future.result()
                    except Exception:
                        # _process_row must never raise; log rather than leak a 'processing' row until stale recovery.
                        self.log.exception("Unexpected error in %s thread", self.worker_name)
                        continue
                    self._persist_outcome(audit_id, result)
                    self._log_outcome(audit_id, result)

                batch_counter += 1
                rss_after = current_rss_bytes()
                self.log.info(
                    "[BATCH] worker=%s phase=%s batch=%d processed=%d rss_mb=%s "
                    "delta_since_boot_mb=%+d cgroup_used_mb=%s",
                    self.worker_id,
                    self.worker_name,
                    batch_counter,
                    len(claimed),
                    mb(rss_after),
                    int((rss_after - rss_at_boot) / (1024 * 1024)),
                    mb(cgroup_memory_current_bytes()),
                )
        finally:
            executor.shutdown(wait=True)
            self.log.info("Worker %s shut down", self.worker_id)
