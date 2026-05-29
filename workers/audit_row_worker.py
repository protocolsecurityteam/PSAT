"""Base class for workers that drain a column-state-machine on ``audit_reports``.

Text-extraction and scope-extraction workers share claim + threadpool +
stale-recovery scaffolding. Subclasses override only what differs:

    _pending_rows_query   — eligibility SELECT (+ FOR UPDATE SKIP LOCKED)
    _mark_processing      — flip a claimed row to 'processing'
    _stale_recovery_query — reset a stuck row back to NULL
    _process_row          — the real work (runs on a thread)
    _persist_outcome      — write the result (opens its own session)

Not a ``workers.base.BaseWorker`` subclass: that drives the ``jobs``
queue via ``db.queue.claim_job``; this one drives the ``audit_reports``
column state machine. Same shape, different table — kept separate so
they can't drift into each other.
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
    """Poll-based worker drain for one phase of the ``audit_reports`` state machine."""

    # -- Subclass customization (class attributes) -------------------------

    # Prefix for worker_id and the starting log line. Override per-phase.
    worker_name: str = "AuditRow"

    # Canonical fleet process name for the ``/api/fleet`` heartbeat. Subclasses
    # set this to a ``db.queue.HEARTBEAT_*`` constant; left None for the base
    # so an un-specialised worker simply doesn't beat.
    heartbeat_process: str | None = None

    # Per-tick rows to claim; thread pool size; idle sleep when no work.
    batch_size: int = 4
    max_concurrent: int = 4
    idle_poll_interval: float = 10.0

    # Rows stuck in "processing" past this many seconds are reset.
    # Per poll cycles between recovery passes: higher = less DB traffic.
    stale_processing_seconds: int = 600
    stale_recovery_every_n_polls: int = 20

    thread_name_prefix: str = "audit-row"

    # Subclass should assign its own module logger so log lines carry the
    # right source location; defaults to this module's logger.
    log: logging.Logger = logger

    # -- Init / signals ---------------------------------------------------

    def __init__(self) -> None:
        # Idempotent — installs the JSON formatter so log lines from the
        # audit row state machine match the BaseWorker fleet's shape.
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

    # -- Abstract hooks ---------------------------------------------------

    def _pending_rows_query(self) -> Select:
        """SELECT of ``AuditReport`` rows ready to claim (with FOR UPDATE SKIP LOCKED)."""
        raise NotImplementedError

    def _mark_processing(self, row: AuditReport, now: datetime) -> None:
        """Flip the row's phase status + worker + started_at to 'processing'."""
        raise NotImplementedError

    def _stale_recovery_query(self, cutoff: datetime) -> Update:
        """UPDATE ... RETURNING id that resets rows stuck past ``cutoff``."""
        raise NotImplementedError

    def _process_row(self, audit: AuditReport) -> tuple[int, Any]:
        """Perform the phase's real work for one claimed row.

        Runs on a worker thread. Must NEVER raise — wrap any exceptions
        internally and return a failure-shaped outcome. The return value
        is handed verbatim to ``_persist_outcome`` (and ``_log_outcome``).
        The specific outcome type is phase-local.
        """
        raise NotImplementedError

    def _persist_outcome(self, audit_id: int, result: Any) -> None:
        """Write ``result`` back to the row. Uses its OWN session.

        Each row gets a fresh session so one row's failure never poisons
        another's commit. Subclass handles all row-state updates here,
        including any downstream refreshes (e.g. coverage) that should
        land in the same transaction as the state flip.
        """
        raise NotImplementedError

    def _log_outcome(self, audit_id: int, result: Any) -> None:
        """Default per-row log — one line with status and optional error.

        Subclasses override when the outcome type carries extra fields
        worth surfacing at INFO level (e.g. ``method``, ``contracts``
        count). The run loop logs AFTER persist so the log line reflects
        the write that actually happened.
        """
        status = getattr(result, "status", "?")
        error = getattr(result, "error", None)
        self.log.info(
            "Audit %s → %s%s",
            audit_id,
            status,
            f" ({error})" if error else "",
        )

    # -- Claim + stale recovery (shared) ----------------------------------

    def _claim_batch(self, session: Session) -> list[AuditReport]:
        """Atomically claim up to ``batch_size`` pending rows.

        SKIP LOCKED lets multiple workers run without coordinating:
        each one gets a distinct slice, locked rows pass silently, and
        no row is ever claimed twice. Rows are expunged so worker
        threads can read the fields off them without the session
        following the thread.
        """
        rows = list(session.execute(self._pending_rows_query()).scalars().all())
        if not rows:
            return []

        now = datetime.now(timezone.utc)
        for row in rows:
            self._mark_processing(row, now)
        session.commit()
        for row in rows:
            session.expunge(row)
        return rows

    def _recover_stale_rows(self, session: Session) -> None:
        """Reset rows stuck in 'processing' past ``stale_processing_seconds``.

        The prior claimer's process is assumed dead (crashed, hard-killed,
        or just lost connectivity past the timeout). Flipping their
        status back to pending lets the next claim pass re-run them.
        Rolls back when there's nothing to do so we don't leave an
        empty transaction open against Postgres.
        """
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

    # -- Main loop --------------------------------------------------------

    def run_loop(self) -> None:
        """Poll → claim → dispatch → persist → log, with periodic stale recovery.

        A single thread pool lives for the worker's lifetime. Inside one
        tick we claim a batch, fan it out to the pool, and serialize
        persist calls in whatever order the futures complete — each
        persist opens its own DB session so ordering is safe. Sleeps
        ``idle_poll_interval`` seconds when there's no work.
        """
        self.log.info(
            "%s worker %s starting (batch=%d, pool=%d, idle=%ss, stale=%ss)",
            self.worker_name,
            self.worker_id,
            self.batch_size,
            self.max_concurrent,
            self.idle_poll_interval,
            self.stale_processing_seconds,
        )

        # Mirror BaseWorker's [BOOT] line so audit-side RSS lands in the
        # same log shape the OOM-attribution scrapes already understand.
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

        # Per-batch RSS deltas vs boot let a leak hypothesis be tested
        # from logs alone: a clean worker plateaus, a leaking one drifts
        # monotonically. Tracked outside the loop so the delta is over
        # the whole worker lifetime, not just this batch.
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
                    # ``claimed_last_pass`` is the per-pass throughput count the
                    # fleet view diffs into a rate. The beat fires before the
                    # batch is processed (and on idle polls, so the daemon never
                    # reads as stale), so it's "rows claimed this pass" — 0 idle.
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

                # Per-submission ``copy_context`` so contextvars (e.g.
                # the worker_id bound by ``configure_logging`` callers)
                # survive the thread fan-out. ``Context.run`` cannot be
                # entered concurrently, so each future needs its own copy.
                futures = {}
                for row in claimed:
                    ctx = contextvars.copy_context()
                    futures[executor.submit(ctx.run, self._process_row, row)] = row.id
                for future in as_completed(futures):
                    try:
                        audit_id, result = future.result()
                    except Exception:
                        # _process_row contract says "never raise"; if
                        # one does, log and move on rather than leaking
                        # a 'processing' row until stale recovery runs.
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
