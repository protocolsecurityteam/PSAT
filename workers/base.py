"""Base worker loop with graceful SIGTERM handling."""

from __future__ import annotations

import contextvars
import logging
import os
import signal
import threading
import time
import traceback
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Job, JobDependency, JobStage, JobStatus, SessionLocal
from db.queue import (
    DEFAULT_JOB_LEASE_TTL_S,
    LeaseLost,
    advance_job,
    claim_job,
    fail_job_terminal,
    get_artifact,
    heartbeat_job,
    reclaim_stuck_jobs,
    release_job_lease,
    requeue_job,
    store_artifact,
    update_job_detail,
)
from schemas.stage_errors import StageError, StageErrors
from utils.logging import bind_trace_context, configure_logging, degraded_errors_var, stage_metrics_var
from utils.memory import (
    cgroup_memory_current_bytes,
    cgroup_memory_max_bytes,
    count_sibling_python_procs,
    current_rss_bytes,
    mb,
)
from workers.retry_policy import classify, compute_next_attempt, max_retries

logger = logging.getLogger(__name__)

# Bumped to 600 alongside the threaded fan-outs: any single fan-out section can now legitimately go
# minutes without a status/detail write, so the previous 180s default would requeue live jobs.
# Mid-fan-out heartbeats (``BaseWorker._heartbeat``) keep ``updated_at`` fresh inside the long sections.
STALE_JOB_TIMEOUT = int(os.getenv("PSAT_STALE_JOB_TIMEOUT", "600"))  # seconds

# Per-worker throttle for the stuck-job sweep; default 30s keeps fleet sweeps well under the 900s stale_timeout while
# cutting per-poll DB load.
RECLAIM_INTERVAL_S = float(os.getenv("PSAT_RECLAIM_INTERVAL_S", "30"))


def _job_heartbeat_interval_s() -> float:
    """Resolve the max wait between background job heartbeats."""
    try:
        value = float(os.getenv("PSAT_JOB_HEARTBEAT_INTERVAL_S", os.getenv("PSAT_PARALLEL_HEARTBEAT_INTERVAL_S", "30")))
    except ValueError:
        return 30.0
    return max(0.1, value)


def _resolve_job_concurrency(stage_value: str) -> int:
    """Resolve K (max concurrent jobs per worker process) for *stage_value*.

    Precedence: per-stage env (``PSAT_<STAGE>_JOB_CONCURRENCY``) → global
    ``PSAT_JOB_CONCURRENCY`` → 1. K=1 takes a fast path that's behaviourally
    identical to the pre-concurrency loop; K>1 opts into the futures-based
    dispatcher. Subclasses that override ``_claim_job`` (coverage,
    selection — readiness-gated) stay K=1 implicitly: the per-stage env is
    just never set for them in production.
    """

    def _read(name: str) -> int | None:
        raw = os.getenv(name)
        if not raw:
            return None
        try:
            return max(1, int(raw))
        except ValueError:
            return None

    per_stage = _read(f"PSAT_{stage_value.upper()}_JOB_CONCURRENCY")
    if per_stage is not None:
        return per_stage
    return _read("PSAT_JOB_CONCURRENCY") or 1


class JobHandledDirectly(Exception):
    """Raised by process() when it has already completed/failed the job itself."""

    pass


class BaseWorker:
    """Poll-based worker that claims jobs for a specific pipeline stage."""

    stage: JobStage
    next_stage: JobStage
    poll_interval: float = 2.0

    def __init__(self) -> None:
        # Idempotent — the per-worker ``main()`` may have already called
        # this, but a bare ``BaseWorker()`` constructed in tests still
        # gets the JSON formatter installed so emitted log lines parse.
        configure_logging()
        self.worker_id = f"{self.__class__.__name__}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._running = True
        # -inf = "never swept; sweep now"; throttles _claim_job to RECLAIM_INTERVAL_S between sweeps.
        self._last_reclaim_at: float = float("-inf")
        # Currently-claimed job_id → claim-time lease_id. Populated by
        # ``_execute_job`` for the duration of a single job, drained on
        # success/failure. ``_handle_sigterm`` reads a snapshot of this
        # map and explicitly releases each lease via ``release_job_lease``
        # so a Fly machine drain doesn't strand the row in ``processing``
        # for the full 15-minute lease TTL — observed on PR-63 as a 16+
        # minute static-stage wedge after a worker SIGTERM mid-forge-build.
        self._inflight_jobs: dict[uuid.UUID, uuid.UUID] = {}
        self._inflight_lock = threading.Lock()
        # Set when graceful shutdown has spawned its release thread; idempotent
        # guard against duplicate handler invocations (Fly sends SIGTERM twice
        # before SIGKILL).
        self._shutdown_release_started = False
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigterm)

        # In-process job concurrency: K=1 keeps the legacy single-job loop
        # byte-identical; K>1 spins up a per-worker thread pool so RPC waits
        # in one job overlap with another job's CPU work. Resolved once at
        # boot so per-stage env tuning (e.g. PSAT_RESOLUTION_JOB_CONCURRENCY=2)
        # is visible in the boot banner below.
        stage_attr = getattr(self, "stage", None)
        stage_str = stage_attr.value if stage_attr is not None else "?"
        self._job_concurrency = _resolve_job_concurrency(stage_str)
        self._job_pool: ThreadPoolExecutor | None = None
        self._inflight: set[Future[None]] = set()
        if self._job_concurrency > 1:
            self._job_pool = ThreadPoolExecutor(
                max_workers=self._job_concurrency,
                thread_name_prefix=f"{self.__class__.__name__}-job",
            )

        # One-line boot banner per worker process so a fly-log scrape can
        # reconstruct the fleet shape that hit OOM. Captures stage + RSS at
        # boot + the cgroup memory limit + sibling python proc count.
        # `stage` is a class attribute set by subclasses; default to "?"
        # so bare BaseWorker() in unit tests doesn't trip AttributeError.
        logger.info(
            "[BOOT] worker=%s pid=%d stage=%s rss_mb=%s cgroup_used_mb=%s/%s python_siblings=%d job_concurrency=%d",
            self.worker_id,
            os.getpid(),
            stage_str,
            mb(current_rss_bytes()),
            mb(cgroup_memory_current_bytes()),
            mb(cgroup_memory_max_bytes()),
            count_sibling_python_procs(),
            self._job_concurrency,
        )

    def _handle_sigterm(self, signum: int, frame: object) -> None:
        logger.info("Worker %s received signal %s, shutting down gracefully", self.worker_id, signum)
        self._running = False
        # Release the currently-claimed job's lease on a daemon thread so a
        # sibling worker can immediately reclaim. The main thread is likely
        # blocked in ``subprocess.run`` (forge build, slither) — it cannot
        # release for itself before Fly escalates to SIGKILL. The daemon
        # thread opens its own ``SessionLocal()`` so it doesn't share the
        # main thread's session state, and finishes well within Fly's
        # ``kill_timeout``.
        if self._shutdown_release_started:
            return
        self._shutdown_release_started = True
        threading.Thread(
            target=self._release_inflight_leases,
            name=f"{self.worker_id}-shutdown-release",
            daemon=True,
        ).start()

    def _release_inflight_leases(self) -> None:
        """Release every lease in ``self._inflight_jobs``.

        Runs on a daemon thread spawned by ``_handle_sigterm``. Uses
        ``release_job_lease`` (SQL-level conditional UPDATE on
        ``lease_id``) so the call is a no-op if the main thread raced to
        ``complete_job`` first or ``reclaim_stuck_jobs`` already swept.
        Errors are logged and swallowed — the worker is shutting down
        either way; failing here would just crash the daemon thread.
        """
        with self._inflight_lock:
            snapshot = dict(self._inflight_jobs)
        if not snapshot:
            return
        logger.info(
            "Worker %s releasing %d in-flight job lease(s) before shutdown",
            self.worker_id,
            len(snapshot),
        )
        session = SessionLocal()
        try:
            for job_id, lease_id in snapshot.items():
                try:
                    released = release_job_lease(
                        session,
                        job_id,
                        lease_id=lease_id,
                        reason=f"graceful shutdown of {self.worker_id}",
                    )
                except Exception:
                    logger.exception(
                        "Worker %s: failed to release lease for job %s",
                        self.worker_id,
                        job_id,
                    )
                    continue
                if released:
                    logger.info("Worker %s released lease for job %s", self.worker_id, job_id)
                else:
                    logger.info(
                        "Worker %s: lease for job %s already gone (sibling reclaimed or main "
                        "thread completed it first)",
                        self.worker_id,
                        job_id,
                    )
        finally:
            session.close()

    def process(self, session: Session, job: Job) -> None:
        """Subclasses implement this to run their pipeline stage."""
        raise NotImplementedError

    def _claim_job(self, session: Session) -> Job | None:
        """Throttled stuck-job sweep + claim; override for readiness-gated or multi-phase claim patterns."""
        now = time.monotonic()
        if now - self._last_reclaim_at >= RECLAIM_INTERVAL_S:
            reclaim_stuck_jobs(session)
            self._last_reclaim_at = now
        return claim_job(session, self.stage, self.worker_id)

    def _recover_stale_jobs(self, session: Session) -> None:
        """Requeue jobs stuck in 'processing' for longer than STALE_JOB_TIMEOUT."""
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=STALE_JOB_TIMEOUT)
        stale = (
            session.execute(
                select(Job).where(
                    Job.stage == self.stage,
                    Job.status == JobStatus.processing,
                    Job.updated_at < cutoff,
                )
            )
            .scalars()
            .all()
        )
        for job in stale:
            logger.warning(
                "Worker %s: requeuing stale job %s (%s) — stuck since %s",
                self.worker_id,
                job.id,
                job.name or job.address,
                job.updated_at.isoformat(),
            )
            job.status = JobStatus.queued
            job.worker_id = None
            job.detail = "Re-queued after stale processing timeout"
        if stale:
            session.commit()

    def _execute_job(self, session: Session, job: Job) -> None:
        """Run a single claimed job to completion: process → record timing → advance/complete/fail.

        Owns the full lifecycle of one (session, job) pair. Caller is
        responsible for closing *session* afterwards. Both the legacy
        single-job loop and the K>1 dispatcher route through here so the
        success/JobHandledDirectly/exception branches stay in one place.

        The whole body runs inside a ``bind_trace_context`` so every
        log line emitted from any helper called by ``process()`` carries
        the same ``trace_id`` / ``job_id`` / ``stage`` / ``worker_id``
        without callers having to thread them through.
        """
        # ``getattr`` defaults guard the test stubs that pass a bare
        # ``SimpleNamespace`` job without a request/trace_id field.
        raw_request = getattr(job, "request", None)
        request = raw_request if isinstance(raw_request, dict) else {}
        with bind_trace_context(
            trace_id=getattr(job, "trace_id", None),
            job_id=str(job.id),
            stage=self.stage.value,
            worker_id=self.worker_id,
            address=getattr(job, "address", None),
            chain=request.get("chain"),
        ):
            # Per-job accumulator for ``record_degraded`` calls. Reset
            # alongside ``bind_trace_context`` so K>1 jobs running in
            # parallel pool threads don't share a list (each thread's
            # context is a copy from the dispatcher).
            degraded_accumulator: list[StageError] = []
            accumulator_token = degraded_errors_var.set(degraded_accumulator)
            # Per-job accumulator for ``record_stage_metric`` calls. Bound and
            # reset alongside the degraded accumulator (same per-thread reasons)
            # and folded into this stage's ``stage_timing_<stage>`` artifact by
            # ``_record_stage_timing``.
            stage_metrics: dict[str, Any] = {}
            metrics_token = stage_metrics_var.set(stage_metrics)
            # Snapshot the lease at claim time so every mutating queue
            # write threads it through. ``getattr`` keeps test stubs that
            # build a bare SimpleNamespace job from tripping AttributeError.
            claim_job_id = getattr(job, "id")
            claim_lease_id = getattr(job, "lease_id", None)
            # Heartbeats run from background/parallel helper threads. Keep
            # them on the immutable claim-time token instead of rereading ORM
            # attributes from a long-lived worker session.
            setattr(job, "_heartbeat_job_id", claim_job_id)
            setattr(job, "_heartbeat_lease_id", claim_lease_id)
            # Register this (job_id, lease_id) for graceful-shutdown release.
            # ``_handle_sigterm`` reads this map on its daemon thread; the
            # ``finally`` below removes the entry whether the job completes,
            # advances, or errors so a stale id never lingers.
            inflight_registered = False
            if claim_lease_id is not None:
                with self._inflight_lock:
                    self._inflight_jobs[claim_job_id] = claim_lease_id
                inflight_registered = True
            heartbeat_stop = threading.Event()
            heartbeat_thread: threading.Thread | None = None

            def _background_heartbeat() -> None:
                while not heartbeat_stop.wait(_job_heartbeat_interval_s()):
                    try:
                        self._heartbeat(session, job)
                    except LeaseLost as lease_exc:
                        logger.warning(
                            "Worker %s: background heartbeat lost lease for job %s: %s",
                            self.worker_id,
                            claim_job_id,
                            lease_exc,
                            extra={"phase": "job", "outcome": "lease_lost"},
                        )
                        return
                    except Exception:
                        logger.warning(
                            "Worker %s: background heartbeat failed for job %s",
                            self.worker_id,
                            claim_job_id,
                        )

            if claim_lease_id is not None:
                heartbeat_thread = threading.Thread(
                    target=_background_heartbeat,
                    name=f"{self.worker_id}-heartbeat-{str(job.id)[:8]}",
                    daemon=True,
                )
                heartbeat_thread.start()
            try:
                logger.info("Worker %s claimed job %s", self.worker_id, job.id)
                t0 = time.monotonic()
                rss_before = current_rss_bytes()
                started_at_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                try:
                    self.process(session, job)
                    elapsed = time.monotonic() - t0
                    ended_at_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    rss_after = current_rss_bytes()
                    rss_delta_mb = (rss_after - rss_before) / (1024 * 1024)
                    logger.info(
                        "[JOB] worker=%s job=%s stage=%s elapsed_s=%.1f rss_mb=%s delta_mb=%+.0f cgroup_used_mb=%s",
                        self.worker_id,
                        job.id,
                        self.stage.value,
                        elapsed,
                        mb(rss_after),
                        rss_delta_mb,
                        mb(cgroup_memory_current_bytes()),
                        extra={
                            "duration_ms": int(elapsed * 1000),
                            "phase": "job",
                            "rss_mb": mb(rss_after),
                            "rss_delta_mb": round(rss_delta_mb, 1),
                        },
                    )
                    # Record timing before advancing — otherwise the next-stage worker can race read-modify-write on the
                    # shared stage_timings artifact.
                    self._record_stage_timing(
                        session,
                        job,
                        started_at=started_at_iso,
                        ended_at=ended_at_iso,
                        elapsed_s=elapsed,
                        status="success",
                    )
                    # Drain degraded entries before advancing so a stage_errors
                    # artifact is visible to the next-stage worker at its claim.
                    if degraded_accumulator:
                        self._persist_stage_errors(job, degraded_accumulator)
                    # Flip JobDependency rows where this job is the provider
                    # and its just-completed stage meets-or-exceeds the
                    # depender's required_stage. Queued in the same tx as
                    # advance_job/complete_job below so dependents become
                    # claimable atomically with the stage change.
                    self._satisfy_dependencies(session, job, completed_stage=self.stage)
                    if self.next_stage == JobStage.done:
                        from db.queue import complete_job

                        complete_job(session, job.id, lease_id=claim_lease_id)
                    else:
                        advance_job(
                            session,
                            job.id,
                            self.next_stage,
                            f"Completed {self.stage.value}",
                            lease_id=claim_lease_id,
                        )
                    logger.info(
                        "Worker %s completed job %s in %.1fs",
                        self.worker_id,
                        job.id,
                        elapsed,
                        extra={"duration_ms": int(elapsed * 1000), "phase": "job", "outcome": "success"},
                    )
                except JobHandledDirectly:
                    elapsed = time.monotonic() - t0
                    ended_at_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    # Fresh session — process() may have left the original in an inconsistent state.
                    try:
                        fresh_for_timing = SessionLocal()
                        self._record_stage_timing(
                            fresh_for_timing,
                            job,
                            started_at=started_at_iso,
                            ended_at=ended_at_iso,
                            elapsed_s=elapsed,
                            status="handled_directly",
                        )
                        fresh_for_timing.close()
                    except Exception:
                        logger.exception("Worker %s: failed to record handled_directly timing", self.worker_id)
                    if degraded_accumulator:
                        self._persist_stage_errors(job, degraded_accumulator)
                    logger.info(
                        "Worker %s: job %s handled directly by process()",
                        self.worker_id,
                        job.id,
                        extra={"duration_ms": int(elapsed * 1000), "phase": "job", "outcome": "handled_directly"},
                    )
                except LeaseLost as lease_exc:
                    # The row's lease has rolled to a sibling worker (e.g.
                    # the long-task heartbeat tripped the sweep, then a
                    # sibling claim_job acquired the row). Bailing here
                    # rather than continuing through the requeue/terminal
                    # path is the whole point: any further write would
                    # corrupt the sibling's view of the job.
                    logger.warning(
                        "Worker %s: lease lost for job %s — abandoning attempt: %s",
                        self.worker_id,
                        job.id,
                        lease_exc,
                        extra={"phase": "job", "outcome": "lease_lost"},
                    )
                    return
                except Exception as exc:
                    from utils.secrets import sanitize_string

                    # A failed flush/commit inside ``process()`` leaves the
                    # session in a pending-rollback state and can leave ``job``
                    # with expired attributes. Roll back BEFORE reading any ORM
                    # attribute (``job.retry_count`` just below): on an
                    # un-rolled-back session that lazy-load re-raises
                    # PendingRollbackError, which escapes this handler so the
                    # job is never marked failed/requeued. It stays 'processing'
                    # and only the stale-job sweep recovers it — never bumping
                    # retry_count — i.e. an unbounded poison-retry loop that
                    # stalls the whole pipeline.
                    try:
                        session.rollback()
                    except Exception:
                        logger.exception(
                            "Worker %s: rollback in failure handler failed for job %s",
                            self.worker_id,
                            getattr(job, "id", "?"),
                        )

                    elapsed = time.monotonic() - t0
                    ended_at_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    error = sanitize_string(traceback.format_exc())
                    exc_message = sanitize_string(str(exc))
                    # Decide retry vs terminal up front. ``prior_retry_count``
                    # is the count of attempts that had ALREADY failed before
                    # the current one — i.e. what we tag the just-failed
                    # attempt with in the StageErrors history. ``new_retry_count``
                    # is what the row's ``retry_count`` becomes after this
                    # attempt is recorded.
                    kind = classify(exc)
                    prior_retry_count = getattr(job, "retry_count", 0) or 0
                    new_retry_count = prior_retry_count + 1
                    will_retry = kind == "transient" and new_retry_count < max_retries()
                    next_attempt_at = compute_next_attempt(prior_retry_count) if will_retry else None
                    outcome = "requeued" if will_retry else "failed_terminal"
                    exc_type_str = f"{type(exc).__module__}.{type(exc).__name__}"
                    # Banner: WARNING for retry (the job will run again, so
                    # it's not a failure); ERROR for terminal so ops alerts
                    # still fire on real failures.
                    log_fn = logger.warning if will_retry else logger.error
                    log_fn(
                        "\n=================== WORKER FAILURE ===================\n"
                        "Worker:   %s\n"
                        "Job:      %s\n"
                        "Address:  %s\n"
                        "Name:     %s\n"
                        "Stage:    %s\n"
                        "Outcome:  %s (retry_count=%d)\n"
                        "-------------------------------------------------------\n"
                        "%s"
                        "=======================================================",
                        self.worker_id,
                        job.id,
                        getattr(job, "address", "?"),
                        getattr(job, "name", "?"),
                        self.stage.value,
                        outcome,
                        new_retry_count if will_retry else prior_retry_count,
                        error,
                        extra={
                            "duration_ms": int(elapsed * 1000),
                            "phase": "job",
                            "outcome": outcome,
                            "exc_type": exc_type_str,
                            "retry_count": new_retry_count if will_retry else prior_retry_count,
                            "next_attempt_at": next_attempt_at.isoformat() if next_attempt_at else None,
                            "failure_kind": kind,
                        },
                    )
                    # Append the job-failing exception alongside any degraded
                    # entries the run produced before the crash, tagged with
                    # the just-failed attempt's ``retry_count`` so the
                    # accumulator history reads chronologically (0, 1, 2, …).
                    # Persist via a fresh session inside ``_persist_stage_errors``
                    # so a poisoned primary transaction can't take the
                    # artifact down with it.
                    degraded_accumulator.append(
                        StageError(
                            stage=self.stage.value,
                            severity="error",
                            exc_type=exc_type_str,
                            message=exc_message,
                            traceback=error,
                            phase=None,
                            trace_id=getattr(job, "trace_id", None),
                            job_id=str(job.id),
                            worker_id=self.worker_id,
                            failed_at=datetime.now(timezone.utc),
                            retry_count=prior_retry_count,
                        )
                    )
                    self._persist_stage_errors(job, degraded_accumulator)
                    # On retries-exhaustion (kind=transient but no more
                    # retries left), the row records the full attempt count;
                    # on deterministic terminal (kind=terminal), retry_count
                    # stays at its current value because no retry slot was
                    # consumed by this attempt — we never even scheduled one.
                    terminal_retry_count = new_retry_count if kind == "transient" else None
                    try:
                        session.rollback()
                        if will_retry:
                            assert next_attempt_at is not None  # type-narrow for pyright
                            requeue_job(
                                session,
                                job.id,
                                error,
                                retry_count=new_retry_count,
                                next_attempt_at=next_attempt_at,
                                lease_id=claim_lease_id,
                            )
                        else:
                            # Terminal failure → flip pending deps where this
                            # job is the provider to ``degraded`` so dependents
                            # short-circuit instead of blocking forever.
                            # Queued before fail_job_terminal so the same tx
                            # commits both.
                            self._degrade_dependencies(session, job)
                            fail_job_terminal(
                                session,
                                job.id,
                                error,
                                kind=kind,
                                retry_count=terminal_retry_count,
                                lease_id=claim_lease_id,
                            )
                        self._record_stage_timing(
                            session,
                            job,
                            started_at=started_at_iso,
                            ended_at=ended_at_iso,
                            elapsed_s=elapsed,
                            status="failed",
                        )
                    except LeaseLost as lease_exc:
                        # Same bail as the success path: a sibling owns
                        # the row now; persisting our failure would
                        # corrupt their state.
                        logger.warning(
                            "Worker %s: lease lost during failure path for job %s: %s",
                            self.worker_id,
                            job.id,
                            lease_exc,
                            extra={"phase": "job", "outcome": "lease_lost"},
                        )
                        return
                    except Exception:
                        logger.exception("Failed to update job %s after exception, retrying with fresh session", job.id)
                        try:
                            fresh = SessionLocal()
                            truncated = error[-4000:]
                            if will_retry:
                                assert next_attempt_at is not None
                                requeue_job(
                                    fresh,
                                    job.id,
                                    truncated,
                                    retry_count=new_retry_count,
                                    next_attempt_at=next_attempt_at,
                                    lease_id=claim_lease_id,
                                )
                            else:
                                self._degrade_dependencies(fresh, job)
                                fail_job_terminal(
                                    fresh,
                                    job.id,
                                    truncated,
                                    kind=kind,
                                    retry_count=terminal_retry_count,
                                    lease_id=claim_lease_id,
                                )
                            self._record_stage_timing(
                                fresh,
                                job,
                                started_at=started_at_iso,
                                ended_at=ended_at_iso,
                                elapsed_s=elapsed,
                                status="failed",
                            )
                            fresh.close()
                        except LeaseLost as lease_exc:
                            logger.warning(
                                "Worker %s: lease lost in fresh-session failure path for job %s: %s",
                                self.worker_id,
                                job.id,
                                lease_exc,
                                extra={"phase": "job", "outcome": "lease_lost"},
                            )
                            return
                        except Exception:
                            logger.exception(
                                "Could not update job %s for retry/terminal even with fresh session", job.id
                            )
            finally:
                heartbeat_stop.set()
                if heartbeat_thread is not None:
                    heartbeat_thread.join(timeout=1)
                degraded_errors_var.reset(accumulator_token)
                stage_metrics_var.reset(metrics_token)
                if inflight_registered:
                    with self._inflight_lock:
                        self._inflight_jobs.pop(claim_job_id, None)

    def _run_one_job(self, job_id) -> None:
        """K>1 dispatcher entry point: open a per-job session, re-fetch the job
        ORM object inside that session, run it through ``_execute_job``, close.

        The claim happened on a different (claim-loop) session that's already
        been closed; using ``session.get`` here re-binds the row to *this*
        thread's session so all heartbeats and DB writes belong to one
        identity map. Errors inside the job are absorbed by ``_execute_job``;
        anything that escapes is logged and dropped to keep the dispatcher
        loop alive.
        """
        session = SessionLocal()
        try:
            job = session.get(Job, job_id)
            if job is None:
                logger.warning("Worker %s: claimed job %s vanished before processing", self.worker_id, job_id)
                return
            self._execute_job(session, job)
        except Exception:
            logger.exception("Worker %s: unexpected error in dispatched job %s", self.worker_id, job_id)
        finally:
            session.close()

    def run_loop(self) -> None:
        logger.info(
            "Worker %s starting (stage=%s, job_concurrency=%d)",
            self.worker_id,
            self.stage.value,
            self._job_concurrency,
        )
        if self._job_concurrency > 1:
            self._run_loop_concurrent()
        else:
            self._run_loop_single()
        logger.info("Worker %s shut down", self.worker_id)

    def _run_loop_single(self) -> None:
        """Legacy K=1 loop: one in-flight job per worker process. Path is
        byte-identical to the pre-concurrency implementation."""
        recovery_counter = 0
        while self._running:
            session = SessionLocal()
            try:
                # Check for stale jobs every ~30 poll cycles (~60s at 2s interval)
                recovery_counter += 1
                if recovery_counter >= 30:
                    recovery_counter = 0
                    self._recover_stale_jobs(session)

                job = self._claim_job(session)
                if job is None:
                    session.close()
                    time.sleep(self.poll_interval)
                    continue

                self._execute_job(session, job)
            except Exception:
                logger.exception("Worker %s encountered error in main loop", self.worker_id)
            finally:
                session.close()

    def _run_loop_concurrent(self) -> None:
        """K>1 loop: claim jobs on a short-lived claim session and dispatch
        each into a per-worker ``ThreadPoolExecutor``. The pool is bounded
        at ``self._job_concurrency``; when full, the loop waits on
        ``FIRST_COMPLETED`` for back-pressure instead of polling.

        SIGTERM (``self._running == False``) stops new claims and waits up
        to ``STALE_JOB_TIMEOUT`` for in-flight jobs to drain before
        returning. Survivors are logged; the cross-worker stale-job sweep
        recovers them on a sibling worker.
        """
        assert self._job_pool is not None
        recovery_counter = 0
        while self._running:
            # Drain finished futures so the slot count is accurate.
            self._reap_finished_futures()

            if len(self._inflight) >= self._job_concurrency:
                # Pool is full: block until any future finishes (with a
                # ceiling so we still notice SIGTERM in time).
                wait(self._inflight, timeout=self.poll_interval, return_when=FIRST_COMPLETED)
                continue

            claim_session = SessionLocal()
            job_to_dispatch: Job | None = None
            job_id_for_dispatch = None
            try:
                recovery_counter += 1
                if recovery_counter >= 30:
                    recovery_counter = 0
                    self._recover_stale_jobs(claim_session)

                job_to_dispatch = self._claim_job(claim_session)
                if job_to_dispatch is not None:
                    # Capture the id before the session closes — the ORM
                    # object will be expired/detached on the dispatcher
                    # thread and we rebuild it via session.get there.
                    job_id_for_dispatch = job_to_dispatch.id
            except Exception:
                logger.exception("Worker %s encountered error in claim loop", self.worker_id)
            finally:
                claim_session.close()

            if job_id_for_dispatch is None:
                # Nothing to claim — sleep just enough to avoid hammering
                # Postgres while still letting in-flight futures progress.
                if self._inflight:
                    wait(self._inflight, timeout=self.poll_interval, return_when=FIRST_COMPLETED)
                else:
                    time.sleep(self.poll_interval)
                continue

            # ``ThreadPoolExecutor.submit`` does not propagate contextvars
            # by default; wrap with ``copy_context().run`` so the dispatched
            # job inherits the claim-loop's contextvar state. The per-job
            # ``bind_trace_context`` inside ``_execute_job`` then layers on
            # the job-specific bind once the row is loaded.
            ctx = contextvars.copy_context()
            future = self._job_pool.submit(ctx.run, self._run_one_job, job_id_for_dispatch)
            self._inflight.add(future)

        # Drain on shutdown so in-flight jobs land cleanly. Anything still
        # running past the timeout is logged; the cross-worker sweep
        # (``reclaim_stuck_jobs``) recovers them after STALE_JOB_TIMEOUT.
        if self._inflight:
            logger.info(
                "Worker %s draining %d in-flight job(s) (timeout=%ds)",
                self.worker_id,
                len(self._inflight),
                STALE_JOB_TIMEOUT,
            )
            done, not_done = wait(self._inflight, timeout=STALE_JOB_TIMEOUT)
            if not_done:
                logger.warning(
                    "Worker %s: %d job(s) still running at shutdown; "
                    "abandoning so cross-worker stale sweep can recover",
                    self.worker_id,
                    len(not_done),
                )
            self._inflight.clear()
        if self._job_pool is not None:
            self._job_pool.shutdown(wait=False)

    def _reap_finished_futures(self) -> None:
        """Drop completed futures from ``self._inflight`` to free dispatch slots."""
        finished = {f for f in self._inflight if f.done()}
        if finished:
            self._inflight -= finished

    def update_detail(self, session: Session, job: Job, detail: str) -> None:
        """Update the job's progress detail message."""
        update_job_detail(session, job.id, detail)

    def _heartbeat(self, session: Session, job: Job) -> None:  # noqa: ARG002 — session kept for caller back-compat
        """Extend the row's lease past now+ttl using a fresh session.

        The *session* arg is intentionally ignored. Callers pass their
        worker's main ORM session by reflex, but we open a fresh
        ``SessionLocal()`` for the actual write — see the bug below.

        Used inside long parallel sections so the stale-job sweep doesn't
        requeue live work. The conditional UPDATE inside ``heartbeat_job``
        only matches when ``lease_id`` still equals the row's claim-time
        lease — a reclaimed worker's heartbeat is a no-op and ``LeaseLost``
        is raised so the caller can bail.

        Why a fresh session: the worker's main session sits idle for
        minutes during long parallel sections (forge build fan-outs run
        in the executor pool while the worker thread blocks in semaphore
        / ``as_completed``). Neon's pooler-side SSL idle timeout closes
        that idle connection. If we issued the heartbeat UPDATE through
        the worker's session, ``session.execute`` raises
        ``OperationalError``; the previous version of this method
        swallowed that at DEBUG level — ``updated_at`` never refreshed,
        the stale-job sweep requeued live work to a sibling worker, and
        the symptom looked just like the old materialize_or_wait SSL
        bug. A fresh session goes through the pool with
        ``pool_pre_ping=True`` so dead connections are replaced on
        checkout; the heartbeat write is a single short UPDATE so the
        new session's lifecycle is sub-second.

        ``LeaseLost`` is intentionally NOT swallowed: the catch site in
        ``_execute_job`` needs to see it so the worker stops doing
        further work on a job a sibling now owns. Other exceptions are
        logged at WARNING (used to be DEBUG) — the heartbeat is
        load-bearing for stall detection, and silent failures on a
        critical path is what hid this bug across multiple PR previews.
        """
        missing = object()
        job_id = getattr(job, "_heartbeat_job_id", missing)
        if job_id is missing:
            job_id = getattr(job, "id")
        lease_id = getattr(job, "_heartbeat_lease_id", missing)
        if lease_id is missing:
            lease_id = getattr(job, "lease_id", None)
        if lease_id is None:
            # Pre-migration row, or a job claimed by an out-of-process
            # legacy claim path; fall back to bumping updated_at so the
            # legacy sweep predicate still keeps the row alive.
            from sqlalchemy import update as sa_update

            try:
                with SessionLocal() as fresh:
                    fresh.execute(sa_update(Job).where(Job.id == job_id).values(updated_at=datetime.now(timezone.utc)))
                    fresh.commit()
            except Exception:
                logger.warning("heartbeat (legacy path) write failed", exc_info=True)
            return

        try:
            with SessionLocal() as fresh:
                heartbeat_job(
                    fresh,
                    job_id,
                    lease_id=cast(uuid.UUID, lease_id),
                    lease_ttl_seconds=DEFAULT_JOB_LEASE_TTL_S,
                )
        except LeaseLost:
            raise
        except Exception:
            logger.warning("heartbeat write failed (non-fatal)", exc_info=True)

    def _satisfy_dependencies(self, session: Session, job: Job, *, completed_stage: JobStage) -> int:
        """Mark every pending ``JobDependency`` row whose provider is this
        job as ``satisfied`` when the just-completed stage meets-or-exceeds
        the depender's ``required_stage``.

        Stage ordering follows the natural ``JobStage`` enum order
        (discovery < dapp_crawl < ... < policy < coverage < done). Mutates
        rows IN this session WITHOUT committing — the caller's
        ``advance_job`` / ``complete_job`` commit flushes them in the same
        transaction so dependents become claimable atomically with the
        provider's stage change.

        Returns the count of rows flipped (mostly for logging / tests).
        Best-effort: a query failure logs and returns 0 rather than
        propagating; the success path of stage advancement should not be
        blocked by a dependency-bookkeeping bug.
        """
        chain = self._provider_chain_for(job)
        addr = (getattr(job, "address", None) or "").lower()
        if not addr:
            return 0
        try:
            stage_order = [s.value for s in JobStage]
            completed_idx = stage_order.index(completed_stage.value)
            satisfied_stages = {s for s in JobStage if stage_order.index(s.value) <= completed_idx}
            stmt = select(JobDependency).where(
                JobDependency.provider_chain == chain,
                JobDependency.provider_address == addr,
                JobDependency.status == "pending",
                JobDependency.required_stage.in_(satisfied_stages),
            )
            rows = session.execute(stmt).scalars().all()
            now = datetime.now(timezone.utc)
            for row in rows:
                row.status = "satisfied"
                row.satisfied_at = now
            if rows:
                logger.info(
                    "Worker %s: job %s satisfied %d dependent edge(s) on completing %s",
                    self.worker_id,
                    job.id,
                    len(rows),
                    completed_stage.value,
                    extra={"dependents_satisfied": len(rows), "completed_stage": completed_stage.value},
                )
            return len(rows)
        except Exception as exc:
            logger.warning(
                "satisfy_dependencies failed for job %s: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            return 0

    def _degrade_dependencies(self, session: Session, job: Job) -> int:
        """Mark every pending ``JobDependency`` row whose provider is this
        job as ``degraded`` after the provider terminally fails.

        Dependents short-circuit cross-contract authority leaves to
        ``external_check_only`` rather than block forever. Same
        non-committing semantics as ``_satisfy_dependencies``.
        """
        chain = self._provider_chain_for(job)
        addr = (getattr(job, "address", None) or "").lower()
        if not addr:
            return 0
        try:
            stmt = select(JobDependency).where(
                JobDependency.provider_chain == chain,
                JobDependency.provider_address == addr,
                JobDependency.status == "pending",
            )
            rows = session.execute(stmt).scalars().all()
            now = datetime.now(timezone.utc)
            for row in rows:
                row.status = "degraded"
                row.satisfied_at = now
            if rows:
                logger.info(
                    "Worker %s: job %s degraded %d dependent edge(s) after terminal failure",
                    self.worker_id,
                    job.id,
                    len(rows),
                    extra={"dependents_degraded": len(rows)},
                )
            return len(rows)
        except Exception as exc:
            logger.warning(
                "degrade_dependencies failed for job %s: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            return 0

    @staticmethod
    def _provider_chain_for(job: Job) -> str | None:
        """Pull the provider's chain identifier out of the job's request
        payload. Mirrors the convention ``_queue_discovered_contracts``
        uses when stamping ``request['chain']`` on spawned children.

        ``getattr`` over direct attribute access so test doubles
        (SimpleNamespace fakes that omit ``request``) don't trigger
        AttributeError on the dependency hooks."""
        request = getattr(job, "request", None)
        if not isinstance(request, dict):
            return None
        chain = request.get("chain")
        return chain if isinstance(chain, str) and chain else None

    def _persist_stage_errors(self, job: Job, errors: list[StageError]) -> None:
        """Write the ``stage_errors`` artifact via a fresh session, merging
        with any pre-existing artifact so retries accumulate per-attempt.

        Used on both the success and failure paths so the artifact survives a
        broken primary transaction. ``store_artifact`` does its own commit, so
        the only state to clean up is the fresh session itself. Best-effort —
        we never want a stage_errors write failure to mask the underlying job
        failure or block the success advance.

        Accumulation matters for retries: a job that fails transiently three
        times before succeeding ends up with three error entries plus any
        degraded entries from each attempt. Without the merge step every
        retry would overwrite the prior attempt's history.
        """
        if not errors:
            return
        fresh = SessionLocal()
        try:
            existing = get_artifact(fresh, job.id, "stage_errors")
            merged: list[StageError] = []
            corrupt_prior: dict | list | str | None = None
            if isinstance(existing, dict):
                try:
                    merged = list(StageErrors.model_validate(existing).errors)
                except Exception:
                    # Corrupt body shouldn't block the new write, but it
                    # also shouldn't be silently dropped: pin the raw payload
                    # onto a degraded breadcrumb so an operator forensically
                    # reading the audit log via /api/jobs/{id}/errors can
                    # still see what was there before this attempt.
                    merged = []
                    corrupt_prior = existing
            if corrupt_prior is not None:
                merged.append(
                    StageError(
                        stage=self.stage.value,
                        severity="degraded",
                        exc_type="schema.CorruptPriorArtifact",
                        message="Prior stage_errors body did not validate; raw payload preserved in context.",
                        phase="corrupt_prior",
                        trace_id=getattr(job, "trace_id", None),
                        job_id=str(job.id),
                        worker_id=self.worker_id,
                        failed_at=datetime.now(timezone.utc),
                        context={"raw": corrupt_prior},
                    )
                )
            merged.extend(errors)
            store_artifact(
                fresh,
                job.id,
                "stage_errors",
                data=StageErrors(errors=merged).model_dump(mode="json"),
            )
        except Exception:
            logger.exception(
                "Worker %s: failed to write stage_errors artifact for job %s (non-fatal)",
                self.worker_id,
                job.id,
            )
        finally:
            try:
                fresh.close()
            except Exception:
                logger.debug("stage_errors session close failed", exc_info=True)

    def _record_stage_timing(
        self,
        session: Session,
        job: Job,
        *,
        started_at: str,
        ended_at: str,
        elapsed_s: float,
        status: str,
    ) -> None:
        """Write this stage's timing as a ``stage_timing_<stage>`` artifact (one slot per stage avoids cross-stage RMW
        races); best-effort with session rollback on failure."""
        artifact_name = f"stage_timing_{self.stage.value}"
        payload = {
            "schema_version": "2",
            "stage": self.stage.value,
            "started_at": started_at,
            "ended_at": ended_at,
            "elapsed_s": round(elapsed_s, 3),
            "worker_id": self.worker_id,
            "status": status,
        }
        # Fold in any progress metrics the stage recorded via
        # ``record_stage_metric`` (deps discovered, principals resolved, …).
        # Additive within schema v2 — the key is omitted when empty so legacy
        # readers (bench harness reads ``elapsed_s``) are unaffected. Copied so
        # a later reset of the contextvar can't mutate the stored payload.
        metrics = stage_metrics_var.get()
        if metrics:
            payload["metrics"] = dict(metrics)
        try:
            store_artifact(session, job.id, artifact_name, data=payload)
        except Exception:
            logger.exception("Worker %s: failed to record %s (non-fatal)", self.worker_id, artifact_name)
            # Mid-transaction failure leaves the session needing rollback or the success path's advance_job will raise
            # PendingRollbackError.
            try:
                session.rollback()
            except Exception:
                logger.exception("Worker %s: failed to rollback after timing write failure", self.worker_id)
