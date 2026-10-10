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
    requeue_job,
    store_artifact,
    update_job_detail,
)
from schemas.stage_errors import StageError, StageErrors
from utils.logging import (
    bind_trace_context,
    configure_logging,
    degraded_errors_var,
    job_in_flight,
    stage_metrics_var,
)
from utils.memory import (
    cgroup_memory_current_bytes,
    cgroup_memory_max_bytes,
    count_sibling_python_procs,
    current_rss_bytes,
    mb,
    start_job_rss_span,
)
from workers.retry_policy import classify, compute_next_attempt, max_retries

logger = logging.getLogger(__name__)

# Fan-out sections can go minutes without a status write; mid-fan-out heartbeats keep ``updated_at`` fresh.
STALE_JOB_TIMEOUT = int(os.getenv("PSAT_STALE_JOB_TIMEOUT", "600"))  # seconds

# Per-worker throttle for the stuck-job sweep, well under the stale timeout.
RECLAIM_INTERVAL_S = float(os.getenv("PSAT_RECLAIM_INTERVAL_S", "30"))


class IdlePollDelay:
    def __init__(self, base: float) -> None:
        self.base = max(0.0, base)
        try:
            ceiling = float(os.getenv("PSAT_WORKER_IDLE_MAX_S", "15"))
        except ValueError:
            ceiling = 15.0
        self.ceiling = max(self.base, ceiling)
        self.reset()

    def reset(self) -> None:
        self.delay = self.base

    def next_delay(self) -> float:
        delay = self.delay
        self.delay = min(self.ceiling, self.delay * 2)
        return delay


def _job_heartbeat_interval_s() -> float:
    try:
        value = float(os.getenv("PSAT_JOB_HEARTBEAT_INTERVAL_S", os.getenv("PSAT_PARALLEL_HEARTBEAT_INTERVAL_S", "30")))
    except ValueError:
        return 30.0
    return max(0.1, value)


def _resolve_job_concurrency(stage_value: str) -> int:
    """Max concurrent jobs per process for *stage_value*: ``PSAT_<STAGE>_JOB_CONCURRENCY``, then
    ``PSAT_JOB_CONCURRENCY``, then 1. K=1 uses the original single-job loop; K>1 the futures dispatcher.
    Readiness-gated stages (coverage, selection) stay at 1 in production.
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


def _job_chain_log_value(job: Any, request: dict[str, Any]) -> str | None:
    """Chain label for the ``chain`` logging contextvar: ``request['chain']`` so existing Loki filters
    work, else the name of the job's ``chain_id``, else ``None`` (not bound).
    """
    chain = request.get("chain")
    if chain:
        return chain
    chain_id = getattr(job, "chain_id", None)
    if chain_id is None:
        return None
    from utils.chains import UnknownChainError, chain_by_id

    try:
        return chain_by_id(chain_id).name
    except UnknownChainError:
        return None


class JobHandledDirectly(Exception):
    pass


class BaseWorker:
    stage: JobStage
    next_stage: JobStage
    poll_interval: float = 2.0

    def __init__(self) -> None:
        # Idempotent; ensures bare ``BaseWorker()`` in tests still logs JSON.
        configure_logging()
        self.worker_id = f"{self.__class__.__name__}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._running = True
        # -inf means sweep now.
        self._last_reclaim_at: float = float("-inf")
        # Held until execution, subprocesses and uploads finish.
        self._inflight_jobs: dict[uuid.UUID, uuid.UUID] = {}
        self._inflight_lock = threading.Lock()
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigterm)

        # K>1 runs jobs in a thread pool so one job's RPC waits overlap another's CPU. Resolved once so the boot banner
        # shows it.
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

        # One boot banner per process (stage, RSS, cgroup limit, sibling count) so OOMs can be diagnosed from logs.
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
        # Keep renewing the lease until work and subprocesses finish, or another worker could run the same job. A forced
        # kill leaves it to expire.

    def process(self, session: Session, job: Job) -> None:
        raise NotImplementedError

    def _claim_job(self, session: Session) -> Job | None:
        """Throttled stuck-job sweep plus claim; override for readiness-gated claims."""
        now = time.monotonic()
        if now - self._last_reclaim_at >= RECLAIM_INTERVAL_S:
            reclaim_stuck_jobs(session)
            self._last_reclaim_at = now
        return claim_job(session, self.stage, self.worker_id)

    def _recover_stale_jobs(self, session: Session) -> None:
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
        """Run one claimed job to completion: process, record timing, then advance, complete or fail.

        Shared by the single and K>1 loops. Runs inside ``bind_trace_context`` so every log line carries
        trace/job/stage/worker ids.
        """
        # Test stubs may lack these fields.
        raw_request = getattr(job, "request", None)
        request = raw_request if isinstance(raw_request, dict) else {}
        with (
            bind_trace_context(
                trace_id=getattr(job, "trace_id", None),
                job_id=str(job.id),
                stage=self.stage.value,
                worker_id=self.worker_id,
                address=getattr(job, "address", None),
                chain=_job_chain_log_value(job, request),
            ),
            job_in_flight(),
        ):
            # Per-job ``record_degraded`` accumulator, reset per job so parallel jobs don't share it.
            degraded_accumulator: list[StageError] = []
            accumulator_token = degraded_errors_var.set(degraded_accumulator)
            # Per-job ``record_stage_metric`` accumulator, folded into ``stage_timing_<stage>`` by
            # ``_record_stage_timing``.
            stage_metrics: dict[str, Any] = {}
            metrics_token = stage_metrics_var.set(stage_metrics)
            # The claim-time lease, threaded through every mutating queue write.
            claim_job_id = getattr(job, "id")
            claim_lease_id = getattr(job, "lease_id", None)
            # Heartbeat threads use the immutable claim token rather than rereading ORM attributes.
            setattr(job, "_heartbeat_job_id", claim_job_id)
            setattr(job, "_heartbeat_lease_id", claim_lease_id)
            # Tracked until execution finishes, through SIGTERM; removed in ``finally``.
            inflight_registered = False
            if claim_lease_id is not None:
                with self._inflight_lock:
                    self._inflight_jobs[claim_job_id] = claim_lease_id
                inflight_registered = True
            heartbeat_stop = threading.Event()
            heartbeat_thread: threading.Thread | None = None
            rss_span = None

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
                rss_span = start_job_rss_span()
                rss_before = rss_span.start_bytes

                def finish_memory_span() -> None:
                    # Process RSS during the job, not its allocation (K jobs may share the process).
                    stage_metrics.update(rss_span.finish())

                started_at_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                try:
                    self.process(session, job)
                    elapsed = time.monotonic() - t0
                    ended_at_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    rss_after = current_rss_bytes()
                    finish_memory_span()
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
                    # Before advancing, or the next stage could race the shared stage_timings artifact.
                    self._record_stage_timing(
                        session,
                        job,
                        started_at=started_at_iso,
                        ended_at=ended_at_iso,
                        elapsed_s=elapsed,
                        status="success",
                    )
                    # Before advancing, so the next stage sees stage_errors at its claim.
                    if degraded_accumulator:
                        self._persist_stage_errors(job, degraded_accumulator)
                    # Satisfy dependents in the same transaction as the stage change so they become claimable
                    # atomically.
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
                    finish_memory_span()
                    # Fresh session: process() may have left the original inconsistent.
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
                        extra={
                            "duration_ms": int(elapsed * 1000),
                            "phase": "job",
                            "outcome": "handled_directly",
                            **rss_span.finish(),
                        },
                    )
                except LeaseLost as lease_exc:
                    finish_memory_span()
                    # The lease moved to a sibling; any further write would corrupt its view.
                    logger.warning(
                        "Worker %s: lease lost for job %s — abandoning attempt: %s",
                        self.worker_id,
                        job.id,
                        lease_exc,
                        extra={"phase": "job", "outcome": "lease_lost", **rss_span.finish()},
                    )
                    return
                except Exception as exc:
                    finish_memory_span()
                    from utils.secrets import sanitize_string

                    # Roll back before reading ``job.retry_count``: on a pending-rollback session the lazy load
                    # re-raises, the job is never requeued, and only the stale sweep recovers it without bumping
                    # retry_count, an unbounded poison loop.
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
                    # Decide retry vs terminal up front. ``prior_retry_count`` tags the failed attempt;
                    # ``new_retry_count`` is the row's new count.
                    kind = classify(exc)
                    prior_retry_count = getattr(job, "retry_count", 0) or 0
                    new_retry_count = prior_retry_count + 1
                    will_retry = kind == "transient" and new_retry_count < max_retries()
                    next_attempt_at = compute_next_attempt(prior_retry_count) if will_retry else None
                    outcome = "requeued" if will_retry else "failed_terminal"
                    exc_type_str = f"{type(exc).__module__}.{type(exc).__name__}"
                    # WARNING when retrying, ERROR when terminal. The traceback goes in ``exc_info`` only on the
                    # terminal branch (a requeued job hasn't failed); the StageError below carries it either way.
                    log_fn = logger.warning if will_retry else logger.error
                    log_fn(
                        "worker failure: job %s %s (%s)",
                        job.id,
                        outcome,
                        exc_type_str,
                        exc_info=None if will_retry else exc,
                        extra={
                            "duration_ms": int(elapsed * 1000),
                            "phase": "job",
                            "outcome": outcome,
                            "exc_type": exc_type_str,
                            "exc_message": exc_message,
                            # The other identifiers are bound contextvars.
                            "job_name": getattr(job, "name", None),
                            "retry_count": new_retry_count if will_retry else prior_retry_count,
                            "next_attempt_at": next_attempt_at.isoformat() if next_attempt_at else None,
                            "failure_kind": kind,
                            **rss_span.finish(),
                        },
                    )
                    # Append the failure after any degraded entries, tagged with its attempt number. Persisted via a
                    # fresh session so a poisoned transaction can't lose it.
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
                    # Retries exhausted: record the full count. Deterministic terminal: unchanged (no retry slot was
                    # used).
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
                            # Terminal: degrade dependents so they don't block, then mark failed_terminal, via an
                            # overridable finalizer so fail-forward stages (effects) can advance instead.
                            self._finalize_terminal_failure(
                                session,
                                job,
                                error=error,
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
                        # A sibling owns the row now.
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
                                self._finalize_terminal_failure(
                                    fresh,
                                    job,
                                    error=truncated,
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
                if rss_span is not None:
                    rss_span.finish()
                heartbeat_stop.set()
                if heartbeat_thread is not None:
                    heartbeat_thread.join(timeout=1)
                degraded_errors_var.reset(accumulator_token)
                stage_metrics_var.reset(metrics_token)
                if inflight_registered:
                    with self._inflight_lock:
                        self._inflight_jobs.pop(claim_job_id, None)

    def _run_one_job(self, job_id) -> None:
        """K>1 dispatcher entry: open a per-job session, re-fetch the job into it (the claim session is closed), run
        ``_execute_job``, close. Escaping errors are logged so the dispatcher survives.
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
        idle = IdlePollDelay(self.poll_interval)
        recovery_interval = max(60.0, 30 * self.poll_interval)
        recover_at = time.monotonic() + recovery_interval
        while self._running:
            session = SessionLocal()
            try:
                if time.monotonic() >= recover_at:
                    recover_at = time.monotonic() + recovery_interval
                    self._recover_stale_jobs(session)

                job = self._claim_job(session)
                if job is None:
                    session.close()
                    time.sleep(idle.next_delay())
                    continue

                idle.reset()
                self._execute_job(session, job)
            except Exception:
                logger.exception("Worker %s encountered error in main loop", self.worker_id)
                session.close()
                time.sleep(idle.next_delay())
            finally:
                session.close()

    def _run_loop_concurrent(self) -> None:
        """K>1 loop: claim on short-lived sessions and dispatch into a bounded ``ThreadPoolExecutor``, waiting on
        ``FIRST_COMPLETED`` when full. SIGTERM stops claims and waits for in-flight jobs; idle shutdown never
        abandons futures.
        """
        assert self._job_pool is not None
        idle = IdlePollDelay(self.poll_interval)
        recovery_interval = max(60.0, 30 * self.poll_interval)
        recover_at = time.monotonic() + recovery_interval
        while self._running:
            self._reap_finished_futures()

            if len(self._inflight) >= self._job_concurrency:
                # Pool full: wait for a slot, with a ceiling so SIGTERM is noticed.
                wait(self._inflight, timeout=self.poll_interval, return_when=FIRST_COMPLETED)
                continue

            claim_session = SessionLocal()
            job_to_dispatch: Job | None = None
            job_id_for_dispatch = None
            try:
                if time.monotonic() >= recover_at:
                    recover_at = time.monotonic() + recovery_interval
                    self._recover_stale_jobs(claim_session)

                job_to_dispatch = self._claim_job(claim_session)
                if job_to_dispatch is not None:
                    # Capture the id before the session closes; the dispatcher re-fetches it.
                    job_id_for_dispatch = job_to_dispatch.id
            except Exception:
                logger.exception("Worker %s encountered error in claim loop", self.worker_id)
            finally:
                claim_session.close()

            if job_id_for_dispatch is None:
                if self._inflight:
                    idle.reset()
                    wait(self._inflight, timeout=self.poll_interval, return_when=FIRST_COMPLETED)
                else:
                    time.sleep(idle.next_delay())
                continue

            idle.reset()
            # ``ThreadPoolExecutor.submit`` doesn't propagate contextvars, so run under a copied context.
            ctx = contextvars.copy_context()
            future = self._job_pool.submit(ctx.run, self._run_one_job, job_id_for_dispatch)
            self._inflight.add(future)

        # An idle stop finishes all work before exiting.
        if self._job_pool is not None:
            self._job_pool.shutdown(wait=True)
        self._inflight.clear()

    def _reap_finished_futures(self) -> None:
        finished = {f for f in self._inflight if f.done()}
        if finished:
            self._inflight -= finished

    def update_detail(self, session: Session, job: Job, detail: str) -> None:
        update_job_detail(session, job.id, detail)

    def _heartbeat(self, session: Session, job: Job) -> None:  # noqa: ARG002 — session kept for caller back-compat
        """Extend the row's lease using a fresh session (the *session* argument is ignored).

        Keeps the stale sweep from requeuing live work. ``heartbeat_job`` only matches the claim-time lease; a reclaimed
        worker gets ``LeaseLost``, which is deliberately not swallowed so ``_execute_job`` stops.

        Fresh session because the worker's session idles for minutes during parallel sections and Neon's pooler drops
        idle SSL connections; heartbeats through it failed silently and live jobs were requeued. The pool's
        ``pool_pre_ping`` replaces dead connections. Other errors log at WARNING since stall detection depends on this.
        """
        missing = object()
        job_id = getattr(job, "_heartbeat_job_id", missing)
        if job_id is missing:
            job_id = getattr(job, "id")
        lease_id = getattr(job, "_heartbeat_lease_id", missing)
        if lease_id is missing:
            lease_id = getattr(job, "lease_id", None)
        if lease_id is None:
            # Pre-migration rows or legacy claims: bump updated_at for the legacy sweep.
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
        """Mark this job's pending ``JobDependency`` rows ``satisfied`` when the completed stage meets their
        ``required_stage`` (``JobStage`` order). Doesn't commit; the caller's advance/complete commits it
        atomically. Returns rows flipped. Best-effort: failures log and return 0.
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
        """Mark this job's pending dependencies ``degraded`` after a terminal failure, so dependents fall back to
        ``external_check_only``. Doesn't commit.
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

    def _finalize_terminal_failure(
        self,
        session: Session,
        job: Job,
        *,
        error: str,
        kind: str,
        retry_count: int | None,
        lease_id: uuid.UUID | None,
    ) -> None:
        """Finalize an exhausted or terminal failure: degrade dependents and mark ``failed_terminal``.

        Overridable so fail-forward stages (effects) can advance instead. Called from both failure paths with
        whichever session rolled back successfully.
        """
        self._degrade_dependencies(session, job)
        fail_job_terminal(
            session,
            job.id,
            error,
            kind=kind,
            retry_count=retry_count,
            lease_id=lease_id,
        )

    @staticmethod
    def _provider_chain_for(job: Job) -> str | None:
        """The provider's chain from the job request (as ``_queue_discovered_contracts`` stamps it); ``getattr``
        tolerates test doubles.
        """
        request = getattr(job, "request", None)
        if not isinstance(request, dict):
            return None
        chain = request.get("chain")
        return chain if isinstance(chain, str) and chain else None

    def _persist_stage_errors(self, job: Job, errors: list[StageError]) -> None:
        """Write ``stage_errors`` via a fresh session, merged with the existing artifact so retries accumulate.

        Used on both paths so it survives a broken transaction; best-effort.
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
                    # Keep a corrupt prior body on a degraded breadcrumb rather than dropping it.
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
        """Write this stage's ``stage_timing_<stage>`` artifact (one per stage avoids cross-stage races); best-effort
        with rollback.
        """
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
        # Include ``record_stage_metric`` values (omitted when empty for legacy readers); copied so resetting the
        # contextvar can't mutate it.
        metrics = stage_metrics_var.get()
        if metrics:
            payload["metrics"] = dict(metrics)
        try:
            store_artifact(session, job.id, artifact_name, data=payload)
        except Exception:
            logger.exception("Worker %s: failed to record %s (non-fatal)", self.worker_id, artifact_name)
            # Roll back or the success path's advance raises PendingRollbackError.
            try:
                session.rollback()
            except Exception:
                logger.exception("Worker %s: failed to rollback after timing write failure", self.worker_id)
