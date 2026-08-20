"""Worker that verifies pending source-equivalence rows asynchronously.

The previous design ran source-equivalence inline at coverage-write time —
a coverage refresh fanned out 4-way Etherscan + GitHub bursts per audit,
which 429'd the global Etherscan rate-limit window and cascaded into
every other worker that hit Etherscan (Resolution, Static, etc.). Each
sibling then sat in the shared backoff sleep, sometimes for 30 seconds,
even though it had nothing to do with the burst.

This worker drains rows where ``equivalence_status='pending'`` from
``audit_contract_coverage`` at a steady, controlled rate so Etherscan
sees a trickle instead of a sawtooth. Coverage stage time drops from
minutes to <1s; ``reviewed_commit`` annotations still land, just a few
seconds-to-minutes later than the inline path.

State machine on ``audit_contract_coverage.equivalence_status`` (the
deferred-only lifecycle; semantic statuses are documented in
``services/audits/source_equivalence.EQUIVALENCE_STATUSES``):

    pending           — eligible for claim; coverage refresh wrote this
    verifying         — claimed by this worker; in-flight HTTP probe
    proven / hash_*   — terminal verdict (success or non-transient failure)
    *_fetch_failed    — transient verdict; operator may promote back to pending

Stale recovery: rows stuck in ``verifying`` past
``_STALE_VERIFY_TIMEOUT`` (default 10 min) are reverted to ``pending``
so a wedged worker process doesn't strand its claimed rows.

The worker is intentionally low-concurrency (default 2 threads) — the
goal is to not be the bursty path. A higher-throughput tuning would
just bring back the storm we're trying to avoid.
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

from sqlalchemy import text
from sqlalchemy.orm.exc import StaleDataError

from db.models import SessionLocal
from db.queue import HEARTBEAT_COVERAGE_VERIFY, record_heartbeat
from utils.logging import configure_logging, record_stage_metric, worker_id_var
from utils.memory import (
    cgroup_memory_current_bytes,
    cgroup_memory_max_bytes,
    count_sibling_python_procs,
    current_rss_bytes,
    mb,
)

logger = logging.getLogger("workers.coverage_verify")


# --- Tunables (env-overridable) ------------------------------------------

# Per-poll batch size. Smaller is gentler on Etherscan: with 2 worker
# threads and 4 rows per claim, the worst-case in-flight count stays
# below the global Etherscan rate-limit's per-second budget.
_BATCH_SIZE = int(os.getenv("PSAT_COVERAGE_VERIFY_BATCH_SIZE", "4"))

# Per-process verify concurrency. 2 keeps the cumulative HTTP
# concurrency low; the worker's job is to be polite, not fast.
_MAX_CONCURRENT = int(os.getenv("PSAT_COVERAGE_VERIFY_CONCURRENCY", "2"))

# Idle poll interval. Long-ish (30s) so an empty queue doesn't churn DB
# round-trips. Short enough that a freshly-extracted audit's pending
# rows don't sit around for minutes.
_IDLE_POLL_INTERVAL = float(os.getenv("PSAT_COVERAGE_VERIFY_POLL_INTERVAL", "30.0"))

# How long a ``verifying`` claim is allowed to live before stale-recovery
# reverts it back to ``pending``. Verification can legitimately take
# tens of seconds when GitHub is slow, so 10 minutes leaves comfortable
# margin for retries inside one process.
_STALE_VERIFY_TIMEOUT = int(os.getenv("PSAT_COVERAGE_VERIFY_STALE_TIMEOUT", "600"))

# Run stale recovery every N polls so an idle queue's recovery query
# fires roughly once per ~5 minutes at the default poll interval.
_STALE_RECOVERY_EVERY_N_POLLS = 10

# Per-pass hash_mismatch alerting. The source-equivalence verdict the
# system most wants to watch is hash_mismatch (the audit's declared
# commit fetched cleanly on both sides but the bytes differ). A pass
# where most terminal verdicts are hash_mismatch points at a
# candidate-path or source-fetch regression rather than genuinely
# divergent code, so we surface it as a single WARNING with the rate in
# ``extra`` instead of letting it hide in per-row lines. Gated on a
# minimum sample so a 1-of-1 pass can't trip the alert.
_HASH_MISMATCH_WARN_RATE = float(os.getenv("PSAT_COVERAGE_VERIFY_HASH_MISMATCH_WARN_RATE", "0.5"))
_HASH_MISMATCH_WARN_MIN = int(os.getenv("PSAT_COVERAGE_VERIFY_HASH_MISMATCH_WARN_MIN", "4"))


def _crash_status(exc: BaseException) -> str:
    """Verdict status for a row whose verify thread raised.

    A concurrent coverage rebuild can delete the row mid-verify; SQLAlchemy
    surfaces that as ``StaleDataError``. That is a benign race — the row
    vanished — not a GitHub outage, so it gets its own terminal status and
    must not inflate the ``github_fetch_failed`` transient signal that ops
    use to spot real GitHub trouble.
    """
    return "row_vanished" if isinstance(exc, StaleDataError) else "github_fetch_failed"


# --- Worker --------------------------------------------------------------


class CoverageVerifyWorker:
    """Drain ``audit_contract_coverage`` rows where verification is pending.

    Modeled on ``workers.audit_row_worker.AuditRowWorker`` but operating
    on the coverage join table instead of ``audit_reports``: same poll →
    claim → fan-out → persist shape, just keyed on a different state
    column.
    """

    worker_name = "CoverageVerify"
    batch_size = _BATCH_SIZE
    max_concurrent = _MAX_CONCURRENT
    idle_poll_interval = _IDLE_POLL_INTERVAL
    stale_seconds = _STALE_VERIFY_TIMEOUT
    thread_name_prefix = "coverage-verify"

    def __init__(self) -> None:
        configure_logging()
        self.worker_id = f"{self.worker_name}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum: int, _frame: object) -> None:
        logger.info(
            "Worker %s received signal %s, shutting down",
            self.worker_id,
            signum,
        )
        self._running = False

    # -- Claim --------------------------------------------------------

    def _claim_batch(self, session) -> list[int]:
        """Claim up to ``batch_size`` pending rows by stamping ``verifying``.

        SKIP LOCKED keeps the claim non-blocking under multi-worker
        contention: each worker takes a disjoint slice. The CTE form
        materializes the locked-id set BEFORE the UPDATE matches against
        it — the more obvious ``WHERE id IN (SELECT … FOR UPDATE SKIP
        LOCKED LIMIT n)`` form silently ignores the inner LIMIT in
        Postgres and updates every pending row, which we hit during
        unit-test development. The CTE keeps LIMIT semantics intact.

        The inner SELECT runs against the partial index
        ``ix_acc_equivalence_pending`` so the queue scan stays a single
        index seek even when the table has millions of resolved rows.

        Filters out rows whose contract has since been reclassified as a
        proxy. ``audit_contract_coverage`` carries a ``BEFORE
        INSERT/UPDATE`` trigger (``_reject_proxy_coverage``) that raises
        if the target ``contract_id`` resolves to ``is_proxy=TRUE``.
        Coverage rows are written when the contract is known-impl, but a
        later static-analysis pass can flip ``contracts.is_proxy`` to
        TRUE — the pending row then becomes uncliamable: the UPDATE that
        flips it to ``verifying`` would trigger the raise, propagate out
        of ``run_loop``, and crash the worker. The JOIN here just skips
        them; they accumulate as orphaned ``pending`` rows but never
        gate the worker. Cleanup of the orphans is a follow-up.
        """
        result = session.execute(
            text(
                """
                WITH locked AS (
                    SELECT acc.id FROM audit_contract_coverage acc
                    JOIN contracts c ON c.id = acc.contract_id
                    WHERE acc.equivalence_status = 'pending'
                      AND c.is_proxy = FALSE
                    ORDER BY acc.id
                    FOR UPDATE SKIP LOCKED
                    LIMIT :limit
                )
                UPDATE audit_contract_coverage AS acc
                SET equivalence_status = 'verifying',
                    equivalence_checked_at = NOW()
                FROM locked
                WHERE acc.id = locked.id
                RETURNING acc.id
                """
            ),
            {"limit": self.batch_size},
        )
        ids = [row[0] for row in result]
        if ids:
            session.commit()
        else:
            session.rollback()
        return ids

    def _recover_stale(self, session) -> None:
        """Revert ``verifying`` rows older than the cutoff back to ``pending``.

        A worker that crashes (OOM, fly drain past kill_timeout) leaves
        its claimed rows pinned in ``verifying`` until this sweep
        notices and resets them. Without recovery, the rows would be
        invisible to every future claim — silently lost work.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.stale_seconds)
        result = session.execute(
            text(
                """
                UPDATE audit_contract_coverage
                SET equivalence_status = 'pending',
                    equivalence_checked_at = NULL
                WHERE equivalence_status = 'verifying'
                  AND equivalence_checked_at < :cutoff
                RETURNING id
                """
            ),
            {"cutoff": cutoff},
        )
        ids = [row[0] for row in result]
        if ids:
            logger.warning(
                "Worker %s: reset %d stale verifying row(s) back to pending: %s",
                self.worker_id,
                len(ids),
                ids,
            )
            session.commit()
        else:
            session.rollback()

    # -- Per-row work --------------------------------------------------

    def _process_row(self, row_id: int) -> tuple[int, str | None, BaseException | None, dict[str, object]]:
        """Run source-equivalence on one claimed row in a fresh session.

        Catches every exception so one row's failure can't poison the
        thread pool — the verdict for crashed rows is written via the
        partner ``_handle_crash`` path on the main thread. Returns
        ``(row_id, status, exc, ctx)`` where exactly one of ``status``
        or ``exc`` is set, and ``ctx`` carries enough post-verify state
        for the run loop's outcome log line: ``audit_id``, ``contract_id``,
        ``matched_name`` always, plus ``proof_kind`` / ``matched_commit_sha``
        / ``reason`` for proven rows. The audit_row_worker family
        includes per-row identifiers + outcome details in its log line
        so ops can tie a verdict back to the audit/contract pair
        without a DB lookup.
        """
        from db.models import AuditContractCoverage
        from services.audits.coverage import verify_one_coverage_row

        github_token = os.environ.get("GITHUB_TOKEN") or None
        session = SessionLocal()
        try:
            try:
                # Per-row timing is hot-path detail (one line per claimed
                # row, ~1k/run), so it belongs at DEBUG — not the INFO that
                # ``log_timed_phase`` hard-codes. We still fold the duration
                # into the stage metric so the latency distribution survives
                # even when DEBUG lines are filtered in prod.
                _row_start = time.monotonic()
                status = verify_one_coverage_row(session, row_id, github_token=github_token)
                _row_ms = int((time.monotonic() - _row_start) * 1000)
                record_stage_metric("phase_ms_verify_row", _row_ms)
                logger.debug(
                    "verify_row complete",
                    extra={"phase": "verify_row", "duration_ms": _row_ms, "row_id": row_id},
                )
                session.commit()
                # Re-read so the log line carries the post-verify state
                # (the row may have been deleted by a concurrent rebuild,
                # in which case ``status`` is None and ctx stays empty).
                row = session.get(AuditContractCoverage, row_id)
                ctx: dict[str, object] = {}
                if row is not None:
                    ctx = {
                        "audit_id": row.audit_report_id,
                        "contract_id": row.contract_id,
                        "matched_name": row.matched_name,
                        "proof_kind": row.proof_kind,
                        "matched_commit_sha": row.matched_commit_sha,
                        "reason": row.equivalence_reason,
                    }
                return row_id, status, None, ctx
            except BaseException as exc:  # noqa: BLE001 — preserve every exception type
                # Roll back any partial write so the next attempt sees a
                # clean transaction. The crash handler will stamp a
                # transient status for the row outside this session.
                try:
                    session.rollback()
                except Exception:
                    logger.debug("rollback failed in _process_row", exc_info=True)
                # Re-read identity in a fresh session so the crash line can
                # name the audit/contract pair (the rolled-back session can't
                # be read from). A None re-read means the row vanished — the
                # benign-rebuild race — which the outcome line surfaces.
                return row_id, None, exc, self._read_row_identity(row_id)
        finally:
            session.close()

    def _read_row_identity(self, row_id: int) -> dict[str, object]:
        """Best-effort re-read of a row's identity for the outcome log.

        Used by the crash path, where the working session was rolled back.
        Returns an empty dict if the row vanished or the read itself fails —
        the caller treats an empty identity as "row no longer present".
        """
        from db.models import AuditContractCoverage

        session = SessionLocal()
        try:
            row = session.get(AuditContractCoverage, row_id)
            if row is None:
                return {}
            return {
                "audit_id": row.audit_report_id,
                "contract_id": row.contract_id,
                "matched_name": row.matched_name,
            }
        except Exception:
            logger.debug("identity re-read failed for row %s", row_id, exc_info=True)
            return {}
        finally:
            session.close()

    def _log_outcome(
        self,
        row_id: int,
        status: str | None,
        exc: BaseException | None,
        ctx: dict[str, object],
    ) -> None:
        """Per-row outcome line — facts in ``extra={}``, message constant.

        The source-equivalence verdict (``equivalence_status``) plus the
        ``audit_id`` / ``contract_id`` / ``matched_name`` / ``sha`` identity
        all go in ``extra`` so verdict distributions are a single Loki/jq
        aggregation rather than a message-regex. Crashes log at WARNING
        with ``exc_type`` (and ``crash_status`` so a benign ``row_vanished``
        race is distinguishable from a ``github_fetch_failed`` outage) and
        route into ``_handle_crash`` afterwards for the DB stamp.
        """
        base: dict[str, object] = {
            "row_id": row_id,
            "audit_id": ctx.get("audit_id"),
            "contract_id": ctx.get("contract_id"),
            "matched_name": ctx.get("matched_name"),
        }
        if exc is not None:
            crash_status = _crash_status(exc)
            logger.warning(
                "Coverage row %s verify crashed",
                row_id,
                extra={
                    **base,
                    "exc_type": type(exc).__name__,
                    "crash_status": crash_status,
                    "row_present": bool(ctx),
                },
            )
            return
        if status == "proven":
            sha = str(ctx.get("matched_commit_sha") or "")[:12]
            logger.info(
                "Coverage row %s proven",
                row_id,
                extra={
                    **base,
                    "equivalence_status": status,
                    "proof_kind": ctx.get("proof_kind"),
                    "sha": sha,
                },
            )
            return
        reason = str(ctx.get("reason") or "")[:200]
        logger.info(
            "Coverage row %s verdict",
            row_id,
            extra={
                **base,
                "equivalence_status": status or "vanished",
                "reason": reason,
            },
        )

    def _handle_crash(self, row_id: int, exc: BaseException) -> None:
        """Record a transient verdict for a row whose verify call crashed.

        Uses a fresh session so the crash's broken transaction can't
        propagate into this write. If the row vanished between claim
        and crash (rebuild raced), the UPDATE is simply a no-op.
        """
        crash_status = _crash_status(exc)
        session = SessionLocal()
        try:
            session.execute(
                text(
                    """
                    UPDATE audit_contract_coverage
                    SET equivalence_status = :status,
                        equivalence_reason = :reason,
                        equivalence_checked_at = NOW(),
                        proof_kind = NULL,
                        matched_commit_sha = NULL
                    WHERE id = :id
                      AND equivalence_status = 'verifying'
                    """
                ),
                {
                    "id": row_id,
                    "status": crash_status,
                    "reason": f"verify thread crashed: {type(exc).__name__}: {exc}"[:1000],
                },
            )
            session.commit()
        except Exception:
            logger.exception(
                "Worker %s: failed to stamp crash verdict for row %s",
                self.worker_id,
                row_id,
            )
            try:
                session.rollback()
            except Exception:
                logger.debug("rollback failed in _handle_crash", exc_info=True)
        finally:
            session.close()

    def _summarize_pass(self, claimed_count: int, verdicts: dict[str, int]) -> float:
        """Emit the per-pass verdict rollup: heartbeat detail + a threshold WARNING.

        Daemons can't use ``record_stage_metric``/``record_degraded`` (the
        job-scoped accumulators are unbound), so the per-pass verdict counts
        ride in the heartbeat ``detail`` — the daemon substitute per the
        house standard. A pass dominated by ``hash_mismatch`` is the
        suspicious signal (likely a candidate-path / source-fetch
        regression, not genuinely divergent code), so it also gets a single
        WARNING carrying the rate in ``extra``. Returns the rate for tests.
        """
        total = sum(verdicts.values())
        mismatches = verdicts.get("hash_mismatch", 0)
        rate = (mismatches / total) if total else 0.0
        record_heartbeat(
            HEARTBEAT_COVERAGE_VERIFY,
            status="running",
            detail={
                "verified_last_pass": claimed_count,
                "verdicts": dict(verdicts),
                "hash_mismatch_rate": round(rate, 3),
            },
        )
        if total >= _HASH_MISMATCH_WARN_MIN and rate >= _HASH_MISMATCH_WARN_RATE:
            logger.warning(
                "coverage verify pass: elevated hash_mismatch rate",
                extra={
                    "hash_mismatch_rate": round(rate, 3),
                    "hash_mismatch": mismatches,
                    "verdicts_total": total,
                    "verdicts": dict(verdicts),
                },
            )
        return rate

    # -- Main loop -----------------------------------------------------

    def run_loop(self) -> None:
        """Poll → claim → fan out → log, with periodic stale recovery.

        One thread pool lives for the worker's lifetime so we don't pay
        pthread-creation cost on the hot path. Each claimed row is
        processed in a fresh ``SessionLocal()`` on a worker thread;
        verdicts are committed by the per-row session, the main thread
        only handles logging + crash-fallback writes.
        """
        logger.info(
            "%s worker %s starting (batch=%d, pool=%d, idle=%ss, stale=%ss)",
            self.worker_name,
            self.worker_id,
            self.batch_size,
            self.max_concurrent,
            self.idle_poll_interval,
            self.stale_seconds,
        )

        boot_rss = current_rss_bytes()
        logger.info(
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

        # Bind worker_id for the daemon's lifetime so every line this loop
        # (and its copy_context'd worker threads) emits carries the same
        # queryable identity the BaseWorker pipeline gets for free. The
        # process runs this loop until shutdown, so a lifetime bind via the
        # contextvar is the daemon analogue of BaseWorker's per-job bind.
        worker_id_var.set(self.worker_id)

        rss_at_boot = boot_rss
        batch_counter = 0
        poll_counter = 0
        try:
            while self._running:
                poll_counter += 1

                session = SessionLocal()
                try:
                    try:
                        if poll_counter % _STALE_RECOVERY_EVERY_N_POLLS == 0:
                            self._recover_stale(session)
                        claimed_ids = self._claim_batch(session)
                    except Exception:
                        # Defense in depth: any DB failure during the claim/
                        # recover phase used to propagate out of run_loop and
                        # crash the worker — deploy/start_workers.sh's ``wait -n``
                        # then takes the whole VM down. Roll back the broken
                        # transaction, log the trace, and let the next poll
                        # try again. Specific failure modes we've hit:
                        # ``_reject_proxy_coverage`` trigger violations on
                        # rows whose contract was reclassified mid-flight
                        # (now also filtered in ``_claim_batch``); transient
                        # Neon SSL drops on long-idle sessions.
                        logger.exception(
                            "Worker %s: claim/recover phase raised; rolling back and continuing",
                            self.worker_id,
                        )
                        try:
                            session.rollback()
                        except Exception:
                            logger.debug("rollback failed in run_loop", exc_info=True)
                        claimed_ids = []
                finally:
                    session.close()

                # ``verified_last_pass`` is the per-pass throughput count the
                # fleet view diffs into a rate. The beat fires before the batch
                # is processed (it must also fire on an idle poll so the daemon
                # never reads as stale), so this is "rows taken up to verify
                # this pass" — 0 when idle.
                record_heartbeat(
                    HEARTBEAT_COVERAGE_VERIFY,
                    status="running" if claimed_ids else "idle",
                    detail={"verified_last_pass": len(claimed_ids)},
                )
                if not claimed_ids:
                    time.sleep(self.idle_poll_interval)
                    continue

                logger.info(
                    "Worker %s claimed %d coverage row(s)",
                    self.worker_id,
                    len(claimed_ids),
                )

                futures = {}
                for row_id in claimed_ids:
                    ctx = contextvars.copy_context()
                    futures[executor.submit(ctx.run, self._process_row, row_id)] = row_id
                verdicts: dict[str, int] = {}
                for future in as_completed(futures):
                    try:
                        row_id, status, exc, row_ctx = future.result()
                    except Exception:
                        logger.exception("Unexpected error in %s thread", self.worker_name)
                        continue
                    self._log_outcome(row_id, status, exc, row_ctx)
                    if exc is not None:
                        self._handle_crash(row_id, exc)
                        verdict = _crash_status(exc)
                    else:
                        verdict = status or "vanished"
                    verdicts[verdict] = verdicts.get(verdict, 0) + 1

                # Per-pass verdict rollup (heartbeat detail + hash_mismatch
                # WARNING) — the daemon substitute for a stage metric.
                self._summarize_pass(len(claimed_ids), verdicts)

                batch_counter += 1
                rss_after = current_rss_bytes()
                logger.info(
                    "[BATCH] worker=%s phase=%s batch=%d processed=%d rss_mb=%s "
                    "delta_since_boot_mb=%+d cgroup_used_mb=%s",
                    self.worker_id,
                    self.worker_name,
                    batch_counter,
                    len(claimed_ids),
                    mb(rss_after),
                    int((rss_after - rss_at_boot) / (1024 * 1024)),
                    mb(cgroup_memory_current_bytes()),
                )
        finally:
            executor.shutdown(wait=True)
            logger.info("Worker %s shut down", self.worker_id)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    CoverageVerifyWorker().run_loop()


if __name__ == "__main__":
    main()
