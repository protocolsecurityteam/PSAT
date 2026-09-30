"""Verifies pending source-equivalence rows asynchronously.

Inline verification at coverage-write time fanned out Etherscan + GitHub bursts that 429'd the global Etherscan window
and stalled every other worker in shared backoff. This worker drains ``equivalence_status='pending'`` at a steady
trickle; keep it low-concurrency or the storm comes back.

``pending`` -> ``verifying`` -> terminal (``proven`` / ``hash_*``) or transient (``*_fetch_failed``). Stale
``verifying`` rows revert to ``pending`` after ``_STALE_VERIFY_TIMEOUT``.
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


# With 2 threads, keeps worst-case in-flight below the Etherscan per-second budget.
_BATCH_SIZE = int(os.getenv("PSAT_COVERAGE_VERIFY_BATCH_SIZE", "4"))

_MAX_CONCURRENT = int(os.getenv("PSAT_COVERAGE_VERIFY_CONCURRENCY", "2"))

_IDLE_POLL_INTERVAL = float(os.getenv("PSAT_COVERAGE_VERIFY_POLL_INTERVAL", "30.0"))

# GitHub can be slow; verification legitimately takes tens of seconds.
_STALE_VERIFY_TIMEOUT = int(os.getenv("PSAT_COVERAGE_VERIFY_STALE_TIMEOUT", "600"))

_STALE_RECOVERY_EVERY_N_POLLS = 10

# A pass dominated by hash_mismatch points at a candidate-path or source-fetch regression, not divergent code; warn once
# per pass, gated on a minimum sample.
_HASH_MISMATCH_WARN_RATE = float(os.getenv("PSAT_COVERAGE_VERIFY_HASH_MISMATCH_WARN_RATE", "0.5"))
_HASH_MISMATCH_WARN_MIN = int(os.getenv("PSAT_COVERAGE_VERIFY_HASH_MISMATCH_WARN_MIN", "4"))


def _crash_status(exc: BaseException) -> str:
    """A concurrent coverage rebuild deleting the row surfaces as ``StaleDataError``: a benign race, so it gets its
    own status rather than inflating ``github_fetch_failed``.
    """
    return "row_vanished" if isinstance(exc, StaleDataError) else "github_fetch_failed"


class CoverageVerifyWorker:
    """Drain ``audit_contract_coverage`` rows where verification is pending."""

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

    def _claim_batch(self, session) -> list[int]:
        """Claim up to ``batch_size`` pending rows by stamping ``verifying``.

        The CTE form is required: ``WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED LIMIT n)`` ignores the inner LIMIT in
        Postgres and updates every pending row.

        Rows whose contract became a proxy are skipped: the ``_reject_proxy_coverage`` trigger would raise on the UPDATE
        and crash the worker. They accumulate as orphaned ``pending`` rows.
        """
        from services.worker_lifecycle import claim_allowed, note_claim

        if not claim_allowed(session):
            return []

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
            note_claim(session)
            session.commit()
        else:
            session.rollback()
        return ids

    def _recover_stale(self, session) -> None:
        """A crashed worker leaves rows in ``verifying`` invisible to every claim until this resets them."""
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

    def _process_row(self, row_id: int) -> tuple[int, str | None, BaseException | None, dict[str, object]]:
        """Returns ``(row_id, status, exc, ctx)`` with exactly one of status/exc set; never raises.

        Crashed rows are stamped by ``_handle_crash`` on the main thread.
        """
        from db.models import AuditContractCoverage
        from services.audits.coverage import verify_one_coverage_row

        github_token = os.environ.get("GITHUB_TOKEN") or None
        session = SessionLocal()
        try:
            try:
                # One line per row (~1k/run) belongs at DEBUG; the duration still feeds the stage metric.
                _row_start = time.monotonic()
                status = verify_one_coverage_row(session, row_id, github_token=github_token)
                _row_ms = int((time.monotonic() - _row_start) * 1000)
                record_stage_metric("phase_ms_verify_row", _row_ms)
                logger.debug(
                    "verify_row complete",
                    extra={"phase": "verify_row", "duration_ms": _row_ms, "row_id": row_id},
                )
                session.commit()
                # Row may have been deleted by a concurrent rebuild; then status is None.
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
                try:
                    session.rollback()
                except Exception:
                    logger.debug("rollback failed in _process_row", exc_info=True)
                # The rolled-back session can't be read; an empty re-read means the row vanished.
                return row_id, None, exc, self._read_row_identity(row_id)
        finally:
            session.close()

    def _read_row_identity(self, row_id: int) -> dict[str, object]:
        """Empty dict means the row is gone or the read failed."""
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
        """Facts go in ``extra`` so verdict distributions are one Loki/jq aggregation."""
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
        """Fresh session so the crash's broken transaction can't leak in; a vanished row makes the UPDATE a no-op."""
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
        """Daemons have no job-scoped metric accumulators, so verdict counts ride in the heartbeat ``detail``.

        Returns the hash_mismatch rate.
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

    def run_loop(self) -> None:
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

        # Lifetime bind: the daemon analogue of BaseWorker's per-job worker_id bind.
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
                        # A DB failure here used to crash the worker, and ``wait -n`` in start_workers.sh takes the VM
                        # down. Seen: proxy-coverage trigger violations, Neon SSL drops on idle sessions.
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

                # Fires before the batch (and on idle) so this counts rows taken up this pass.
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
