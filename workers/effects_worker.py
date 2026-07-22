"""Effects worker — behavioral effect simulation (EFFECTS_RESOLUTION_SPEC §3a).

The sixth pipeline stage worker, inserted between ``policy`` and ``coverage``.
It determines what a gated function *does* by observing state transitions on a
fork (idiom-agnostic witnesses), backed by a persistent behavioral-hash cache.

The policy->effects transition is feature-flagged (``PSAT_EFFECTS_STAGE``,
default-off, read in ``PolicyWorker.next_stage``); with the flag off no job ever
enters this stage and the worker simply idles.

**Phase 1 scope: this ``process()`` is an inert stub.** It establishes the
six-phase observability scaffolding (``preflight`` → ``selection`` →
``cache_lookup`` → ``tier1_probes`` → ``tier2_fork`` → ``verdict_write``) and
the fail-forward semantics, but does no real simulation — the harness (Tier 1
eth_call / Tier 2 anvil fork) lands in Phase 2. It is safe to run: it advances
every job straight through to ``coverage`` with zero verdicts.

Everything else — lease claim, stale reclaim, background heartbeat, SIGTERM
release, the ``[BOOT]`` banner, ``StageErrors``, and per-worker in-process
concurrency via ``PSAT_EFFECTS_JOB_CONCURRENCY`` (default 1, single-flight per
inv. 16 because anvil snapshot/revert is process-global) — is inherited from
``BaseWorker``. This file overrides ``process()`` and the terminal-failure
finalizer only.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from db.models import Job, JobStage
from db.queue import advance_job
from utils.logging import log_timed_phase, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.effects_worker")


class EffectsWorker(BaseWorker):
    stage = JobStage.effects
    next_stage = JobStage.coverage

    def process(self, session: Session, job: Job) -> None:
        logger.info(
            "Effects stage started for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )
        durations_ms: dict[str, int] = {}

        # Preflight (Phase 2): probe + persist eth_simulateV1 support per chain
        # (inv. 14); pin/assert the fork hardfork.
        with log_timed_phase(logger, "preflight", durations_ms=durations_ms):
            pass

        # Selection (Phase 2): the §6 cascade (sink non-empty → blank-claim set
        # → gated preferred) + transitive value-at-stake ordering. Owned by
        # ``services.effects.selection`` (Coder 1b) — NOT imported here yet.
        with log_timed_phase(logger, "selection", durations_ms=durations_ms) as ph:
            candidates: list[object] = []
            ph["candidate_count"] = len(candidates)
        record_stage_metric("candidates_in", len(candidates))
        record_stage_metric("candidates_after_cascade", len(candidates))

        # Cache lookup (Phase 3): kernel/projection behavioral-hash dedup.
        with log_timed_phase(logger, "cache_lookup", durations_ms=durations_ms):
            pass
        record_stage_metric("cache_hits_kernel", 0)
        record_stage_metric("cache_hits_projection", 0)
        record_stage_metric("cache_misses", 0)

        # Tier 1 probes (Phase 2): eth_call / eth_simulateV1 with state overrides.
        with log_timed_phase(logger, "tier1_probes", durations_ms=durations_ms):
            pass

        # Tier 2 fork (Phase 2): anvil snapshot/revert for sequencing/time.
        with log_timed_phase(logger, "tier2_fork", durations_ms=durations_ms):
            pass

        # Verdict write (Phase 3): persist gate-relative verdicts + transcripts.
        with log_timed_phase(logger, "verdict_write", durations_ms=durations_ms) as ph:
            verdicts_written = 0
            ph["verdicts_written"] = verdicts_written
        record_stage_metric("verdicts_written", verdicts_written)
        record_stage_metric("discrepancies_filed", 0)

        logger.info(
            "Effects stage (inert stub) complete for job %s: %d candidates, %d verdicts",
            job.id,
            len(candidates),
            verdicts_written,
            extra={"durations_ms": durations_ms},
        )

    def _finalize_terminal_failure(
        self,
        session: Session,
        job: Job,
        *,
        error: str,
        kind: str,
        retry_count: int | None,
        lease_id,
    ) -> None:
        """Fail-forward (inv. 15): the effects stage NEVER emits
        ``failed_terminal``. On retry exhaustion (or a terminal error) advance
        to ``coverage`` instead of killing a job whose upstream policy artifacts
        are already complete and correct — flag-off is otherwise strictly better
        than flag-on, which the whole stage must not be.

        Verdicts default to ``unknown`` (the §8 fail-closed value; the harness
        writes them per behavior in Phase 2+, and with no candidates there is
        nothing to write here). The failing exception is already in the
        ``stage_errors`` artifact — ``BaseWorker`` persisted the degraded
        accumulator before invoking this hook — so the degradation stays
        observable without a bespoke marker.
        """
        logger.warning(
            "Effects stage fail-forward: advancing job %s to %s after %s failure "
            "(retries exhausted); verdicts default to unknown",
            job.id,
            self.next_stage.value,
            kind,
            extra={"phase": "job", "outcome": "degraded_advance", "failure_kind": kind},
        )
        advance_job(
            session,
            job.id,
            self.next_stage,
            "effects degraded → coverage (fail-forward)",
            lease_id=lease_id,
        )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    EffectsWorker().run_loop()


if __name__ == "__main__":
    main()
