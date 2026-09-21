"""Bounded drains of enrollment sources and changed reconciliation inputs."""

from __future__ import annotations

import logging
import uuid
from functools import partial

from sqlalchemy.orm import Session

from db.models import Job, MonitoredContract
from services.resolution.deferred_reconciler import (
    enqueue_reorg_refreshes,
    reconcile_deferred_resolutions,
    reconcile_role_set_drift,
    refresh_invalidated_job,
)
from services.resolution.indexer_work import WorkPending, claim_one, finish, lock_claim, renew_and_commit, repair_due
from utils.chains import supported_chain_ids

logger = logging.getLogger(__name__)


def drain_enrollment(session: Session, *, limit: int = 50, tracked_limit: int = 50) -> int:
    from workers.event_log_indexer import EnrollmentCaches, enroll_from_completed_jobs, enroll_from_tracked_topics

    kinds = ("job", "monitored") if tracked_limit > 0 else ("job",)
    repaired = repair_due(session, kinds, limit=limit)
    enrolled = 0
    deferred = 0
    tracked_processed = 0
    caches = EnrollmentCaches()
    visited: set[tuple[str, str]] = set()
    for _ in range(limit):
        eligible = kinds if tracked_processed < tracked_limit else ("job",)
        claim = claim_one(session, eligible, exclude=visited)
        if claim is None:
            break
        visited.add((claim.kind, claim.key))
        tracked_processed += claim.kind == "monitored"
        pending: set[tuple[int, str]] = set()
        try:
            source_id = uuid.UUID(claim.key)
            if claim.kind == "job":
                gone = session.get(Job, source_id) is None
                count = enroll_from_completed_jobs(
                    session,
                    job_id=source_id,
                    pending=pending,
                    progress=partial(renew_and_commit, session, claim),
                    commit=False,
                    caches=caches,
                )
            else:
                gone = session.get(MonitoredContract, source_id) is None
                count = enroll_from_tracked_topics(
                    session,
                    monitored_id=source_id,
                    pending=pending,
                    progress=partial(renew_and_commit, session, claim),
                    commit=False,
                    caches=caches,
                )
            # Successful cursor inserts commit separately before the next RPC;
            # crashes retry the source and cheaply skip those durable cursors.
            finish(session, claim, success=not pending, remove=gone)
            enrolled += count
            deferred += bool(pending)
        except Exception as exc:
            deferred += 1
            session.rollback()
            finish(session, claim, success=False)
            logger.warning(
                "indexer enrollment deferred",
                extra={
                    "kind": claim.kind,
                    "source_id": claim.key,
                    "exc_type": type(exc).__name__,
                },
            )
    logger.info(
        "indexer enrollment queue pass",
        extra={
            "processed": len(visited),
            "deferred": deferred,
            "repair_enqueued": repaired,
            "enrolled": enrolled,
        },
    )
    return enrolled


def drain_reconciliation(session: Session, *, limit: int = 20, job_limit: int = 200) -> tuple[int, int]:
    repaired = repair_due(session, ("reconcile",), limit=limit)
    deferred = drift = 0
    pending = 0
    visited: set[tuple[str, str]] = set()
    for _ in range(limit):
        claim = claim_one(session, ("reconcile", "reorg", "refresh_job"), exclude=visited)
        if claim is None:
            break
        visited.add((claim.kind, claim.key))
        try:
            if claim.kind == "reorg":
                chain, address = claim.key.split(":", 1)
                if int(chain) not in supported_chain_ids():
                    raise WorkPending("chain is not currently enabled")
                lock_claim(session, claim)
                enqueue_reorg_refreshes(session, chain_id=int(chain), authority=address)
                finish(session, claim, success=True, remove=True)
            elif claim.kind == "refresh_job":
                lock_claim(session, claim)
                count = refresh_invalidated_job(session, uuid.UUID(claim.key))
                finish(session, claim, success=True, remove=True)
                drift += count
            else:
                chain_id = int(claim.key)
                if chain_id not in supported_chain_ids():
                    raise WorkPending("chain is not currently enabled")
                a = reconcile_deferred_resolutions(session, chain_id=chain_id, limit=job_limit)
                b = reconcile_role_set_drift(session, chain_id=chain_id, limit=job_limit)
                deferred += a
                drift += b
                # Existing reconcilers commit their progress; a cap must retain
                # the remainder even if nothing else changes on the chain.
                finish(session, claim, success=a < job_limit and b < job_limit)
                pending += a >= job_limit or b >= job_limit
        except Exception as exc:
            pending += 1
            session.rollback()
            finish(session, claim, success=False)
            logger.warning(
                "indexer reconciliation deferred",
                extra={
                    "kind": claim.kind,
                    "source_id": claim.key,
                    "exc_type": type(exc).__name__,
                },
            )
    logger.info(
        "indexer reconciliation queue pass",
        extra={
            "processed": len(visited),
            "deferred": pending,
            "repair_enqueued": repaired,
            "reenqueued": deferred,
            "drift_reenqueued": drift,
        },
    )
    return deferred, drift
