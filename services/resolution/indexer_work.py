"""Trigger-backed indexer work with revision checks and leases across commits."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, func, or_, select, text, tuple_, update
from sqlalchemy.orm import Session

from db.models import IndexerWork

REPAIR_AGE_S = 86400
LEASE_S = 900


class WorkPending(Exception):
    """Inputs are temporarily unavailable; retain this work for a later pass."""


@dataclass(frozen=True)
class Claim:
    kind: str
    key: str
    revision: int
    lease_id: uuid.UUID
    attempts: int


def mark_dirty(session: Session, kind: str, key: str) -> None:
    session.execute(text("SELECT indexer_mark_dirty(:kind, :key)"), {"kind": kind, "key": key})


def repair_due(session: Session, kinds: tuple[str, ...], *, limit: int = 50) -> int:
    """Bounded daily safety sweep. Never accelerate a pending failure's retry."""
    rows = (
        session.execute(
            select(IndexerWork)
            .where(
                IndexerWork.kind.in_(kinds),
                IndexerWork.dirty.is_(False),
                IndexerWork.completed_at < func.statement_timestamp() - timedelta(seconds=REPAIR_AGE_S),
            )
            .order_by(IndexerWork.completed_at, IndexerWork.kind, IndexerWork.key)
            .limit(limit)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    for row in rows:
        row.dirty = True
        row.revision += 1
        row.available_at = func.statement_timestamp()
    session.commit()
    return len(rows)


def claim_one(session: Session, kinds: tuple[str, ...], *, exclude: set[tuple[str, str]] | None = None) -> Claim | None:
    row = session.execute(
        select(IndexerWork)
        .where(
            IndexerWork.kind.in_(kinds),
            tuple_(IndexerWork.kind, IndexerWork.key).not_in(sorted(exclude or set())),
            IndexerWork.dirty.is_(True),
            IndexerWork.available_at <= func.statement_timestamp(),
            or_(IndexerWork.lease_expires_at.is_(None), IndexerWork.lease_expires_at <= func.statement_timestamp()),
        )
        .order_by(IndexerWork.available_at, IndexerWork.kind, IndexerWork.key)
        .limit(1)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        session.rollback()
        return None
    token = uuid.uuid4()
    claim = Claim(row.kind, row.key, row.revision, token, row.attempts)
    row.lease_id = token
    row.lease_expires_at = func.statement_timestamp() + timedelta(seconds=LEASE_S)
    session.commit()
    return claim


def finish(session: Session, claim: Claim, *, success: bool, remove: bool = False) -> None:
    owned = (
        IndexerWork.kind == claim.kind,
        IndexerWork.key == claim.key,
        IndexerWork.lease_id == claim.lease_id,
    )
    if success and remove:
        session.execute(delete(IndexerWork).where(*owned, IndexerWork.revision == claim.revision))
    else:
        values = (
            dict(dirty=False, completed_at=func.statement_timestamp(), attempts=0)
            if success
            else dict(
                attempts=claim.attempts + 1,
                available_at=func.statement_timestamp()
                + timedelta(seconds=min(3600, 60 * 2 ** min(claim.attempts, 6))),
            )
        )
        session.execute(update(IndexerWork).where(*owned, IndexerWork.revision == claim.revision).values(**values))
    # A new revision keeps its dirty flag and immediate due time, but can now be
    # claimed. A stolen lease remains completely untouched.
    session.execute(update(IndexerWork).where(*owned).values(lease_id=None, lease_expires_at=None))
    session.commit()


def renew_and_commit(session: Session, claim: Claim) -> None:
    """Commit cursor progress before RPC only while this worker owns a live lease."""
    renew_claim(session, claim)
    session.commit()


def renew_claim(session: Session, claim: Claim) -> None:
    """Fence writes and renew within the caller's transaction, without committing."""
    result = session.execute(
        update(IndexerWork)
        .where(
            IndexerWork.kind == claim.kind,
            IndexerWork.key == claim.key,
            IndexerWork.lease_id == claim.lease_id,
            IndexerWork.lease_expires_at > func.statement_timestamp(),
        )
        .values(lease_expires_at=func.statement_timestamp() + timedelta(seconds=LEASE_S))
        .returning(IndexerWork.lease_id)
    ).scalar_one_or_none()
    if result is None:
        raise WorkPending("indexer work lease was lost")


def lock_claim(session: Session, claim: Claim) -> None:
    """Fence short database-only reorg actions through their atomic commit."""
    owned = session.execute(
        select(IndexerWork.lease_id)
        .where(
            IndexerWork.kind == claim.kind,
            IndexerWork.key == claim.key,
            IndexerWork.lease_id == claim.lease_id,
            IndexerWork.lease_expires_at > func.statement_timestamp(),
        )
        .with_for_update()
    ).scalar_one_or_none()
    if owned is None:
        raise WorkPending("indexer work lease was lost")
