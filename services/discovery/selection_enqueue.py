"""Selection-pass enqueue for newly promoted members.

Outside the gate and ``workers/`` to avoid an import cycle; used by the gate's event-2 wrapper and the discovery worker.
A queued or processing pass already covers new members, and empty promotion sets enqueue nothing.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Sequence

from sqlalchemy import select

from db.models import Contract, Job, JobStage, JobStatus
from db.queue import create_job

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def enqueue_selection_pass(session: Session, protocol_id: int, *, reason: str) -> bool:
    pending = session.execute(
        select(Job.id)
        .where(
            Job.stage == JobStage.selection,
            Job.status.in_([JobStatus.queued, JobStatus.processing]),
            Job.protocol_id == protocol_id,
        )
        .limit(1)
    ).first()
    if pending is not None:
        return False
    create_job(
        session,
        {"protocol_id": protocol_id, "name": f"{reason}_selection_{protocol_id}"},
        initial_stage=JobStage.selection,
    )
    logger.info("selection pass enqueued", extra={"protocol_id": protocol_id, "reason": reason})
    return True


def enqueue_selection_for_promotions(
    session: Session, promoted_contract_ids: Sequence[int], *, reason: str
) -> list[int]:
    """One selection pass per protocol that gained members, read off the promoted rows (rows already unstamped
    contribute nothing). Returns the protocol ids, sorted.
    """
    ids = sorted({cid for cid in promoted_contract_ids})
    if not ids:
        return []
    protocol_ids = sorted(
        {
            int(protocol_id)
            for (protocol_id,) in session.execute(
                select(Contract.protocol_id).where(Contract.id.in_(ids), Contract.protocol_id.is_not(None)).distinct()
            )
        }
    )
    return [pid for pid in protocol_ids if enqueue_selection_pass(session, pid, reason=reason)]
