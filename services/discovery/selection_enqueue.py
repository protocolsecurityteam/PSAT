"""Selection-pass enqueue for newly promoted members.

A promotion changes the set of rows selection ranks, so a protocol that just
gained members needs a selection pass. This lives outside the gate module and
outside ``workers/`` so both can call it without an import cycle: the gate's
event-2 wrapper fires it, and the discovery worker's direct-``evaluate`` sites
fire it for their own promotions.

Enqueue is guarded twice — a queued/processing pass for the protocol already
covers the new members (the selection worker ranks the full unanalyzed set),
and an empty promotion set fires nothing at all.
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
    """One selection pass per protocol. Returns whether a job was created."""
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
    """Enqueue one selection pass per protocol that gained members. Reads the
    protocol off the promoted rows themselves — a row whose stamp is already
    gone again by the time this runs contributes nothing. Returns the protocol
    ids enqueued, sorted."""
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
