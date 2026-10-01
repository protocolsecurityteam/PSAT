"""Per-address deploy-floor witnesses (``address_floor_witnesses``): written by the indexer's seed witness, read by
live-scan floors.
"""

from __future__ import annotations

from typing import Literal

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import (
    CURSOR_BASIS_NOT_DETERMINED,
    FIRST_INDEXED_BASIS_CREATION,
    FLOOR_WITNESS_FAILED,
    FLOOR_WITNESS_PRIOR_INCARNATION,
    FLOOR_WITNESS_PROVEN,
    FLOOR_WITNESS_RETRYABLE,
    AddressFloorWitness,
)

# ``prior_incarnation``: logs exist at or below the seed, which disproves that number as a floor. ``failed``: the
# witness could not decide (read error, timeout, code-shape mismatch).
WitnessOutcome = Literal["proven", "prior_incarnation", "failed"]
WITNESS_PROVEN: WitnessOutcome = FLOOR_WITNESS_PROVEN
WITNESS_PRIOR_INCARNATION: WitnessOutcome = FLOOR_WITNESS_PRIOR_INCARNATION
WITNESS_FAILED: WitnessOutcome = FLOOR_WITNESS_FAILED

RETRY_BASE_S = 600
RETRY_CAP_S = 86_400
# 10 min · 2^8 already exceeds the cap; bounding the exponent keeps the interval arithmetic finite.
_RETRY_MAX_EXPONENT = 8


def retry_delay_s(prior_attempts: int) -> int:
    """Seconds until the next retry after a failure that follows ``prior_attempts`` consecutive ones."""
    return min(RETRY_BASE_S * 2 ** min(max(0, prior_attempts), _RETRY_MAX_EXPONENT), RETRY_CAP_S)


def record_floor_witness(
    session: Session,
    *,
    chain_id: int,
    address: str,
    outcome: WitnessOutcome,
    first_indexed_block: int | None = None,
    seed_block: int | None = None,
) -> int | None:
    """Upsert one witness result; returns the row's consecutive failure count, or ``None`` when the row kept a decided
    verdict.

    A decided row (proven or prior incarnation) is never replaced by a failure. A prior-incarnation result replaces
    anything, since it disproves the number. A proof replaces anything except a prior-incarnation verdict about the
    same seed: logs observed below a seed outweigh a later empty read of it.
    """
    proven = outcome == WITNESS_PROVEN
    if proven and first_indexed_block is None:
        raise ValueError("a proven floor witness needs its block")
    seed = first_indexed_block if proven and seed_block is None else seed_block
    table = AddressFloorWitness.__table__
    failed = outcome == WITNESS_FAILED
    stmt = pg_insert(AddressFloorWitness).values(
        chain_id=chain_id,
        address=address.lower(),
        first_indexed_block=first_indexed_block if proven else None,
        basis=FIRST_INDEXED_BASIS_CREATION if proven else CURSOR_BASIS_NOT_DETERMINED,
        outcome=outcome,
        seed_block=seed,
        attempts=1 if failed else 0,
        next_attempt_at=(func.now() + text(f"interval '{retry_delay_s(0)} seconds'")) if failed else None,
    )
    update: dict[str, object] = {
        "first_indexed_block": stmt.excluded.first_indexed_block,
        "basis": stmt.excluded.basis,
        "outcome": stmt.excluded.outcome,
        "seed_block": stmt.excluded.seed_block,
        "witnessed_at": func.now(),
    }
    if failed:
        exponent = func.least(table.c.attempts, _RETRY_MAX_EXPONENT)
        update["attempts"] = table.c.attempts + 1
        update["next_attempt_at"] = func.now() + func.least(
            text(f"interval '{RETRY_BASE_S} seconds'") * func.power(2, exponent),
            text(f"interval '{RETRY_CAP_S} seconds'"),
        )
        where = table.c.outcome.in_(FLOOR_WITNESS_RETRYABLE)
    else:
        update["attempts"] = 0
        update["next_attempt_at"] = None
        where = None
        if proven:
            where = ~(
                (table.c.outcome == FLOOR_WITNESS_PRIOR_INCARNATION)
                & table.c.seed_block.is_not_distinct_from(stmt.excluded.seed_block)
            )
    stmt = stmt.on_conflict_do_update(index_elements=["chain_id", "address"], set_=update, where=where).returning(
        table.c.attempts, table.c.outcome
    )
    row = session.execute(stmt).first()
    if row is None or row[1] != WITNESS_FAILED:
        return None
    return int(row[0])


def read_floor_witness(session: Session, *, chain_id: int, address: str) -> tuple[int | None, str] | None:
    """``(first_indexed_block, basis)`` for the address, or ``None`` when no witness was ever recorded."""
    row = session.execute(
        select(AddressFloorWitness.first_indexed_block, AddressFloorWitness.basis)
        .where(AddressFloorWitness.chain_id == chain_id)
        .where(AddressFloorWitness.address == address.lower())
    ).first()
    if row is None:
        return None
    return (int(row[0]) if row[0] is not None else None), str(row[1])
