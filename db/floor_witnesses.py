"""Per-address deploy-floor witnesses (``address_floor_witnesses``): written by the indexer's seed witness, read by
live-scan floors.
"""

from __future__ import annotations

from typing import Literal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import CURSOR_BASIS_NOT_DETERMINED, FIRST_INDEXED_BASIS_CREATION, AddressFloorWitness

# ``prior_incarnation``: logs exist at or below the seed, which disproves that number as a floor. ``failed``: the
# witness could not decide (read error, timeout, code-shape mismatch).
WitnessOutcome = Literal["proven", "prior_incarnation", "failed"]
WITNESS_PROVEN: WitnessOutcome = "proven"
WITNESS_PRIOR_INCARNATION: WitnessOutcome = "prior_incarnation"
WITNESS_FAILED: WitnessOutcome = "failed"


def record_floor_witness(
    session: Session,
    *,
    chain_id: int,
    address: str,
    outcome: WitnessOutcome,
    first_indexed_block: int | None = None,
) -> None:
    """Upsert one witness result.

    A proven row is replaced only by another proof or by a prior-incarnation result; a failure never downgrades it.
    """
    proven = outcome == WITNESS_PROVEN
    if proven and first_indexed_block is None:
        raise ValueError("a proven floor witness needs its block")
    stmt = pg_insert(AddressFloorWitness).values(
        chain_id=chain_id,
        address=address.lower(),
        first_indexed_block=first_indexed_block if proven else None,
        basis=FIRST_INDEXED_BASIS_CREATION if proven else CURSOR_BASIS_NOT_DETERMINED,
    )
    update = {
        "first_indexed_block": stmt.excluded.first_indexed_block,
        "basis": stmt.excluded.basis,
        "witnessed_at": stmt.excluded.witnessed_at,
    }
    if outcome == WITNESS_FAILED:
        stmt = stmt.on_conflict_do_update(
            index_elements=["chain_id", "address"],
            set_=update,
            where=AddressFloorWitness.basis != FIRST_INDEXED_BASIS_CREATION,
        )
    else:
        stmt = stmt.on_conflict_do_update(index_elements=["chain_id", "address"], set_=update)
    session.execute(stmt)


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
