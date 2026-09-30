"""Re-witness deploy floors: every restaking cursor, and every cursored address with no ``address_floor_witnesses``
row, gets one run of the indexer's seed witness.

Dry-run by default: reads the chain, records no witness and rewrites no cursor (the Etherscan creation lookup may
still fill its own response cache):

    uv run python -m workers.floor_witness_backfill
    uv run python -m workers.floor_witness_backfill --apply

Results go through the witness upsert, so a failed read never downgrades a proven floor. A restaking cursor's own
``first_indexed_block`` is rewritten only when the witness proves the seed, the cursor has reached it, and no indexed
row sits at or below it (restaking enrolment always seeded at the same Etherscan ``creation - 1``).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass

from sqlalchemy import and_, func, select, update
from sqlalchemy.orm import Session

from db.floor_witnesses import read_floor_witness
from db.models import (
    CURSOR_BASIS_NOT_DETERMINED,
    FIRST_INDEXED_BASIS_CREATION,
    AddressFloorWitness,
    IndexedEventCursor,
    IndexedEventLog,
    SessionLocal,
)
from services.monitoring.restaking_enrollment import PUBKEY_LINKED_TOPIC0, RESTAKING_FOLD_ENROLLMENT_BASIS
from utils.logging import configure_logging
from workers.event_log_indexer import EnrollmentCaches, _seed_block, _witness_seed_block

logger = logging.getLogger(__name__)

REASON_RESTAKING_CURSOR = "restaking_cursor"
REASON_NO_WITNESS_ROW = "no_witness_row"


@dataclass(frozen=True)
class RewitnessResult:
    chain_id: int
    address: str
    reason: str
    seed: int | None
    first_indexed_block: int | None
    basis: str | None
    prior_witness: list[int | str | None] | None
    cursors_rewritten: int
    applied: bool


def rewitness_candidates(session: Session, *, chain_id: int | None = None) -> list[tuple[int, str, str]]:
    """``(chain_id, address, reason)``, restaking cursors first; an address appears once."""
    restaking = select(IndexedEventCursor.chain_id, func.lower(IndexedEventCursor.event_address)).where(
        IndexedEventCursor.topic0 == PUBKEY_LINKED_TOPIC0,
        IndexedEventCursor.enrollment_basis == RESTAKING_FOLD_ENROLLMENT_BASIS,
    )
    unwitnessed = (
        select(IndexedEventCursor.chain_id, func.lower(IndexedEventCursor.event_address))
        .outerjoin(
            AddressFloorWitness,
            and_(
                AddressFloorWitness.chain_id == IndexedEventCursor.chain_id,
                AddressFloorWitness.address == func.lower(IndexedEventCursor.event_address),
            ),
        )
        .where(AddressFloorWitness.address.is_(None))
    )
    if chain_id is not None:
        restaking = restaking.where(IndexedEventCursor.chain_id == chain_id)
        unwitnessed = unwitnessed.where(IndexedEventCursor.chain_id == chain_id)
    out: list[tuple[int, str, str]] = []
    seen: set[tuple[int, str]] = set()
    for query, reason in ((restaking, REASON_RESTAKING_CURSOR), (unwitnessed, REASON_NO_WITNESS_ROW)):
        for row_chain, address in sorted(set(session.execute(query.distinct()).all())):
            key = (int(row_chain), str(address))
            if key in seen:
                continue
            seen.add(key)
            out.append((key[0], key[1], reason))
    return out


def _rewrite_restaking_cursors(session: Session, *, chain_id: int, address: str, seed: int) -> int:
    """Stamp the proven floor on the address's unwitnessed restaking cursors that were enrolled at ``seed``.

    A cursor already past ``seed`` with no indexed row at or below it is consistent with that enrolment; anything else
    keeps ``not_determined``.
    """
    cursor_filter = (
        IndexedEventCursor.chain_id == chain_id,
        func.lower(IndexedEventCursor.event_address) == address,
        IndexedEventCursor.topic0 == PUBKEY_LINKED_TOPIC0,
        IndexedEventCursor.enrollment_basis == RESTAKING_FOLD_ENROLLMENT_BASIS,
        IndexedEventCursor.first_indexed_block_basis == CURSOR_BASIS_NOT_DETERMINED,
        IndexedEventCursor.last_indexed_block >= seed,
    )
    below_seed = (
        select(IndexedEventLog.block_number)
        .where(IndexedEventLog.chain_id == chain_id)
        .where(func.lower(IndexedEventLog.event_address) == address)
        .where(IndexedEventLog.topic0 == PUBKEY_LINKED_TOPIC0)
        .where(IndexedEventLog.block_number <= seed)
        .limit(1)
    )
    if session.execute(below_seed).first() is not None:
        return 0
    result = session.execute(
        update(IndexedEventCursor)
        .where(*cursor_filter)
        .values(first_indexed_block=seed, first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION)
        .execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0) or 0)


def rewitness_floor_witnesses(
    session: Session,
    *,
    apply: bool = False,
    chain_id: int | None = None,
    limit: int | None = None,
) -> list[RewitnessResult]:
    """Run the seed witness once per candidate address. ``apply=False`` records no witness and rewrites no cursor."""
    caches = EnrollmentCaches()
    results: list[RewitnessResult] = []
    candidates = rewitness_candidates(session, chain_id=chain_id)
    if limit is not None:
        candidates = candidates[: max(0, limit)]
    for row_chain, address, reason in candidates:
        prior = read_floor_witness(session, chain_id=row_chain, address=address)
        seed = _seed_block(address, caches.seeds, chain_id=row_chain)
        if seed is None:
            results.append(
                RewitnessResult(
                    chain_id=row_chain,
                    address=address,
                    reason=reason,
                    seed=None,
                    first_indexed_block=None,
                    basis=None,
                    prior_witness=list(prior) if prior is not None else None,
                    cursors_rewritten=0,
                    applied=False,
                )
            )
            continue
        first_indexed_block, basis = _witness_seed_block(
            address, seed, caches.witnesses, chain_id=row_chain, session=session if apply else None
        )
        rewritten = 0
        if apply:
            if reason == REASON_RESTAKING_CURSOR and basis == FIRST_INDEXED_BASIS_CREATION:
                rewritten = _rewrite_restaking_cursors(session, chain_id=row_chain, address=address, seed=seed)
            session.commit()
        results.append(
            RewitnessResult(
                chain_id=row_chain,
                address=address,
                reason=reason,
                seed=seed,
                first_indexed_block=first_indexed_block,
                basis=basis,
                prior_witness=list(prior) if prior is not None else None,
                cursors_rewritten=rewritten,
                applied=apply,
            )
        )
    if not apply:
        session.rollback()
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True, help="read the chain, write nothing (default)")
    mode.add_argument("--apply", action="store_true", help="record results and rewrite proven restaking cursors")
    parser.add_argument("--chain-id", type=int, default=None)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)
    configure_logging()
    with SessionLocal() as session:
        results = rewitness_floor_witnesses(session, apply=args.apply, chain_id=args.chain_id, limit=args.limit)
    for result in results:
        print(json.dumps(asdict(result), sort_keys=True))
    proven = sum(1 for r in results if r.basis == FIRST_INDEXED_BASIS_CREATION)
    logger.info(
        "floor witness backfill finished",
        extra={
            "apply": args.apply,
            "candidates": len(results),
            "proven": proven,
            "not_proven": len(results) - proven,
            "cursors_rewritten": sum(r.cursors_rewritten for r in results),
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
