"""Writes to ``contract_creation_witnesses``. Concurrent jobs probe the same address, so every write is an upsert."""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import ContractCreationWitness

_WRITABLE = frozenset(
    {"creation_tx_hash", "creation_block", "creation_factory", "code_probe_block", "code_absent_at_probe"}
)


def upsert_creation_witness(
    session: Session, *, chain_id: int, address: str, keep_existing: bool = False, **fields: Any
) -> None:
    """Insert the ``(chain_id, address)`` row or overwrite only the given columns on it. With *keep_existing*, a row
    another writer created first is left untouched.

    A ``None`` value never erases a fact another writer recorded, and an older ``code_probe_block`` reading never
    replaces a newer one.
    """
    unknown = set(fields) - _WRITABLE
    if unknown:
        raise ValueError(f"not creation-witness columns: {sorted(unknown)}")
    address = address.lower()
    fields = {name: value for name, value in fields.items() if value is not None}
    stmt = pg_insert(ContractCreationWitness).values(chain_id=chain_id, address=address, **fields)
    if fields and not keep_existing:
        updates: dict[str, Any] = {name: stmt.excluded[name] for name in fields}
        if "code_probe_block" in fields:
            newer = stmt.excluded.code_probe_block >= func.coalesce(ContractCreationWitness.code_probe_block, -1)
            for name in ("code_probe_block", "code_absent_at_probe"):
                if name in fields:
                    updates[name] = case((newer, stmt.excluded[name]), else_=getattr(ContractCreationWitness, name))
        stmt = stmt.on_conflict_do_update(index_elements=["chain_id", "address"], set_=updates)
    else:
        stmt = stmt.on_conflict_do_nothing(index_elements=["chain_id", "address"])
    session.execute(stmt)
    # The statement bypasses the unit of work, so a row already loaded in this session would read stale values.
    loaded = session.identity_map.get(session.identity_key(ContractCreationWitness, (chain_id, address)))
    if loaded is not None:
        session.expire(loaded)
