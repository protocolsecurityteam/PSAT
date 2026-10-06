"""Atomic, field-preserving writes from concurrent discovery and monitoring probes."""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from db.models import ContractCreationWitness


def upsert_creation_witness(session: Session, *, chain_id: int, address: str, **fields: Any) -> ContractCreationWitness:
    # A missing response never erases a fact another worker already recorded.
    supplied = {key: value for key, value in fields.items() if value is not None}
    stmt = insert(ContractCreationWitness).values(chain_id=chain_id, address=address.lower(), **supplied)
    updates = {key: getattr(stmt.excluded, key) for key in supplied}
    if "code_probe_block" in supplied:
        newer = stmt.excluded.code_probe_block >= func.coalesce(ContractCreationWitness.code_probe_block, -1)
        for key in ("code_probe_block", "code_absent_at_probe"):
            if key in supplied:
                updates[key] = case((newer, getattr(stmt.excluded, key)), else_=getattr(ContractCreationWitness, key))
    if not updates:
        updates = {"address": stmt.excluded.address}
    stmt = stmt.on_conflict_do_update(index_elements=["chain_id", "address"], set_=updates)
    return session.execute(
        stmt.returning(ContractCreationWitness), execution_options={"populate_existing": True}
    ).scalar_one()
