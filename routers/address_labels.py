"""Admin-curated address → name labels."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from db.models import AddressLabel
from schemas.api_requests import AddressLabelUpsert

from . import deps

router = APIRouter()


@router.get("/api/address_labels")
def list_address_labels() -> dict[str, Any]:
    """Return every stored address → name mapping as a flat dict.

    Public read endpoint so any page (principal detail, surface node, etc.)
    can decorate raw hex addresses with the admin-assigned name. The admin
    key is only required to mutate labels (PUT/DELETE below).
    """
    with deps.SessionLocal() as session:
        rows = session.execute(select(AddressLabel)).scalars().all()
        return {
            "labels": {
                row.address: {
                    "name": row.name,
                    "note": row.note,
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                }
                for row in rows
            },
        }


@router.put("/api/address_labels/{address}", dependencies=[Depends(deps.require_admin_key)])
def upsert_address_label(address: str, payload: AddressLabelUpsert) -> dict[str, Any]:
    """Create or update the human-readable name for an address.

    Idempotent — repeated calls with the same body leave the row unchanged
    (aside from ``updated_at``). The frontend uses this to label Safe
    signers and EOA principals.
    """
    a = deps._normalize_address_or_400(address)
    with deps.SessionLocal() as session:
        row = session.get(AddressLabel, a)
        if row is None:
            row = AddressLabel(address=a, name=payload.name.strip(), note=payload.note)
            session.add(row)
        else:
            row.name = payload.name.strip()
            row.note = payload.note
        session.commit()
        deps.log_admin_mutation("address_label_upsert", id=a)
        return {
            "address": a,
            "name": row.name,
            "note": row.note,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }


@router.delete("/api/address_labels/{address}", dependencies=[Depends(deps.require_admin_key)])
def delete_address_label(address: str) -> dict[str, Any]:
    a = deps._normalize_address_or_400(address)
    with deps.SessionLocal() as session:
        row = session.get(AddressLabel, a)
        if row is None:
            raise HTTPException(status_code=404, detail="Label not found")
        session.delete(row)
        session.commit()
        deps.log_admin_mutation("address_label_delete", id=a)
        return {"address": a, "deleted": True}
