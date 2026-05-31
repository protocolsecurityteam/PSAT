"""Admin-curated address → name labels."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from db.models import AddressLabel
from schemas.api_requests import AddressLabelUpsert
from utils.chains import canonical_chain

from . import deps

router = APIRouter()


def _canon_chain(chain: str | None) -> str:
    return canonical_chain(chain) or "ethereum"


@router.get("/api/address_labels")
def list_address_labels() -> dict[str, Any]:
    """Return every stored (address, chain) → name mapping.

    Public read endpoint so any page (principal detail, surface node, etc.)
    can decorate raw hex addresses with the admin-assigned name. Keyed by
    ``"<chain>:<address>"`` because the same address can carry a different
    label per network; each entry also carries ``address`` and ``chain`` so
    clients can index however they like. The admin key is only required to
    mutate labels (PUT/DELETE below).
    """
    with deps.SessionLocal() as session:
        rows = session.execute(select(AddressLabel)).scalars().all()
        return {
            "labels": {
                f"{row.chain}:{row.address}": {
                    "address": row.address,
                    "chain": row.chain,
                    "name": row.name,
                    "note": row.note,
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                }
                for row in rows
            },
        }


@router.put("/api/address_labels/{address}", dependencies=[Depends(deps.require_admin_key)])
def upsert_address_label(address: str, payload: AddressLabelUpsert, chain: str = "ethereum") -> dict[str, Any]:
    """Create or update the human-readable name for an address on *chain*.

    Idempotent — repeated calls with the same body leave the row unchanged
    (aside from ``updated_at``). ``chain`` defaults to ``ethereum`` so existing
    single-chain clients keep working. The frontend uses this to label Safe
    signers and EOA principals.
    """
    a = deps._normalize_address_or_400(address)
    c = _canon_chain(chain)
    with deps.SessionLocal() as session:
        row = session.get(AddressLabel, (a, c))
        if row is None:
            row = AddressLabel(address=a, chain=c, name=payload.name.strip(), note=payload.note)
            session.add(row)
        else:
            row.name = payload.name.strip()
            row.note = payload.note
        session.commit()
        return {
            "address": a,
            "chain": c,
            "name": row.name,
            "note": row.note,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }


@router.delete("/api/address_labels/{address}", dependencies=[Depends(deps.require_admin_key)])
def delete_address_label(address: str, chain: str = "ethereum") -> dict[str, Any]:
    a = deps._normalize_address_or_400(address)
    c = _canon_chain(chain)
    with deps.SessionLocal() as session:
        row = session.get(AddressLabel, (a, c))
        if row is None:
            raise HTTPException(status_code=404, detail="Label not found")
        session.delete(row)
        session.commit()
        return {"address": a, "chain": c, "deleted": True}
