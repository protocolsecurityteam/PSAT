"""Admin-curated address labels: a row is global (``chain IS NULL``, right for EOAs/Safe signers) or a
chain-qualified override (safe for contracts cross-chain). Global rows keep the historical address-keyed shape.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from db.models import AddressLabel
from schemas.api_requests import AddressLabelUpsert
from schemas.api_responses import (
    AddressLabelDeleteResponse,
    AddressLabelsResponse,
    AddressLabelUpsertResponse,
    AddressLabelView,
)
from utils.chains import UnknownChainError, chain_by_name

from . import deps

router = APIRouter()


def _resolve_chain_or_400(chain: str | None) -> str | None:
    """Aliases collapse to one canonical name; an unknown chain is a 400, never a silent fallthrough."""
    if chain is None or not chain.strip():
        return None
    try:
        return chain_by_name(chain).name
    except UnknownChainError:
        raise HTTPException(status_code=400, detail=f"Unknown chain: {chain!r}") from None


def _row_view(row: AddressLabel) -> AddressLabelView:
    return {
        "name": row.name,
        "note": row.note,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("/api/address_labels", response_model=None)
def list_address_labels() -> AddressLabelsResponse:
    """Public so any page can decorate addresses.

    ``labels`` holds global rows in the original shape; overrides are under ``chain_labels``.
    """
    with deps.SessionLocal() as session:
        rows = session.execute(select(AddressLabel)).scalars().all()
        labels: dict[str, AddressLabelView] = {}
        chain_labels: dict[str, dict[str, AddressLabelView]] = {}
        for row in rows:
            if row.chain is None:
                labels[row.address] = _row_view(row)
            else:
                chain_labels.setdefault(row.chain, {})[row.address] = _row_view(row)
        return {"labels": labels, "chain_labels": chain_labels}


@router.put("/api/address_labels/{address}", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def upsert_address_label(
    address: str,
    payload: AddressLabelUpsert,
    chain: str | None = Query(default=None),
) -> AddressLabelUpsertResponse:
    """Without ``?chain=`` writes the global row; with it, a chain-qualified override."""
    a = deps._normalize_address_or_400(address)
    c = _resolve_chain_or_400(chain)
    with deps.SessionLocal() as session:
        stmt = select(AddressLabel).where(AddressLabel.address == a)
        stmt = stmt.where(AddressLabel.chain == c) if c is not None else stmt.where(AddressLabel.chain.is_(None))
        row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            row = AddressLabel(address=a, chain=c, name=payload.name.strip(), note=payload.note)
            session.add(row)
        else:
            row.name = payload.name.strip()
            row.note = payload.note
        session.commit()
        deps.log_admin_mutation("address_label_upsert", id=a if c is None else f"{c}:{a}")
        return {
            "address": a,
            "chain": c,
            "name": row.name,
            "note": row.note,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }


@router.delete("/api/address_labels/{address}", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def delete_address_label(
    address: str,
    chain: str | None = Query(default=None),
) -> AddressLabelDeleteResponse:
    a = deps._normalize_address_or_400(address)
    c = _resolve_chain_or_400(chain)
    with deps.SessionLocal() as session:
        stmt = select(AddressLabel).where(AddressLabel.address == a)
        stmt = stmt.where(AddressLabel.chain == c) if c is not None else stmt.where(AddressLabel.chain.is_(None))
        row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Label not found")
        session.delete(row)
        session.commit()
        deps.log_admin_mutation("address_label_delete", id=a if c is None else f"{c}:{a}")
        return {"address": a, "chain": c, "deleted": True}
