"""MonitoredContract listing and updates + MonitoredEvent listing."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select

from db.models import Contract, MonitoredContract, MonitoredEvent, Protocol
from schemas.api_requests import UpdateMonitoredContractRequest, UpsertMonitoredContractRequest

from . import deps

router = APIRouter()


def _monitored_contract_payload(c: MonitoredContract) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "address": c.address,
        "chain": c.chain,
        "protocol_id": c.protocol_id,
        "contract_id": c.contract_id,
        "contract_type": c.contract_type,
        "monitoring_config": c.monitoring_config,
        "last_known_state": c.last_known_state,
        "last_scanned_block": c.last_scanned_block,
        "needs_polling": c.needs_polling,
        "is_active": c.is_active,
        "enrollment_source": c.enrollment_source,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


@router.get("/api/monitored-contracts")
def list_monitored_contracts(
    protocol_id: int | None = None,
    chain: str | None = None,
) -> list[dict[str, Any]]:
    """List all MonitoredContract rows, optionally filtered."""
    with deps.SessionLocal() as session:
        stmt = select(MonitoredContract).order_by(MonitoredContract.created_at.desc())
        if protocol_id is not None:
            stmt = stmt.where(MonitoredContract.protocol_id == protocol_id)
        if chain is not None:
            stmt = stmt.where(MonitoredContract.chain == chain)
        contracts = session.execute(stmt).scalars().all()
        return [_monitored_contract_payload(c) for c in contracts]


@router.post("/api/protocols/{protocol_id}/monitoring", dependencies=[Depends(deps.require_admin_key)])
def upsert_protocol_monitoring(protocol_id: int, request: UpsertMonitoredContractRequest) -> dict[str, Any]:
    """Create or update one monitored contract for a protocol."""
    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")

        contract_stmt = select(Contract).where(
            Contract.protocol_id == protocol_id,
            func.lower(Contract.address) == request.address.lower(),
        )
        if request.chain:
            contract_stmt = contract_stmt.where(Contract.chain == request.chain)
        contract = session.execute(contract_stmt).scalar_one_or_none()

        existing = session.execute(
            select(MonitoredContract).where(
                func.lower(MonitoredContract.address) == request.address.lower(),
                MonitoredContract.chain == request.chain,
            )
        ).scalar_one_or_none()

        if existing is None:
            existing = MonitoredContract(
                address=request.address,
                chain=request.chain,
                protocol_id=protocol_id,
                contract_id=contract.id if contract else None,
                contract_type=request.contract_type,
                monitoring_config=request.monitoring_config,
                last_known_state={},
                last_scanned_block=0,
                needs_polling=request.needs_polling,
                is_active=request.is_active,
                enrollment_source="surface_alert",
            )
            session.add(existing)
        else:
            existing.protocol_id = protocol_id
            existing.contract_id = contract.id if contract else existing.contract_id
            existing.contract_type = request.contract_type
            existing.monitoring_config = request.monitoring_config
            existing.needs_polling = request.needs_polling
            existing.is_active = request.is_active
            existing.enrollment_source = existing.enrollment_source or "surface_alert"

        session.commit()
        session.refresh(existing)
        return _monitored_contract_payload(existing)


@router.patch("/api/monitored-contracts/{contract_id}", dependencies=[Depends(deps.require_admin_key)])
def update_monitored_contract(contract_id: str, request: UpdateMonitoredContractRequest) -> dict[str, Any]:
    """Update monitoring_config, is_active, or needs_polling on a MonitoredContract."""
    with deps.SessionLocal() as session:
        mc = session.get(MonitoredContract, uuid.UUID(contract_id))
        if mc is None:
            raise HTTPException(status_code=404, detail="MonitoredContract not found")

        if request.monitoring_config is not None:
            mc.monitoring_config = request.monitoring_config
        if request.is_active is not None:
            mc.is_active = request.is_active
        if request.needs_polling is not None:
            mc.needs_polling = request.needs_polling

        session.commit()
        session.refresh(mc)
        return _monitored_contract_payload(mc)


@router.get("/api/monitored-events")
def list_monitored_events(
    contract_id: str | None = None,
    address: str | None = None,
    chain: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List MonitoredEvent rows, optionally filtered.

    Filter modes (apply additively):
      - ``contract_id``: by MonitoredContract.id (uuid)
      - ``address`` (+ optional ``chain``): resolves to monitored_contract_id
        on the fly so the front-end can query by address — useful for
        rendering a Safe/Timelock 'recent activity' panel without first
        having to look up the MonitoredContract row.
      - ``event_type``: filter to a single event_type
    """
    with deps.SessionLocal() as session:
        # Multi-key sort. detected_at desc is the primary axis, but the
        # column has a now()-default that ties events written in the
        # same scan pass — so block_number desc disambiguates within a
        # tie (newer-block-first matches the recency story). id desc
        # is the final fallback purely for *deterministic* output —
        # MonitoredEvent.id is a UUIDv4 and carries no insertion or
        # log-order semantics, but a deterministic tiebreaker beats
        # exposing arbitrary DB scan order to clients.
        # If exact log-order ever becomes user-visible (e.g. step #4c
        # historical backfill rendering each batch CallScheduled
        # individually), promote log_index from the data JSON to a
        # real column and sort on it before id.
        stmt = (
            select(MonitoredEvent)
            .order_by(
                MonitoredEvent.detected_at.desc(),
                MonitoredEvent.block_number.desc(),
                MonitoredEvent.id.desc(),
            )
            .limit(limit)
        )
        if contract_id is not None:
            stmt = stmt.where(MonitoredEvent.monitored_contract_id == contract_id)
        # address and/or chain — resolve to a set of MonitoredContract ids
        # then narrow events. Either filter alone is supported; together
        # they intersect at the contract level. Without either, we don't
        # touch the contracts table.
        if address is not None or chain is not None:
            mc_q = select(MonitoredContract.id)
            if address is not None:
                mc_q = mc_q.where(MonitoredContract.address == address.lower())
            if chain is not None:
                mc_q = mc_q.where(MonitoredContract.chain == chain)
            mc_ids = session.execute(mc_q).scalars().all()
            if not mc_ids:
                # No matching MonitoredContract → no events to return.
                # Avoids scanning the events table when the answer is
                # structurally empty.
                return []
            stmt = stmt.where(MonitoredEvent.monitored_contract_id.in_(mc_ids))
        if event_type is not None:
            stmt = stmt.where(MonitoredEvent.event_type == event_type)
        events = session.execute(stmt).scalars().all()
        return [
            {
                "id": str(e.id),
                "monitored_contract_id": str(e.monitored_contract_id),
                "event_type": e.event_type,
                "block_number": e.block_number,
                "tx_hash": e.tx_hash,
                "data": e.data,
                "detected_at": e.detected_at.isoformat() if e.detected_at else None,
            }
            for e in events
        ]
