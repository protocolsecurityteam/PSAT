"""MonitoredContract listing and updates + MonitoredEvent listing."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select

from db.models import Contract, MonitoredContract, MonitoredEvent, Protocol
from schemas.api_requests import UpdateMonitoredContractRequest, UpsertMonitoredContractRequest
from utils.rpc import require_supported_chain_id

from . import deps

router = APIRouter()
logger = logging.getLogger(__name__)


def _monitored_contract_payload(c: MonitoredContract) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "address": c.address,
        "chain_id": c.chain_id,
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
    chain_id: int | None = None,
) -> list[dict[str, Any]]:
    """List all MonitoredContract rows, optionally filtered."""
    effective_chain_id: int | None = None
    if chain_id is not None:
        try:
            effective_chain_id = require_supported_chain_id(
                chain_id=chain_id,
                context="monitored contract list filter",
            )
        except RuntimeError as exc:
            logger.error("%s", exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    with deps.SessionLocal() as session:
        stmt = select(MonitoredContract).order_by(MonitoredContract.created_at.desc())
        if protocol_id is not None:
            stmt = stmt.where(MonitoredContract.protocol_id == protocol_id)
        if effective_chain_id is not None:
            stmt = stmt.where(MonitoredContract.chain_id == effective_chain_id)
        contracts = session.execute(stmt).scalars().all()
        return [_monitored_contract_payload(c) for c in contracts]


@router.post("/api/protocols/{protocol_id}/monitoring", dependencies=[Depends(deps.require_admin_key)])
def upsert_protocol_monitoring(protocol_id: int, request: UpsertMonitoredContractRequest) -> dict[str, Any]:
    """Create or update one monitored contract for a protocol."""
    try:
        effective_chain_id = require_supported_chain_id(
            chain_id=request.chain_id,
            context=f"monitoring upsert for {request.address}",
        )
    except RuntimeError as exc:
        logger.error("%s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")

        contract_stmt = select(Contract).where(
            Contract.protocol_id == protocol_id,
            func.lower(Contract.address) == request.address.lower(),
        )
        contract_stmt = contract_stmt.where(Contract.chain_id == effective_chain_id)
        contract = session.execute(contract_stmt).scalar_one_or_none()

        existing = session.execute(
            select(MonitoredContract).where(
                func.lower(MonitoredContract.address) == request.address.lower(),
                MonitoredContract.chain_id == effective_chain_id,
            )
        ).scalar_one_or_none()

        if existing is None:
            existing = MonitoredContract(
                address=request.address,
                chain_id=effective_chain_id,
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
    chain_id: int | None = None,
    event_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List MonitoredEvent rows, optionally filtered.

    Filter modes (apply additively):
      - ``contract_id``: by MonitoredContract.id (uuid)
      - ``address`` + ``chain_id``: resolves to monitored_contract_id
        on the fly so the front-end can query by address — useful for
        rendering a Safe/Timelock 'recent activity' panel without first
        having to look up the MonitoredContract row.
      - ``event_type``: filter to a single event_type
    """
    effective_chain_id: int | None = None
    if chain_id is not None:
        try:
            effective_chain_id = require_supported_chain_id(
                chain_id=chain_id,
                context="monitored event list filter",
            )
        except RuntimeError as exc:
            logger.error("%s", exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    with deps.SessionLocal() as session:
        # Multi-key sort. detected_at desc is the primary axis, but the
        # column has a now()-default that ties events written in the
        # same scan pass, so block_number desc disambiguates within a
        # tie. id desc is only a deterministic tiebreaker for DB scan
        # order; exact log-order should be promoted into a real column if
        # it becomes user-visible.
        # If exact log-order ever becomes user-visible (e.g. step #4c
        # historical backfill rendering each batch CallScheduled
        # individually), promote log_index from the data JSON to a
        # real column and sort on it before id.
        stmt = (
            select(MonitoredEvent, MonitoredContract)
            .join(MonitoredContract, MonitoredContract.id == MonitoredEvent.monitored_contract_id)
            .order_by(
                MonitoredEvent.detected_at.desc(),
                MonitoredEvent.block_number.desc(),
                MonitoredEvent.id.desc(),
            )
            .limit(limit)
        )
        if contract_id is not None:
            stmt = stmt.where(MonitoredEvent.monitored_contract_id == contract_id)
        if address is not None and effective_chain_id is None:
            raise HTTPException(status_code=400, detail="address event filtering requires chain_id")
        # Address filters must include chain_id to avoid cross-chain event
        # leakage; chain_id-only remains a valid chain-wide filter.
        if address is not None or effective_chain_id is not None:
            if address is not None:
                stmt = stmt.where(func.lower(MonitoredContract.address) == address.lower())
            if effective_chain_id is not None:
                stmt = stmt.where(MonitoredContract.chain_id == effective_chain_id)
        if event_type is not None:
            stmt = stmt.where(MonitoredEvent.event_type == event_type)
        rows = session.execute(stmt).all()
        out: list[dict[str, Any]] = []
        for event, monitored_contract in rows:
            try:
                event_chain_id = require_supported_chain_id(
                    chain_id=monitored_contract.chain_id,
                    context=f"monitored event {event.id}",
                )
            except RuntimeError as exc:
                logger.error(
                    "monitored event serialization failed event_id=%s monitored_contract_id=%s: %s",
                    event.id,
                    monitored_contract.id,
                    exc,
                )
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            out.append(
                {
                    "id": str(event.id),
                    "monitored_contract_id": str(event.monitored_contract_id),
                    "event_type": event.event_type,
                    "chain_id": event_chain_id,
                    "block_number": event.block_number,
                    "tx_hash": event.tx_hash,
                    "data": {
                        **(event.data or {}),
                        "contract_address": monitored_contract.address,
                        "chain_id": event_chain_id,
                    },
                    "detected_at": event.detected_at.isoformat() if event.detected_at else None,
                }
            )
        return out
