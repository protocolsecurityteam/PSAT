from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from db.models import Contract, MonitoredContract, MonitoredEvent, Protocol
from schemas.api_requests import UpdateMonitoredContractRequest, UpsertMonitoredContractRequest
from schemas.api_responses import MonitoredContractItem, MonitoredEventItem
from services.clients.rpc import rpc_request
from services.monitoring.chain_rpc import chain_id_for, rpc_for_chain
from services.monitoring.tracking_plan_state import CONFIG_SUPPLIED_BY_CALLER, preserve_scan_plane_facts
from utils.chains import UnsupportedChainError, require_supported_chain

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


def _current_head_block(chain: str | None) -> int | None:
    """Head on the contract's own chain, seeding a manual add's cursor and enrollment floor; ``None`` if unanswered.

    A mainnet head on another chain gave a wrong immutable floor. Block 0 is never a stand-in (whole chain as backlog,
    all history as live); the caller refuses.
    """
    try:
        return int(
            rpc_request(
                rpc_for_chain(chain, deps.DEFAULT_RPC_URL),
                "eth_blockNumber",
                [],
                chain_id=chain_id_for(chain),
            ),
            16,
        )
    except Exception as exc:
        logger.warning(
            "Could not read head block for monitoring upsert: %s",
            exc,
            extra={"exc_type": type(exc).__name__, "chain": chain, "reason": "head_read_not_determined"},
        )
        return None


# Caller-authored configs lack the builder's provenance (``tracked_topics`` / ``tracking_plan_not_determined``); this
# token says so rather than letting them pose as builder output.
CALLER_SUPPLIED_TRACKING_PLAN = CONFIG_SUPPLIED_BY_CALLER


def _stamp_caller_supplied(
    monitoring_config: dict[str, Any] | None,
    existing_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Stamp a caller-authored config's provenance.

    The route owns ``tracking_plan_not_determined`` (overwritten, never merged) so a caller can't forge an analyzer
    reason. ``tracked_topics`` / ``polling_plan`` are rejected upstream in ``schemas.api_requests``. ``scan_gaps`` from
    *existing_config* is carried over, or the row would claim coverage nothing read.
    """
    stamped = dict(monitoring_config or {})
    stamped["tracking_plan_not_determined"] = CALLER_SUPPLIED_TRACKING_PLAN
    return preserve_scan_plane_facts(stamped, existing_config)


def monitored_contract_payload(c: MonitoredContract) -> MonitoredContractItem:
    return {
        "id": str(c.id),
        "address": c.address,
        "chain": c.chain,
        "protocol_id": c.protocol_id,
        "contract_id": c.contract_id,
        "contract_type": c.contract_type,
        "monitoring_config": c.monitoring_config,
        "last_known_state": c.last_known_state,
        "last_poll_status": c.last_poll_status,
        "last_scanned_block": c.last_scanned_block,
        "enrollment_block": c.enrollment_block,
        "needs_polling": c.needs_polling,
        "is_active": c.is_active,
        "enrollment_source": c.enrollment_source,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


@router.get("/api/monitored-contracts", response_model=None)
def list_monitored_contracts(
    protocol_id: int | None = None,
    chain: str | None = None,
) -> list[MonitoredContractItem]:
    with deps.SessionLocal() as session:
        stmt = select(MonitoredContract).order_by(MonitoredContract.created_at.desc())
        if protocol_id is not None:
            stmt = stmt.where(MonitoredContract.protocol_id == protocol_id)
        if chain is not None:
            stmt = stmt.where(MonitoredContract.chain == chain)
        contracts = session.execute(stmt).scalars().all()
        return [monitored_contract_payload(c) for c in contracts]


@router.post(
    "/api/protocols/{protocol_id}/monitoring", dependencies=[Depends(deps.require_admin_key)], response_model=None
)
def upsert_protocol_monitoring(protocol_id: int, request: UpsertMonitoredContractRequest) -> MonitoredContractItem:
    # Allowlist: enrollment takes scanner leases and RPC on that chain.
    try:
        require_supported_chain(chain=request.chain, context="monitored-contract enrollment")
    except UnsupportedChainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
            # Monitor from now on; scanning from 0 would replay years. ``enrollment_block`` is the pre-watch floor.
            head_block = _current_head_block(request.chain)
            if head_block is None:
                raise HTTPException(
                    status_code=503,
                    detail="Chain head not determined; cannot seed a scan cursor or enrollment floor. Retry.",
                )
            existing = MonitoredContract(
                address=request.address,
                chain=request.chain,
                protocol_id=protocol_id,
                contract_id=contract.id if contract else None,
                contract_type=request.contract_type,
                monitoring_config=_stamp_caller_supplied(request.monitoring_config),
                last_known_state={},
                last_scanned_block=head_block,
                enrollment_block=head_block,
                needs_polling=request.needs_polling,
                is_active=request.is_active,
                enrollment_source="surface_alert",
            )
            session.add(existing)
        else:
            existing.protocol_id = protocol_id
            existing.contract_id = contract.id if contract else existing.contract_id
            existing.contract_type = request.contract_type
            existing.monitoring_config = _stamp_caller_supplied(request.monitoring_config, existing.monitoring_config)
            existing.needs_polling = request.needs_polling
            existing.is_active = request.is_active
            existing.enrollment_source = existing.enrollment_source or "surface_alert"

        session.commit()
        session.refresh(existing)
        deps.log_admin_mutation("monitoring_upsert", id=str(existing.id), protocol_id=protocol_id)
        return monitored_contract_payload(existing)


@router.patch(
    "/api/monitored-contracts/{contract_id}", dependencies=[Depends(deps.require_admin_key)], response_model=None
)
def update_monitored_contract(contract_id: str, request: UpdateMonitoredContractRequest) -> MonitoredContractItem:
    try:
        parsed = uuid.UUID(contract_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=404, detail="MonitoredContract not found") from exc
    with deps.SessionLocal() as session:
        mc = session.get(MonitoredContract, parsed)
        if mc is None:
            raise HTTPException(status_code=404, detail="MonitoredContract not found")

        if request.monitoring_config is not None:
            mc.monitoring_config = _stamp_caller_supplied(request.monitoring_config, mc.monitoring_config)
        if request.is_active is not None:
            mc.is_active = request.is_active
        if request.needs_polling is not None:
            mc.needs_polling = request.needs_polling

        session.commit()
        session.refresh(mc)
        deps.log_admin_mutation("monitored_contract_update", id=str(mc.id))
        return monitored_contract_payload(mc)


@router.get("/api/monitored-events", response_model=None)
def list_monitored_events(
    contract_id: str | None = None,
    address: str | None = None,
    chain: str | None = None,
    event_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[MonitoredEventItem]:
    """MonitoredEvent rows, filters additive: ``contract_id``, ``address`` (+ ``chain``) resolved to contracts on the
    fly, ``event_type``.
    """
    parsed_contract_id: uuid.UUID | None = None
    if contract_id is not None:
        try:
            parsed_contract_id = uuid.UUID(contract_id)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail="contract_id is not a valid UUID") from exc
    with deps.SessionLocal() as session:
        # detected_at ties within a scan pass (now() default), so block_number then id (deterministic only; UUIDv4 has
        # no order).
        stmt = (
            select(MonitoredEvent)
            .order_by(
                MonitoredEvent.detected_at.desc(),
                MonitoredEvent.block_number.desc(),
                MonitoredEvent.id.desc(),
            )
            .limit(limit)
        )
        if parsed_contract_id is not None:
            stmt = stmt.where(MonitoredEvent.monitored_contract_id == parsed_contract_id)
        if address is not None or chain is not None:
            mc_q = select(MonitoredContract.id)
            if address is not None:
                mc_q = mc_q.where(MonitoredContract.address == address.lower())
            if chain is not None:
                mc_q = mc_q.where(MonitoredContract.chain == chain)
            mc_ids = session.execute(mc_q).scalars().all()
            if not mc_ids:
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
