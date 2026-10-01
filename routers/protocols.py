from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select

from db.models import (
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
    TvlSnapshot,
)
from schemas.api_requests import ProtocolSubscribeRequest
from schemas.api_responses import (
    EnrolledContractBrief,
    MonitoredContractItem,
    MonitoredEventItem,
    ProtocolTvlResponse,
    ReEnrollResponse,
    SubscriptionItem,
)
from utils.chains import UnsupportedChainError, require_supported_chain

from . import deps
from .monitored import monitored_contract_payload

router = APIRouter()


@router.get("/api/protocols/{protocol_id}/monitoring", response_model=None)
def list_protocol_monitoring(protocol_id: int) -> list[MonitoredContractItem]:
    with deps.SessionLocal() as session:
        stmt = select(MonitoredContract).where(
            MonitoredContract.protocol_id == protocol_id,
        )
        contracts = session.execute(stmt).scalars().all()
        return [monitored_contract_payload(c) for c in contracts]


@router.post(
    "/api/protocols/{protocol_id}/re-enroll", dependencies=[Depends(deps.require_admin_key)], response_model=None
)
def re_enroll_protocol(protocol_id: int, chain: str = "ethereum") -> ReEnrollResponse:
    """Run enrollment directly, bypassing in-flight job checks; for fixing wrong results or manual DB changes."""
    # Allowlist: re-enroll spawns monitoring work on that chain.
    try:
        require_supported_chain(chain=chain, context="protocol re-enroll")
    except UnsupportedChainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rpc_url = deps.DEFAULT_RPC_URL
    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")

        from services.monitoring.enrollment import enroll_protocol_contracts, mark_enrollment_dirty

        # Commit the dirty mark first so a raising synchronous enroll still self-heals via the reconciler.
        mark_enrollment_dirty(session, protocol_id, "manual")
        session.commit()

        enrolled = enroll_protocol_contracts(session, protocol_id, rpc_url, chain)
        deps.log_admin_mutation("re_enroll", id=protocol_id, count=len(enrolled))
        contracts: list[EnrolledContractBrief] = [
            {
                "id": str(mc.id),
                "address": mc.address,
                "contract_type": mc.contract_type,
                "monitoring_config": mc.monitoring_config,
                "needs_polling": mc.needs_polling,
                "is_active": mc.is_active,
            }
            for mc in enrolled
        ]
        return {
            "status": "enrolled",
            "protocol_id": protocol_id,
            "contracts_enrolled": len(enrolled),
            "contracts": contracts,
        }


@router.post(
    "/api/protocols/{protocol_id}/subscribe", dependencies=[Depends(deps.require_admin_key)], response_model=None
)
def subscribe_to_protocol(protocol_id: int, request: ProtocolSubscribeRequest) -> SubscriptionItem:
    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")

        from utils.secrets import sanitize_url

        sub = ProtocolSubscription(
            protocol_id=protocol_id,
            discord_webhook_url=request.discord_webhook_url,
            label=request.label,
            event_filter=request.event_filter,
        )
        session.add(sub)
        session.commit()
        session.refresh(sub)
        deps.log_admin_mutation("subscribe", id=str(sub.id), protocol_id=protocol_id)
        return {
            "id": str(sub.id),
            "protocol_id": sub.protocol_id,
            "discord_webhook_url": (sanitize_url(sub.discord_webhook_url) if sub.discord_webhook_url else None),
            "label": sub.label,
            "event_filter": sub.event_filter,
            "created_at": sub.created_at.isoformat() if sub.created_at else None,
        }


@router.get(
    "/api/protocols/{protocol_id}/subscriptions", dependencies=[Depends(deps.require_admin_key)], response_model=None
)
def list_protocol_subscriptions(protocol_id: int) -> list[SubscriptionItem]:
    from utils.secrets import sanitize_url

    with deps.SessionLocal() as session:
        stmt = select(ProtocolSubscription).where(ProtocolSubscription.protocol_id == protocol_id)
        subs = session.execute(stmt).scalars().all()
        return [
            {
                "id": str(s.id),
                "protocol_id": s.protocol_id,
                "discord_webhook_url": (sanitize_url(s.discord_webhook_url) if s.discord_webhook_url else None),
                "label": s.label,
                "event_filter": s.event_filter,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in subs
        ]


@router.delete("/api/protocol-subscriptions/{sub_id}", dependencies=[Depends(deps.require_admin_key)])
def delete_protocol_subscription(sub_id: str) -> dict[str, str]:
    try:
        parsed = uuid.UUID(sub_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=404, detail="Subscription not found") from exc
    with deps.SessionLocal() as session:
        sub = session.get(ProtocolSubscription, parsed)
        if sub is None:
            raise HTTPException(status_code=404, detail="Subscription not found")
        session.delete(sub)
        session.commit()
        deps.log_admin_mutation("delete_subscription", id=sub_id)
        return {"status": "removed"}


@router.get("/api/protocols/{protocol_id}/events", response_model=None)
def list_protocol_events(
    protocol_id: int, limit: int = Query(default=50, ge=1, le=500), chain: str | None = None
) -> list[MonitoredEventItem]:
    """Scope by ``chain``: ``contract_address`` alone can't separate a shared Safe's chains.

    NULL/``mainnet`` fold to ``ethereum``.
    """
    with deps.SessionLocal() as session:
        stmt = (
            select(MonitoredEvent, MonitoredContract)
            .join(MonitoredContract, MonitoredEvent.monitored_contract_id == MonitoredContract.id)
            .where(MonitoredContract.protocol_id == protocol_id)
            .order_by(MonitoredEvent.detected_at.desc())
            .limit(limit)
        )
        if chain:
            token = chain.strip().lower()
            token = "ethereum" if token in ("", "mainnet") else token
            row_chain = func.lower(func.coalesce(MonitoredContract.chain, "ethereum"))
            row_token = case((row_chain == "mainnet", "ethereum"), else_=row_chain)
            stmt = stmt.where(row_token == token)
        rows = session.execute(stmt).all()
        return [
            {
                "id": str(e.id),
                "monitored_contract_id": str(e.monitored_contract_id),
                "event_type": e.event_type,
                "block_number": e.block_number,
                "tx_hash": e.tx_hash,
                # Self-describing rows so consumers never guess from a lookup that can miss.
                "data": {
                    **(e.data or {}),
                    "contract_address": mc.address,
                    "chain": mc.chain,
                    "contract_type": mc.contract_type,
                },
                "detected_at": e.detected_at.isoformat() if e.detected_at else None,
            }
            for e, mc in rows
        ]


@router.get("/api/protocols/{protocol_id}/tvl", response_model=None)
def protocol_tvl(protocol_id: int, days: int = 30) -> ProtocolTvlResponse:
    days = min(days, deps.MAX_TVL_HISTORY_DAYS)

    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = (
            select(TvlSnapshot)
            .where(
                TvlSnapshot.protocol_id == protocol_id,
                TvlSnapshot.timestamp >= cutoff,
            )
            .order_by(TvlSnapshot.timestamp.desc())
        )
        snapshots = session.execute(stmt).scalars().all()

        latest = snapshots[0] if snapshots else None
        from services.aggregations.tvl import snapshot_payload

        return {
            "protocol_id": protocol_id,
            "protocol_name": protocol.name,
            "current": {
                **snapshot_payload(latest),
                "contract_breakdown": latest.contract_breakdown if latest else None,
                "chain_breakdown": latest.chain_breakdown if latest else None,
            },
            "history": [snapshot_payload(snapshot) for snapshot in snapshots],
        }
