"""Unified protocol monitoring + TVL endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from db.models import (
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
    TvlSnapshot,
)
from schemas.api_requests import ProtocolSubscribeRequest

from . import deps

router = APIRouter()


@router.get("/api/protocols/{protocol_id}/monitoring")
def list_protocol_monitoring(protocol_id: int) -> list[dict[str, Any]]:
    """List all MonitoredContract rows for a protocol (including inactive)."""
    with deps.SessionLocal() as session:
        stmt = select(MonitoredContract).where(
            MonitoredContract.protocol_id == protocol_id,
        )
        contracts = session.execute(stmt).scalars().all()
        return [
            {
                "id": str(c.id),
                "address": c.address,
                "chain": c.chain,
                "contract_type": c.contract_type,
                "monitoring_config": c.monitoring_config,
                "last_known_state": c.last_known_state,
                "last_scanned_block": c.last_scanned_block,
                "needs_polling": c.needs_polling,
                "is_active": c.is_active,
                "enrollment_source": c.enrollment_source,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in contracts
        ]


@router.post("/api/protocols/{protocol_id}/re-enroll", dependencies=[Depends(deps.require_admin_key)])
def re_enroll_protocol(protocol_id: int, chain: str = "ethereum") -> dict[str, Any]:
    """Manually trigger monitoring enrollment for a protocol.

    Calls enroll_protocol_contracts directly, bypassing the automatic
    in-flight job checks. Useful when enrollment produced wrong results
    or after manual DB changes.
    """
    rpc_url = deps.DEFAULT_RPC_URL
    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")

        from services.monitoring.enrollment import enroll_protocol_contracts

        enrolled = enroll_protocol_contracts(session, protocol_id, rpc_url, chain)
        return {
            "status": "enrolled",
            "protocol_id": protocol_id,
            "contracts_enrolled": len(enrolled),
            "contracts": [
                {
                    "id": str(mc.id),
                    "address": mc.address,
                    "contract_type": mc.contract_type,
                    "monitoring_config": mc.monitoring_config,
                    "needs_polling": mc.needs_polling,
                    "is_active": mc.is_active,
                }
                for mc in enrolled
            ],
        }


@router.post("/api/protocols/{protocol_id}/subscribe", dependencies=[Depends(deps.require_admin_key)])
def subscribe_to_protocol(protocol_id: int, request: ProtocolSubscribeRequest) -> dict[str, Any]:
    """Create a ProtocolSubscription for governance event notifications."""
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
        return {
            "id": str(sub.id),
            "protocol_id": sub.protocol_id,
            "discord_webhook_url": (sanitize_url(sub.discord_webhook_url) if sub.discord_webhook_url else None),
            "label": sub.label,
            "event_filter": sub.event_filter,
            "created_at": sub.created_at.isoformat() if sub.created_at else None,
        }


@router.get("/api/protocols/{protocol_id}/subscriptions")
def list_protocol_subscriptions(protocol_id: int) -> list[dict[str, Any]]:
    """List all ProtocolSubscription rows for a protocol."""
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
    """Delete a ProtocolSubscription by id."""
    with deps.SessionLocal() as session:
        sub = session.get(ProtocolSubscription, uuid.UUID(sub_id))
        if sub is None:
            raise HTTPException(status_code=404, detail="Subscription not found")
        session.delete(sub)
        session.commit()
        return {"status": "removed"}


@router.get("/api/protocols/{protocol_id}/events")
def list_protocol_events(protocol_id: int, limit: int = 50) -> list[dict[str, Any]]:
    """List MonitoredEvents for all contracts in a protocol."""
    with deps.SessionLocal() as session:
        stmt = (
            select(MonitoredEvent, MonitoredContract)
            .join(MonitoredContract, MonitoredEvent.monitored_contract_id == MonitoredContract.id)
            .where(MonitoredContract.protocol_id == protocol_id)
            .order_by(MonitoredEvent.detected_at.desc())
            .limit(limit)
        )
        rows = session.execute(stmt).all()
        return [
            {
                "id": str(e.id),
                "monitored_contract_id": str(e.monitored_contract_id),
                "event_type": e.event_type,
                "block_number": e.block_number,
                "tx_hash": e.tx_hash,
                "data": {**(e.data or {}), "contract_address": mc.address},
                "detected_at": e.detected_at.isoformat() if e.detected_at else None,
            }
            for e, mc in rows
        ]


@router.get("/api/protocols/{protocol_id}/tvl")
def protocol_tvl(protocol_id: int, days: int = 30) -> dict[str, Any]:
    """Current TVL and historical snapshots for a protocol."""
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
        return {
            "protocol_id": protocol_id,
            "protocol_name": protocol.name,
            "current": {
                "total_usd": float(latest.total_usd) if latest and latest.total_usd else None,
                "defillama_tvl": float(latest.defillama_tvl) if latest and latest.defillama_tvl else None,
                "source": latest.source if latest else None,
                "timestamp": latest.timestamp.isoformat() if latest else None,
                "contract_breakdown": latest.contract_breakdown if latest else None,
                "chain_breakdown": latest.chain_breakdown if latest else None,
            },
            "history": [
                {
                    "timestamp": s.timestamp.isoformat(),
                    "total_usd": float(s.total_usd) if s.total_usd else None,
                    "defillama_tvl": float(s.defillama_tvl) if s.defillama_tvl else None,
                    "source": s.source,
                }
                for s in snapshots
            ],
        }
