"""Unified protocol monitoring + TVL endpoints."""

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
from services.monitoring.config import load_monitoring_config
from utils.chains import UnsupportedChainError, require_supported_chain

from . import deps
from .monitored import monitored_contract_payload

router = APIRouter()


@router.get("/api/protocols/{protocol_id}/monitoring", response_model=None)
def list_protocol_monitoring(protocol_id: int) -> list[MonitoredContractItem]:
    """List all MonitoredContract rows for a protocol (including inactive)."""
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
    """Manually trigger monitoring enrollment for a protocol.

    Calls enroll_protocol_contracts directly, bypassing the automatic
    in-flight job checks. Useful when enrollment produced wrong results
    or after manual DB changes.
    """
    # Allowlist enforcement (inv. 14): re-enroll spawns monitoring work on the
    # resolved chain, so a chain this deployment has not enabled is rejected here.
    # The admin-edge default 'ethereum' stays and is supported everywhere.
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

        # Commit the dirty mark first so a raising synchronous enroll still leaves
        # a queued row for the reconciler drain to self-heal. The synchronous run
        # below stays as the urgent escape hatch for the common (success) case.
        mark_enrollment_dirty(session, protocol_id, "manual")
        session.commit()

        enrolled = enroll_protocol_contracts(session, protocol_id, rpc_url, chain)
        deps.log_admin_mutation("re_enroll", id=protocol_id, count=len(enrolled))
        contracts: list[EnrolledContractBrief] = [
            {
                "id": str(mc.id),
                "address": mc.address,
                "contract_type": mc.contract_type,
                "monitoring_config": dict(load_monitoring_config(mc.monitoring_config)),
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
        deps.log_admin_mutation("subscribe", id=str(sub.id), protocol_id=protocol_id)
        return {
            "id": str(sub.id),
            "protocol_id": sub.protocol_id,
            "discord_webhook_url": (sanitize_url(sub.discord_webhook_url) if sub.discord_webhook_url else None),
            "label": sub.label,
            "event_filter": sub.event_filter,
            "created_at": sub.created_at.isoformat() if sub.created_at else None,
        }


@router.get("/api/protocols/{protocol_id}/subscriptions", response_model=None)
def list_protocol_subscriptions(protocol_id: int) -> list[SubscriptionItem]:
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
    """List MonitoredEvents for all contracts in a protocol.

    ``chain`` scopes the feed to one chain's monitored rows. The same address
    is a distinct deployment per chain, so this is the only correct place to
    scope — the payload's ``contract_address`` alone cannot distinguish a
    shared Safe's ethereum events from its base ones. NULL/``mainnet``
    monitored rows fold to ``ethereum`` (the legacy-read convention).
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
                # ``chain`` and ``contract_type`` ride beside
                # ``contract_address`` so a row is self-describing even in an
                # unscoped fetch — the consumer must never re-derive either
                # from a local lookup that can miss (and then guess).
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
