"""Agent chat endpoints for the protocol surface sidebar."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from db.models import Contract, EffectiveFunction, FunctionPrincipal, Protocol
from schemas.api_responses import AddressTouchesResponse
from services.chat.agent import AgentContext, run_agent_stream
from utils.chains import UnknownChainError, chain_by_name

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


class AgentChatMessage(BaseModel):
    role: str
    content: str


class AgentChatRequest(BaseModel):
    company: str
    message: str
    selected_address: str | None = None
    selected_chain: str | None = None
    history: list[AgentChatMessage] = Field(default_factory=list)


@router.post("/api/agent/chat", dependencies=[Depends(deps.require_admin_key)])
def agent_chat(req: AgentChatRequest):
    """Stream a chat completion as server-sent events."""
    ctx = AgentContext(
        company=req.company,
        selected_address=req.selected_address,
        selected_chain=req.selected_chain,
    )
    history = [{"role": m.role, "content": m.content} for m in req.history]

    def sse_iter():
        try:
            for evt in run_agent_stream(req.message, history, ctx):
                name = evt.get("event", "message")
                payload = json.dumps(evt.get("data") or {}, default=str)
                yield f"event: {name}\ndata: {payload}\n\n"
        except Exception as exc:
            logger.warning("agent stream failed: %s", exc, extra={"exc_type": type(exc).__name__})
            err = json.dumps({"message": "Agent request failed."})
            yield f"event: error\ndata: {err}\n\n"

    return StreamingResponse(
        sse_iter(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/agent/address-touches", dependencies=[Depends(deps.require_admin_key)], response_model=None)
def agent_address_touches(
    company: str,
    address: str,
    chain: str | None = Query(default=None),
) -> AddressTouchesResponse:
    """Return contracts an address has function-level authority over.

    ``chain`` scopes the returned contracts to one deployment (inv. 12): the same
    address can govern contracts on two chains within one protocol, and the
    chain-scoped Surface page wants only the active chain's touch set. Optional —
    omitted returns every chain (legacy behavior). Legacy NULL-chain rows are
    mainnet, so the coalesce keeps a ``chain=ethereum`` filter matching them.
    """
    addr_lc = (address or "").lower()
    chain_name: str | None = None
    if chain is not None:
        try:
            chain_name = chain_by_name(chain).name
        except UnknownChainError:
            raise HTTPException(status_code=400, detail=f"Unknown chain: {chain}") from None
    with deps.SessionLocal() as session:
        proto = session.execute(select(Protocol).where(Protocol.name == company)).scalar_one_or_none()
        if proto is None:
            return {"address": address, "touches": []}
        stmt = (
            select(
                Contract.address,
                Contract.contract_name,
                func.count(EffectiveFunction.id).label("fn_count"),
            )
            .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(Contract.protocol_id == proto.id)
            .where(func.lower(FunctionPrincipal.address) == addr_lc)
            .group_by(Contract.address, Contract.contract_name)
        )
        if chain_name is not None:
            stmt = stmt.where(func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_name)
        rows = session.execute(stmt).all()
        return {
            "address": address,
            "touches": [{"address": row[0], "label": row[1], "function_count": int(row[2])} for row in rows],
        }
