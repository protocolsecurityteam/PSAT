"""Agent chat endpoints for the protocol surface sidebar."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from db.models import Contract, EffectiveFunction, FunctionPrincipal, Protocol
from services.chat.agent import AgentContext, run_agent_stream
from utils.rpc import require_supported_chain_id

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
    selected_chain_id: int | None = None
    history: list[AgentChatMessage] = Field(default_factory=list)


@router.post("/api/agent/chat", dependencies=[Depends(deps.require_admin_key)])
def agent_chat(req: AgentChatRequest):
    """Stream a chat completion as server-sent events."""
    selected_chain_id: int | None = None
    if req.selected_chain_id is not None:
        try:
            selected_chain_id = require_supported_chain_id(
                chain_id=req.selected_chain_id,
                context="agent chat selected contract",
            )
        except RuntimeError as exc:
            logger.error("agent chat rejected unsupported selected_chain_id=%r: %s", req.selected_chain_id, exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if req.selected_address and selected_chain_id is None:
        message = "agent chat selected_address requires selected_chain_id"
        logger.error("%s: address=%s", message, req.selected_address)
        raise HTTPException(status_code=400, detail=message)

    ctx = AgentContext(
        company=req.company,
        selected_address=req.selected_address,
        selected_chain_id=selected_chain_id,
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
            err = json.dumps({"message": str(exc)})
            yield f"event: error\ndata: {err}\n\n"

    return StreamingResponse(
        sse_iter(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/agent/address-touches", dependencies=[Depends(deps.require_admin_key)])
def agent_address_touches(company: str, address: str, chain_id: int) -> dict[str, Any]:
    """Return contracts an address has function-level authority over."""
    addr_lc = (address or "").lower()
    effective_chain_id = require_supported_chain_id(chain_id=chain_id, context=f"agent address touches for {addr_lc}")
    with deps.SessionLocal() as session:
        proto = session.execute(select(Protocol).where(Protocol.name == company)).scalar_one_or_none()
        if proto is None:
            return {"address": address, "chain_id": effective_chain_id, "touches": []}
        rows = session.execute(
            select(
                Contract.address,
                Contract.chain_id,
                Contract.contract_name,
                func.count(EffectiveFunction.id).label("fn_count"),
            )
            .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(Contract.protocol_id == proto.id)
            .where(Contract.chain_id == effective_chain_id)
            .where(func.lower(FunctionPrincipal.address) == addr_lc)
            .group_by(Contract.address, Contract.chain_id, Contract.contract_name)
        ).all()
        return {
            "address": address,
            "chain_id": effective_chain_id,
            "touches": [
                {
                    "address": row[0],
                    "chain_id": row[1],
                    "label": row[2],
                    "function_count": int(row[3]),
                }
                for row in rows
            ],
        }
