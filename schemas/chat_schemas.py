"""Schemas owned by chat services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

from schemas.common import Address, JsonObject, ServiceBoundaryMetadata


@dataclass
class AgentContext:
    company: str
    selected_address: Address | None = None
    selected_chain: str | None = None


class ChatInput(TypedDict):
    metadata: ServiceBoundaryMetadata
    message: str
    history: list[JsonObject]
    context: AgentContext


class ChatEvent(TypedDict):
    type: str
    data: JsonObject


class ChatOutput(TypedDict):
    metadata: ServiceBoundaryMetadata
    events: list[ChatEvent]
    final_message: str | None


__all__ = ["AgentContext", "ChatEvent", "ChatInput", "ChatOutput"]
