"""Schemas owned by chat services."""

from __future__ import annotations

from dataclasses import dataclass

from schemas.common import Address


@dataclass
class AgentContext:
    company: str
    selected_address: Address | None = None
    selected_chain: str | None = None


__all__ = ["AgentContext"]
