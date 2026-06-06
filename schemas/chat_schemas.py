"""Schemas owned by chat services."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AgentContext:
    company: str
    selected_address: str | None = None
    selected_chain: str | None = None


__all__ = ["AgentContext"]
