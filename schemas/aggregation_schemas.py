"""Schemas owned by aggregation services."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GovernanceView:
    contracts: list[dict[str, Any]] = field(default_factory=list)
    principals: list[dict[str, Any]] = field(default_factory=list)
    hierarchy: list[dict[str, Any]] = field(default_factory=list)
    fund_flows: list[dict[str, Any]] = field(default_factory=list)


__all__ = ["GovernanceView"]
