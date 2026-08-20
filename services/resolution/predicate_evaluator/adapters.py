"""Adapter protocol (week-4 placeholder) and the null adapter."""

from __future__ import annotations

import logging
from typing import Protocol

from services.static.contract_analysis_pipeline.predicate_types import (
    SetDescriptor,
)

from ..capabilities import (
    CapabilityExpr,
)

logger = logging.getLogger("services.resolution.predicate_evaluator")

# ---------------------------------------------------------------------------
# Adapter protocol (placeholder — week-5 fully-typed registry replaces this)
# ---------------------------------------------------------------------------


class SetAdapter(Protocol):
    """Minimal adapter interface for week-4. The full SetAdapter
    Protocol (with EvaluationContext, matches/enumerate/membership)
    lands in week 5 alongside concrete adapters."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr: ...


class _NullAdapter:
    """Fallback when no real adapter is registered. Returns
    finite_set(empty, lower_bound) — the structural skeleton without
    a populated members list."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )
