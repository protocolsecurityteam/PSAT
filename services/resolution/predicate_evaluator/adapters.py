"""Minimal adapter protocol and the null adapter."""

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


class SetAdapter(Protocol):
    """Minimal adapter interface; the full protocol is ``services.resolution.adapters``."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr: ...


class _NullAdapter:
    """Fallback when no adapter is registered: an empty lower_bound finite_set."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )
