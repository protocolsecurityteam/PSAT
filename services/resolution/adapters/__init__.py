"""Compatibility imports for resolver adapter types."""

from __future__ import annotations

from schemas.resolution_schemas import (
    AdapterEnumerationResult,
    AdapterRegistry,
    BytecodeRepo,
    CallFrame,
    CapabilityExpr,
    EvaluationContext,
    EventLogRepo,
    SetAdapter,
    Trit,
)
from schemas.resolution_schemas import (
    CapabilityConfidence as Confidence,
)

EnumerationResult = AdapterEnumerationResult

__all__ = [
    "AdapterRegistry",
    "BytecodeRepo",
    "CallFrame",
    "CapabilityExpr",
    "Confidence",
    "EnumerationResult",
    "EventLogRepo",
    "EvaluationContext",
    "SetAdapter",
    "Trit",
]
