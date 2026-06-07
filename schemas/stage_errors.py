"""Typed schema for the ``stage_errors`` artifact.

A single ``stage_errors`` artifact per job records every recoverable failure
the pipeline saw — both the whole-job-failing exception (``severity="error"``)
and any swallowed-but-degraded sub-phase failure (``severity="degraded"``).

The shape is one ``StageErrors`` envelope holding a list of ``StageError``
entries. The error and degraded entries share one slot so a downstream
consumer (the planned ``GET /api/jobs/{id}/errors`` endpoint, log shipping,
etc.) reads one artifact and gets the full picture.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# Caps tuned so a single StageError row stays well under the 1MB Postgres
# JSONB column limit even after a few-hundred-entry accumulator. ``message``
# typically holds an exception message that's already short; ``context`` is
# the only place an unbounded blob can sneak in.
_MAX_MESSAGE_BYTES = 4 * 1024
_MAX_CONTEXT_BYTES = 4 * 1024
_TRUNCATED_SENTINEL = {"_truncated": True}


class StageErrorSeverity(str, Enum):
    ERROR = "error"
    DEGRADED = "degraded"


def _truncate_text(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    # Decode with errors="ignore" so we don't slice mid-multibyte char.
    return encoded[:limit].decode("utf-8", errors="ignore")


class StageError(BaseModel):
    """One failure observation within a job run."""

    stage: str
    severity: StageErrorSeverity
    exc_type: str
    message: str
    traceback: str | None = None
    phase: str | None = None
    trace_id: str | None = None
    job_id: str
    worker_id: str
    failed_at: datetime
    retry_count: int = 0
    context: dict[str, Any] | None = None

    @field_validator("message", mode="before")
    @classmethod
    def _truncate_message(cls, value: Any) -> Any:
        if isinstance(value, str):
            return _truncate_text(value, _MAX_MESSAGE_BYTES)
        return value

    @field_validator("context", mode="before")
    @classmethod
    def _truncate_context(cls, value: Any) -> Any:
        if value is None or not isinstance(value, dict):
            return value
        try:
            encoded = json.dumps(value, default=str).encode("utf-8")
        except Exception:
            # ``default=str`` calls ``str(obj)``, which can itself raise
            # for hostile objects (e.g. broken ``__repr__``). Fall back to
            # the sentinel rather than punching the validator.
            return dict(_TRUNCATED_SENTINEL)
        if len(encoded) > _MAX_CONTEXT_BYTES:
            return dict(_TRUNCATED_SENTINEL)
        return value


class StageErrors(BaseModel):
    """Wrapper for the ``stage_errors`` artifact body."""

    errors: list[StageError] = Field(default_factory=list)


__all__ = [
    "StageErrorSeverity",
    "StageError",
    "StageErrors",
]
