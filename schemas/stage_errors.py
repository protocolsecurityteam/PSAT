"""The ``stage_errors`` artifact: every job-failing (``error``) and swallowed (``degraded``) failure, in one envelope
so consumers read one artifact.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# Keeps rows well under the 1MB JSONB limit; ``context`` is where unbounded blobs sneak in.
_MAX_MESSAGE_BYTES = 4 * 1024
_MAX_CONTEXT_BYTES = 4 * 1024
_TRUNCATED_SENTINEL = {"_truncated": True}

Severity = Literal["error", "degraded"]


def _truncate_text(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    # Avoid slicing mid-character.
    return encoded[:limit].decode("utf-8", errors="ignore")


class StageError(BaseModel):
    stage: str
    severity: Severity
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
            # ``str(obj)`` can itself raise for hostile objects.
            return dict(_TRUNCATED_SENTINEL)
        if len(encoded) > _MAX_CONTEXT_BYTES:
            return dict(_TRUNCATED_SENTINEL)
        return value


class StageErrors(BaseModel):
    errors: list[StageError] = Field(default_factory=list)


__all__ = [
    "Severity",
    "StageError",
    "StageErrors",
]
