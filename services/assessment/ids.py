"""Stable ids for canonical assessment objects."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def stable_id(kind: str, value: Any) -> str:
    """Return a deterministic id for a JSON-shaped identity value.

    The prefix stays human-readable while the full SHA-256 avoids relying on
    database row ids or process-local ordering.  ``default=str`` is limited to
    the identity boundary so legacy analyzer scalars can be migrated without
    making them part of core claim interpretation.
    """

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return f"{kind}:{hashlib.sha256(encoded).hexdigest()}"


__all__ = ["stable_id"]
