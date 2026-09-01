"""Natural domain keys and content keys for Assessment references."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal


def entity_key(chain_id: int, address: str) -> str:
    """The natural identity of an address on a chain."""

    return f"{chain_id}:{address.lower()}"


def content_key(kind: Literal["claim", "evidence"], value: Any) -> str:
    """Content-address a claim or evidence record."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return f"{kind}:{hashlib.sha256(encoded).hexdigest()}"


__all__ = ["content_key", "entity_key"]
