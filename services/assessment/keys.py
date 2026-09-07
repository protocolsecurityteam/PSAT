"""Natural domain keys and content keys for Assessment references."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, cast

from pydantic import JsonValue

from schemas.assessment import Entity


def entity_key(chain_id: int, address: str) -> str:
    """The natural identity of an address on a chain."""

    return f"{chain_id}:{address.lower()}"


def entity_record(chain_id: int, address: str, resolved_type: str) -> tuple[str, Entity]:
    """Construct one chain-scoped entity consistently across analytical stages."""
    normalized = address.lower()
    return entity_key(chain_id, normalized), {
        "chain_id": chain_id,
        "address": normalized,
        "kind": "contract"
        if resolved_type in {"safe", "timelock", "proxy_admin", "contract", "cross_chain_authority"}
        else "account",
        "tags": [] if resolved_type in ("eoa", "contract", "unknown") else [resolved_type],
    }


def content_key(kind: Literal["claim", "evidence"], value: Any) -> str:
    """Content-address a claim or evidence record."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return f"{kind}:{hashlib.sha256(encoded).hexdigest()}"


__all__ = ["content_key", "entity_key"]


def json_value(value: Any) -> JsonValue:
    """Normalize analyzer and chain observations at their JSON boundary."""
    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))
