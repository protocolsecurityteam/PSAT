"""Shared uncertainty check for predicate operands and nested descriptor inputs."""

from collections.abc import Mapping
from typing import Any


def has_unknown_predicate_provenance(leaf: Mapping[str, Any]) -> bool:
    pending: list[Any] = [leaf.get("operands"), leaf.get("set_descriptor")]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if not isinstance(value, (Mapping, list, tuple)) or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, Mapping):
            if value.get("source") == "top":
                return True
            pending.extend(value.values())
        else:
            pending.extend(value)
    return False
