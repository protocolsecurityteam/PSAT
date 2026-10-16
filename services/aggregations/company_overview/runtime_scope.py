"""Exact runtime identity for report projections; NULL belongs only to the code deployment."""

from __future__ import annotations

from typing import Any, TypeVar

RuntimeKey = int | tuple[int, str]
T = TypeVar("T")


def runtime_key(contract_id: int, deployment_address: str | None = None) -> RuntimeKey:
    return (contract_id, deployment_address.lower()) if deployment_address else contract_id


def code_id(key: RuntimeKey) -> int:
    return key[0] if isinstance(key, tuple) else key


def entry_key(contract_id: int, entry: Any) -> RuntimeKey:
    """Rows owned by the rendered contract are own-storage; implementation rows require its exact address.

    Untagged legacy implementation rows cannot prove which proxy supplied the storage and are not borrowed.
    """
    own_id = entry.get("contract_id") if isinstance(entry, dict) else entry.id
    address = entry.get("address") if isinstance(entry, dict) else entry.address
    return runtime_key(contract_id, address if own_id != contract_id else None)


def scoped_rows(rows: dict[RuntimeKey, T], keys: list[RuntimeKey]) -> dict[int, T]:
    return {code_id(key): rows[key] for key in keys if key in rows}


def scoped_walks(rows: dict[RuntimeKey, dict[str, dict]], keys: list[RuntimeKey]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for key in keys:
        out.update(rows.get(key, {}))
    return out


def principal_classification(contracts: dict, values: dict, nodes: dict) -> dict:
    """Reuse address classification, never deployment-specific configuration or terminal walks."""
    from .principals import _build_principal_lookup

    def by_code(rows: dict) -> dict:
        out: dict[int, list] = {}
        for key, records in rows.items():
            out.setdefault(code_id(key), []).extend(records)
        return out

    lookup = _build_principal_lookup(contracts, by_code(values), by_code(nodes))
    return {key: {**meta, "details": {}} for key, meta in lookup.items()}


def with_classification(local: dict, classification: dict) -> dict:
    for key, meta in classification.items():
        current = local.get(key)
        if current is None:
            local[key] = meta
        elif current.get("resolved_type") in (None, "", "unknown", "contract"):
            local[key] = {**meta, "details": current.get("details") or {}}
    return local
