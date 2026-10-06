"""Expand display-grouped inventory into chain-specific persistence rows."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from utils.chains import canonical_chain_list


def inventory_deployments(inventory: dict[str, Any], *, default_chain: str) -> Iterator[dict[str, Any]]:
    """Flatten presentation groups without borrowing another deployment's chain."""
    for entry in inventory.get("contracts", []):
        deployments = ([entry] if entry.get("address") else []) + list(entry.get("deployments") or [])
        for deployment in deployments:
            item = {**entry, **deployment}
            address = item.get("address")
            if not address:
                continue
            chains = canonical_chain_list(deployment.get("chains"))
            if not chains:
                chains = canonical_chain_list([deployment.get("chain")])
            if not chains:
                chains = canonical_chain_list(entry.get("chains")) or [entry.get("chain") or default_chain]
            for chain in chains:
                yield {
                    k: v
                    for k, v in {**item, "address": str(address).lower(), "chain": chain, "chains": [chain]}.items()
                    if k != "deployments"
                }


def inventory_rows(inventory: dict[str, Any], *, default_chain: str) -> list[dict[str, Any]]:
    sources = inventory.get("sources") or {}
    rows: list[dict[str, Any]] = []
    for item in inventory_deployments(inventory, default_chain=default_chain):
        address = item["address"]
        source_ids = item.get("source_ids") or []
        source_url = item.get("discovery_url") or next((sources[sid] for sid in source_ids if sid in sources), None)
        tags = item.get("source") or ["inventory"]
        if not isinstance(tags, list):
            tags = [str(tags)]
        rows.append(
            {
                "address": str(address),
                "chain": item["chain"],
                "chains": item["chains"],
                "new_sources": tags,
                "contract_name": item.get("name"),
                "confidence": item.get("confidence"),
                "discovery_url": source_url,
            }
        )
    return rows
