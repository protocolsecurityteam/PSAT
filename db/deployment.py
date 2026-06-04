"""Per-deployment scoping for resolution-result rows.

A single implementation-bytecode contract row can back N proxy deployments
(EIP-1167 clone / beacon families); each resolves its controllers against its
own proxy storage. The result tables (``effective_functions``,
``controller_values``, ``control_graph_nodes``, ``control_graph_edges``,
``principal_labels``) carry a ``deployment_address`` — the proxy a row was
resolved against, or NULL for a contract resolved against its own (sole / legacy)
storage.

These helpers centralize the value derivation and the scope predicate so every
writer and reader stays consistent. The predicate always includes legacy NULL
rows, so the dominant 1:1 proxy⇄impl case (one deployment per contract row,
frequently untagged) is unchanged.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_


def normalize_deployment(proxy_address: str | None) -> str | None:
    """The deployment a resolution job reads against: the proxy address
    (lowercased) when an impl is analyzed in proxy context (``request.proxy_address``
    set), else ``None`` (own / sole deployment)."""
    if isinstance(proxy_address, str) and proxy_address.startswith("0x") and len(proxy_address) == 42:
        return proxy_address.lower()
    return None


def deployment_scope(column: Any, deployment_address: str | None):
    """SQL condition selecting rows for ``deployment_address`` plus any legacy
    NULL (untagged) rows.

    Used for BOTH the wholesale-delete scope — a re-resolution of deployment D
    clears D's rows and sweeps untagged NULL rows from before this migration /
    from a prior standalone resolution — and reader disambiguation. When
    ``deployment_address`` resolves to ``None`` it matches only NULL rows.
    """
    dep = normalize_deployment(deployment_address)
    if dep is None:
        return column.is_(None)
    return or_(column == dep, column.is_(None))
