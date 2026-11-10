"""Per-deployment scoping for resolution-result rows.

One implementation contract row can back many proxies (clones, beacons), each resolving against its own storage. Result
tables carry ``deployment_address`` (the proxy, or NULL for own/legacy storage). These helpers keep writers and readers
consistent; the predicate always includes legacy NULL rows, so the common 1:1 case is unchanged.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_


def normalize_deployment(proxy_address: str | None) -> str | None:
    """The deployment a resolution job reads against: the lowercased proxy when the job has
    ``request.proxy_address``, else ``None``.
    """
    if isinstance(proxy_address, str) and proxy_address.startswith("0x") and len(proxy_address) == 42:
        return proxy_address.lower()
    return None


def deployment_scope(column: Any, deployment_address: str | None):
    """SQL condition for ``deployment_address`` rows plus legacy NULL rows.

    Used for the re-resolution delete scope (which also sweeps old untagged rows) and for reads. ``None`` matches only
    NULL rows.
    """
    dep = normalize_deployment(deployment_address)
    if dep is None:
        return column.is_(None)
    return or_(column == dep, column.is_(None))


def resolved_against(row_deployment: str | None, holder_address: str | None, deployment: str | None) -> bool:
    """Whether a row filed on *holder_address*'s contract was resolved against *deployment*'s storage.

    A tagged row names its deployment. An untagged row is the holder's own storage, so on any other contract (a shared
    impl's legacy set, or the impl read standalone) it is never attributed to *deployment*.
    """
    target = (deployment or "").lower()
    if not target:
        return False
    if row_deployment is not None:
        return row_deployment.lower() == target
    return (holder_address or "").lower() == target
