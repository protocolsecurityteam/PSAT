"""Artifact naming for per-sub-contract bundles from recursive resolution.

Runtime slices (``snapshot``, ``effective_permissions``) are stored as ``recursive.<address>.<kind>`` artifacts for the
policy stage. Static slices live in ``contract_materializations`` instead. ``.`` rather than ``:`` because
``db.storage._safe_name`` only allows ``[A-Za-z0-9._-]``. Shared by both workers as the single source of truth.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from sqlalchemy.orm import Session

from db.queue import store_artifact

logger = logging.getLogger(__name__)

ARTIFACT_KINDS: tuple[str, ...] = ("snapshot", "effective_permissions")
KEY_PREFIX = "recursive"


def artifact_key(address: str, kind: str) -> str:
    return f"{KEY_PREFIX}.{address.lower()}.{kind}"


def parse_key(name: str) -> tuple[str, str] | None:
    """Inverse of ``artifact_key``: ``(address, kind)`` or ``None``."""
    if not name.startswith(f"{KEY_PREFIX}."):
        return None
    parts = name.split(".", 2)
    if len(parts) != 3:
        return None
    _, address, kind = parts
    return address, kind


def store_bundle(session: Session, job_id: Any, nested: Mapping[str, Mapping[str, Any]]) -> None:
    """Persist per-address ``LoadedArtifacts`` bundles as artifacts, warning when an expected kind is missing so
    absent authority enrichment is traceable.
    """
    for address, bundle in nested.items():
        for kind in ARTIFACT_KINDS:
            payload = bundle.get(kind)
            if payload is None:
                logger.warning("Recursive artifact missing: address=%s kind=%s", address, kind)
                continue
            store_artifact(session, job_id, artifact_key(address, kind), data=payload)
