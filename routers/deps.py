"""Shared FastAPI dependencies, constants, and external symbols.

Every router references external symbols via attribute access on this
module (``deps.SessionLocal``, ``deps.create_job``, ...) rather than
``from db.models import SessionLocal``. That gives tests a single patch
point per symbol — patching ``routers.deps.SessionLocal`` once affects
every router instead of each router's own local binding.
"""

from __future__ import annotations

import hmac
import logging
import os
import re

from fastapi import Header, HTTPException, status

from db.models import SessionLocal
from db.queue import (
    create_job,
    find_existing_job_for_address,
    get_all_artifacts,
    get_artifact,
)
from db.storage import (
    StorageError,
    StorageUnavailable,
    deserialize_artifact,
    get_storage_client,
)
from utils.rpc import PUBLIC_ETH_RPC_URL, default_rpc_url

logger = logging.getLogger(__name__)

ADMIN_KEY = os.environ.get("PSAT_ADMIN_KEY")
if not ADMIN_KEY:
    logger.warning(
        "PSAT_ADMIN_KEY is not set — write endpoints will reject every request. "
        "Set PSAT_ADMIN_KEY in the environment to enable admin operations."
    )

DEFAULT_RPC_URL = (
    default_rpc_url(chain_id=1, fallback_url=os.environ.get("ETH_RPC") or PUBLIC_ETH_RPC_URL) or PUBLIC_ETH_RPC_URL
)
MAX_TVL_HISTORY_DAYS = 90

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def require_admin_key(x_psat_admin_key: str | None = Header(default=None)) -> None:
    """Reject any non-GET request that does not carry a valid admin key."""
    if not ADMIN_KEY or not x_psat_admin_key or not hmac.compare_digest(x_psat_admin_key, ADMIN_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin key required")


def _normalize_address_or_400(address: str) -> str:
    a = (address or "").strip().lower()
    if not _ADDRESS_RE.match(a):
        raise HTTPException(status_code=400, detail="Invalid address format")
    return a


__all__ = [
    "ADMIN_KEY",
    "DEFAULT_RPC_URL",
    "MAX_TVL_HISTORY_DAYS",
    "SessionLocal",
    "StorageError",
    "StorageUnavailable",
    "_ADDRESS_RE",
    "_normalize_address_or_400",
    "create_job",
    "deserialize_artifact",
    "find_existing_job_for_address",
    "get_all_artifacts",
    "get_artifact",
    "get_storage_client",
    "require_admin_key",
]
