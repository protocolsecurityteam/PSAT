"""Shared FastAPI dependencies. Routers use ``deps.X`` attribute access so tests have one patch point per symbol."""

from __future__ import annotations

import hmac
import logging
import os
import re
from typing import Any

from fastapi import Header, HTTPException, Request, status

from db.models import SessionLocal
from db.queue import (
    create_job,
    find_existing_job_for_address,
    get_all_artifacts,
    get_artifact,
)
from db.storage import (
    StorageContentAbsent,
    StorageContentIncomplete,
    StorageContentNotDetermined,
    StorageError,
    StorageUnavailable,
    deserialize_artifact,
    get_storage_client,
)
from services.clients.rpc import default_rpc_url
from utils.logging import trace_id_var

logger = logging.getLogger(__name__)

ADMIN_KEY = os.environ.get("PSAT_ADMIN_KEY")
if not ADMIN_KEY:
    logger.warning(
        "PSAT_ADMIN_KEY is not set — write endpoints will reject every request. "
        "Set PSAT_ADMIN_KEY in the environment to enable admin operations."
    )

# Explicit mainnet default: a required chain param at this layer is impractical.
DEFAULT_RPC_URL = default_rpc_url(chain_id=1) or ""
logger.info("routers.deps: DEFAULT_RPC_URL bound to mainnet (chain_id=1) eRPC route")
MAX_TVL_HISTORY_DAYS = 90

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def require_admin_key(request: Request, x_psat_admin_key: str | None = Header(default=None)) -> None:
    """Raises 401 unless an admin key is configured and the header matches."""
    if not ADMIN_KEY:
        reason = "admin_key_not_configured"
    elif not x_psat_admin_key:
        reason = "missing_key"
    elif not hmac.compare_digest(x_psat_admin_key, ADMIN_KEY):
        reason = "key_mismatch"
    else:
        return
    # Never log the supplied key.
    logger.warning(
        "admin key rejected on %s",
        request.url.path,
        extra={"trace_id": trace_id_var.get(), "path": request.url.path, "reason": reason},
    )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin key required")


def admin_key_valid(x_psat_admin_key: str | None) -> bool:
    """Non-raising variant for endpoints that broaden their response for admins."""
    return bool(ADMIN_KEY) and bool(x_psat_admin_key) and hmac.compare_digest(x_psat_admin_key, ADMIN_KEY)


def log_admin_mutation(action: str, **fields: Any) -> None:
    """One INFO audit line per successful admin mutation, fields in ``extra``."""
    extra: dict[str, Any] = {"action": action, **fields}
    tid = trace_id_var.get()
    if tid is not None:
        extra["trace_id"] = tid
    logger.info("admin mutation: %s", action, extra=extra)


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
    "StorageContentAbsent",
    "StorageContentIncomplete",
    "StorageContentNotDetermined",
    "StorageError",
    "StorageUnavailable",
    "_ADDRESS_RE",
    "_normalize_address_or_400",
    "admin_key_valid",
    "create_job",
    "deserialize_artifact",
    "find_existing_job_for_address",
    "get_all_artifacts",
    "get_artifact",
    "get_storage_client",
    "log_admin_mutation",
    "require_admin_key",
]
