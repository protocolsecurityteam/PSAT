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
from utils.logging import trace_id_var
from utils.rpc import default_rpc_url

logger = logging.getLogger(__name__)

ADMIN_KEY = os.environ.get("PSAT_ADMIN_KEY")
if not ADMIN_KEY:
    logger.warning(
        "PSAT_ADMIN_KEY is not set — write endpoints will reject every request. "
        "Set PSAT_ADMIN_KEY in the environment to enable admin operations."
    )

# Mainnet-scoped default RPC for the admin/API dependency layer (inv. 6 edge):
# these endpoints serve mainnet paths today, and a required chain param at the
# FastAPI dependency is impractical. An explicit, documented mainnet choice —
# not a buried default — logged so the assumption is visible in startup logs.
DEFAULT_RPC_URL = default_rpc_url(chain_id=1) or ""
logger.info("routers.deps: DEFAULT_RPC_URL bound to mainnet (chain_id=1) eRPC route")
MAX_TVL_HISTORY_DAYS = 90

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def require_admin_key(request: Request, x_psat_admin_key: str | None = Header(default=None)) -> None:
    """Gate the depending route on a valid ``X-PSAT-Admin-Key`` header.

    Wired via ``dependencies=[Depends(require_admin_key)]`` on every operator
    route — admin mutations and ops/internal GET reads alike. Raises 401 unless
    a key is configured and the supplied header matches it.
    """
    if not ADMIN_KEY:
        reason = "admin_key_not_configured"
    elif not x_psat_admin_key:
        reason = "missing_key"
    elif not hmac.compare_digest(x_psat_admin_key, ADMIN_KEY):
        reason = "key_mismatch"
    else:
        return
    # The rejection itself is the fact worth alerting on (admin-key drift,
    # probing). Never log the supplied key — only the discriminating reason.
    logger.warning(
        "admin key rejected on %s",
        request.url.path,
        extra={"trace_id": trace_id_var.get(), "path": request.url.path, "reason": reason},
    )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin key required")


def admin_key_valid(x_psat_admin_key: str | None) -> bool:
    """True when *x_psat_admin_key* matches the configured admin key.

    Non-raising, non-logging companion to :func:`require_admin_key` for the
    endpoints that broaden their *response* for an authenticated caller
    (e.g. extra fields) rather than rejecting an anonymous one outright.
    """
    return bool(ADMIN_KEY) and bool(x_psat_admin_key) and hmac.compare_digest(x_psat_admin_key, ADMIN_KEY)


def log_admin_mutation(action: str, **fields: Any) -> None:
    """Emit one INFO audit line per successful admin mutation.

    ``action`` names the operation (e.g. ``"job_retry"``); ``fields`` carry the
    affected id(s)/counts. All go in ``extra`` so the audit trail (who changed
    what) is a queryable stream, correlatable by ``trace_id`` to the request
    line emitted by the API middleware.
    """
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
