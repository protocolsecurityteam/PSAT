"""Shared FastAPI dependencies. Routers use ``deps.X`` attribute access so tests have one patch point per symbol."""

from __future__ import annotations

import hmac
import logging
import os
import re
from typing import Any, NoReturn
from urllib.parse import urlsplit

from fastapi import Header, HTTPException, Request, status

from db.models import SessionLocal, User
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
from services.auth.sessions import SESSION_COOKIE, is_admin, resolve_session
from services.clients.rpc import default_rpc_url
from utils.edge import is_production
from utils.logging import trace_id_var

logger = logging.getLogger(__name__)

# Previews and local only; production refuses to start with it set (``check_production_admin_config``).
ADMIN_KEY = os.environ.get("PSAT_ADMIN_KEY")
if not ADMIN_KEY:
    logger.info("PSAT_ADMIN_KEY is not set; admin endpoints accept only signed-in admin accounts")

# Explicit mainnet default: a required chain param at this layer is impractical.
DEFAULT_RPC_URL = default_rpc_url(chain_id=1) or ""
logger.info("routers.deps: DEFAULT_RPC_URL bound to mainnet (chain_id=1) eRPC route")
MAX_TVL_HISTORY_DAYS = 90

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def _reject_admin(request: Request, reason: str) -> NoReturn:
    # Never log the supplied key.
    logger.warning(
        "admin access rejected on %s",
        request.url.path,
        extra={"trace_id": trace_id_var.get(), "path": request.url.path, "reason": reason},
    )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin access required")


def _key_reason(x_psat_admin_key: str | None) -> str | None:
    if not ADMIN_KEY:
        return "admin_key_not_configured"
    if not x_psat_admin_key:
        return "missing_key"
    if not hmac.compare_digest(x_psat_admin_key, ADMIN_KEY):
        return "key_mismatch"
    return None


def _allowed_origins() -> set[str]:
    return {o.strip() for o in os.environ.get("PSAT_SITE_ORIGIN", "").split(",") if o.strip()}


def is_site_origin(request: Request, origin: str | None) -> bool:
    return bool(origin) and (origin in _allowed_origins() or urlsplit(origin).netloc == request.headers.get("host"))


def check_same_origin(request: Request) -> None:
    """CSRF gate for cookie-authenticated writes: the Origin must be the site itself or a configured site origin."""
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if is_site_origin(request, request.headers.get("origin")):
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-origin request refused")


def current_user(request: Request) -> User | None:
    """The signed-in user from the session cookie, or ``None``. Resolved once per request."""
    if hasattr(request.state, "psat_user"):
        return request.state.psat_user
    user = None
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with SessionLocal() as session:
            user = resolve_session(session, token)
    request.state.psat_user = user
    return user


def require_user(request: Request) -> User:
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in required")
    check_same_origin(request)
    return user


def _account_rejection(request: Request, user: User) -> str | None:
    """Why ``user`` isn't an admin for this request, or ``None`` when they are."""
    if not is_admin(user):
        return "not_admin"
    if getattr(request.state, "edge_mode", None) != "cloudflare" and not is_production():
        return None
    # Behind operator Access the account must be the operator Access authenticated, not merely any admin account.
    identity = getattr(request.state, "access_identity", None)
    email = identity.get("email") if isinstance(identity, dict) else None
    if isinstance(email, str) and email.lower() == user.email.lower():
        return None
    return "access_identity_mismatch"


def require_admin(request: Request, x_psat_admin_key: str | None = Header(default=None)) -> None:
    """An admin is a signed-in account on the admin allowlist, or the shared key where one is configured
    (previews, local).
    """
    reason = _key_reason(x_psat_admin_key)
    if reason is None:
        return
    # A wrong key is a hard fail even with a valid cookie, so a stale key in a script surfaces instead of hiding.
    if x_psat_admin_key:
        _reject_admin(request, reason)
    user = current_user(request)
    if user is None:
        _reject_admin(request, "no_session")
    rejection = _account_rejection(request, user)
    if rejection is not None:
        _reject_admin(request, rejection)
    check_same_origin(request)
    # Mutation audit lines carry the same trace_id, which ties them to this account.
    logger.info(
        "admin access via account",
        extra={"trace_id": trace_id_var.get(), "path": request.url.path, "user_id": str(user.id)},
    )


def is_admin_request(request: Request, x_psat_admin_key: str | None) -> bool:
    if _key_reason(x_psat_admin_key) is None:
        return True
    user = current_user(request)
    return user is not None and _account_rejection(request, user) is None


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
    "check_same_origin",
    "create_job",
    "current_user",
    "deserialize_artifact",
    "find_existing_job_for_address",
    "get_all_artifacts",
    "get_artifact",
    "get_storage_client",
    "is_admin_request",
    "log_admin_mutation",
    "require_admin",
    "require_user",
]
