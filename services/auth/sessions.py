"""Server-side sessions. The cookie carries a random token; only its sha256 is stored, so a database read never yields a
usable session, and deleting the row revokes it immediately.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Mapping

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from db.models import User, UserSession
from utils.edge import is_production

SESSION_COOKIE = "psat_session"
SESSION_TTL = timedelta(days=30)
_LAST_SEEN_RESOLUTION = timedelta(minutes=1)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def admin_emails(env: Mapping[str, str] | None = None) -> frozenset[str]:
    raw = (os.environ if env is None else env).get("PSAT_ADMIN_EMAILS", "")
    return frozenset(e.strip().lower() for e in raw.split(",") if e.strip())


def check_production_admin_config(access_emails: frozenset[str], env: Mapping[str, str] | None = None) -> None:
    """Production admins are signed-in accounts that also pass operator Access; the shared key is preview/local only."""
    env = os.environ if env is None else env
    if not is_production(env):
        return
    if env.get("PSAT_ADMIN_KEY"):
        raise ValueError("PSAT_ADMIN_KEY must not be set in production")
    if not admin_emails(env) <= access_emails:
        raise ValueError("Every PSAT_ADMIN_EMAILS entry must also be in PSAT_ACCESS_EMAILS")


def is_admin(user: User) -> bool:
    # Checked against the live allowlist too, so removing an email demotes open sessions without waiting for a login.
    # An unverified email proves nothing about who registered it.
    return bool(user.is_admin) and user.email_verified and user.email.lower() in admin_emails()


def create_session(session: Session, user: User, *, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    session.add(UserSession(token_hash=_hash(token), user_id=user.id, expires_at=now + SESSION_TTL, last_seen_at=now))
    return token


def resolve_session(session: Session, token: str | None, *, now: datetime | None = None) -> User | None:
    if not token:
        return None
    now = now or datetime.now(timezone.utc)
    row = session.execute(select(UserSession).where(UserSession.token_hash == _hash(token))).scalar_one_or_none()
    if row is None:
        return None
    if row.expires_at <= now:
        session.delete(row)
        session.commit()
        return None
    if row.last_seen_at is None or now - row.last_seen_at >= _LAST_SEEN_RESOLUTION:
        row.last_seen_at = now
        session.commit()
    return session.get(User, row.user_id)


def revoke_session(session: Session, token: str | None) -> None:
    if token:
        session.execute(delete(UserSession).where(UserSession.token_hash == _hash(token)))
        session.commit()


def upsert_neon_user(
    session: Session,
    *,
    neon_auth_id: str,
    email: str,
    email_verified: bool,
    display_name: str | None,
    avatar_url: str | None,
    now: datetime | None = None,
) -> User:
    """Find the user by Neon Auth id, else by email (a user Neon re-created), else create one.

    The email match only relinks when Neon has verified the address; an unverified claim to an existing account's
    email is refused rather than handed that account.
    """
    now = now or datetime.now(timezone.utc)
    email = email.strip().lower()
    user = session.execute(select(User).where(User.neon_auth_id == neon_auth_id)).scalar_one_or_none()
    if user is None:
        by_email = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if by_email is not None:
            if not email_verified:
                raise PermissionError("email belongs to another account")
            user = by_email
            user.neon_auth_id = neon_auth_id
    if user is None:
        user = User(neon_auth_id=neon_auth_id, email=email)
        session.add(user)
    user.email = email
    user.email_verified = email_verified
    user.display_name = display_name or user.display_name
    user.avatar_url = avatar_url or user.avatar_url
    user.is_admin = email_verified and email in admin_emails()
    user.last_login_at = now
    session.flush()
    return user


def upsert_dev_user(session: Session, email: str, *, now: datetime | None = None) -> User:
    """Local dev-login only: a verified account with no Neon identity."""
    email = email.strip().lower()
    user = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None:
        user = User(email=email)
        session.add(user)
    user.email_verified = True
    user.is_admin = email in admin_emails()
    user.last_login_at = now or datetime.now(timezone.utc)
    session.flush()
    return user
