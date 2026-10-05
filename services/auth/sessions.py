"""Server-side sessions. The cookie carries a random token; only its sha256 is stored, so a database read never yields a
usable session, and deleting the row revokes it immediately.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from db.models import OAuthIdentity, User, UserSession
from services.auth.passwords import forget_unverified_claims

SESSION_COOKIE = "psat_session"
SESSION_TTL = timedelta(days=30)
_LAST_SEEN_RESOLUTION = timedelta(minutes=1)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def admin_emails() -> frozenset[str]:
    return frozenset(e.strip().lower() for e in os.environ.get("PSAT_ADMIN_EMAILS", "").split(",") if e.strip())


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


def upsert_oauth_user(
    session: Session,
    *,
    provider: str,
    subject: str,
    email: str,
    display_name: str | None,
    avatar_url: str | None,
    now: datetime | None = None,
) -> User:
    """Find the user by identity, else by email (linking the identity), else create one.

    The provider has verified ``email``. If it matches a password account whose email was never verified, that
    account's unproven registrant loses it: the provider login is the first proof of ownership.
    """
    now = now or datetime.now(timezone.utc)
    email = email.strip().lower()
    identity = session.execute(
        select(OAuthIdentity).where(OAuthIdentity.provider == provider, OAuthIdentity.provider_subject == subject)
    ).scalar_one_or_none()
    user = session.get(User, identity.user_id) if identity else None
    if user is None:
        user = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is not None and not user.email_verified:
            forget_unverified_claims(session, user)
    if user is None:
        user = User(email=email)
        session.add(user)
        session.flush()
    if identity is None:
        session.add(OAuthIdentity(user_id=user.id, provider=provider, provider_subject=subject))
    user.display_name = display_name or user.display_name
    user.avatar_url = avatar_url or user.avatar_url
    user.email_verified = True
    user.is_admin = user.email in admin_emails()
    user.last_login_at = now
    return user
