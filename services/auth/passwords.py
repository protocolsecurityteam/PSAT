"""Email/password accounts: argon2id hashing and single-use email tokens.

A password is only ever set through an emailed link (``verify`` for a new account, ``reset`` for an existing one), so
whoever sets it has proven they read that inbox. Signing up never takes a password: otherwise someone could register
a victim's email with their own password and have the victim activate it by clicking the verification mail.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from db.models import EmailToken, User, UserSession

MIN_PASSWORD_LENGTH = 10
# argon2 cost doesn't grow with input length, but request bodies should stay small.
MAX_PASSWORD_LENGTH = 256
TOKEN_TTL = {"verify": timedelta(hours=24), "reset": timedelta(hours=1)}

_hasher = PasswordHasher()
# Verified against when the email has no password, so a miss costs the same as a wrong password.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def check_password(session: Session, user: User | None, password: str) -> bool:
    """Constant-work check; rehashes in place when the stored parameters are outdated."""
    stored = user.password_hash if user is not None else None
    try:
        _hasher.verify(stored or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    if user is None or stored is None:
        return False
    if _hasher.check_needs_rehash(stored):
        user.password_hash = _hasher.hash(password)
        session.commit()
    return True


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(session: Session, user: User, purpose: str, *, now: datetime | None = None) -> str:
    """A fresh token for ``purpose``; earlier ones for the same purpose stop working."""
    now = now or datetime.now(timezone.utc)
    session.execute(delete(EmailToken).where(EmailToken.user_id == user.id, EmailToken.purpose == purpose))
    token = secrets.token_urlsafe(32)
    session.add(
        EmailToken(user_id=user.id, purpose=purpose, token_hash=_hash(token), expires_at=now + TOKEN_TTL[purpose])
    )
    return token


def consume_token(session: Session, token: str | None, *, now: datetime | None = None) -> User | None:
    """The token's user if it is live, deleting it either way (single use); caller commits."""
    if not token:
        return None
    now = now or datetime.now(timezone.utc)
    row = session.execute(select(EmailToken).where(EmailToken.token_hash == _hash(token))).scalar_one_or_none()
    if row is None:
        return None
    session.delete(row)
    if row.expires_at <= now:
        return None
    return session.get(User, row.user_id)


def revoke_all_sessions(session: Session, user: User) -> None:
    session.execute(delete(UserSession).where(UserSession.user_id == user.id))


def forget_unverified_claims(session: Session, user: User) -> None:
    """Someone has just proven they own this unverified account's email: drop anything its unproven registrant could
    still use (sessions, pending links), so a pre-registered account can't be held against its real owner.
    """
    user.password_hash = None
    revoke_all_sessions(session, user)
    session.execute(delete(EmailToken).where(EmailToken.user_id == user.id))


def set_password(session: Session, user: User, password: str) -> None:
    """Set the password and sign out everywhere else; callers have proven the email (link token) or the old password.

    Caller commits and issues the new session.
    """
    user.password_hash = hash_password(password)
    user.email_verified = True
    revoke_all_sessions(session, user)
    session.execute(delete(EmailToken).where(EmailToken.user_id == user.id))
