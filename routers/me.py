"""The signed-in user's profile, saved Discord webhooks, and protocol subscriptions.

Every lookup is scoped by ``user_id``; another user's row is a 404, never a 403, so ids can't be probed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from db.models import Protocol, ProtocolSubscription, User, UserWebhook
from schemas.api_requests import AccountSubscribeRequest, SaveWebhookRequest, UpdateWebhookRequest
from services.auth.passwords import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, check_password, set_password
from services.auth.sessions import is_admin
from utils.ratelimit import SlidingWindowRateLimiter
from utils.secrets import sanitize_url

from . import deps
from .auth import open_session

router = APIRouter()

MAX_WEBHOOKS_PER_USER = 10
MAX_SUBSCRIPTIONS_PER_USER = 50
_test_limiter = SlidingWindowRateLimiter(limit=5, window_s=60)
_password_limiter = SlidingWindowRateLimiter(limit=10, window_s=900)


def _parse_id(raw: str, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail=f"{what} not found") from None


def _own_webhook(session, user: User, webhook_id: uuid.UUID) -> UserWebhook:
    hook = session.get(UserWebhook, webhook_id)
    if hook is None or hook.user_id != user.id:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return hook


def _webhook_payload(hook: UserWebhook) -> dict:
    return {
        "id": str(hook.id),
        "label": hook.label,
        "discord_webhook_url": sanitize_url(hook.discord_webhook_url),
        "created_at": hook.created_at.isoformat() if hook.created_at else None,
    }


def _subscription_payload(sub: ProtocolSubscription, protocol_name: str | None) -> dict:
    return {
        "id": str(sub.id),
        "protocol_id": sub.protocol_id,
        "protocol_name": protocol_name,
        "webhook_id": str(sub.webhook_id) if sub.webhook_id else None,
        "webhook_label": sub.webhook.label if sub.webhook is not None else None,
        "discord_webhook_url": sanitize_url(sub.delivery_url) if sub.delivery_url else None,
        "label": sub.label,
        "event_filter": sub.event_filter,
        "created_at": sub.created_at.isoformat() if sub.created_at else None,
    }


@router.get("/api/me")
def get_me(user: User = Depends(deps.require_user)) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "is_admin": is_admin(user),
        "has_password": user.password_hash is not None,
    }


class ChangePasswordRequest(BaseModel):
    # Omitted only by accounts that have no password yet (provider sign-in).
    current_password: str | None = Field(default=None, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


@router.post("/api/me/password")
def change_password(
    body: ChangePasswordRequest, request: Request, user: User = Depends(deps.require_user)
) -> JSONResponse:
    """Set or change the password; every other session is signed out."""
    if _password_limiter.hit(str(user.id)) is not None:
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")
    with deps.SessionLocal() as session:
        account = session.get(User, user.id)
        if account is None:
            raise HTTPException(status_code=401, detail="Sign in required")
        if account.password_hash is not None and not check_password(session, account, body.current_password or ""):
            raise HTTPException(status_code=403, detail="Current password is incorrect")
        set_password(session, account, body.new_password)
        response = JSONResponse({"status": "password_set"})
        open_session(session, request, response, account)
    return response


@router.get("/api/me/webhooks")
def list_webhooks(user: User = Depends(deps.require_user)) -> list[dict]:
    with deps.SessionLocal() as session:
        hooks = session.execute(
            select(UserWebhook).where(UserWebhook.user_id == user.id).order_by(UserWebhook.created_at)
        ).scalars()
        return [_webhook_payload(h) for h in hooks]


@router.post("/api/me/webhooks", status_code=201)
def save_webhook(body: SaveWebhookRequest, user: User = Depends(deps.require_user)) -> dict:
    with deps.SessionLocal() as session:
        count = session.execute(
            select(func.count()).select_from(UserWebhook).where(UserWebhook.user_id == user.id)
        ).scalar_one()
        if count >= MAX_WEBHOOKS_PER_USER:
            raise HTTPException(status_code=409, detail=f"At most {MAX_WEBHOOKS_PER_USER} saved webhooks")
        hook = UserWebhook(user_id=user.id, label=body.label, discord_webhook_url=body.discord_webhook_url)
        session.add(hook)
        session.commit()
        session.refresh(hook)
        return _webhook_payload(hook)


@router.patch("/api/me/webhooks/{webhook_id}")
def update_webhook(webhook_id: str, body: UpdateWebhookRequest, user: User = Depends(deps.require_user)) -> dict:
    with deps.SessionLocal() as session:
        hook = _own_webhook(session, user, _parse_id(webhook_id, "Webhook"))
        if body.discord_webhook_url is not None:
            hook.discord_webhook_url = body.discord_webhook_url
        if "label" in body.model_fields_set:
            hook.label = body.label
        session.commit()
        return _webhook_payload(hook)


@router.delete("/api/me/webhooks/{webhook_id}")
def delete_webhook(webhook_id: str, user: User = Depends(deps.require_user)) -> dict[str, str]:
    """Also removes every subscription delivering to it (FK cascade)."""
    with deps.SessionLocal() as session:
        session.delete(_own_webhook(session, user, _parse_id(webhook_id, "Webhook")))
        session.commit()
        return {"status": "removed"}


@router.post("/api/me/webhooks/{webhook_id}/test")
def test_webhook(webhook_id: str, user: User = Depends(deps.require_user)) -> dict[str, bool]:
    if _test_limiter.hit(str(user.id)) is not None:
        raise HTTPException(status_code=429, detail="Too many test messages; wait a minute")
    with deps.SessionLocal() as session:
        url = _own_webhook(session, user, _parse_id(webhook_id, "Webhook")).discord_webhook_url
    from services.monitoring.notifier import _send_discord

    embed = {
        "title": "PSAT test notification",
        "description": "This webhook is connected to your PSAT account.",
        "color": 0x5865F2,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        delivered = _send_discord(url, embed)
    except Exception:
        delivered = False
    return {"delivered": delivered}


@router.get("/api/me/subscriptions")
def list_subscriptions(user: User = Depends(deps.require_user)) -> list[dict]:
    with deps.SessionLocal() as session:
        rows = session.execute(
            select(ProtocolSubscription, Protocol.name)
            .join(Protocol, Protocol.id == ProtocolSubscription.protocol_id)
            .where(ProtocolSubscription.user_id == user.id)
            .order_by(ProtocolSubscription.created_at)
        ).all()
        return [_subscription_payload(sub, name) for sub, name in rows]


@router.post("/api/me/subscriptions", status_code=201)
def subscribe(body: AccountSubscribeRequest, user: User = Depends(deps.require_user)) -> dict:
    with deps.SessionLocal() as session:
        protocol = session.get(Protocol, body.protocol_id)
        if protocol is None:
            raise HTTPException(status_code=404, detail="Protocol not found")
        _own_webhook(session, user, body.webhook_id)
        count = session.execute(
            select(func.count()).select_from(ProtocolSubscription).where(ProtocolSubscription.user_id == user.id)
        ).scalar_one()
        if count >= MAX_SUBSCRIPTIONS_PER_USER:
            raise HTTPException(status_code=409, detail=f"At most {MAX_SUBSCRIPTIONS_PER_USER} subscriptions")
        sub = ProtocolSubscription(
            protocol_id=protocol.id,
            user_id=user.id,
            webhook_id=body.webhook_id,
            label=body.label,
            event_filter=body.event_filter,
        )
        session.add(sub)
        session.commit()
        session.refresh(sub)
        return _subscription_payload(sub, protocol.name)


@router.delete("/api/me/subscriptions/{sub_id}")
def unsubscribe(sub_id: str, user: User = Depends(deps.require_user)) -> dict[str, str]:
    with deps.SessionLocal() as session:
        sub = session.get(ProtocolSubscription, _parse_id(sub_id, "Subscription"))
        if sub is None or sub.user_id != user.id:
            raise HTTPException(status_code=404, detail="Subscription not found")
        session.delete(sub)
        session.commit()
        return {"status": "removed"}
