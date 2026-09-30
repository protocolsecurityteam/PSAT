"""Optional targeted Cloudflare invalidation, backed by a coalescing DB outbox.

Only the background worker calls this. A failed/missing purge credential cannot
extend freshness: the origin refuses dirty prepared rows and caps edge TTL at
60s from validation. Use a zone-scoped Cache Purge token, not a management key.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from datetime import timedelta

import requests
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from db.models import CompanyPagePurge as Purge
from db.models import SessionLocal
from services.company_pages import cache_tag

logger = logging.getLogger(__name__)


def enqueue_purge(session: Session, name: str) -> None:
    session.execute(
        insert(Purge)
        .values(company_name=name)
        .on_conflict_do_update(
            index_elements=["company_name"],
            set_={"token": uuid.uuid4(), "attempts": 0, "next_attempt_at": func.clock_timestamp()},
        )
    )


def purge_config() -> tuple[str, str] | None:
    # Opt-in only: never discover/reuse .env.live management credentials or
    # let a staging/local worker invalidate the production hostname.
    if os.getenv("PSAT_COMPANY_PURGE_ENABLED", "0") != "1" or os.getenv("FLY_APP_NAME") != "psat":
        return None
    zone = os.getenv("PSAT_CLOUDFLARE_ZONE_ID", "")
    token = os.getenv("PSAT_CLOUDFLARE_PURGE_TOKEN", "")
    if not re.fullmatch(r"[a-f0-9]{32}", zone) or not token:
        return None
    return zone, token


def purge_one(session_factory=SessionLocal) -> str:
    config = purge_config()
    if config is None:
        return "disabled"
    zone, token = config
    with session_factory() as session:
        if not session.execute(text("SELECT pg_try_advisory_xact_lock(210031, 1)")).scalar():
            return "leased"
        row = session.execute(
            select(Purge.company_name, Purge.token, Purge.attempts)
            .where(Purge.next_attempt_at <= func.clock_timestamp())
            .order_by(Purge.next_attempt_at, Purge.company_name)
            .limit(1)
        ).first()
        if row is None:
            return "idle"
        name, generation, attempts = row
        matched = (Purge.company_name == name, Purge.token == generation)
        try:
            response = requests.post(
                f"https://api.cloudflare.com/client/v4/zones/{zone}/purge_cache",
                headers={"Authorization": f"Bearer {token}"},
                # Tags cover encoding aliases and avoid GET-only Cache Rule
                # mismatches during URL purges. Never purge the whole zone.
                json={"tags": [cache_tag(name)]},
                timeout=(3, 5),
                allow_redirects=False,
            )
            if response.status_code != 200 or response.json().get("success") is not True:
                raise ValueError("Cloudflare did not confirm purge")
        except (requests.RequestException, ValueError, AttributeError):
            # Do not log provider bodies or credentials. Generation guards
            # preserve a newer publication/rename that arrived during HTTP.
            logger.warning("Company cache purge failed; retry scheduled", extra={"company": name})
            session.execute(
                update(Purge)
                .where(*matched)
                .values(
                    attempts=attempts + 1,
                    next_attempt_at=func.clock_timestamp() + timedelta(seconds=min(300, 5 * 2 ** min(attempts, 6))),
                )
            )
            outcome = "failed"
        else:
            session.execute(delete(Purge).where(*matched))
            outcome = "purged"
        session.commit()
        return outcome
