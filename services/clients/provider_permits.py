"""Credential-scoped Etherscan quotas shared across processes; no wire under a lock."""

import hashlib
import time
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from db.models import SessionLocal
from db.models.balance_collection import ProviderPermit
from services.clients.request_budget import check_budget


def wait_etherscan_permit(credential: str, *, token_page: bool, rate: float) -> None:
    from services.clients.request_budget import RequestBudgetExceeded

    started = time.monotonic()
    identity = hashlib.sha256(credential.encode()).hexdigest()[:24]
    quotas = [(f"etherscan:{identity}:all", 1.0 / max(rate, 0.1))]
    if token_page:
        quotas.append((f"etherscan:{identity}:token_page", 1.0))
    # Acquire both quotas together. Losing contenders do not reserve future slots;
    # a dead process cannot leave a queue of abandoned reservations.
    while True:
        check_budget()
        if time.monotonic() - started > 30:
            raise RequestBudgetExceeded("shared Etherscan permit wait exceeded 30 seconds")
        with SessionLocal() as session:
            now = session.execute(select(func.clock_timestamp())).scalar_one()
            for key, _interval in quotas:
                session.execute(
                    insert(ProviderPermit).values(quota_key=key, next_allowed_at=now).on_conflict_do_nothing()
                )
            rows = {
                row.quota_key: row
                for row in session.scalars(
                    select(ProviderPermit)
                    .where(ProviderPermit.quota_key.in_([q[0] for q in quotas]))
                    .order_by(ProviderPermit.quota_key)
                    .with_for_update()
                )
            }
            delay = max(0.0, *((rows[key].next_allowed_at - now).total_seconds() for key, _ in quotas))
            if delay <= 0:
                for key, interval in quotas:
                    rows[key].next_allowed_at = now + timedelta(seconds=interval)
                session.commit()
                return
            session.commit()
        time.sleep(min(delay, 0.5))
