"""Fleet-wide RPC admission and overload protection; database failure never opens the gate."""

from __future__ import annotations

import hashlib
import math
import os
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from utils.logging import record_stage_metric


class RpcBackpressure(RuntimeError):
    """No chain observation was made; retry only after the shared cooldown."""

    def __init__(self, message: str, retry_after: float = 30):
        super().__init__(message)
        self.retry_after = retry_after


class RpcBudgetExceeded(RuntimeError):
    """A bounded run/stage exhausted its allowance; repeating it automatically is unsafe."""


@dataclass
class RpcScope:
    run_id: str
    stage_limit: int = 1000
    stage: str = "adhoc"
    attempts: int = 0
    sent: int = 0
    lock: Lock = field(default_factory=Lock)
    cache: dict[str, Any] = field(default_factory=dict)
    cache_bytes: int = 0
    failure: RpcBackpressure | RpcBudgetExceeded | None = None

    def charge(self, count: int) -> None:
        with self.lock:
            if self.failure is not None:
                raise self.failure
            if self.attempts + count > self.stage_limit:
                self.failure = RpcBudgetExceeded(f"RPC stage allowance exhausted ({self.stage_limit} calls)")
                raise self.failure
            self.attempts += count
            record_stage_metric("rpc_admissions_requested", self.attempts)

    def note_sent(self, count: int) -> None:
        with self.lock:
            self.sent += count
            record_stage_metric("rpc_calls_sent", self.sent)


_scope: ContextVar[RpcScope | None] = ContextVar("rpc_scope", default=None)


def current_scope() -> RpcScope | None:
    return _scope.get()


@contextmanager
def rpc_scope(run_id: str, stage: str = "adhoc"):
    scope = RpcScope(run_id, int(os.getenv("PSAT_RPC_STAGE_LIMIT", "1000")), stage=stage)
    token = _scope.set(scope)
    try:
        yield scope
        if scope.failure is not None:
            raise scope.failure  # A swallowed read failure cannot make this stage look successful.
    finally:
        _scope.reset(token)


def _remote(url: str) -> bool:
    base = os.getenv("ERPC_BASE_URL", "").rstrip("/")
    if base and (url == base or url.startswith(base + "/")):
        return True
    return urlsplit(url).hostname not in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _key(url: str) -> str:
    # All chains routed through one gateway share its capacity. No secrets in row keys.
    parts = urlsplit(url)
    prefix = parts.path.split("/evm/", 1)[0]
    identity = f"{parts.scheme}://{parts.netloc}{prefix}"
    return "rpc:gateway:" + hashlib.sha256(identity.encode()).hexdigest()[:40]


def _session():
    from db.models import SessionLocal

    return SessionLocal()


def _row(session, key: str):
    from db.models import OpsKv

    session.execute(insert(OpsKv).values(key=key, value={}).on_conflict_do_nothing(index_elements=["key"]))
    return session.execute(select(OpsKv).where(OpsKv.key == key).with_for_update()).scalar_one()


def _reserve(url: str, count: int, max_wait: float = 0) -> float:
    """Book ``count`` tokens when they are available within ``max_wait``; return the delay to sleep first.

    Booking ahead lets the bucket go negative, so later callers queue behind it instead of
    taking each refilled token before a waiting batch can accumulate enough. A delay above
    ``max_wait`` books nothing.
    """
    rate = float(os.getenv("PSAT_RPC_RPS", "5"))
    burst = int(os.getenv("PSAT_RPC_BURST", "10"))
    hourly_limit = int(os.getenv("PSAT_RPC_HOURLY_LIMIT", "20000"))
    run_limit = int(os.getenv("PSAT_RPC_RUN_LIMIT", "20000"))
    if not math.isfinite(rate) or rate <= 0 or burst < 1 or count > burst or hourly_limit < 1 or run_limit < 1:
        raise RpcBudgetExceeded("Invalid RPC allowance or batch larger than burst allowance")
    try:
        with _session() as session:
            row = _row(session, _key(url))
            now = session.execute(select(func.extract("epoch", func.clock_timestamp()))).scalar_one()
            now = float(now)
            state = dict(row.value)
            blocked = float(state.get("blocked_until", 0)) - now
            if blocked > 0:
                raise RpcBackpressure(f"RPC gateway cooling down for {blocked:.0f}s", blocked)
            window = float(state.get("window", now))
            used = int(state.get("used", 0)) if now - window < 3600 else 0
            if used + count > hourly_limit:
                raise RpcBackpressure("RPC gateway hourly allowance exhausted", max(1, window + 3600 - now))
            tokens = min(burst, float(state.get("tokens", burst)) + max(0, now - float(state.get("at", now))) * rate)
            delay = max(0.0, (count - tokens) / rate)
            if delay > max_wait:
                session.commit()
                return delay
            scope = current_scope()
            if scope is not None:
                run_key = "rpc:run:" + hashlib.sha256(scope.run_id.encode()).hexdigest()[:40]
                run = _row(session, run_key)
                total = int(run.value.get("calls", 0))
                if total + count > run_limit:
                    raise RpcBudgetExceeded("RPC run allowance exhausted")
                run.value = {"calls": total + count}
            state.update(tokens=tokens - count, at=now, used=used + count, window=window if used else now)
            row.value = state
            session.commit()
        return delay
    except (RpcBackpressure, RpcBudgetExceeded):
        raise
    except Exception as exc:
        raise RpcBackpressure("Shared RPC admission store unavailable") from exc


def admit(url: str, count: int) -> None:
    if count < 1 or not _remote(url):
        return
    scope = current_scope()
    if scope is not None:
        scope.charge(count)
    from services.clients.request_budget import charge_attempt

    for _ in range(count):
        charge_attempt("rpc")
    if os.getenv("PSAT_RPC_LIMITER_MODE", "postgres") == "off":
        return  # Explicit CLI/test escape hatch; production defaults to shared enforcement.
    max_wait = float(os.getenv("PSAT_RPC_ADMISSION_TIMEOUT_S", "30"))
    try:
        delay = _reserve(url, count, max_wait)
        if delay > max_wait:
            raise RpcBackpressure("RPC admission wait exceeded its deadline", delay)
        if delay:
            time.sleep(delay)
    except (RpcBackpressure, RpcBudgetExceeded) as exc:
        if scope is not None:
            scope.failure = exc
        raise


def retry_after_seconds(value: Any) -> float:
    if not isinstance(value, str):
        return 0
    try:
        number = float(value)
        return max(0, number) if math.isfinite(number) and number <= 86400 else 86400
    except ValueError:
        try:
            return max(0, (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return 0


def overload(url: str, retry_after: Any = None) -> float:
    scope = current_scope()
    delay = max(30, retry_after_seconds(retry_after))
    if scope is not None:
        scope.failure = RpcBackpressure("RPC provider overloaded", delay)
    if not _remote(url) or os.getenv("PSAT_RPC_LIMITER_MODE", "postgres") == "off":
        return delay
    try:
        with _session() as session:
            row = _row(session, _key(url))
            now = float(session.execute(select(func.extract("epoch", func.clock_timestamp()))).scalar_one())
            state = dict(row.value)
            # A batch of rejected replies is one overload episode, not 500 exponential bumps.
            strikes = int(state.get("strikes", 0)) if now - float(state.get("limited_at", 0)) < 600 else 0
            if now >= float(state.get("blocked_until", 0)):
                strikes = min(5, strikes + 1)
            delay = max(retry_after_seconds(retry_after), min(300, 30 * 2 ** max(0, strikes - 1)))
            state.update(
                blocked_until=max(float(state.get("blocked_until", 0)), now + delay),
                limited_at=now,
                strikes=strikes,
                # Keep booked-ahead debt; resetting to 0 would forgive it.
                tokens=min(0.0, float(state.get("tokens", 0))),
                at=now,
            )
            row.value = state
            session.commit()
            delay = state["blocked_until"] - now
            if scope is not None and isinstance(scope.failure, RpcBackpressure):
                scope.failure.retry_after = delay
            return delay
    except Exception as exc:
        raise RpcBackpressure("Cannot persist RPC overload cooldown") from exc


def error_kind(error: Any) -> str:
    """Keep infrastructure/unsupported errors separate from observed EVM rejection."""
    if not isinstance(error, dict):
        return "transport"
    codes: set[Any] = set()
    pending: list[Any] = [error]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key in ("code", "originalCode", "statusCode"):
                code = value.get(key)
                if isinstance(code, (str, int)):
                    codes.add(code)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    if codes & {429, -32005, "ErrEndpointCapacityExceeded", "ErrRateLimitRuleExceeded"}:
        return "capacity"
    if "ErrUpstreamsExhausted" in codes:
        return "transport"
    if codes & {-32601, "ErrEndpointUnsupported", "ErrUpstreamMethodIgnored"}:
        return "unsupported"
    message = str(error.get("message", "")).lower()
    if codes & {3, "ErrEndpointExecutionException"} or "execution reverted" in message:
        return "execution"
    return "transport"
