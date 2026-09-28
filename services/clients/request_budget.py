"""Bound physical provider attempts in one collection pass, including retries."""

import time
from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


class RequestBudgetExceeded(RuntimeError):
    pass


@dataclass
class RequestBudget:
    limit: int = 250
    seconds: float = 120
    started: float = field(default_factory=time.monotonic)
    attempts: Counter = field(default_factory=Counter)

    def check(self) -> None:
        if sum(self.attempts.values()) >= self.limit or time.monotonic() - self.started >= self.seconds:
            raise RequestBudgetExceeded("balance collection request/time budget exhausted")

    def take(self, provider: str) -> None:
        self.check()
        self.attempts[provider] += 1


_current: ContextVar[RequestBudget | None] = ContextVar("balance_request_budget", default=None)


def charge_attempt(provider: str) -> None:
    budget = _current.get()
    if budget is not None:
        budget.take(provider)


@contextmanager
def request_budget(budget: RequestBudget):
    token = _current.set(budget)
    try:
        yield budget
    finally:
        _current.reset(token)
