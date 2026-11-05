"""Bounded, server-side TypeSafe transport. Credentials never enter saved results."""

from __future__ import annotations

import re
from typing import Any

import requests

ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-1.14.0"


class JevError(RuntimeError):
    pass


class JevBudgetExceeded(JevError):
    pass


def validate_model(model: str) -> None:
    if not isinstance(model, str) or not re.fullmatch(r"jev-\d+\.\d+\.\d+", model):
        raise ValueError("use a versioned Jev model, not a moving alias")


class JevClient:
    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_MODEL,
        max_requests: int = 8,
        max_request_bytes: int | None = None,
        long_context: bool = False,
        timeout: float = 45,
        session: Any = None,
    ):
        if not api_key:
            raise ValueError("TYPESAFE_API_KEY or JEV_API_KEY is required for live requests")
        validate_model(model)
        if type(long_context) is not bool:
            raise ValueError("long_context must be a boolean")
        if max_request_bytes is None:
            max_request_bytes = 1_000_000 if long_context else 100_000
        self.long_context = long_context
        if max_requests < 0 or max_request_bytes <= 0 or timeout <= 0:
            raise ValueError("invalid Jev request limits")
        self.model, self.max_requests, self.max_request_bytes = model, max_requests, max_request_bytes
        self.timeout, self.sent = timeout, 0
        self._api_key, self._session = api_key, session or requests.Session()

    def ask(self, state: dict, questions: dict) -> dict:
        import json

        if self.sent >= self.max_requests:
            raise JevBudgetExceeded("Jev request budget exhausted")
        body = json.dumps(
            {"model": self.model, "state": state, "questions": questions}, ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(body) > self.max_request_bytes:
            raise JevBudgetExceeded("Jev context exceeds request size budget; no silent truncation")
        self.sent += 1  # A timeout can still have reached the service. It consumes the budget.
        try:
            response = self._session.post(
                ENDPOINT,
                data=body,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    **({"TypeSafe-Danger-Zone-Long-Context": "true"} if self.long_context else {}),
                },
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise JevError("Jev transport failed; no automatic retry") from None
        if response.status_code == 400:
            try:
                detail = response.json().get("detail", {})
            except (ValueError, AttributeError):
                detail = {}
            if isinstance(detail, dict) and detail.get("error_type") == "max_tokens_exceeded":
                raise JevBudgetExceeded("Jev model context limit exceeded; no answer accepted")
        if response.status_code != 200:
            raise JevError(f"Jev HTTP {response.status_code}; no answer accepted")
        try:
            result = response.json()
        except ValueError:
            raise JevError("Jev returned invalid JSON") from None
        if not isinstance(result, dict) or result.get("model") != self.model:
            raise JevError("Jev response did not identify the requested pinned model")
        return result
