from __future__ import annotations


class ScopeExtractionError(RuntimeError): ...


class LLMUnavailableError(ScopeExtractionError):
    """LLM call failed or returned unparseable output.

    ``failure_kind`` separates ``"api"`` (402/429/connection) from ``"parse"``; both fall back to regex, so without it
    they're conflated.
    """

    def __init__(self, *args: object, failure_kind: str = "api") -> None:
        super().__init__(*args)
        self.failure_kind = failure_kind
