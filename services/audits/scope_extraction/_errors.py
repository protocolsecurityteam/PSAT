"""Exception types raised during scope extraction."""

from __future__ import annotations


class ScopeExtractionError(RuntimeError):
    """Base class for recoverable failures during scope extraction."""


class LLMUnavailableError(ScopeExtractionError):
    """LLM call failed or returned unparseable output.

    ``failure_kind`` distinguishes an upstream API outage (``"api"`` —
    402/429/connection error, the etherfi 55→4 collapse signature) from a
    parser-side failure (``"parse"`` — the model answered but the output
    couldn't be decoded). Both currently fall back to regex, so without this
    discriminator the two are conflated in the logs; it rides into ``extra``
    at the call site so the no-match rate can be split by cause.
    """

    def __init__(self, *args: object, failure_kind: str = "api") -> None:
        super().__init__(*args)
        self.failure_kind = failure_kind
