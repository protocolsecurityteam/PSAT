"""TVL serialization with collection completeness and observation time."""

from __future__ import annotations

from typing import Any

from schemas.api_responses import TvlSummary


def snapshot_payload(snapshot: Any | None) -> TvlSummary:
    def number(name: str) -> float | None:
        value = getattr(snapshot, name, None)
        return float(value) if value is not None else None

    def timestamp(name: str) -> str | None:
        value = getattr(snapshot, name, None)
        return value.isoformat() if value is not None else None

    return {
        "total_usd": number("total_usd"),
        "defillama_tvl": number("defillama_tvl"),
        "source": getattr(snapshot, "source", None),
        "timestamp": timestamp("timestamp"),
        "holdings_observed_at": timestamp("holdings_observed_at"),
        "holdings_partial": getattr(snapshot, "holdings_partial", None),
        "valuation_partial": getattr(snapshot, "valuation_partial", None),
    }
