"""On-chain activity scoring for contract inventory ranking.

``activity_score = 1 / (1 + days_since_last_tx / 30)``: ~1.0 active today, 0.5 after 30 days, ~0.08 after a year.
Missing data (unsupported chain, Etherscan error) scores a neutral 0.5.

``rank_score = confidence * 0.35 + activity_score * 0.65``, so activity dominates while evidence quality still counts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from services.clients import etherscan
from utils.logging import record_degraded

from .inventory_domain import CHAIN_IDS, CHAIN_SORT_ORDER, _debug_log

logger = logging.getLogger(__name__)

_HALF_LIFE_DAYS = 30

_NEUTRAL_SCORE = 0.5

_W_CONFIDENCE = 0.35
_W_ACTIVITY = 0.65


def _fetch_last_active_ts(
    address: str,
    chain_id: int,
    debug: bool = False,
) -> tuple[float | None, BaseException | None]:
    """``(timestamp, exc)`` for the most recent tx; ``exc`` distinguishes an outage from a miss (both give a ``None``
    timestamp).
    """
    try:
        data = etherscan.get(
            "account",
            "txlist",
            chain_id=chain_id,
            address=address,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=1,
            sort="desc",
        )
        results = data.get("result", [])
        if isinstance(results, list) and results:
            ts = results[0].get("timeStamp")
            if ts:
                return float(ts), None
    except Exception as exc:
        _debug_log(debug, f"Activity fetch failed for {address}: {exc}")
        return None, exc
    return None, None


def _activity_score(last_active_ts: float | None) -> float:
    """Half-life activity score in [0, 1]; ``_NEUTRAL_SCORE`` when unknown."""
    if last_active_ts is None:
        return _NEUTRAL_SCORE
    now = datetime.now(timezone.utc).timestamp()
    days_since = max(0.0, (now - last_active_ts)) / 86400
    return 1.0 / (1.0 + days_since / _HALF_LIFE_DAYS)


def _primary_chain(contract: dict[str, Any]) -> str:
    chains = contract.get("chains", [])
    return chains[0] if chains else "unknown"


def enrich_with_activity(
    contracts: list[dict[str, Any]],
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Add ``activity`` and ``rank_score`` to each contract (in place) and return them sorted by ``rank_score``
    descending. Rate-limited by ``services.clients.etherscan``.
    """
    if not contracts:
        return contracts

    _debug_log(debug, f"Fetching on-chain activity for {len(contracts)} contract(s)")

    # Counted once per pass (an outage hits every address), keeping only the last exception to avoid pinning tracebacks.
    fetch_failures = 0
    last_failure: BaseException | None = None
    failure_types: set[str] = set()

    for contract in contracts:
        address = contract["address"]
        chain = _primary_chain(contract)
        if chain not in CHAIN_IDS:
            # Unknown chain: can't query the right explorer, and mainnet would rank it by an unrelated address's
            # activity.
            last_ts = None
            score = 0.0
        else:
            last_ts, exc = _fetch_last_active_ts(address, chain_id=CHAIN_IDS[chain], debug=debug)
            if exc is not None:
                fetch_failures += 1
                last_failure = exc
                failure_types.add(type(exc).__name__)
            score = _activity_score(last_ts)

        contract["activity"] = {
            "last_active": (
                datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts is not None else None
            ),
            "score": round(score, 4),
        }

        confidence = contract.get("confidence", 0.5)
        contract["rank_score"] = round(
            confidence * _W_CONFIDENCE + score * _W_ACTIVITY,
            4,
        )

    if last_failure is not None:
        # The last error carries the provider's text; the count says how much of the ranking it affected.
        record_degraded(
            phase="activity_enrichment",
            exc=last_failure,
            context={"failed": fetch_failures, "contracts": len(contracts)},
        )
        logger.warning(
            "Activity lookup failed for %d of %d contract(s); those rank on the neutral score",
            fetch_failures,
            len(contracts),
            extra={
                "failed": fetch_failures,
                "contracts": len(contracts),
                "exc_types": sorted(failure_types),
            },
        )

    _debug_log(debug, "Activity enrichment complete")

    contracts.sort(
        key=lambda c: (
            -c.get("rank_score", 0),
            -c.get("confidence", 0),
            c.get("name") is None,
            str(c.get("name") or ""),
            CHAIN_SORT_ORDER.get(_primary_chain(c), 50),
            c["address"],
        ),
    )

    return contracts
