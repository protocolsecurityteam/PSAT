"""On-chain activity scoring for contract inventory ranking.

Fetches the most recent transaction timestamp from Etherscan for each
discovered contract and computes a half-life decay score.  Contracts that
are actively used rank higher, ensuring the analysis pipeline targets the
most relevant addresses first.

Scoring
-------
- ``activity_score = 1 / (1 + days_since_last_tx / HALF_LIFE)``
  with HALF_LIFE = 30 days.  A contract active today scores ~1.0;
  one inactive for 30 days scores 0.5; one inactive for a year scores ~0.08.
- When activity data is unavailable (unsupported chain, Etherscan error),
  the contract receives a neutral score of 0.5 so it is neither penalised
  nor boosted.

Blended ranking
---------------
``rank_score = confidence * 0.35 + activity_score * 0.65``

This keeps evidence-quality (confidence) as a factor while letting on-chain
activity dominate the ordering so the most-used contracts surface first.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from utils import etherscan
from utils.logging import record_degraded

from .inventory_domain import CHAIN_IDS, CHAIN_SORT_ORDER, _debug_log

logger = logging.getLogger(__name__)

# Half-life in days for the activity decay function.
_HALF_LIFE_DAYS = 30

# Score assigned when activity data is unavailable (e.g. unsupported chain).
_NEUTRAL_SCORE = 0.5

# Blended ranking weights.
_W_CONFIDENCE = 0.35
_W_ACTIVITY = 0.65


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fetch_last_active_ts(
    address: str,
    chain_id: int,
    debug: bool = False,
) -> tuple[float | None, BaseException | None]:
    """Return ``(timestamp, exc)`` for the most recent transaction.

    ``exc`` is the explorer failure and is ``None`` when the call succeeded — a
    miss and an outage both yield a ``None`` timestamp, and only the caller can
    tell them apart with this second value.
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
    """Compute an activity score in [0, 1] using half-life decay.

    Returns ``_NEUTRAL_SCORE`` when the timestamp is unknown so that
    contracts on unsupported chains are neither penalised nor boosted.
    """
    if last_active_ts is None:
        return _NEUTRAL_SCORE
    now = datetime.now(timezone.utc).timestamp()
    days_since = max(0.0, (now - last_active_ts)) / 86400
    return 1.0 / (1.0 + days_since / _HALF_LIFE_DAYS)


def _primary_chain(contract: dict[str, Any]) -> str:
    """Return the first chain from a contract's chains list, or 'unknown'."""
    chains = contract.get("chains", [])
    return chains[0] if chains else "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enrich_with_activity(
    contracts: list[dict[str, Any]],
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Add activity metrics to each contract and re-sort by blended rank score.

    Mutates the contract dicts in-place (adds ``activity`` and ``rank_score``
    keys) and returns the list sorted by ``rank_score`` descending.

    Rate-limited centrally by ``utils.etherscan``.
    """
    if not contracts:
        return contracts

    _debug_log(debug, f"Fetching on-chain activity for {len(contracts)} contract(s)")

    # Explorer failures are counted and reported once per pass rather than per
    # contract: an outage hits every address in the inventory, and the fact
    # worth surfacing is how much of the ranking ran on the neutral score.
    # Only the last exception is held — keeping one per contract would pin every
    # failed call's traceback frames (and the response bodies inside them) for
    # the whole pass.
    fetch_failures = 0
    last_failure: BaseException | None = None
    failure_types: set[str] = set()

    for contract in contracts:
        address = contract["address"]
        chain = _primary_chain(contract)
        if chain not in CHAIN_IDS:
            # Unregistered/unknown chain: we can't query the right explorer, and
            # defaulting to mainnet would rank this contract by an unrelated
            # address's mainnet activity (inv. 12). Skip the fetch and floor it.
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
        # The last failure carries the provider's own error text into the
        # StageError; the count says how much of the ranking it moved.
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
