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

from datetime import datetime, timezone
from typing import Any

from utils import etherscan

from .inventory_domain import CHAIN_IDS, CHAIN_SORT_ORDER, _debug_log

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
) -> float | None:
    """Return the Unix timestamp of the most recent transaction, or None."""
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
                return float(ts)
    except Exception as exc:
        _debug_log(debug, f"Activity fetch failed for {address}: {exc}")
    return None


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

    for contract in contracts:
        address = contract["address"]
        chain = _primary_chain(contract)
        chain_id = CHAIN_IDS.get(chain, CHAIN_IDS["ethereum"])

        last_ts = _fetch_last_active_ts(address, chain_id=chain_id, debug=debug)
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
