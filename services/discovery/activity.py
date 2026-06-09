"""On-chain activity scoring for contract inventory ranking.

Activity ranking can use address-level transaction history when an eRPC-backed
index exists. PSAT now runs in eRPC-only mode for on-chain calls, and plain
JSON-RPC does not expose an address transaction index. Until that index exists,
this stage assigns an explicit neutral activity score instead of querying an
explorer or guessing a timestamp.

Scoring
-------
- ``activity_score = 1 / (1 + days_since_last_tx / HALF_LIFE)``
  with HALF_LIFE = 30 days.  A contract active today scores ~1.0;
  one inactive for 30 days scores 0.5; one inactive for a year scores ~0.08.
- Missing or invalid chain ids raise instead of receiving a guessed score.

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

from utils.rpc import require_supported_chain_id

from .inventory_domain import _debug_log

logger = logging.getLogger(__name__)

# Half-life in days for the activity decay function.
_HALF_LIFE_DAYS = 30

# Score assigned when activity data is unavailable from a supported source.
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
    """Return the Unix timestamp of the most recent transaction, if available."""
    resolved_chain_id = require_supported_chain_id(chain_id=chain_id, context=f"activity scoring for {address}")
    message = (
        f"activity scoring for {address} on chain_id={resolved_chain_id} requires an eRPC-backed "
        "address transaction index; using neutral activity score because explorer txlist is disabled"
    )
    logger.warning("%s", message)
    _debug_log(debug, message)
    return None


def _activity_score(last_active_ts: float | None) -> float:
    """Compute an activity score in [0, 1] using half-life decay.

    Returns ``_NEUTRAL_SCORE`` when the timestamp is unknown on a supported
    chain.
    """
    if last_active_ts is None:
        return _NEUTRAL_SCORE
    now = datetime.now(timezone.utc).timestamp()
    days_since = max(0.0, (now - last_active_ts)) / 86400
    return 1.0 / (1.0 + days_since / _HALF_LIFE_DAYS)


def _blended_score(confidence: float, activity_score: float) -> float:
    return confidence * _W_CONFIDENCE + activity_score * _W_ACTIVITY


def _primary_chain_id(contract: dict[str, Any]) -> int:
    """Return the explicit chain id used for activity scoring."""
    raw_chain_id = contract.get("chain_id")
    try:
        return require_supported_chain_id(
            chain_id=raw_chain_id,
            context=f"activity scoring for {contract.get('address')}",
        )
    except RuntimeError as exc:
        raise RuntimeError(f"Activity scoring requires supported chain_id for {contract.get('address')}") from exc


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

    Uses a neutral activity score when an eRPC-backed address transaction index
    is unavailable. It does not query explorer APIs or guess a timestamp.
    """
    if not contracts:
        return contracts

    _debug_log(debug, f"Fetching on-chain activity for {len(contracts)} contract(s)")

    for contract in contracts:
        address = contract["address"]
        chain_id = _primary_chain_id(contract)

        last_ts = _fetch_last_active_ts(address, chain_id=chain_id, debug=debug)
        score = _activity_score(last_ts)

        contract["activity"] = {
            "last_active": (
                datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts is not None else None
            ),
            "score": round(score, 4),
        }

        confidence = contract.get("confidence", 0.5)
        contract["rank_score"] = round(_blended_score(confidence, score), 4)

    _debug_log(debug, "Activity enrichment complete")

    contracts.sort(
        key=lambda c: (
            -c.get("rank_score", 0),
            -c.get("confidence", 0),
            c.get("name") is None,
            str(c.get("name") or ""),
            _primary_chain_id(c),
            c["address"],
        ),
    )

    return contracts
