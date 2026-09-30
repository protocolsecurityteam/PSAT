"""Scan-floor resolution for resolution-time live event scans.

A contract emits no events before deployment, so flooring a live HyperSync scan at the creation block returns the same
logs without the genesis range that 429-storms upstream. ``resolve_scan_floor`` mirrors the indexer's ``_seed_block``
(``workers/event_log_indexer.py``) and never fails open to ``0``:

  1. the durable ``IndexedEventCursor`` (min ``last_indexed_block``, seeded at creation_block-1);
  2. the PG-cached ``getcontractcreation`` block, minus one;
  3. a live ``getcontractcreation`` call;
  4. ``None``: defer the scan.

Memoized per ``(address, chain_id)``. Resolved floors are kept for the process life. Deferrals re-read the cheap cursor
on every call when a session is passed (so a newly seeded cursor is picked up), while the Etherscan lookup and
session-less cursor read are throttled by a defer TTL. Size-capped.
"""

from __future__ import annotations

import logging
import os
import threading
import time

from services.clients.etherscan import get_contract_creation_block

logger = logging.getLogger(__name__)

# ``(floor, monotonic_ts)`` per (address, chain_id); see the module docstring for the defer/TTL policy. Oldest 25%
# evicted at the bound.
_FLOOR_CACHE: dict[tuple[str, int], tuple[int | None, float]] = {}
_FLOOR_LOCK = threading.Lock()
_FLOOR_CACHE_MAX = 4096
_FLOOR_DEFER_TTL_S = float(os.getenv("PSAT_SCAN_FLOOR_DEFER_TTL_S", "1800"))
_FLOOR_PRESSURE_NAME = "scan_floor"


def _evict_floor_if_needed() -> None:
    """Drop the oldest 25% at the bound (caller holds _FLOOR_LOCK)."""
    if len(_FLOOR_CACHE) < _FLOOR_CACHE_MAX:
        return
    cutoff = sorted(_FLOOR_CACHE.values(), key=lambda v: v[1])[len(_FLOOR_CACHE) // 4][1]
    for k in [k for k, v in _FLOOR_CACHE.items() if v[1] <= cutoff]:
        _FLOOR_CACHE.pop(k, None)


def _log_floor_pressure() -> None:
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message(_FLOOR_PRESSURE_NAME, len(_FLOOR_CACHE), _FLOOR_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


_ZERO_ADDRESS = "0x" + "0" * 40


def _is_address(address: str | None) -> bool:
    return (
        isinstance(address, str)
        and len(address) == 42
        and address.startswith("0x")
        and address.lower() != _ZERO_ADDRESS
    )


def _floor_from_cursor(address: str, chain_id: int, session: object | None) -> int | None:
    """Min ``last_indexed_block`` across the address's cursors, or ``None``.

    Never calls Etherscan; opens its own session when ``session`` is None.
    """
    try:
        from sqlalchemy import func, select

        from db.models import IndexedEventCursor, SessionLocal
    except Exception:
        return None

    def _query(sess) -> int | None:
        stmt = (
            select(func.min(IndexedEventCursor.last_indexed_block))
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(func.lower(IndexedEventCursor.event_address) == address.lower())
        )
        value = sess.execute(stmt).scalar()
        return int(value) if isinstance(value, int) else None

    try:
        if session is not None and hasattr(session, "execute"):
            return _query(session)
        with SessionLocal() as sess:
            return _query(sess)
    except Exception:
        return None


def resolve_scan_floor(
    address: str | None,
    chain_id: int,
    *,
    session: object | None = None,
) -> int | None:
    """The ``from_block`` for a live scan of *address*, or ``None`` to defer.

    Cursor floor, then creation block −1, then ``None``; never ``0``. See the module docstring for memoization.
    """
    if not _is_address(address):
        return None
    assert address is not None  # narrowed by _is_address
    key = (address.lower(), chain_id)
    now = time.monotonic()

    with _FLOOR_LOCK:
        cached = _FLOOR_CACHE.get(key)
    if cached is not None and cached[0] is not None:
        # Creation blocks are immutable.
        return cached[0]

    # Re-read the cheap cursor every call when a session is threaded (the deferred reconciler relies on it); throttle
    # Etherscan and session-less reads to _FLOOR_DEFER_TTL_S.
    within_defer_ttl = cached is not None and now - cached[1] < _FLOOR_DEFER_TTL_S
    session_live = session is not None and hasattr(session, "execute")
    if within_defer_ttl and not session_live:
        return None

    floor = _floor_from_cursor(key[0], chain_id, session)
    if floor is None and not within_defer_ttl:
        try:
            created = get_contract_creation_block(key[0], chain_id=chain_id)
        except Exception:
            created = None
        if isinstance(created, int) and created > 0:
            floor = created - 1

    with _FLOOR_LOCK:
        if floor is None and within_defer_ttl and cached is not None:
            # Keep the original timestamp so the TTL keeps counting down.
            _FLOOR_CACHE[key] = (None, cached[1])
        else:
            _evict_floor_if_needed()
            _FLOOR_CACHE[key] = (floor, now)
            _log_floor_pressure()
    return floor


def clear_scan_floor_cache() -> None:
    from utils.memory import reset_cache_pressure_state

    with _FLOOR_LOCK:
        _FLOOR_CACHE.clear()
    reset_cache_pressure_state(_FLOOR_PRESSURE_NAME)
