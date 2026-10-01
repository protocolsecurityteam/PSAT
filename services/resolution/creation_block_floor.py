"""Scan-floor resolution for resolution-time live event scans.

A contract emits no events before deployment, so flooring a live HyperSync scan at the creation block returns the same
logs without the genesis range that 429-storms upstream. ``resolve_scan_floor`` never fails open to ``0``:

  1. the address's witnessed floor: its ``address_floor_witnesses`` row, else the minimum ``first_indexed_block`` of
     its ``creation_block_minus_one`` cursors;
  2. a witness that was attempted and did not prove the floor: ``None`` (defer). Etherscan's creation block is the
     number such a witness rejected, so it is never consulted;
  3. never witnessed: the PG-cached, then live, ``getcontractcreation`` block, minus one;
  4. ``None``: defer the scan.

A cursor's ``last_indexed_block`` is its frontier, never a floor.

Memoized per ``(address, chain_id)``. Witnessed floors are kept for the process life. A cached Etherscan floor re-reads
the cheap witness on every call, so a newly recorded witness (proven or refuted) wins. Deferrals re-read the witness on
every call when a session is passed, while the Etherscan lookup and session-less reads are throttled by a defer TTL.
Size-capped.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Final, Literal

from services.clients.etherscan import get_contract_creation_block

logger = logging.getLogger(__name__)

# ``(floor, floor_basis, monotonic_ts)`` per (address, chain_id); see the module docstring for the defer/TTL policy.
# Oldest 25% evicted at the bound.
_FLOOR_CACHE: dict[tuple[str, int], tuple[int | None, str | None, float]] = {}
_FLOOR_LOCK = threading.Lock()
_FLOOR_CACHE_MAX = 4096
_FLOOR_DEFER_TTL_S = float(os.getenv("PSAT_SCAN_FLOOR_DEFER_TTL_S", "1800"))
_FLOOR_PRESSURE_NAME = "scan_floor"

# ``floor_basis`` values recorded on live-scan trace steps.
FLOOR_BASIS_WITNESS = "cursor_first_indexed"
FLOOR_BASIS_CREATION_LOOKUP = "creation_block_lookup"
FLOOR_BASIS_TAIL = "durable_frontier_tail"


def _evict_floor_if_needed() -> None:
    """Drop the oldest 25% at the bound (caller holds _FLOOR_LOCK)."""
    if len(_FLOOR_CACHE) < _FLOOR_CACHE_MAX:
        return
    cutoff = sorted(_FLOOR_CACHE.values(), key=lambda v: v[2])[len(_FLOOR_CACHE) // 4][2]
    for k in [k for k, v in _FLOOR_CACHE.items() if v[2] <= cutoff]:
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


_DEFER: Final = "defer"


def _floor_from_cursor(address: str, chain_id: int, session: object | None) -> int | Literal["defer"] | None:
    """The address's witnessed deploy floor: an int when proven, ``"defer"`` when a witness was attempted and did not
    prove it (or the witness can't be read), ``None`` when none was ever attempted.

    Never calls Etherscan; opens its own session when ``session`` is None.
    """
    try:
        from sqlalchemy import func, select

        from db.floor_witnesses import read_floor_witness
        from db.models import (
            CURSOR_BASIS_NOT_DETERMINED,
            FIRST_INDEXED_BASIS_CREATION,
            IndexedEventCursor,
            SessionLocal,
        )
    except Exception:
        return _DEFER

    def _query(sess) -> int | Literal["defer"] | None:
        witness = read_floor_witness(sess, chain_id=chain_id, address=address)
        if witness is not None:
            block, basis = witness
            return block if basis == FIRST_INDEXED_BASIS_CREATION and block is not None else _DEFER
        proven, attempted = sess.execute(
            select(
                func.min(IndexedEventCursor.first_indexed_block).filter(
                    IndexedEventCursor.first_indexed_block_basis == FIRST_INDEXED_BASIS_CREATION
                ),
                func.count().filter(IndexedEventCursor.first_indexed_block_basis == CURSOR_BASIS_NOT_DETERMINED),
            )
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(func.lower(IndexedEventCursor.event_address) == address.lower())
        ).one()
        if isinstance(proven, int):
            return int(proven)
        return _DEFER if attempted else None

    try:
        if session is not None and hasattr(session, "execute"):
            return _query(session)
        with SessionLocal() as sess:
            return _query(sess)
    except Exception:
        return _DEFER


def resolve_scan_floor(
    address: str | None,
    chain_id: int,
    *,
    session: object | None = None,
) -> int | None:
    """The ``from_block`` for a live scan of *address*, or ``None`` to defer."""
    return resolve_scan_floor_with_basis(address, chain_id, session=session)[0]


def resolve_scan_floor_with_basis(
    address: str | None,
    chain_id: int,
    *,
    session: object | None = None,
) -> tuple[int | None, str | None]:
    """``(from_block, floor_basis)`` for a live scan of *address*; ``(None, None)`` defers.

    ``floor_basis`` is ``cursor_first_indexed`` for a witnessed floor, ``creation_block_lookup`` for Etherscan. See the
    module docstring for precedence and memoization.
    """
    if not _is_address(address):
        return None, None
    assert address is not None  # narrowed by _is_address
    key = (address.lower(), chain_id)
    now = time.monotonic()

    session_live = session is not None and hasattr(session, "execute")
    with _FLOOR_LOCK:
        cached = _FLOOR_CACHE.get(key)
    if cached is not None and cached[0] is not None:
        if cached[1] == FLOOR_BASIS_WITNESS:
            return cached[0], cached[1]
        # An Etherscan floor stands only until a witness exists: a witness recorded since (proven or refuted) wins.
        witnessed_now = _floor_from_cursor(key[0], chain_id, session)
        if witnessed_now is None:
            return cached[0], cached[1]
        resolved = (witnessed_now, FLOOR_BASIS_WITNESS) if isinstance(witnessed_now, int) else (None, None)
        with _FLOOR_LOCK:
            _FLOOR_CACHE[key] = (resolved[0], resolved[1], now)
        return resolved

    # Re-read the cheap witness every call when a session is threaded (the deferred reconciler relies on it); throttle
    # Etherscan and session-less reads to _FLOOR_DEFER_TTL_S.
    within_defer_ttl = cached is not None and now - cached[2] < _FLOOR_DEFER_TTL_S
    if within_defer_ttl and not session_live:
        return None, None

    floor: int | None = None
    basis: str | None = None
    witnessed = _floor_from_cursor(key[0], chain_id, session)
    if isinstance(witnessed, int):
        floor, basis = witnessed, FLOOR_BASIS_WITNESS
    elif witnessed is None and not within_defer_ttl:
        try:
            created = get_contract_creation_block(key[0], chain_id=chain_id)
        except Exception:
            created = None
        if isinstance(created, int) and created > 0:
            floor, basis = created - 1, FLOOR_BASIS_CREATION_LOOKUP

    with _FLOOR_LOCK:
        if floor is None and within_defer_ttl and cached is not None:
            # Keep the original timestamp so the TTL keeps counting down.
            _FLOOR_CACHE[key] = (None, None, cached[2])
        else:
            _evict_floor_if_needed()
            _FLOOR_CACHE[key] = (floor, basis, now)
            _log_floor_pressure()
    return floor, basis


def clear_scan_floor_cache() -> None:
    from utils.memory import reset_cache_pressure_state

    with _FLOOR_LOCK:
        _FLOOR_CACHE.clear()
    reset_cache_pressure_state(_FLOOR_PRESSURE_NAME)
