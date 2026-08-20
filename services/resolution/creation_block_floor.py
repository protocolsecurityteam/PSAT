"""Scan-floor resolution for resolution-time live event scans.

A live HyperSync fallback that scans an event address from genesis wastes the
whole pre-deployment range and 429-storms upstream on high-volume contracts. A
contract emits no events before it exists, so flooring the scan at its creation
block returns the identical log set; deferring when the floor is unknown returns
the identical member set once the durable index warms.

``resolve_scan_floor`` is the single floor-or-defer helper. It mirrors the
durable indexer's ``_seed_block`` discipline (``workers/event_log_indexer.py``):
a floor is resolved from non-rate-limited sources in preference order and, when
no floor can be determined, ``None`` is returned so the caller DEFERS rather than
scanning from genesis. It NEVER fails open to ``0`` — a single transient
Etherscan failure must not pin a scan to a full-chain backfill.

Preference order (cheapest / least-rate-limited first):
  1. the durable ``IndexedEventCursor`` (MIN ``last_indexed_block`` across the
     address's cursors) — a pure PG read, never rate-limited. The indexer seeds
     these at creation_block-1, so the cursor IS the deploy-block floor.
  2. the PG-cached, immutable ``getcontractcreation`` creation block (a cache
     HIT issues no Etherscan call); ``creation_block - 1`` to match the cursor.
  3. a live ``getcontractcreation`` Etherscan call (the cache-miss case of #2).
  4. ``None`` — DEFER. The floor is unknown; the caller must skip the live scan.

The lookup is memoized per process keyed on ``(address, chain_id)`` so a multi-key
fold or sibling functions don't issue N duplicate lookups. A resolved (immutable)
creation-block floor is held for the process life. A DEFER (``None``) re-reads the
durable cursor on every call when the caller threads a live session — a cheap,
never-rate-limited PG read, so a floor the indexer seeds mid-run self-heals at once
— while the rate-limited Etherscan creation-block re-lookup (and the session-less
cursor read, which would open a fresh ``SessionLocal``) is throttled to a defer TTL
so a still-deferring address can't re-probe upstream on every call within a run. The
memo is size-capped, evicting the oldest entries at the bound.
"""

from __future__ import annotations

import logging
import os
import threading
import time

from services.clients.etherscan import get_contract_creation_block

logger = logging.getLogger(__name__)

# Per-process memo of resolved floors, ``(floor, monotonic_ts)`` per (address,
# chain_id). A resolved int floor is immutable → served for the process life. A DEFER
# (``None``) is provisional — the durable cursor or creation-block lookup may succeed
# once the index backfills. The cheap cursor is re-read on every call when a live
# session is threaded; only the rate-limited Etherscan re-lookup (and the session-less
# cursor read) is throttled to this TTL, so a still-deferring address can't re-probe
# upstream on every call while a freshly-seeded cursor is still picked up at once.
# Size-capped; oldest 25% evicted at the bound.
_FLOOR_CACHE: dict[tuple[str, int], tuple[int | None, float]] = {}
_FLOOR_LOCK = threading.Lock()
_FLOOR_CACHE_MAX = 4096
_FLOOR_DEFER_TTL_S = float(os.getenv("PSAT_SCAN_FLOOR_DEFER_TTL_S", "1800"))
_FLOOR_PRESSURE_NAME = "scan_floor"


def _evict_floor_if_needed() -> None:
    """Drop the oldest 25% of _FLOOR_CACHE entries by insertion time when the bound is
    reached (caller holds _FLOOR_LOCK)."""
    if len(_FLOOR_CACHE) < _FLOOR_CACHE_MAX:
        return
    cutoff = sorted(_FLOOR_CACHE.values(), key=lambda v: v[1])[len(_FLOOR_CACHE) // 4][1]
    for k in [k for k, v in _FLOOR_CACHE.items() if v[1] <= cutoff]:
        _FLOOR_CACHE.pop(k, None)


def _log_floor_pressure() -> None:
    """Log when _FLOOR_CACHE crosses 50/75/95% of the bound (caller holds _FLOOR_LOCK)."""
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
    """MIN ``last_indexed_block`` across the address's durable cursors, or
    ``None`` when no cursor row exists / the table can't be read. Pure PG read;
    never issues an Etherscan call. ``session`` may be a live SQLAlchemy Session
    (cross-contract inlining path) or ``None`` (we open our own)."""
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
    """The ``from_block`` a live scan of *address* should start at, or ``None``
    when no floor can be determined and the caller must DEFER the scan.

    Resolution order: durable cursor floor → cached/looked-up creation block −1 →
    ``None``. Never returns ``0`` as a fail-open: a missing/zero address or an
    unresolvable creation block defers rather than scanning from genesis. The
    result is memoized per ``(address, chain_id)``; a deferring ``None`` re-reads
    the cheap durable cursor on every call (when a live session is threaded) while
    throttling the rate-limited Etherscan re-lookup — see the module docstring."""
    if not _is_address(address):
        return None
    assert address is not None  # narrowed by _is_address
    key = (address.lower(), chain_id)
    now = time.monotonic()

    with _FLOOR_LOCK:
        cached = _FLOOR_CACHE.get(key)
    if cached is not None and cached[0] is not None:
        # A resolved creation-block floor is immutable — serve it for process life.
        return cached[0]

    # ``cached`` is absent (first lookup) or a DEFER (None floor). Re-read the
    # durable cursor every call when the caller threads a live session: it is a
    # cheap, never-rate-limited PG read, so a cursor the indexer seeds mid-run is
    # picked up at once (the deferred-reconciler convergence depends on it). The
    # rate-limited Etherscan creation-block lookup — and the session-less cursor
    # read, which would open a fresh SessionLocal (the Neon-checkout churn this
    # removes) — are throttled to _FLOOR_DEFER_TTL_S so a still-deferring address
    # can't re-probe upstream on every call within a run.
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
            # Still deferring inside the throttle window — keep the ORIGINAL defer
            # timestamp so the TTL counts down to the next Etherscan retry rather
            # than resetting on each cheap cursor re-check.
            _FLOOR_CACHE[key] = (None, cached[1])
        else:
            _evict_floor_if_needed()
            _FLOOR_CACHE[key] = (floor, now)
            _log_floor_pressure()
    return floor


def clear_scan_floor_cache() -> None:
    """Test helper — drop the per-process floor memo."""
    from utils.memory import reset_cache_pressure_state

    with _FLOOR_LOCK:
        _FLOOR_CACHE.clear()
    reset_cache_pressure_state(_FLOOR_PRESSURE_NAME)
