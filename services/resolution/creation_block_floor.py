"""Creation-block floor for resolution-time live event scans.

A live HyperSync fallback that scans an event address from genesis wastes the
whole pre-deployment range and 429-storms upstream on high-volume contracts. A
contract emits no events before it exists, so flooring the scan at its creation
block returns the identical log set. This mirrors the durable indexer's
``_seed_block`` discipline (``workers/event_log_indexer.py``); the floor here is
fail-open: a creation-block lookup failure returns ``0`` so no logs are dropped.

The lookup hits Etherscan ``getcontractcreation`` (PG-cached but a call), so it
is memoized per process keyed on ``(address, chain_id)`` to keep a multi-key
fold or sibling functions from issuing N duplicate lookups.
"""

from __future__ import annotations

import threading

from utils.etherscan import get_contract_creation_block

_FLOOR_CACHE: dict[tuple[str, int], int] = {}
_FLOOR_LOCK = threading.Lock()

_ZERO_ADDRESS = "0x" + "0" * 40


def creation_block_floor(address: str | None, chain_id: int) -> int:
    """The ``from_block`` a live scan of *address* should start at: one below its
    creation block (matching ``_seed_block``), or ``0`` when the address is
    missing/zero or its creation block can't be determined (fail open)."""
    if not isinstance(address, str) or len(address) != 42 or not address.startswith("0x"):
        return 0
    key = (address.lower(), chain_id)
    if key[0] == _ZERO_ADDRESS:
        return 0
    with _FLOOR_LOCK:
        cached = _FLOOR_CACHE.get(key)
    if cached is not None:
        return cached
    floor = 0
    try:
        created = get_contract_creation_block(key[0], chain_id=chain_id)
        if isinstance(created, int) and created > 0:
            floor = created - 1
    except Exception:
        floor = 0
    with _FLOOR_LOCK:
        _FLOOR_CACHE[key] = floor
    return floor
