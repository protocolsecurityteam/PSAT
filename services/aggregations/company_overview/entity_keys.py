"""``"<chain>::<address>"`` entity keys, byte-identical to the frontend ``entityKey``
(site/src/surface/entityKey.js).
"""

from __future__ import annotations

import functools


def _coalesce_chain(chain: str | None) -> str:
    """Mirrors the frontend ``coalesceChain``: NULL/empty/``mainnet`` -> ``ethereum``, else lowercase.

    Deliberately not ``canonical_chain``, which folds aliases the frontend doesn't.
    """
    c = str(chain or "").strip().lower()
    if not c or c == "mainnet":
        return "ethereum"
    return c


def _entity_key(chain: str | None, address: str | None) -> str:
    """``::`` appears in neither chain names nor addresses, so the key is collision-free."""
    return f"{_coalesce_chain(chain)}::{str(address or '').lower()}"


@functools.lru_cache(maxsize=64)
def _entity_prefix(chain: str | None) -> str:
    """``_entity_key(chain, "")``, cached for loops that key many addresses on one chain."""
    return _entity_key(chain, "")


def _entity_addr(entity: str) -> str:
    """Bare lowercased address; plain addresses pass through."""
    return entity.rsplit("::", 1)[-1]


def _entity_chain(entity: str) -> str:
    return entity.split("::", 1)[0] if "::" in entity else _coalesce_chain(None)
