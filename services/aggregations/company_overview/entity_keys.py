"""Composite entity-key helpers (``"<chain>::<address>"``), byte-identical to
the frontend ``entityKey`` (site/src/surface/entityKey.js)."""

from __future__ import annotations


def _coalesce_chain(chain: str | None) -> str:
    """Chain token matching the frontend's ``coalesceChain`` (site/src/surface/
    entityKey.js): NULL/empty/``"mainnet"`` fold to ``"ethereum"`` (the
    NULL≡ethereum legacy-read convention), everything else lowercases as-is.

    Deliberately NOT :func:`utils.chains.canonical_chain` — that folds extra
    aliases (``eth``→``ethereum``, ``avax``→``avalanche``) the frontend key does
    not, so a token built here must mirror the JS exactly or the frontend's
    lookup can never match it. Contract ``chain`` strings are already stored
    canonical, so the two agree in practice.
    """
    c = str(chain or "").strip().lower()
    if not c or c == "mainnet":
        return "ethereum"
    return c


def _entity_key(chain: str | None, address: str | None) -> str:
    """Composite ``"<chain>::<address>"`` entity key, byte-identical to the
    frontend ``entityKey`` (site/src/surface/entityKey.js) so a backend-built
    functions map aligns with the frontend's per-(chain, address) lookups.
    ``"::"`` appears in neither a chain name nor a ``0x`` address, so the
    composite is collision-free."""
    return f"{_coalesce_chain(chain)}::{str(address or '').lower()}"


def _entity_addr(entity: str) -> str:
    """Bare lowercased address of a composite ``<chain>::<address>`` entity —
    the inverse of :func:`_entity_key`'s address half. A token without ``"::"``
    (a plain address) passes through unchanged."""
    return entity.rsplit("::", 1)[-1]


def _entity_chain(entity: str) -> str:
    """Coalesced chain token of a composite ``<chain>::<address>`` entity."""
    return entity.split("::", 1)[0] if "::" in entity else _coalesce_chain(None)
