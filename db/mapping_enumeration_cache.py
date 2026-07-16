"""Cross-process cache for mapping_enumerator hypersync scans.

A row per ``(chain, address, specs_hash)`` holding the
``EnumerationResult`` from ``services.resolution.mapping_enumerator``.
Workers running the resolution and policy stages on the same job no
longer re-pay the 60s hypersync pagination — they hit this row instead.

The module is deliberately small and stateless — every entry point
opens its own short-lived ``SessionLocal()`` so callers (the
mapping_enumerator sync wrapper) don't have to plumb a session through
the resolution graph. Reads and writes commit independently; partial
results are visible to other processes immediately.

Cache freshness is wall-clock TTL (env
``PSAT_MAPPING_ENUMERATION_CACHE_TTL_S``, default 1800s) — same default
as the legacy in-process cache, so behaviour is unchanged for the
single-process case while the cross-process case stops re-scanning.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.models import MappingEnumerationCache, SessionLocal
from utils.chains import chain_cache_token

logger = logging.getLogger(__name__)


def _ttl_seconds() -> float:
    return float(os.getenv("PSAT_MAPPING_ENUMERATION_CACHE_TTL_S", "1800"))


def is_enabled() -> bool:
    """Env-gated kill switch. Defaults ON; tests opt out via
    ``PSAT_MAPPING_ENUMERATION_DB_CACHE=0`` when they want to drive
    the in-process layer in isolation.
    """
    return os.getenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "1").lower() in ("1", "true", "yes")


def specs_fingerprint(
    writer_specs: list[dict[str, Any]],
    *,
    value_predicate: dict[str, Any] | None = None,
) -> str:
    """Stable SHA-256 of the normalized writer-spec list.

    Only the fields that affect the enumeration semantics participate:
    event_signature, mapping_name, direction, key_position, and the
    sorted set of indexed_positions. A change to any of these yields a
    fresh cache row instead of silently returning a stale enumeration
    keyed off prior config.

    D.1+: ``value_position`` and the ``value_predicate`` (op +
    rhs_values + value_type) are folded into the hash too so that an
    "set ev → latest value per key, filter by op" pass can't return a
    cache row populated by a "set ev → latest value, filter by
    different op" pass on the same address. ``value_position=None``
    and ``value_predicate=None`` collapse back to the legacy
    fingerprint (the JSON keys are just absent in the canonical form).
    """
    legacy_specs = [
        {
            "event_signature": s["event_signature"],
            "mapping_name": s["mapping_name"],
            "direction": s["direction"],
            "key_position": s["key_position"],
            "indexed_positions": sorted(s.get("indexed_positions") or []),
        }
        for s in writer_specs
    ]
    has_new_fields = value_predicate is not None or any(s.get("value_position") is not None for s in writer_specs)
    if not has_new_fields:
        # Legacy fingerprint — must remain byte-identical to pre-D.1
        # output so existing cache rows stay valid after the upgrade.
        canonical = json.dumps(legacy_specs, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    extended_specs = []
    for legacy, original in zip(legacy_specs, writer_specs, strict=True):
        out = dict(legacy)
        if original.get("value_position") is not None:
            out["value_position"] = int(original["value_position"])
        extended_specs.append(out)
    payload: dict[str, Any] = {"specs": extended_specs}
    if value_predicate is not None:
        payload["value_predicate"] = {
            "op": value_predicate.get("op"),
            "rhs_values": list(value_predicate.get("rhs_values") or []),
            "value_type": value_predicate.get("value_type"),
            "mask": value_predicate.get("mask"),
        }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def find_fresh(
    *,
    chain: str | None,
    address: str,
    specs_hash: str,
    ttl_s: float | None = None,
) -> dict[str, Any] | None:
    """Return the cached EnumerationResult if a row exists and is fresher
    than the TTL; ``None`` otherwise. The caller treats ``None`` as a
    miss and runs the actual hypersync scan.

    A stale row is intentionally *not* returned as a degraded fallback —
    the caller may want partial data, but baking that into the cache
    layer would hide the policy decision. If a future caller wants a
    "stale-OK" mode, expose it via a separate ``find_any`` rather than
    re-purposing this entry point.
    """
    chain_norm = chain_cache_token(chain)
    addr_norm = address.lower()
    eff_ttl = _ttl_seconds() if ttl_s is None else ttl_s

    session = SessionLocal()
    try:
        row = session.execute(
            select(MappingEnumerationCache).where(
                MappingEnumerationCache.chain == chain_norm,
                MappingEnumerationCache.address == addr_norm,
                MappingEnumerationCache.specs_hash == specs_hash,
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        materialized_at = row.materialized_at
        if materialized_at.tzinfo is None:
            materialized_at = materialized_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - materialized_at).total_seconds()
        if age > eff_ttl:
            return None
        return {
            "principals": list(row.principals or []),
            "status": row.status,
            "pages_fetched": int(row.pages_fetched),
            "last_block_scanned": int(row.last_block_scanned),
            "error": row.error,
        }
    finally:
        session.close()


def upsert(
    *,
    chain: str | None,
    address: str,
    specs_hash: str,
    result: dict[str, Any],
) -> None:
    """Upsert the EnumerationResult for the key. Commits its own
    short-lived transaction so the row is visible to other processes
    immediately. Failures are swallowed and logged — the cache is a
    pure optimization; a write failure must not break the resolution
    pipeline that just produced a valid enumeration.
    """
    chain_norm = chain_cache_token(chain)
    addr_norm = address.lower()

    session = SessionLocal()
    try:
        stmt = pg_insert(MappingEnumerationCache).values(
            chain=chain_norm,
            address=addr_norm,
            specs_hash=specs_hash,
            principals=result["principals"],
            status=result["status"],
            pages_fetched=int(result["pages_fetched"]),
            last_block_scanned=int(result["last_block_scanned"]),
            error=result.get("error"),
        )
        stmt = stmt.on_conflict_do_update(
            constraint="mapping_enumeration_cache_pkey",
            set_={
                "principals": stmt.excluded.principals,
                "status": stmt.excluded.status,
                "pages_fetched": stmt.excluded.pages_fetched,
                "last_block_scanned": stmt.excluded.last_block_scanned,
                "error": stmt.excluded.error,
                "materialized_at": func.now(),
                "updated_at": func.now(),
            },
        )
        session.execute(stmt)
        session.commit()
    except Exception as exc:
        logger.warning(
            "mapping_enumeration_cache: upsert failed for chain=%s address=%s: %s",
            chain_norm,
            addr_norm,
            exc,
        )
        session.rollback()
    finally:
        session.close()
