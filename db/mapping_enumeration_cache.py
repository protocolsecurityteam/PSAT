"""Cross-process cache for mapping_enumerator HyperSync scans, one row per ``(chain, address, specs_hash)``, so the
resolution and policy stages don't repeat the same slow scan.

Each entry point opens its own short session; writes commit immediately. Freshness is a wall-clock TTL
(``PSAT_MAPPING_ENUMERATION_CACHE_TTL_S``, default 1800s), matching the in-process cache.
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
from sqlalchemy.exc import DataError

from db.models import MappingEnumerationCache, SessionLocal
from utils.chains import chain_cache_token
from utils.logging import record_degraded

logger = logging.getLogger(__name__)


def _ttl_seconds() -> float:
    return float(os.getenv("PSAT_MAPPING_ENUMERATION_CACHE_TTL_S", "1800"))


def is_enabled() -> bool:
    """Env kill switch, default on; tests set ``PSAT_MAPPING_ENUMERATION_DB_CACHE=0`` to exercise the in-process
    layer alone.
    """
    return os.getenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "1").lower() in ("1", "true", "yes")


def specs_fingerprint(
    writer_specs: list[dict[str, Any]],
    *,
    value_predicate: dict[str, Any] | None = None,
) -> str:
    """Stable SHA-256 of the normalized writer specs.

    Includes the fields that affect enumeration (event_signature, mapping_name, direction, key_position, sorted
    indexed_positions) and, since D.1, ``value_position`` and ``value_predicate``, so passes with different predicates
    don't share rows. When those are None the fingerprint equals the legacy one.
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
        # Must stay byte-identical to pre-D.1 so existing rows remain valid.
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
    """The cached EnumerationResult if fresher than the TTL, else ``None`` (a miss).

    Stale rows aren't returned as a fallback; add a separate ``find_any`` if that's ever wanted.
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
    """Upsert the result in its own short transaction.

    Transient DB failures are logged and swallowed (the cache is an optimization). ``DataError`` raises after a degraded
    breadcrumb: the value doesn't fit the schema, retrying can't help, and a rejected upsert would leave an older in-TTL
    ``complete`` row serving in place of a truncated re-scan.
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
    except DataError as exc:
        session.rollback()
        record_degraded(
            phase="mapping_enumeration_cache_schema",
            exc=exc,
            context={
                "chain": chain_norm,
                "address": addr_norm,
                "status": str(result.get("status")),
                "status_len": len(str(result.get("status", ""))),
            },
        )
        logger.error(
            "mapping_enumeration_cache: upsert rejected by schema for chain=%s address=%s status=%r: %s",
            chain_norm,
            addr_norm,
            result.get("status"),
            exc,
        )
        raise
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
