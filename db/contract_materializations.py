"""Cross-job, cross-process materialization cache.

One row per ``(chain, bytecode_keccak)`` holding the static analysis and tracking-plan bundle, so identical bytecode
pays forge+Slither once. Concurrent requests coalesce on ``pg_advisory_xact_lock(hashtext(chain || ':' || keccak))``.
Each entry point opens its own short session so callers don't share a connection with blocking locks.

``chain`` is always the canonical decimal id (:func:`utils.chains.chain_cache_token`); ``None`` means mainnet ``"1"``.

Payloads can be many MB, so with object storage configured they go to blobs (``*_blob_key``) and the JSONB columns stay
NULL; otherwise they're inline. ``hydrate_*`` reads the blob and falls back to inline; with neither available it raises
``StorageContentIncomplete``, since "the bucket couldn't answer" differs from "nothing was stored".
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import ContractMaterialization, SessionLocal
from db.storage import (
    JSON_CONTENT_TYPE,
    StorageError,
    StorageKeyMissing,
    _key_prefix,
    content_shortfall,
    get_storage_client,
)
from utils.chains import chain_cache_token

logger = logging.getLogger(__name__)

# Stamped on every row; reads serve only matching rows, so older rows rebuild. Bump by hand when the analysis,
# tracking-plan or predicate-tree output shape changes; not tied to a git SHA, which would rebuild every multi-MB bundle
# on unrelated deploys. If the change also moves an effects probe input, consider ``EFFECT_CACHE_SCHEMA_VERSION``
# (db/effect_cache.py). Bump reasons are in the commit history.
ANALYSIS_SCHEMA_VERSION = 10


# Who produced a row and from which job; provenance requires the source job for anything monitoring enrolls from.
PRODUCED_BY_RESOLUTION = "resolution"
PRODUCED_BY_PIPELINE = "pipeline"
PRODUCED_BY_PROMOTION_SWEEP = "promotion_sweep"

PUBLISH_WRITTEN = "written"
PUBLISH_REFRESHED = "refreshed"
PUBLISH_ALREADY_CURRENT = "already_current"
PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS = "keccak_bound_to_other_address"
PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK = "address_bound_to_other_keccak"
PUBLISH_INCOMPLETE_BUNDLE = "incomplete_bundle"


def build_provenance(
    produced_by: str,
    *,
    source_job_id: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The provenance stamp for one write.

    ``source_job_id`` is written even when None (producer known, job unknown); a NULL ``provenance`` means nothing was
    recorded.
    """
    return {
        "produced_by": produced_by,
        "source_job_id": str(source_job_id) if source_job_id is not None else None,
        "materialized_at": (now or datetime.now(timezone.utc)).isoformat(),
    }


def _builder_staleness_s() -> float:
    """How long a ``building`` row is trusted as in flight before a crashed builder is presumed and taken over.

    Default 15 min covers the slowest observed build (~6.5 min); env-tunable.
    """
    try:
        return max(60.0, float(os.getenv("PSAT_MATERIALIZE_BUILDER_STALENESS_S", "900")))
    except ValueError:
        return 900.0


def _wait_poll_interval_s() -> float:
    """Poll interval while waiting on another builder: short for fast builds, long enough not to hammer the lock
    space.
    """
    try:
        return max(0.05, float(os.getenv("PSAT_MATERIALIZE_WAIT_POLL_INTERVAL_S", "1.0")))
    except ValueError:
        return 1.0


def is_enabled() -> bool:
    """Env kill switch (like ``PSAT_BYTECODE_PG_CACHE``), default on.

    Tests disable it via ``_scrub_contract_materializations_env`` and re-enable via ``cm_session_local``.
    """
    return os.getenv("PSAT_CONTRACT_MATERIALIZATIONS", "1").lower() in ("1", "true", "yes")


def _normalize(chain: str | int | None, address: str, bytecode_keccak: str) -> tuple[str, str, str]:
    return (
        chain_cache_token(chain),
        address.lower(),
        bytecode_keccak.lower() if bytecode_keccak.startswith("0x") else "0x" + bytecode_keccak.lower(),
    )


def _blob_key(chain_norm: str, keccak_norm: str, kind: str) -> str:
    """Deterministic blob key for a payload (``kind`` is ``"analysis"`` or ``"tracking_plan"``), with the
    ``ARTIFACT_STORAGE_PREFIX`` preview prefix.
    """
    return f"{_key_prefix()}contract_materializations/{chain_norm}/{keccak_norm}/{kind}.json"


def find_by_keccak(
    session: Session,
    *,
    chain: str | int | None,
    bytecode_keccak: str,
) -> ContractMaterialization | None:
    """The ready, current-version row for ``(chain, bytecode_keccak)``.

    Pending rows aren't returned (take the lock and re-read).
    """
    chain_norm = chain_cache_token(chain)
    keccak_norm = bytecode_keccak.lower() if bytecode_keccak.startswith("0x") else "0x" + bytecode_keccak.lower()
    row = session.execute(
        select(ContractMaterialization).where(
            ContractMaterialization.chain == chain_norm,
            ContractMaterialization.bytecode_keccak == keccak_norm,
            ContractMaterialization.status == "ready",
            ContractMaterialization.analysis_schema_version == ANALYSIS_SCHEMA_VERSION,
        )
    ).scalar_one_or_none()
    return row


def find_by_address(
    session: Session,
    *,
    chain: str | int | None,
    address: str,
) -> ContractMaterialization | None:
    """The ready, current-version row for ``(chain, address)``, via the address unique index (the legacy entry path)."""
    chain_norm = chain_cache_token(chain)
    addr_norm = address.lower()
    row = session.execute(
        select(ContractMaterialization).where(
            ContractMaterialization.chain == chain_norm,
            ContractMaterialization.address == addr_norm,
            ContractMaterialization.status == "ready",
            ContractMaterialization.analysis_schema_version == ANALYSIS_SCHEMA_VERSION,
        )
    ).scalar_one_or_none()
    return row


def _hydrate(row: ContractMaterialization, *, blob_key_attr: str, inline_attr: str) -> dict | None:
    """Blob-or-inline read for a payload column. Three outcomes:

      * ``dict``: present (blob, or inline when the blob is unreadable; stale beats crashing).
      * ``None``: proven absent, no blob key and no inline (``status='failed'`` rows).
      * ``StorageContentIncomplete``: a blob key whose content couldn't be obtained, with no inline copy. Returning
    ``None`` there made a bucket outage read as "no analysis" and got cached as a witness. ``StorageContentAbsent`` when
    the bucket answered with no object, else ``StorageContentNotDetermined``; ``workers.retry_policy`` classifies by
    type.

    Deep-copy before mutating: the inline path returns the ORM-cached dict.
    """
    blob_key: str | None = getattr(row, blob_key_attr, None)
    inline: dict | None = getattr(row, inline_attr, None)
    subject = f"{getattr(row, 'chain', '?')}/{getattr(row, 'address', '?')}"

    if not blob_key:
        if inline is None:
            logger.info(
                "contract_materializations: %s records no %s and no inline %s — nothing was stored",
                subject,
                blob_key_attr,
                inline_attr,
            )
        return inline

    reason: str | None = None
    object_proven_absent = False
    client = get_storage_client()
    if client is None:
        # A blob key but storage now unconfigured; we can't ask.
        reason = "storage is not configured"
    else:
        try:
            body = client.get(blob_key)
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
            # Payloads are always JSON objects; anything else is corruption.
            reason = f"blob decoded to {type(parsed).__name__}, expected dict"
        except StorageKeyMissing as exc:
            object_proven_absent = True
            reason = str(exc)
        except (StorageError, ValueError) as exc:
            reason = str(exc)

    if inline is not None:
        logger.warning(
            "contract_materializations: blob fetch for %s failed (%s); using inline JSONB",
            blob_key,
            reason,
        )
        return inline

    logger.error(
        "contract_materializations: %s %s=%s unreadable (%s) and no inline fallback",
        subject,
        blob_key_attr,
        blob_key,
        reason,
    )
    detail = {blob_key_attr: reason or "unknown"}
    raise content_shortfall(
        f"contract_materializations {subject}: {blob_key_attr}={blob_key} unreadable ({reason}) "
        "and no inline fallback — this contract's payload could not be produced",
        values=None,
        proven_absent=detail if object_proven_absent else None,
        not_determined=None if object_proven_absent else detail,
    )


def hydrate_analysis(row: ContractMaterialization) -> dict | None:
    """The row's ``analysis`` (blob, else inline).

    ``None`` means nothing was stored; raises ``StorageContentIncomplete`` when a blob key's content can't be obtained.
    """
    return _hydrate(row, blob_key_attr="analysis_blob_key", inline_attr="analysis")


def hydrate_tracking_plan(row: ContractMaterialization) -> dict | None:
    """Like ``hydrate_analysis``, for ``tracking_plan``."""
    return _hydrate(row, blob_key_attr="tracking_plan_blob_key", inline_attr="tracking_plan")


def hydrate_predicate_trees(row: ContractMaterialization) -> dict | None:
    """The row's predicate trees.

    ``None`` for rows predating c1d2e3f4a5b6 (callers may rebuild from the analysis). Raises
    ``StorageContentIncomplete`` for an unreadable blob, which the rebuild fallback must not mask.
    """
    return _hydrate(row, blob_key_attr="predicate_trees_blob_key", inline_attr="predicate_trees")


def _advisory_lock(session: Session, chain_norm: str, keccak_norm: str) -> None:
    """Take ``pg_advisory_xact_lock`` on ``chain || ':' || keccak``, so chains sharing a keccak don't serialize."""
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"{chain_norm}:{keccak_norm}"},
    )


def _put_blob(client, blob_key: str, payload: dict) -> None:
    """Upload one payload. Errors propagate so the transaction rolls back rather than point at a missing key."""
    body = json.dumps(payload, default=str).encode("utf-8")
    client.put(blob_key, body, JSON_CONTENT_TYPE)


def find_reusable_by_source_hash(
    session: Session,
    *,
    source_content_hash: str,
) -> ContractMaterialization | None:
    """Any ready, current-version row with this source hash, on any chain: the bundle is a pure
    function of the source, so all matches are identical.
    """
    if not source_content_hash:
        return None
    return session.execute(
        select(ContractMaterialization)
        .where(
            ContractMaterialization.source_content_hash == source_content_hash,
            ContractMaterialization.status == "ready",
            ContractMaterialization.analysis_schema_version == ANALYSIS_SCHEMA_VERSION,
        )
        .limit(1)
    ).scalar_one_or_none()


def _copy_bundle_row(
    session: Session,
    donor: ContractMaterialization,
    *,
    chain_norm: str,
    keccak_norm: str,
    addr_norm: str,
    source_content_hash: str,
) -> ContractMaterialization:
    """Write a ready row for ``(chain_norm, keccak_norm)`` reusing *donor*'s bundle.

    Blob keys are shared, not copied: blobs are content-addressed, never deleted, and reads use the stored key column.
    Inline payloads are copied by value.
    """
    values = dict(
        chain=chain_norm,
        bytecode_keccak=keccak_norm,
        address=addr_norm,
        contract_name=donor.contract_name,
        analysis=donor.analysis,
        tracking_plan=donor.tracking_plan,
        predicate_trees=donor.predicate_trees,
        analysis_blob_key=donor.analysis_blob_key,
        tracking_plan_blob_key=donor.tracking_plan_blob_key,
        predicate_trees_blob_key=donor.predicate_trees_blob_key,
        source_content_hash=source_content_hash,
        status="ready",
        error=None,
        builder_started_at=None,
        # Record the donor as provenance.
        provenance={
            **build_provenance(PRODUCED_BY_RESOLUTION),
            "reused_from": {"chain": donor.chain, "bytecode_keccak": donor.bytecode_keccak},
        },
        analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
    )
    stmt = pg_insert(ContractMaterialization).values(**values)
    stmt = stmt.on_conflict_do_update(
        constraint="contract_materializations_pkey",
        set_={
            "address": stmt.excluded.address,
            "contract_name": stmt.excluded.contract_name,
            "analysis": stmt.excluded.analysis,
            "tracking_plan": stmt.excluded.tracking_plan,
            "predicate_trees": stmt.excluded.predicate_trees,
            "analysis_blob_key": stmt.excluded.analysis_blob_key,
            "tracking_plan_blob_key": stmt.excluded.tracking_plan_blob_key,
            "predicate_trees_blob_key": stmt.excluded.predicate_trees_blob_key,
            "source_content_hash": stmt.excluded.source_content_hash,
            "status": "ready",
            "error": None,
            "builder_started_at": None,
            "provenance": stmt.excluded.provenance,
            "analysis_schema_version": stmt.excluded.analysis_schema_version,
            "materialized_at": func.now(),
            "updated_at": func.now(),
        },
    )
    session.execute(stmt)
    session.commit()
    session.expire_all()
    return session.execute(
        select(ContractMaterialization).where(
            ContractMaterialization.chain == chain_norm,
            ContractMaterialization.bytecode_keccak == keccak_norm,
        )
    ).scalar_one()


def materialize_or_wait(
    *,
    chain: str | None,
    address: str,
    bytecode_keccak: str,
    builder: Callable[[], Mapping[str, Any]],
    source_hash_fn: Callable[[], str | None] | None = None,
) -> ContractMaterialization:
    """Look up or build the materialization row for a content key.

    ``source_hash_fn`` enables cross-chain reuse; called at most once, only on a keccak miss. A ready row
    with the same source hash is copied instead of building.

    Three phases, each its own short transaction so no connection idles during ``builder()`` (Neon's pooler drops idle
    SSL):

      1. Under the lock, re-read: ``ready`` returns; a recent ``building`` releases and polls; a stale ``building``
    (crashed worker), missing, ``failed`` or legacy ``pending`` row is claimed as ``building`` with our timestamp.
      2. Build with no session held; upload blobs if configured.
      3. Under the lock, recheck (a takeover may have finished first; serve theirs), else write ``ready``.

    The ``building`` claim lets a second caller wait instead of duplicating a 60-150 s build. Builder failure writes
    ``failed`` with the error, then re-raises. Blob upload failure writes nothing.
    """
    chain_norm, addr_norm, keccak_norm = _normalize(chain, address, bytecode_keccak)
    staleness_s = _builder_staleness_s()
    poll_interval_s = _wait_poll_interval_s()

    # Lazy, only on a keccak miss.
    _src = {"done": False, "hash": None}  # type: dict[str, Any]

    def _get_source_hash() -> str | None:
        if not _src["done"]:
            _src["done"] = True
            if source_hash_fn is not None:
                try:
                    _src["hash"] = source_hash_fn()
                except Exception as exc:
                    # Only disables cross-chain reuse for this call.
                    logger.debug("contract_materializations: source_hash_fn failed: %s", exc)
                    _src["hash"] = None
        return _src["hash"]

    # Phase 1: poll while another caller is building, until it's ready or stale.
    wait_deadline = time.monotonic() + staleness_s
    while True:
        with SessionLocal() as session:
            _advisory_lock(session, chain_norm, keccak_norm)
            row = session.execute(
                select(ContractMaterialization).where(
                    ContractMaterialization.chain == chain_norm,
                    ContractMaterialization.bytecode_keccak == keccak_norm,
                )
            ).scalar_one_or_none()
            if row is not None and row.status == "ready" and row.analysis_schema_version == ANALYSIS_SCHEMA_VERSION:
                session.commit()
                return row
            # An old-version ready row falls through to be rebuilt.

            if row is not None and row.status == "building":
                started = row.builder_started_at
                age_s = (
                    (datetime.now(timezone.utc) - started).total_seconds() if started is not None else staleness_s + 1
                )
                if age_s < staleness_s and time.monotonic() < wait_deadline:
                    session.commit()
                    time.sleep(poll_interval_s)
                    continue
                # Stale: take over.
                logger.info(
                    "contract_materializations: taking over stale building row for %s:%s (age=%.1fs)",
                    chain_norm,
                    keccak_norm,
                    age_s,
                )

            # Cross-chain reuse: an identical source set analysed under another ``(chain, keccak)`` is copied here
            # instead of building (per-chain immutables make the keccak miss). Under our lock.
            src_hash = _get_source_hash()
            if src_hash:
                donor = find_reusable_by_source_hash(session, source_content_hash=src_hash)
                if donor is not None:
                    logger.info(
                        "contract_materializations: cross-chain reuse for %s:%s from %s:%s (source_hash=%s)",
                        chain_norm,
                        keccak_norm,
                        donor.chain,
                        donor.bytecode_keccak,
                        src_hash[:12],
                    )
                    return _copy_bundle_row(
                        session,
                        donor,
                        chain_norm=chain_norm,
                        keccak_norm=keccak_norm,
                        addr_norm=addr_norm,
                        source_content_hash=src_hash,
                    )

            now_dt = datetime.now(timezone.utc)
            claim_stmt = pg_insert(ContractMaterialization).values(
                chain=chain_norm,
                bytecode_keccak=keccak_norm,
                address=addr_norm,
                status="building",
                builder_started_at=now_dt,
                error=None,
                source_content_hash=src_hash,
                analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
            )
            claim_stmt = claim_stmt.on_conflict_do_update(
                constraint="contract_materializations_pkey",
                set_={
                    "status": "building",
                    "builder_started_at": now_dt,
                    "address": claim_stmt.excluded.address,
                    "error": None,
                    "source_content_hash": claim_stmt.excluded.source_content_hash,
                    "updated_at": func.now(),
                },
            )
            session.execute(claim_stmt)
            session.commit()
            break

    # Phase 2: build and upload, no DB connection held.
    try:
        bundle = builder()
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"[:4000]
        with SessionLocal() as session:
            stmt = pg_insert(ContractMaterialization).values(
                chain=chain_norm,
                bytecode_keccak=keccak_norm,
                address=addr_norm,
                status="failed",
                error=err,
                builder_started_at=None,
                source_content_hash=_src["hash"],
                provenance=build_provenance(PRODUCED_BY_RESOLUTION),
                analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="contract_materializations_pkey",
                set_={
                    "status": "failed",
                    "error": err,
                    "builder_started_at": None,
                    "source_content_hash": stmt.excluded.source_content_hash,
                    "provenance": stmt.excluded.provenance,
                    "updated_at": func.now(),
                },
            )
            session.execute(stmt)
            session.commit()
        raise

    analysis_payload = bundle.get("analysis")
    tracking_plan_payload = bundle.get("tracking_plan")
    predicate_trees_payload = bundle.get("predicate_trees")
    analysis_blob_key: str | None = None
    tracking_plan_blob_key: str | None = None
    predicate_trees_blob_key: str | None = None
    analysis_inline: dict | None = analysis_payload if isinstance(analysis_payload, dict) else None
    tracking_plan_inline: dict | None = tracking_plan_payload if isinstance(tracking_plan_payload, dict) else None
    predicate_trees_inline: dict | None = predicate_trees_payload if isinstance(predicate_trees_payload, dict) else None

    client = get_storage_client()
    if client is not None:
        # Uploads before re-locking so a slow PUT doesn't idle the connection; failures write no row.
        if analysis_inline is not None:
            analysis_blob_key = _blob_key(chain_norm, keccak_norm, "analysis")
            _put_blob(client, analysis_blob_key, analysis_inline)
            analysis_inline = None
        if tracking_plan_inline is not None:
            tracking_plan_blob_key = _blob_key(chain_norm, keccak_norm, "tracking_plan")
            _put_blob(client, tracking_plan_blob_key, tracking_plan_inline)
            tracking_plan_inline = None
        if predicate_trees_inline is not None:
            predicate_trees_blob_key = _blob_key(chain_norm, keccak_norm, "predicate_trees")
            _put_blob(client, predicate_trees_blob_key, predicate_trees_inline)
            predicate_trees_inline = None

    # Phase 3.
    with SessionLocal() as session:
        _advisory_lock(session, chain_norm, keccak_norm)

        # A takeover may have committed first; its bundle is equivalent, so serve it.
        existing = session.execute(
            select(ContractMaterialization).where(
                ContractMaterialization.chain == chain_norm,
                ContractMaterialization.bytecode_keccak == keccak_norm,
            )
        ).scalar_one_or_none()
        if (
            existing is not None
            and existing.status == "ready"
            and existing.analysis_schema_version == ANALYSIS_SCHEMA_VERSION
        ):
            session.commit()
            return existing

        stmt = pg_insert(ContractMaterialization).values(
            chain=chain_norm,
            bytecode_keccak=keccak_norm,
            address=addr_norm,
            contract_name=bundle.get("contract_name"),
            analysis=analysis_inline,
            tracking_plan=tracking_plan_inline,
            predicate_trees=predicate_trees_inline,
            analysis_blob_key=analysis_blob_key,
            tracking_plan_blob_key=tracking_plan_blob_key,
            predicate_trees_blob_key=predicate_trees_blob_key,
            source_content_hash=_src["hash"],
            status="ready",
            builder_started_at=None,
            # No source job: the walking job isn't the job this bundle is of.
            provenance=build_provenance(PRODUCED_BY_RESOLUTION),
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="contract_materializations_pkey",
            set_={
                "status": "ready",
                "contract_name": stmt.excluded.contract_name,
                "analysis": stmt.excluded.analysis,
                "tracking_plan": stmt.excluded.tracking_plan,
                "predicate_trees": stmt.excluded.predicate_trees,
                "analysis_blob_key": stmt.excluded.analysis_blob_key,
                "tracking_plan_blob_key": stmt.excluded.tracking_plan_blob_key,
                "predicate_trees_blob_key": stmt.excluded.predicate_trees_blob_key,
                "source_content_hash": stmt.excluded.source_content_hash,
                "address": stmt.excluded.address,
                "error": None,
                "builder_started_at": None,
                "provenance": stmt.excluded.provenance,
                "analysis_schema_version": stmt.excluded.analysis_schema_version,
                "materialized_at": func.now(),
                "updated_at": func.now(),
            },
        )
        session.execute(stmt)
        session.commit()
        # Phase 1 cached the ``building`` row; refetch so callers see ``ready``.
        session.expire_all()

        ready = session.execute(
            select(ContractMaterialization).where(
                ContractMaterialization.chain == chain_norm,
                ContractMaterialization.bytecode_keccak == keccak_norm,
            )
        ).scalar_one()
        return ready


def _publish_blobs(
    chain_norm: str,
    keccak_norm: str,
    analysis: dict,
    tracking_plan: dict,
    predicate_trees: dict | None,
) -> tuple[dict | None, dict | None, dict | None, str | None, str | None, str | None]:
    """Upload the bundle if storage is configured, else keep it inline.

    Returns the inline/blob split ``materialize_or_wait`` uses. Upload failures propagate.
    """
    client = get_storage_client()
    if client is None:
        return analysis, tracking_plan, predicate_trees, None, None, None
    analysis_key = _blob_key(chain_norm, keccak_norm, "analysis")
    _put_blob(client, analysis_key, analysis)
    tracking_plan_key = _blob_key(chain_norm, keccak_norm, "tracking_plan")
    _put_blob(client, tracking_plan_key, tracking_plan)
    predicate_trees_key: str | None = None
    if predicate_trees is not None:
        predicate_trees_key = _blob_key(chain_norm, keccak_norm, "predicate_trees")
        _put_blob(client, predicate_trees_key, predicate_trees)
    return None, None, None, analysis_key, tracking_plan_key, predicate_trees_key


def publish_materialization(
    *,
    chain: str | int | None,
    address: str,
    bytecode_keccak: str,
    contract_name: str | None,
    analysis: dict | None,
    tracking_plan: dict | None,
    predicate_trees: dict | None = None,
    source_content_hash: str | None = None,
    provenance: dict[str, Any],
    refresh_on_differ: bool = False,
) -> str:
    """Write a ready row for an already-built bundle; returns an outcome token.

    The record-side counterpart to :func:`materialize_or_wait`, used for the pipeline's own analysis (F4a) and for
    promoting completed jobs' artifacts (F4b).

    Any row not ready at the current version is overwritten (a live ``building`` claim then discards its duplicate in
    phase 3). A ready current row is compared:

    * ``refresh_on_differ=True``: the caller produced this bundle under the current analyzer, so a difference means it's
    newer; refresh. Analyzer improvements don't always bump the version.
    * ``refresh_on_differ=False``: the caller is passing on someone else's older bundle; the stored row stands (or two
    such callers would flip-flop forever).

    Identical bundles return ``already_current`` and touch nothing (compared under the lock, before upload). A ready
    row's ``address`` is never changed.

    Refusals:

    ``incomplete_bundle``
        Missing analysis or tracking plan; publishing it would claim "no analysis".
    ``keccak_bound_to_other_address``
        A ready row for this bytecode already names another address.
    ``address_bound_to_other_keccak``
        Another row holds ``(chain, address)`` under a different keccak; we didn't witness which is current.
    """
    if not isinstance(analysis, dict) or not isinstance(tracking_plan, dict):
        return PUBLISH_INCOMPLETE_BUNDLE

    chain_norm, addr_norm, keccak_norm = _normalize(chain, address, bytecode_keccak)
    written = PUBLISH_WRITTEN

    # One lock spans decide, upload and write, so ``already_current`` also means the payload was untouched. No builder
    # runs inside it.
    with SessionLocal() as session:
        _advisory_lock(session, chain_norm, keccak_norm)
        existing = session.execute(
            select(ContractMaterialization).where(
                ContractMaterialization.chain == chain_norm,
                ContractMaterialization.bytecode_keccak == keccak_norm,
            )
        ).scalar_one_or_none()
        outcome = _publish_precheck(existing, addr_norm)
        if outcome == PUBLISH_ALREADY_CURRENT:
            if not refresh_on_differ or not _bundle_differs(existing, analysis, tracking_plan, predicate_trees):
                session.commit()
                return PUBLISH_ALREADY_CURRENT
            written = PUBLISH_REFRESHED
        elif outcome is not None:
            session.commit()
            return outcome

        # Re-checked under the lock; the conflicting row can appear in between.
        conflict = session.execute(
            select(ContractMaterialization.bytecode_keccak).where(
                ContractMaterialization.chain == chain_norm,
                ContractMaterialization.address == addr_norm,
                ContractMaterialization.bytecode_keccak != keccak_norm,
            )
        ).scalar_one_or_none()
        if conflict is not None:
            logger.warning(
                "contract_materializations: %s/%s is already bound to keccak %s; not publishing %s",
                chain_norm,
                addr_norm,
                conflict,
                keccak_norm,
            )
            session.commit()
            return PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK

        (
            analysis_inline,
            plan_inline,
            trees_inline,
            analysis_key,
            plan_key,
            trees_key,
        ) = _publish_blobs(chain_norm, keccak_norm, analysis, tracking_plan, predicate_trees)

        stmt = pg_insert(ContractMaterialization).values(
            chain=chain_norm,
            bytecode_keccak=keccak_norm,
            address=addr_norm,
            contract_name=contract_name,
            analysis=analysis_inline,
            tracking_plan=plan_inline,
            predicate_trees=trees_inline,
            analysis_blob_key=analysis_key,
            tracking_plan_blob_key=plan_key,
            predicate_trees_blob_key=trees_key,
            source_content_hash=source_content_hash,
            status="ready",
            error=None,
            builder_started_at=None,
            provenance=provenance,
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="contract_materializations_pkey",
            set_={
                "address": stmt.excluded.address,
                "contract_name": stmt.excluded.contract_name,
                "analysis": stmt.excluded.analysis,
                "tracking_plan": stmt.excluded.tracking_plan,
                "predicate_trees": stmt.excluded.predicate_trees,
                "analysis_blob_key": stmt.excluded.analysis_blob_key,
                "tracking_plan_blob_key": stmt.excluded.tracking_plan_blob_key,
                "predicate_trees_blob_key": stmt.excluded.predicate_trees_blob_key,
                "source_content_hash": stmt.excluded.source_content_hash,
                "status": "ready",
                "error": None,
                "builder_started_at": None,
                "provenance": stmt.excluded.provenance,
                "analysis_schema_version": stmt.excluded.analysis_schema_version,
                "materialized_at": func.now(),
                "updated_at": func.now(),
            },
        )
        session.execute(stmt)
        session.commit()
    return written


def _bundle_differs(
    existing: ContractMaterialization | None,
    analysis: dict,
    tracking_plan: dict,
    predicate_trees: dict | None,
) -> bool:
    """Whether the stored bundle differs from the caller's, on serialized payloads.

    An unreadable stored payload counts as differing ("same" is a positive claim).
    """
    if existing is None:
        return True
    try:
        stored = (
            hydrate_analysis(existing),
            hydrate_tracking_plan(existing),
            hydrate_predicate_trees(existing),
        )
    except Exception as exc:
        logger.info(
            "contract_materializations: %s/%s stored bundle unreadable (%s); treating as differing",
            getattr(existing, "chain", "?"),
            getattr(existing, "address", "?"),
            exc,
        )
        return True
    return [_canonical(p) for p in stored] != [_canonical(p) for p in (analysis, tracking_plan, predicate_trees)]


def _canonical(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return json.dumps(payload, sort_keys=True, default=str)


def builder_claim_is_stale(status: str | None, builder_started_at: datetime | None) -> bool:
    """Whether a ``building`` claim is stale (:func:`_builder_staleness_s`), exported so the reconciler counts
    crashed claims as rows to rebuild.
    """
    if status != "building":
        return False
    if builder_started_at is None:
        return True
    started = builder_started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - started).total_seconds() >= _builder_staleness_s()


def _publish_precheck(existing: ContractMaterialization | None, addr_norm: str) -> str | None:
    """The outcome when *existing* forbids a write, else None; one implementation so reads can't drift."""
    if existing is None:
        return None
    if existing.status != "ready" or existing.analysis_schema_version != ANALYSIS_SCHEMA_VERSION:
        return None
    if (existing.address or "").lower() != addr_norm:
        return PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS
    return PUBLISH_ALREADY_CURRENT
