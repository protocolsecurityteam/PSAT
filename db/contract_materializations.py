"""Cross-job, cross-process materialization cache.

A row per ``(chain, bytecode_keccak)`` holding the static analysis +
tracking-plan bundle so two impl jobs requesting the same contract pay
the expensive forge+Slither cost exactly once. Concurrent requests are
serialized via ``pg_advisory_xact_lock(hashtext(chain || ':' || keccak))``:
the lock winner runs the builder; the loser blocks on the lock, finds
``status='ready'`` on its second read, and returns the cached bundle
without rebuilding.

The module is deliberately small and stateless — every entry point opens
its own short-lived session so the caller doesn't have to share its DB
connection with potentially blocking advisory locks.

The ``chain`` key is the canonical decimal-string chain id (``"1"``,
``"8453"``) per invariant 11: callers may pass a chain name, alias, id,
or ``None``, and :func:`utils.chains.chain_cache_token` collapses them all
onto the id token so a name-keyed writer and an id-keyed reader hit the
same row. ``None``/empty resolves to the mainnet token ``"1"``, matching
how ``Job.request['chain']`` defaults.

Bundle storage: the ``analysis`` and ``tracking_plan`` payloads can be
multi-megabyte JSON blobs (a Compound-v3-class contract analysis is
~5-20 MB). Postgres JSONB stores fine but detoasts on every read,
inflates page-cache pressure on this hot table, and slows backup /
dump / restore. The schema therefore carries paired columns:

  - ``analysis`` (JSONB) and ``analysis_blob_key`` (Text)
  - ``tracking_plan`` (JSONB) and ``tracking_plan_blob_key`` (Text)

When object storage is configured (``ARTIFACT_STORAGE_*`` env vars set,
``db.storage.get_storage_client()`` returns non-None) new writes go to
blob storage and the JSONB columns are persisted as NULL. The blob_key
columns are then the source of truth. When storage is unconfigured
(local dev, offline tests without minio) writes fall back to inline
JSONB and blob_key is NULL.

Reads are always handled by ``hydrate_analysis`` / ``hydrate_tracking_plan``
which try the blob first and transparently fall back to inline JSONB.
That fallback is what lets pre-migration rows keep working while the
backfill (``scripts/backfill_contract_materializations_to_blob.py``)
catches up — and what insulates the pipeline from a transient Tigris
outage when the inline copy still exists.
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
    get_storage_client,
)
from utils.chains import chain_cache_token

logger = logging.getLogger(__name__)

# Analyzer/pipeline schema version stamped on every materialized row. The read
# paths (``find_by_keccak``/``find_by_address``/``materialize_or_wait``) only
# serve a row whose ``analysis_schema_version`` equals this constant, so a row
# written by an older analyzer reads as a miss and is rebuilt. Bump by hand only
# when the static-analysis / tracking-plan / predicate-tree *output shape*
# changes — deliberately NOT tied to a git SHA, which would cold-rebuild every
# multi-MB forge+Slither bundle on unrelated deploys (frontend, docs, workers).
ANALYSIS_SCHEMA_VERSION = 1


def _builder_staleness_s() -> float:
    """How long a ``status='building'`` row stays trusted as in-flight.

    A worker that started a build longer ago than this is presumed dead
    (process crash, SIGKILL on OOM, machine restart). The next caller
    takes over the build. Default 15 minutes covers the worst observed
    forge+Slither+predicate-pipeline run (~6.5 min on EtherFi contracts
    in PR-79) with comfortable headroom; tunable via env for incident
    response.
    """
    try:
        return max(60.0, float(os.getenv("PSAT_MATERIALIZE_BUILDER_STALENESS_S", "900")))
    except ValueError:
        return 900.0


def _wait_poll_interval_s() -> float:
    """How long the loser sleeps between polls while waiting on a winner.

    Short enough that a fast cache hit (~10s build) doesn't cost extra
    latency; long enough that 100 waiting callers don't hammer the DB
    advisory-lock space.
    """
    try:
        return max(0.05, float(os.getenv("PSAT_MATERIALIZE_WAIT_POLL_INTERVAL_S", "1.0")))
    except ValueError:
        return 1.0


def is_enabled() -> bool:
    """Env-gated kill switch (mirrors ``PSAT_BYTECODE_PG_CACHE``).

    Default ON in production. Tests that don't intend to exercise this
    layer turn it off via the autouse ``_scrub_contract_materializations_env``
    fixture; tests that do exercise it re-enable via ``cm_session_local``.
    """
    return os.getenv("PSAT_CONTRACT_MATERIALIZATIONS", "1").lower() in ("1", "true", "yes")


def _normalize(chain: str | None, address: str, bytecode_keccak: str) -> tuple[str, str, str]:
    return (
        chain_cache_token(chain),
        address.lower(),
        bytecode_keccak.lower() if bytecode_keccak.startswith("0x") else "0x" + bytecode_keccak.lower(),
    )


def _blob_key(chain_norm: str, keccak_norm: str, kind: str) -> str:
    """Deterministic blob key for an analysis/tracking_plan payload.

    ``kind`` is the payload name without extension (``"analysis"`` or
    ``"tracking_plan"``). Includes the PR-preview prefix from
    ``ARTIFACT_STORAGE_PREFIX`` so previews scope cleanly under one
    bucket. Path separators around chain and keccak make S3-console
    browsing usable.
    """
    return f"{_key_prefix()}contract_materializations/{chain_norm}/{keccak_norm}/{kind}.json"


def find_by_keccak(
    session: Session,
    *,
    chain: str | int | None,
    bytecode_keccak: str,
) -> ContractMaterialization | None:
    """Return the row for ``(chain, bytecode_keccak)`` if status='ready'.

    ``status='pending'`` rows are NOT returned — a pending row means a
    builder is still in flight; the caller should take the advisory
    lock and re-read inside it. Rows stamped with a different
    ``analysis_schema_version`` are likewise skipped (read as a miss) so
    a bumped analyzer rebuilds rather than serving a stale bundle.
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
    """Return the row for ``(chain, address)`` if status='ready'.

    Address-keyed lookup is the legacy entry path — same-bytecode-different-address
    contracts share one row keyed by keccak, but a known address still
    resolves to that row via the unique index. A row stamped with a
    different ``analysis_schema_version`` reads as a miss so a bumped
    analyzer rebuilds rather than serving a stale bundle.
    """
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
    """Generic blob-or-inline read for analysis / tracking_plan columns.

    Resolution order:
      1. If ``blob_key_attr`` is set and storage is configured, GET the
         blob and parse JSON.
      2. On a transient blob fetch error, fall through to inline JSONB
         when present — better to serve possibly-stale data than to
         crash the pipeline. ``StorageKeyMissing`` is treated the same
         (the row says we have a key but the bucket disagrees, so we
         either had a wipe or the write never landed).
      3. If neither a blob nor inline JSONB is available, return None.

    Callers that need to mutate the returned dict should ``copy.deepcopy``
    it themselves — the inline JSONB read returns the ORM-cached dict
    and mutations would leak across rows.
    """
    blob_key: str | None = getattr(row, blob_key_attr, None)
    inline: dict | None = getattr(row, inline_attr, None)

    if blob_key:
        client = get_storage_client()
        if client is not None:
            try:
                body = client.get(blob_key)
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict):
                    return parsed
                # The serializer always emits JSON objects for these
                # payloads; a non-dict is corruption, not a normal case.
                logger.warning(
                    "contract_materializations: blob %s decoded to %s, expected dict",
                    blob_key,
                    type(parsed).__name__,
                )
            except (StorageError, StorageKeyMissing, ValueError) as exc:
                if inline is not None:
                    logger.warning(
                        "contract_materializations: blob fetch for %s failed (%s); using inline JSONB",
                        blob_key,
                        exc,
                    )
                else:
                    logger.error(
                        "contract_materializations: blob %s unreadable (%s) and no inline fallback",
                        blob_key,
                        exc,
                    )
                    return None
        else:
            # blob_key set but storage unconfigured (e.g. test env that
            # turned ARTIFACT_STORAGE_* off after the row was written) —
            # silently fall through to inline if present, else None.
            if inline is None:
                logger.warning(
                    "contract_materializations: blob_key %s but storage unconfigured; no inline fallback",
                    blob_key,
                )

    return inline


def hydrate_analysis(row: ContractMaterialization) -> dict | None:
    """Load the row's ``analysis`` payload, transparently picking the
    blob path when ``analysis_blob_key`` is set and falling back to the
    inline JSONB column otherwise. ``None`` means the row genuinely
    has no analysis (a corner case for ``status != 'ready'`` rows)."""
    return _hydrate(row, blob_key_attr="analysis_blob_key", inline_attr="analysis")


def hydrate_tracking_plan(row: ContractMaterialization) -> dict | None:
    """Symmetric to ``hydrate_analysis`` for ``tracking_plan``."""
    return _hydrate(row, blob_key_attr="tracking_plan_blob_key", inline_attr="tracking_plan")


def hydrate_predicate_trees(row: ContractMaterialization) -> dict | None:
    """Load the row's predicate-tree artifact (semantic source of truth
    for revert/auth guards). Returns None if the cache row predates the
    predicate-pipeline migration (pre-c1d2e3f4a5b6) so callers can fall
    back to rebuilding the artifact from the analysis dict if they need
    mapping-writer enumeration."""
    return _hydrate(row, blob_key_attr="predicate_trees_blob_key", inline_attr="predicate_trees")


def _advisory_lock(session: Session, chain_norm: str, keccak_norm: str) -> None:
    """Take ``pg_advisory_xact_lock`` for the dedup key.

    ``hashtext`` is built into Postgres and returns a 32-bit signed int —
    fine for the advisory-lock space which is a 64-bit int. Using the
    composite ``chain || ':' || keccak`` rather than just keccak keeps
    chains independent so an Ethereum and a Base contract sharing keccak
    don't serialize on the same lock unnecessarily.
    """
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"{chain_norm}:{keccak_norm}"},
    )


def _put_blob(client, blob_key: str, payload: dict) -> None:
    """Serialize and upload one payload. Errors propagate so the
    enclosing transaction rolls back — avoids persisting a row that
    points at a key the bucket doesn't have."""
    body = json.dumps(payload, default=str).encode("utf-8")
    client.put(blob_key, body, JSON_CONTENT_TYPE)


def find_reusable_by_source_hash(
    session: Session,
    *,
    source_content_hash: str,
) -> ContractMaterialization | None:
    """Return any ``status='ready'`` current-version row with this source hash.

    The cross-chain code-plane lookup (invariant 1): the bundle is a pure
    function of the source, so a ready row for the same ``source_content_hash``
    on *any* chain/address/keccak carries a bundle the new deployment can reuse.
    Version-gated like the keccak/address reads so a bumped analyzer rebuilds
    rather than serving a stale bundle. Returns the first match (all matches are
    byte-identical bundles by construction).
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

    Blob keys are SHARED, not copied: materialization blobs are content-addressed
    (``contract_materializations/{chain}/{keccak}/{kind}.json``), written once,
    and never deleted (no delete path touches them — only ``SourceFile`` /
    ``Artifact`` orphans are cleaned up). Reads always dereference the row's
    stored ``*_blob_key`` column, never re-derive it from ``(chain, keccak)``, so
    the new row pointing at the donor's blob is safe and avoids re-uploading a
    multi-MB payload. Inline JSONB (storage-unconfigured rows) is copied by value.
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
    """Look up or build the materialization row for the given content key.

    ``source_hash_fn`` enables cross-chain code-plane reuse (invariant 1). It is
    called at most once, and only on the path where we would otherwise build (a
    ``(chain, bytecode_keccak)`` miss) — so a cheap keccak hit never pays for
    it. It returns the deployment's source content hash (see
    ``services.discovery.fetch.source_content_hash``); if a ready row for that
    hash already exists on any chain, its bundle is copied into this row and the
    expensive ``builder()`` is skipped. When ``None`` (or it returns ``None``),
    behaviour is exactly the pre-reuse keccak cache.

    Three phases, each in its own short-lived transaction so no PG
    connection sits idle during ``builder()``:

      1. **Ready check + claim** — open a session, take the advisory lock,
         re-read the row. Branch on status:
           * ``ready`` → return it.
           * ``building`` + ``builder_started_at`` recent → release lock,
             sleep, retry phase 1. This is the wait path: the loser blocks
             on the winner instead of running a duplicate builder.
           * ``building`` + stale (older than ``_builder_staleness_s``) →
             upsert ``status='building'`` with our timestamp and proceed
             to phase 2. Stale rows mean the prior worker crashed or was
             SIGKILLed; we take over.
           * no row, ``failed``, or legacy ``pending`` → upsert
             ``status='building'``, set ``builder_started_at = NOW()``,
             release lock, proceed to phase 2.
      2. **Build** — call ``builder()`` with no DB session held. The
         bundle has ``contract_name``, ``analysis``, ``tracking_plan``,
         and optionally ``predicate_trees``. Blob uploads (if storage
         is configured) happen here too.
      3. **Write** — open a fresh session, take the advisory lock, recheck
         (a concurrent fresh-takeover may have written ``status='ready'``
         while our builder was running — serve theirs, drop ours), else
         upsert to ``status='ready'``, commit.

    Why this shape: the original design released the lock between phase 1
    and phase 2 to avoid keeping a PG connection idle for the multi-minute
    builder (which trips Neon's pooler-side SSL idle timeout). But it
    persisted *nothing* about in-flight builds, so two callers racing
    through phase 1 within the build window both ran the builder — wasted
    60-150 s of CPU per collision. The ``status='building'`` claim row +
    ``builder_started_at`` lets the second caller wait on the first, while
    the staleness check keeps a crashed worker from wedging the cache.

    On builder failure, a fresh session writes a ``status='failed'`` row
    with the exception text so an operator can triage, then re-raises.

    On a blob upload failure the exception propagates without writing a
    row — better to leave nothing committed than a row pointing at a
    blob key the bucket doesn't have.
    """
    chain_norm, addr_norm, keccak_norm = _normalize(chain, address, bytecode_keccak)
    staleness_s = _builder_staleness_s()
    poll_interval_s = _wait_poll_interval_s()

    # Computed lazily and at most once, only when we are about to build (a keccak
    # miss). Kept off the cheap keccak-hit path so a same-chain re-run pays
    # nothing extra.
    _src = {"done": False, "hash": None}  # type: dict[str, Any]

    def _get_source_hash() -> str | None:
        if not _src["done"]:
            _src["done"] = True
            if source_hash_fn is not None:
                try:
                    _src["hash"] = source_hash_fn()
                except Exception as exc:
                    # A hash-computation failure must never fail-stop the build —
                    # it only disables cross-chain reuse for this call.
                    logger.debug("contract_materializations: source_hash_fn failed: %s", exc)
                    _src["hash"] = None
        return _src["hash"]

    # ── Phase 1: ready check / claim under a short-lived lock ──────
    # Loop: a ``status='building'`` row from another caller sends us to
    # sleep+retry until that caller transitions us to ``ready`` (cache
    # hit return) or the row goes stale (we take over).
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
            # An old-version 'ready' row falls through to the claim below and
            # is rebuilt; its status is overwritten to 'building' then 'ready'
            # with the current version in phase 3.

            if row is not None and row.status == "building":
                started = row.builder_started_at
                age_s = (
                    (datetime.now(timezone.utc) - started).total_seconds() if started is not None else staleness_s + 1
                )
                if age_s < staleness_s and time.monotonic() < wait_deadline:
                    # Active builder elsewhere — release the lock and poll.
                    session.commit()
                    time.sleep(poll_interval_s)
                    continue
                # Fall through: take over (insert/update our claim).
                logger.info(
                    "contract_materializations: taking over stale building row for %s:%s (age=%.1fs)",
                    chain_norm,
                    keccak_norm,
                    age_s,
                )

            # Cross-chain code-plane reuse: before claiming a build, see whether
            # an identical verified-source set was already analyzed under any
            # ``(chain, keccak)``. Per-chain immutables make this deployment's
            # keccak miss, but the source-derived bundle is reusable, so we copy
            # it into this ``(chain, keccak)`` row and skip the forge/Slither
            # build entirely. Runs under our advisory lock (we hold the
            # ``(chain, keccak)`` lock), so the write races cleanly with siblings.
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

            # Claim: upsert ``status='building'`` and record our start time.
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

    # ── Phase 2: builder + blob uploads, no DB connection held ─────
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
                analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="contract_materializations_pkey",
                set_={
                    "status": "failed",
                    "error": err,
                    "builder_started_at": None,
                    "source_content_hash": stmt.excluded.source_content_hash,
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
        # Blob uploads happen before reacquiring the PG lock so a slow
        # Tigris PUT doesn't push us back into idle-connection territory.
        # On failure, propagate without writing a row — the next caller
        # retries the build cleanly.
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

    # ── Phase 3: write under a short-lived lock ────────────────────
    with SessionLocal() as session:
        _advisory_lock(session, chain_norm, keccak_norm)

        # Recheck: a stale-takeover caller may have raced past phase 1
        # with us and committed first. Their bundle is keccak-equivalent
        # (same bytecode → same static analysis), so we serve it and
        # discard ours.
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
                "analysis_schema_version": stmt.excluded.analysis_schema_version,
                "materialized_at": func.now(),
                "updated_at": func.now(),
            },
        )
        session.execute(stmt)
        session.commit()
        # Phase 1's claim already loaded the row into the identity map
        # with ``status='building'``; ``expire_all`` forces the next read
        # to refetch the row's columns from Postgres so callers see the
        # post-upsert state (``status='ready'``, predicate_trees, …).
        session.expire_all()

        ready = session.execute(
            select(ContractMaterialization).where(
                ContractMaterialization.chain == chain_norm,
                ContractMaterialization.bytecode_keccak == keccak_norm,
            )
        ).scalar_one()
        return ready
