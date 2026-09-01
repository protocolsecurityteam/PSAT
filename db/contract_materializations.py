"""Cross-job, cross-process materialization cache.

A row per ``(chain, bytecode_keccak)`` holding the static static_facts +
tracking-plan bundle so two impl jobs requesting the same contract pay
the expensive forge+Slither cost exactly once. Concurrent requests are
serialized via ``pg_advisory_xact_lock(hashtext(chain || ':' || keccak))``:
the lock winner runs the builder; the loser blocks on the lock, finds
``status='ready'`` on its second read, and returns the cached bundle
without rebuilding.

The module is deliberately small and stateless — every entry point opens
its own short-lived session so the caller doesn't have to share its DB
connection with potentially blocking advisory locks.

The ``chain`` key is always the canonical decimal-string chain id (``"1"``,
``"8453"``): callers may pass a chain name, alias, id,
or ``None``, and :func:`utils.chains.chain_cache_token` collapses them all
onto the id token so a name-keyed writer and an id-keyed reader hit the
same row. ``None``/empty resolves to the mainnet token ``"1"``, matching
how ``Job.request['chain']`` defaults.

Bundle storage: the ``static_facts`` and ``observation_plan`` payloads can be
multi-megabyte JSON blobs (a Compound-v3-class contract static_facts is
~5-20 MB). Postgres JSONB stores fine but detoasts on every read,
inflates page-cache pressure on this hot table, and slows backup /
dump / restore. The schema therefore carries paired columns:

  - ``static_facts`` (JSONB) and ``static_facts_blob_key`` (Text)
  - ``observation_plan`` (JSONB) and ``observation_plan_blob_key`` (Text)

When object storage is configured (``ARTIFACT_STORAGE_*`` env vars set,
``db.storage.get_storage_client()`` returns non-None) new writes go to
blob storage and the JSONB columns are persisted as NULL. The blob_key
columns are then the source of truth. When storage is unconfigured
(local dev, offline tests without minio) writes fall back to inline
JSONB and blob_key is NULL.

Reads are always handled by ``hydrate_static_facts`` / ``hydrate_observation_plan``
which try the blob first and transparently fall back to inline JSONB.
That fallback is what lets pre-migration rows keep working while the
materialization writes
catches up — and what insulates the pipeline from a transient Tigris
outage when the inline copy still exists. When it does not, the read
raises ``StorageContentIncomplete``: "the bucket could not answer" and
"this row stored nothing" are different facts, and the caller
(``services/resolution/recursive``) turns the second into an empty
static_facts that the effects probe is then seeded from.
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

# Analyzer/pipeline schema version stamped on every materialized row. The read
# paths (``find_by_keccak``/``find_by_address``/``materialize_or_wait``) only
# serve a row whose ``static_facts_schema_version`` equals this constant, so a row
# written by an older analyzer reads as a miss and is rebuilt. Bump by hand only
# when the static-static_facts / tracking-plan / predicate-tree *output shape*
# changes — deliberately NOT tied to a git SHA, which would cold-rebuild every
# multi-MB forge+Slither bundle on unrelated deploys (frontend, docs, workers).
# v2: the effects sink emitter resolves a library-wrapped/cast token receiver to
# the state var it aliases (was a Slither temporary) and records a canonical
# selector for a UDT-param direct call — both change the persisted sink shape, so
# an existing deployment must rebuild rather than serve materializations written
# against the old heads.
# v3: ``computed`` operands carry ``derived_from`` (the origins that reached the
# value through the arguments of the computation that produced it), so the
# predicate-tree output shape changed. Without this bump a materialized row keeps
# serving trees in which a hash-commitment gate is unbound from the parameters it
# commits, and the fix never reaches any deployment already in the cache.
# v4: ``view_call`` / ``external_call`` operands now carry ``derived_from`` too,
# and an un-lowerable single-address-param SELF gate is emitted as an
# ``external_set`` descriptor instead of a bare-bool leaf. A v3 tree records
# neither, so its caller-tainted role gate still reads PUBLIC — the fix would
# never reach a deployment already in the cache. v4 also pins provenance frame
# purity: a parameter's origin set never unions other call sites' arguments
# (the entry-parameter Phi is excluded), so ``derived_from`` is frame-local.
# Both landed within the unreleased v4 window — no v4 row was ever
# materialized under the pre-purity shape (verified: local DB carries only
# v2/v3 rows; production runs pre-v4 code).
# Also in the same unreleased v4 window: operand
# tie-breaking is now cross-process stable — ``provenance._digest`` derives
# ``callee_args_digest`` from content instead of ``hash()``, so the operand
# slots that previously flickered with PYTHONHASHSEED settle to one canonical
# byte form. The tree SCHEMA gains and loses no key, but WHICH computed source
# wins a slot changes, and ``derived_from`` on the winner is a witness input:
# ``claims/matchers/_facts.param_constraints`` reads it to mint the
# destination-constraint fragment. The verdict movement is retreat-from-proof
# by construction (its magnitude is base-sample-dependent — the pre-fix
# tie-break varies even at a fixed seed); that and the cache non-bump
# decision are recorded at ``EFFECT_CACHE_SCHEMA_VERSION``
# (db/effect_cache.py), where the probe-input consumers live. Noted per the
# same-unreleased-version precedent rather than minting a version no row was
# ever written under.
# v5: an ``external_bool`` leaf carries ``authority_role='delegated_authority'``
# (and its ``external_set``/``authority_contract`` descriptor) only when the
# callee is GATE-SHAPED (view/pure/nonview_library, or the void-call
# ``bytes32[]`` merkle-witness carve-out) — a v4 tree still stamps delegated
# authority on value-movement calls (``permit(msg.sender,…)``,
# ``transferFrom(msg.sender,…)``, ``burnShares(msg.sender,…)``,
# ``vault.enter(msg.sender,…)``), and a materialized v4 row would keep minting
# the fabricated ``caller_gate`` controllers those leaves produced (PR-161:
# 21 controller rows, incl. wstETH published as a controller of
# WithdrawalQueueERC721). Result-checked const-compare external_bool leaves
# now also carry ``callee_state_mutability``/``callee_signature``/``gate_kind``.
# Same v5 window: pause-var classification requires a LATCH shape (bool flag;
# constant-toggle uint; a uint read by a revert-carrying modifier — directly
# or through a helper call; or a uint a non-writer's revert read compares for
# EQUALITY against a CONSTANT, tested on the predicate-leaf plane so
# polarity-folded if/revert custom-error gates, getter hops, and mask
# arithmetic all count, with a same-node IR fallback for degraded trees), so
# a governed duration like OZ TimelockController's ``_minDelay`` — whose
# revert read is RELATIONAL against a parameter — is no longer classified as
# a pause var, and its comparison leaves lose the ``authority_role='pause'``
# stamp v4 trees carried.
# Same v5 window: ``subject.source_verified`` carries the FETCH's verification fact
# out of ``contract_meta.json`` and has three states, where a v4 row holds a two-state
# boolean computed as ``bool(project_dir.rglob("src/**/*.sol"))`` — a Foundry-layout
# glob that published FALSE for 9 of 90 Etherscan-verified contracts on the 2026-07-28
# run (Lido, WithdrawalQueueERC721, two TimelockControllers, …), all of them analysed
# from that verified source in the same job. Serving a cached v4 subject would keep
# republishing that FALSE into ``contract_summaries.source_verified`` and the
# frontend's data-confidence axis; the version was already minted on this unreleased
# branch and this rides it.
# v6: predicate-tree operands carry the element-record fields — which base
# variable an element read is rooted in, the member path reached on it, and
# which parameter keys it. A v5 tree records none of them, and the self-service
# payout witness reads a missing base variable as "not determined", never as
# "not an element read" — so a served v5 tree would silently withhold the
# witness on every cached deployment while a rebuilt one proves it, which is a
# verdict that depends on cache age rather than on the code. Minted with the
# safety prep (index-based operand exclusion, element-aware operand ordering)
# so the shape change and its invalidation land together rather than thrashing
# through ``_bundle_differs``, which compares the whole serialized tree.
STATIC_FACTS_SCHEMA_VERSION = 8


# ── Provenance ─────────────────────────────────────────────────────────────
# Who established a row, and from what. Recorded because a materialization is
# the versioned store monitoring enrolls from: invariant 7 forbids a per-job
# artifact entering it without the source job written down, and once three
# producers exist "which one wrote this" stops being reconstructable.
PRODUCED_BY_RESOLUTION = "resolution"
PRODUCED_BY_PIPELINE = "pipeline"
PRODUCED_BY_PROMOTION_SWEEP = "promotion_sweep"

# What :func:`publish_materialization` did, as a token the caller reports.
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
    """The provenance stamp for one row write.

    ``source_job_id`` is written even when it is None: the producer is known
    and the job is not, and those are two different facts. A NULL
    ``provenance`` column means no producer was recorded at all.
    """
    return {
        "produced_by": produced_by,
        "source_job_id": str(source_job_id) if source_job_id is not None else None,
        "materialized_at": (now or datetime.now(timezone.utc)).isoformat(),
    }


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


def _normalize(chain: str | int | None, address: str, bytecode_keccak: str) -> tuple[str, str, str]:
    return (
        chain_cache_token(chain),
        address.lower(),
        bytecode_keccak.lower() if bytecode_keccak.startswith("0x") else "0x" + bytecode_keccak.lower(),
    )


def _blob_key(chain_norm: str, keccak_norm: str, kind: str) -> str:
    """Deterministic blob key for an static_facts/observation_plan payload.

    ``kind`` is the payload name without extension (``"static_facts"`` or
    ``"observation_plan"``). Includes the PR-preview prefix from
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

    Non-ready rows are not returned. Rows stamped with a different
    ``static_facts_schema_version`` are likewise skipped (read as a miss) so
    a bumped analyzer rebuilds rather than serving a stale bundle.
    """
    chain_norm = chain_cache_token(chain)
    keccak_norm = bytecode_keccak.lower() if bytecode_keccak.startswith("0x") else "0x" + bytecode_keccak.lower()
    row = session.execute(
        select(ContractMaterialization).where(
            ContractMaterialization.chain == chain_norm,
            ContractMaterialization.bytecode_keccak == keccak_norm,
            ContractMaterialization.status == "ready",
            ContractMaterialization.static_facts_schema_version == STATIC_FACTS_SCHEMA_VERSION,
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
    different ``static_facts_schema_version`` reads as a miss so a bumped
    analyzer rebuilds rather than serving a stale bundle.
    """
    chain_norm = chain_cache_token(chain)
    addr_norm = address.lower()
    row = session.execute(
        select(ContractMaterialization).where(
            ContractMaterialization.chain == chain_norm,
            ContractMaterialization.address == addr_norm,
            ContractMaterialization.status == "ready",
            ContractMaterialization.static_facts_schema_version == STATIC_FACTS_SCHEMA_VERSION,
        )
    ).scalar_one_or_none()
    return row


def _hydrate(row: ContractMaterialization, *, blob_key_attr: str, inline_attr: str) -> dict | None:
    """Generic blob-or-inline read for static_facts / observation_plan columns.

    Three outcomes, and a caller can tell them apart — which is the whole point,
    because this function's output *is* the static_facts state the resolution stage
    reasons over and the effects probe is seeded from:

      * a ``dict`` — **proven present**: read from the blob, or from the inline
        JSONB when the blob is unreadable but inline holds a (possibly stale)
        copy. Serving stale beats crashing the pipeline, and it is still a real
        payload rather than a claim about the subject.
      * ``None`` — **proven absent**: the row records no blob key *and* no
        inline payload, so nothing was ever stored for this column. On the
        working DB this is exactly the 6 ``status='failed'`` rows, where no
        static_facts was ever produced.
      * ``StorageContentIncomplete`` — the row records a blob key and we could
        not obtain its content, with no inline fallback. Returning ``None`` here
        is what let a bucket outage read as "this contract has no static_facts, no
        plan, no predicate trees" at ``services/resolution/recursive`` — and that
        verdict then gets cached as a witness. Which subclass says why, and the
        type is the only thing ``workers.retry_policy`` sees:
        ``StorageContentAbsent`` when the bucket answered and holds no such
        object (determined — a retry re-asks an answered question), else
        ``StorageContentNotDetermined`` (unreachable, unconfigured, corrupt).

    Callers that need to mutate the returned dict should ``copy.deepcopy``
    it themselves — the inline JSONB read returns the ORM-cached dict
    and mutations would leak across rows.
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
        # blob_key set but storage unconfigured (e.g. an env that turned
        # ARTIFACT_STORAGE_* off after the row was written). We cannot ask.
        reason = "storage is not configured"
    else:
        try:
            body = client.get(blob_key)
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
            # The serializer always emits JSON objects for these
            # payloads; a non-dict is corruption, not a normal case.
            reason = f"blob decoded to {type(parsed).__name__}, expected dict"
        except StorageKeyMissing as exc:
            # The bucket was asked about every candidate and holds none of them.
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


def hydrate_static_facts(row: ContractMaterialization) -> dict | None:
    """Load the row's ``static_facts`` payload, transparently picking the
    blob path when ``static_facts_blob_key`` is set and falling back to the
    inline JSONB column otherwise. ``None`` means the row genuinely
    has no static_facts (nothing was ever stored — the ``status='failed'``
    corner case). Raises ``StorageContentIncomplete`` when a blob key is
    recorded but its content cannot be obtained: that is not the same fact and
    must not reach a consumer as an empty static_facts."""
    return _hydrate(row, blob_key_attr="static_facts_blob_key", inline_attr="static_facts")


def hydrate_observation_plan(row: ContractMaterialization) -> dict | None:
    """Symmetric to ``hydrate_static_facts`` for ``observation_plan``, including the
    ``StorageContentIncomplete`` third state."""
    return _hydrate(row, blob_key_attr="observation_plan_blob_key", inline_attr="observation_plan")


def hydrate_predicate_trees(row: ContractMaterialization) -> dict | None:
    """Load the row's predicate-tree artifact (semantic source of truth
    for revert/auth guards). Returns None if the cache row predates the
    predicate-pipeline migration (pre-c1d2e3f4a5b6) so callers can fall
    back to rebuilding the artifact from the static_facts dict if they need
    mapping-writer enumeration. Raises ``StorageContentIncomplete`` when the
    row records a blob key whose content cannot be obtained — "written before
    the migration" and "the bucket is down" are different facts and the
    fallback is only correct for the first."""
    return _hydrate(row, blob_key_attr="predicate_trees_blob_key", inline_attr="predicate_trees")


def hydrate_effects(row: ContractMaterialization) -> dict | None:
    """Load the low-level effects input required to rebuild nested permissions."""

    return row.effects if isinstance(row.effects, dict) else None


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
            ContractMaterialization.static_facts_schema_version == STATIC_FACTS_SCHEMA_VERSION,
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
        static_facts=donor.static_facts,
        observation_plan=donor.observation_plan,
        predicate_trees=donor.predicate_trees,
        effects=donor.effects,
        static_facts_blob_key=donor.static_facts_blob_key,
        observation_plan_blob_key=donor.observation_plan_blob_key,
        predicate_trees_blob_key=donor.predicate_trees_blob_key,
        source_content_hash=source_content_hash,
        status="ready",
        error=None,
        builder_started_at=None,
        # The donor's bundle, recorded as this row's own provenance: the copy is
        # the recursion's write, and which row it came from is the fact that
        # would otherwise be unreconstructable.
        provenance={
            **build_provenance(PRODUCED_BY_RESOLUTION),
            "reused_from": {"chain": donor.chain, "bytecode_keccak": donor.bytecode_keccak},
        },
        static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
    )
    stmt = pg_insert(ContractMaterialization).values(**values)
    stmt = stmt.on_conflict_do_update(
        constraint="contract_materializations_pkey",
        set_={
            "address": stmt.excluded.address,
            "contract_name": stmt.excluded.contract_name,
            "static_facts": stmt.excluded.static_facts,
            "observation_plan": stmt.excluded.observation_plan,
            "predicate_trees": stmt.excluded.predicate_trees,
            "effects": stmt.excluded.effects,
            "static_facts_blob_key": stmt.excluded.static_facts_blob_key,
            "observation_plan_blob_key": stmt.excluded.observation_plan_blob_key,
            "predicate_trees_blob_key": stmt.excluded.predicate_trees_blob_key,
            "source_content_hash": stmt.excluded.source_content_hash,
            "status": "ready",
            "error": None,
            "builder_started_at": None,
            "provenance": stmt.excluded.provenance,
            "static_facts_schema_version": stmt.excluded.static_facts_schema_version,
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
           * no row or ``failed`` → upsert
             ``status='building'``, set ``builder_started_at = NOW()``,
             release lock, proceed to phase 2.
      2. **Build** — call ``builder()`` with no DB session held. The
         bundle has ``contract_name``, ``static_facts``, ``observation_plan``,
         and optionally ``predicate_trees`` and ``effects``. Blob uploads (if storage
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
            if (
                row is not None
                and row.status == "ready"
                and row.static_facts_schema_version == STATIC_FACTS_SCHEMA_VERSION
            ):
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
                static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
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
        if not all(isinstance(bundle.get(name), dict) for name in ("static_facts", "observation_plan", "effects")):
            raise ValueError("materialization builder returned an incomplete semantic bundle")
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
                static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
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

    analysis_payload = bundle.get("static_facts")
    observation_plan_payload = bundle.get("observation_plan")
    predicate_trees_payload = bundle.get("predicate_trees")
    effects_payload = bundle.get("effects")
    static_facts_blob_key: str | None = None
    observation_plan_blob_key: str | None = None
    predicate_trees_blob_key: str | None = None
    analysis_inline: dict | None = analysis_payload if isinstance(analysis_payload, dict) else None
    observation_plan_inline: dict | None = (
        observation_plan_payload if isinstance(observation_plan_payload, dict) else None
    )
    predicate_trees_inline: dict | None = predicate_trees_payload if isinstance(predicate_trees_payload, dict) else None
    effects_inline: dict | None = effects_payload if isinstance(effects_payload, dict) else None

    client = get_storage_client()
    if client is not None:
        # Blob uploads happen before reacquiring the PG lock so a slow
        # Tigris PUT doesn't push us back into idle-connection territory.
        # On failure, propagate without writing a row — the next caller
        # retries the build cleanly.
        if analysis_inline is not None:
            static_facts_blob_key = _blob_key(chain_norm, keccak_norm, "static_facts")
            _put_blob(client, static_facts_blob_key, analysis_inline)
            analysis_inline = None
        if observation_plan_inline is not None:
            observation_plan_blob_key = _blob_key(chain_norm, keccak_norm, "observation_plan")
            _put_blob(client, observation_plan_blob_key, observation_plan_inline)
            observation_plan_inline = None
        if predicate_trees_inline is not None:
            predicate_trees_blob_key = _blob_key(chain_norm, keccak_norm, "predicate_trees")
            _put_blob(client, predicate_trees_blob_key, predicate_trees_inline)
            predicate_trees_inline = None

    # ── Phase 3: write under a short-lived lock ────────────────────
    with SessionLocal() as session:
        _advisory_lock(session, chain_norm, keccak_norm)

        # Recheck: a stale-takeover caller may have raced past phase 1
        # with us and committed first. Their bundle is keccak-equivalent
        # (same bytecode → same static static_facts), so we serve it and
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
            and existing.static_facts_schema_version == STATIC_FACTS_SCHEMA_VERSION
        ):
            session.commit()
            return existing

        stmt = pg_insert(ContractMaterialization).values(
            chain=chain_norm,
            bytecode_keccak=keccak_norm,
            address=addr_norm,
            contract_name=bundle.get("contract_name"),
            static_facts=analysis_inline,
            observation_plan=observation_plan_inline,
            predicate_trees=predicate_trees_inline,
            effects=effects_inline,
            static_facts_blob_key=static_facts_blob_key,
            observation_plan_blob_key=observation_plan_blob_key,
            predicate_trees_blob_key=predicate_trees_blob_key,
            source_content_hash=_src["hash"],
            status="ready",
            builder_started_at=None,
            # No source job: the recursion materializes whatever dependency it
            # walks onto, so the job that happens to be walking is not the job
            # this bundle is *of*. The producer is known, the job is not, and
            # the stamp says exactly that.
            provenance=build_provenance(PRODUCED_BY_RESOLUTION),
            static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="contract_materializations_pkey",
            set_={
                "status": "ready",
                "contract_name": stmt.excluded.contract_name,
                "static_facts": stmt.excluded.static_facts,
                "observation_plan": stmt.excluded.observation_plan,
                "predicate_trees": stmt.excluded.predicate_trees,
                "effects": stmt.excluded.effects,
                "static_facts_blob_key": stmt.excluded.static_facts_blob_key,
                "observation_plan_blob_key": stmt.excluded.observation_plan_blob_key,
                "predicate_trees_blob_key": stmt.excluded.predicate_trees_blob_key,
                "source_content_hash": stmt.excluded.source_content_hash,
                "address": stmt.excluded.address,
                "error": None,
                "builder_started_at": None,
                "provenance": stmt.excluded.provenance,
                "static_facts_schema_version": stmt.excluded.static_facts_schema_version,
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


def _publish_blobs(
    chain_norm: str,
    keccak_norm: str,
    static_facts: dict,
    observation_plan: dict,
    predicate_trees: dict | None,
) -> tuple[dict | None, dict | None, dict | None, str | None, str | None, str | None]:
    """Upload the bundle when storage is configured; else keep it inline.

    Returns ``(analysis_inline, observation_plan_inline, predicate_trees_inline,
    analysis_key, observation_plan_key, predicate_trees_key)`` — the same
    inline-or-blob split ``materialize_or_wait`` phase 2 produces. Upload
    failures propagate: a row pointing at a key the bucket does not have reads
    as "this contract's payload could not be produced" forever after.
    """
    client = get_storage_client()
    if client is None:
        return static_facts, observation_plan, predicate_trees, None, None, None
    analysis_key = _blob_key(chain_norm, keccak_norm, "static_facts")
    _put_blob(client, analysis_key, static_facts)
    observation_plan_key = _blob_key(chain_norm, keccak_norm, "observation_plan")
    _put_blob(client, observation_plan_key, observation_plan)
    predicate_trees_key: str | None = None
    if predicate_trees is not None:
        predicate_trees_key = _blob_key(chain_norm, keccak_norm, "predicate_trees")
        _put_blob(client, predicate_trees_key, predicate_trees)
    return None, None, None, analysis_key, observation_plan_key, predicate_trees_key


def publish_materialization(
    *,
    chain: str | int | None,
    address: str,
    bytecode_keccak: str,
    contract_name: str | None,
    static_facts: dict | None,
    observation_plan: dict | None,
    predicate_trees: dict | None = None,
    effects: dict | None = None,
    source_content_hash: str | None = None,
    provenance: dict[str, Any],
    refresh_on_differ: bool = False,
) -> str:
    """Write a ready row for an ALREADY-BUILT bundle. Returns an outcome token.

    The producer-side counterpart to :func:`materialize_or_wait`: that function
    exists to *build* a bundle under request coalescing, this one exists to
    *record* one the caller already holds — the main pipeline's own static_facts
    artifacts (F4a), or a completed job's artifacts promoted into the versioned
    store (F4b). Coverage then follows from static_facts having run, instead of from
    which dependencies the authority recursion happened to visit.

    **Fill-or-refresh, never a downgrade.** Any row that is not ready at the
    current schema version is written outright — absent, ``failed``,
    superseded, or ``building``. Overwriting a live ``building`` claim is safe
    and deliberate: that builder's phase-3 recheck finds our ready row and
    discards its own duplicate build, which is the same coalescing
    ``materialize_or_wait`` performs between two builders.

    A ready row at the current schema version is compared, not assumed:

    * ``refresh_on_differ=True`` — the caller's bundle was PRODUCED BY THE CALLER
      under the current analyzer, so where it DIFFERS from the stored bundle it
      is the later record and the row is refreshed (``refreshed``). Identical
      bytecode does not imply an identical bundle: the analyzer improves without
      every improvement earning an ``STATIC_FACTS_SCHEMA_VERSION`` bump (a bump
      invalidates the whole fleet at once and bills a re-static_facts of it), so
      without this a ready row is frozen forever and later analyzer work never
      reaches the store it was written to.
    * ``refresh_on_differ=False`` — the caller is passing on a bundle SOMEONE
      ELSE produced earlier: the promotion sweep's older job artifact, or a
      static-cache job's copy of an ancestor's. Same era is not the same as
      later, and two such callers that disagree would take turns overwriting
      each other forever, so the stored row stands.

    Either way an identical bundle returns ``already_current`` and touches
    nothing — including the blobs, which is why the comparison happens under the
    lock, before any upload. And a ready row's ``address`` is never flipped to
    ours: that would move the row out from under the address already resolving
    to it.

    Refusals, each a fact the caller reports rather than a silent no-op:

    ``incomplete_bundle``
        No static_facts or no tracking plan. A ready row whose ``static_facts`` is
        absent reads to the resolution stage as *this contract has no static_facts*
        — a claim about the contract that a missing artifact never made.
    ``keccak_bound_to_other_address``
        A ready current row for this bytecode already names a different
        address. One row per ``(chain, keccak)`` is the table's key, so this
        address cannot be served by address lookup; saying so is honest, and
        stealing the row is not.
    ``address_bound_to_other_keccak``
        Another row already holds ``(chain, address)`` under a different
        keccak (``uq_contract_materializations_chain_address``). Which bytecode
        is current at that address is not something this writer witnessed, so
        it does not overwrite the other row's claim.
    """
    if not isinstance(static_facts, dict) or not isinstance(observation_plan, dict) or not isinstance(effects, dict):
        return PUBLISH_INCOMPLETE_BUNDLE

    chain_norm, addr_norm, keccak_norm = _normalize(chain, address, bytecode_keccak)
    written = PUBLISH_WRITTEN

    # One lock spans decide → upload → write. Holding it across the upload is
    # what makes ``already_current`` mean what it says: deciding first and
    # uploading second is the only order in which a row we decline to touch also
    # keeps the payload it had. Unlike ``materialize_or_wait``, no builder runs
    # inside this lock — the payload is already in memory and the uploads are a
    # few PUTs, not the multi-minute forge+Slither pass the lock-release dance in
    # that function exists to keep a connection out of.
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
            if not refresh_on_differ or not _bundle_differs(
                existing, static_facts, observation_plan, predicate_trees, effects
            ):
                session.commit()
                return PUBLISH_ALREADY_CURRENT
            written = PUBLISH_REFRESHED
        elif outcome is not None:
            session.commit()
            return outcome

        # Re-checked here rather than only before the lock: the row that owns
        # ``(chain, address)`` can appear between the two, and the unique index
        # would then fail the insert instead of reporting the collision.
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
        ) = _publish_blobs(chain_norm, keccak_norm, static_facts, observation_plan, predicate_trees)

        stmt = pg_insert(ContractMaterialization).values(
            chain=chain_norm,
            bytecode_keccak=keccak_norm,
            address=addr_norm,
            contract_name=contract_name,
            static_facts=analysis_inline,
            observation_plan=plan_inline,
            predicate_trees=trees_inline,
            effects=effects,
            static_facts_blob_key=analysis_key,
            observation_plan_blob_key=plan_key,
            predicate_trees_blob_key=trees_key,
            source_content_hash=source_content_hash,
            status="ready",
            error=None,
            builder_started_at=None,
            provenance=provenance,
            static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="contract_materializations_pkey",
            set_={
                "address": stmt.excluded.address,
                "contract_name": stmt.excluded.contract_name,
                "static_facts": stmt.excluded.static_facts,
                "observation_plan": stmt.excluded.observation_plan,
                "predicate_trees": stmt.excluded.predicate_trees,
                "effects": stmt.excluded.effects,
                "static_facts_blob_key": stmt.excluded.static_facts_blob_key,
                "observation_plan_blob_key": stmt.excluded.observation_plan_blob_key,
                "predicate_trees_blob_key": stmt.excluded.predicate_trees_blob_key,
                "source_content_hash": stmt.excluded.source_content_hash,
                "status": "ready",
                "error": None,
                "builder_started_at": None,
                "provenance": stmt.excluded.provenance,
                "static_facts_schema_version": stmt.excluded.static_facts_schema_version,
                "materialized_at": func.now(),
                "updated_at": func.now(),
            },
        )
        session.execute(stmt)
        session.commit()
    return written


def _bundle_differs(
    existing: ContractMaterialization | None,
    static_facts: dict,
    observation_plan: dict,
    predicate_trees: dict | None,
    effects: dict | None,
) -> bool:
    """Does the stored bundle say something other than the caller's?

    Compared on the serialized payloads, which is what a consumer reads. An
    unreadable stored payload counts as DIFFERING: "the same" is a positive
    claim, and a bucket that cannot answer has not made it. Refreshing on that
    answer is safe — the caller's bundle is complete by the time we are here.
    """
    if existing is None:
        return True
    try:
        stored = (
            hydrate_static_facts(existing),
            hydrate_observation_plan(existing),
            hydrate_predicate_trees(existing),
            hydrate_effects(existing),
        )
    except Exception as exc:
        logger.info(
            "contract_materializations: %s/%s stored bundle unreadable (%s); treating as differing",
            getattr(existing, "chain", "?"),
            getattr(existing, "address", "?"),
            exc,
        )
        return True
    return [_canonical(p) for p in stored] != [
        _canonical(p) for p in (static_facts, observation_plan, predicate_trees, effects)
    ]


def _canonical(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return json.dumps(payload, sort_keys=True, default=str)


def builder_claim_is_stale(status: str | None, builder_started_at: datetime | None) -> bool:
    """Is a ``building`` claim old enough that no builder is presumed behind it?

    Same rule ``materialize_or_wait`` phase 1 takes over on
    (:func:`_builder_staleness_s`), exported so the reconciler's census counts a
    crashed worker's leftover claim as a row to rebuild rather than reporting
    "a builder is running" about a process that died.
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
    """The outcome when *existing* forbids a write, else None.

    One implementation for every read of "already current" so they cannot drift.
    """
    if existing is None:
        return None
    if existing.status != "ready" or existing.static_facts_schema_version != STATIC_FACTS_SCHEMA_VERSION:
        return None
    if (existing.address or "").lower() != addr_norm:
        return PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS
    return PUBLISH_ALREADY_CURRENT
