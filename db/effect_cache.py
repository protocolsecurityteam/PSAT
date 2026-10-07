"""Effect-verdict cache with kernel-vs-projection scope and a self-audit.

Mirrors ``db/contract_materializations.py`` (schema-version invalidation, advisory-lock coalescing, cross-job and
cross-chain reuse), minus the blob split since verdicts are small.

* kernel: function-local verdicts (latch flip, gate mutation, code change, supply sign, destination shape), keyed on the
resolved-function hash with an empty surface sentinel; transfers across every deployment sharing it.
* projection: contract-scoped (blast radius, authorization delta), also keyed on the whole-contract surface hash.

Concrete per-deployment values are never keys; they live in ``effect_verdicts``. The self-audit
(``kernel_verdicts_agree``) re-simulates the second sighting of a kernel hash before trusting it, catching hash
collisions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, case, func, null, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import EffectBehaviorCache, EffectiveFunction, EffectVerdict
from utils.logging import record_degraded

logger = logging.getLogger(__name__)


class EffectVerdictUnlinked(Exception):
    """A verdict persisted with no ``function_id`` because the function row vanished mid-write.

    Only constructed for ``record_degraded``; the write succeeded, unlinked.
    """


# Bump to invalidate every stored verdict when the verdict output shape or anything the probe's input is built from
# changes (claim witnesses, predicate trees, candidate ordering, plane splits). Not tied to a git SHA, so unrelated
# deploys don't cold-miss. The reason for each bump is in the commit history; if a change moves a probe input and you
# decide not to bump, record why in the commit.
EFFECT_CACHE_SCHEMA_VERSION = 38

# A sentinel rather than NULL keeps the UniqueConstraint portable; matches ``server_default=""``.
KERNEL_SURFACE_SENTINEL = ""

AUDIT_PASSED = "passed"
AUDIT_FAILED = "failed"

# Residue keys that are probing bookkeeping rather than observations. They survive a verdict flip, or an unreproducible
# deployment would get a fresh re-probe budget forever.
RESIDUE_BOOKKEEPING_KEYS = ("destination_probe_attempts",)

# Columns excluded from replay identity. This cache mutates on read (``bump_hit``/``mark_audited`` from
# ``workers/effects_worker.py``), so identical runs over an unchanged chain leave different rows;
# ``scripts/determinism_gate.sh`` can't see it. Accepted: these are probing bookkeeping nothing user-facing reads, and
# ``audit_status`` must persist so a caught collision isn't re-trusted. Replay checks must compare modulo these.
#
# ``hit_count`` counts times served as a trusted hit; misses are per-job ``cache_misses`` metrics.
REPLAY_IDENTITY_EXCLUDED_COLUMNS = (
    "hit_count",
    "audit_status",
    "audit_peer_hash",
    "audited_at",
    "updated_at",
)

# Same for ``observed_residue``: re-probe bookkeeping that decides the next run's probe set.
REPLAY_IDENTITY_EXCLUDED_RESIDUE_KEYS = RESIDUE_BOOKKEEPING_KEYS


def _lock_key(behavior_hash: str, effect_class: str, scope: str, surface: str, gate_ref: str) -> str:
    return f"effect:{behavior_hash}:{effect_class}:{scope}:{surface}:{gate_ref}"


def _advisory_lock(session: Session, key: str) -> None:
    """Serialize writers for one identity via ``pg_advisory_xact_lock(hashtext(...))``."""
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})


def find_cached_verdict(
    session: Session,
    *,
    behavior_hash: str,
    effect_class: str,
    scope: str,
    contract_surface_hash: str = KERNEL_SURFACE_SENTINEL,
    gate_ref: str = "",
) -> EffectBehaviorCache | None:
    """The current-version cached verdict for this identity, or ``None``.

    Stale ``analysis_schema_version`` rows read as a miss.
    """
    surface = contract_surface_hash if scope != "kernel" else KERNEL_SURFACE_SENTINEL
    return session.execute(
        select(EffectBehaviorCache).where(
            EffectBehaviorCache.behavior_hash == behavior_hash,
            EffectBehaviorCache.effect_class == effect_class,
            EffectBehaviorCache.scope == scope,
            EffectBehaviorCache.contract_surface_hash == surface,
            EffectBehaviorCache.gate_ref == gate_ref,
            EffectBehaviorCache.analysis_schema_version == EFFECT_CACHE_SCHEMA_VERSION,
        )
    ).scalar_one_or_none()


def find_cached_verdicts_batch(
    session: Session,
    identities: "Any",
) -> dict[tuple[str, str, str, str, str], EffectBehaviorCache]:
    """Batch :func:`find_cached_verdict` for a job's plans in one composite ``IN`` query.

    ``identities`` are ``(behavior_hash, effect_class, scope, contract_surface_hash, gate_ref)``; results are keyed by
    the normalized identity (kernel scope uses :data:`KERNEL_SURFACE_SENTINEL`). Same version gate; at most one row per
    key.
    """
    keys: set[tuple[str, str, str, str, str]] = set()
    for behavior_hash, effect_class, scope, surface, gate_ref in identities:
        surf = surface if scope != "kernel" else KERNEL_SURFACE_SENTINEL
        keys.add((behavior_hash, effect_class, scope, surf, gate_ref))
    if not keys:
        return {}
    rows = (
        session.execute(
            select(EffectBehaviorCache).where(
                tuple_(
                    EffectBehaviorCache.behavior_hash,
                    EffectBehaviorCache.effect_class,
                    EffectBehaviorCache.scope,
                    EffectBehaviorCache.contract_surface_hash,
                    EffectBehaviorCache.gate_ref,
                ).in_(list(keys)),
                EffectBehaviorCache.analysis_schema_version == EFFECT_CACHE_SCHEMA_VERSION,
            )
        )
        .scalars()
        .all()
    )
    return {(r.behavior_hash, r.effect_class, r.scope, r.contract_surface_hash, r.gate_ref): r for r in rows}


def find_verdict_residue_batch(
    session: Session,
    *,
    chain_id: int,
    identities: "Any",
) -> dict[tuple[str, str, str], tuple[str | None, bool | None, dict[str, Any] | None]]:
    """Persisted state-plane residue for deployment identities ``(contract_address, selector, effect_class)``, as
    ``{identity: (concrete_destination, current_check_passed, observed_residue)}``. Absent keys have no row.
    Batched because it's asked once per job about every cache hit (a hit carries no residue of its own).
    """
    keys: set[tuple[str, str, str]] = set()
    for address, selector, effect_class in identities:
        keys.add((address.lower(), selector or "", effect_class))
    if not keys:
        return {}
    rows = session.execute(
        select(
            EffectVerdict.contract_address,
            EffectVerdict.selector,
            EffectVerdict.effect_class,
            EffectVerdict.concrete_destination,
            EffectVerdict.current_check_passed,
            EffectVerdict.observed_residue,
        ).where(
            EffectVerdict.chain_id == chain_id,
            tuple_(
                EffectVerdict.contract_address,
                EffectVerdict.selector,
                EffectVerdict.effect_class,
            ).in_(list(keys)),
        )
    ).all()
    return {(r[0], r[1], r[2]): (r[3], r[4], r[5]) for r in rows}


def upsert_cached_verdict(
    session: Session,
    *,
    behavior_hash: str,
    effect_class: str,
    scope: str,
    verdict: str,
    tier: str,
    contract_surface_hash: str = KERNEL_SURFACE_SENTINEL,
    gate_ref: str = "",
    transcript_ptr: str | None = None,
    details: dict[str, Any] | None = None,
    audit_status: str | None = None,
    audit_peer_hash: str | None = None,
) -> EffectBehaviorCache:
    """Write or refresh a code-plane verdict row under an advisory lock.

    ``gate_ref`` names gate structure, never an address; concurrent writers coalesce on the unique constraint.
    """
    surface = contract_surface_hash if scope != "kernel" else KERNEL_SURFACE_SENTINEL
    _advisory_lock(session, _lock_key(behavior_hash, effect_class, scope, surface, gate_ref))
    now = datetime.now(timezone.utc)
    # Enforced at write: the row is served to every deployment sharing the bytecode (:data:`DEPLOYMENT_PLANE_KEYS`).
    details = code_plane_details(details)
    stmt = pg_insert(EffectBehaviorCache).values(
        behavior_hash=behavior_hash,
        effect_class=effect_class,
        scope=scope,
        contract_surface_hash=surface,
        gate_ref=gate_ref,
        verdict=verdict,
        tier=tier,
        transcript_ptr=transcript_ptr,
        details=details,
        analysis_schema_version=EFFECT_CACHE_SCHEMA_VERSION,
        audit_status=audit_status,
        audit_peer_hash=audit_peer_hash,
        audited_at=now if audit_status is not None else None,
        updated_at=now,
    )
    # Only written on a miss, so every rewrite is a fresh simulation.
    set_ = {
        "verdict": stmt.excluded.verdict,
        "tier": stmt.excluded.tier,
        "transcript_ptr": stmt.excluded.transcript_ptr,
        "details": stmt.excluded.details,
        "analysis_schema_version": stmt.excluded.analysis_schema_version,
        "updated_at": stmt.excluded.updated_at,
    }
    # A plain refresh mustn't wipe a prior audit.
    if audit_status is not None:
        set_["audit_status"] = stmt.excluded.audit_status
        set_["audit_peer_hash"] = stmt.excluded.audit_peer_hash
        set_["audited_at"] = stmt.excluded.audited_at
    stmt = stmt.on_conflict_do_update(constraint="uq_effect_behavior_cache_identity", set_=set_)
    session.execute(stmt)
    session.flush()
    row = find_cached_verdict(
        session,
        behavior_hash=behavior_hash,
        effect_class=effect_class,
        scope=scope,
        contract_surface_hash=surface,
        gate_ref=gate_ref,
    )
    assert row is not None  # just written under the lock
    return row


def mark_audited(session: Session, row: EffectBehaviorCache, *, passed: bool, peer_hash: str) -> None:
    """Stamp the self-audit result on a kernel row; ``peer_hash`` records which surface was compared."""
    row.audit_status = AUDIT_PASSED if passed else AUDIT_FAILED
    row.audit_peer_hash = peer_hash
    row.audited_at = datetime.now(timezone.utc)
    session.flush()


def bump_hit(session: Session, row: EffectBehaviorCache) -> None:
    row.hit_count = (row.hit_count or 0) + 1
    session.flush()


# Code-plane fields defining a kernel verdict; a disagreement means a hash collision. Per-deployment keys are excluded.
# ``reason`` is excluded too: it legitimately varies between sightings, and a mismatch would poison the key with
# AUDIT_FAILED. An allowlist, so new witness keys need no version bump.
_KERNEL_SIGNATURE_KEYS = (
    "latch_flip",
    "gate_mutation",
    "upgradeable",
    "supply_delta_sign",
    "destination_shape",
)

# State-plane keys never stored on a code-plane row: each is an observation of one deployment's fork state, and the
# cache re-serves to every twin.
#
# Stripped on write. An audited hit re-attaches its fresh probe's keys
# (``effects_worker._details_with_fresh_deployment_plane``); a self-hit keeps its stored keys (``merge_witness``); a
# twin's first plain hit publishes absence, which consumers read as "no observation of my own".
DEPLOYMENT_PLANE_KEYS = (
    "observed_blast_radius",
    "pre_pause_succeeding",
    "scored_denominator",
    "input_seeded",
    "contract_balance_seeded",
    "backing",
    # Whether the pauser could enact the pause on this forked state. Not a kernel-signature key.
    "pause_effective",
    # A predicate on this fork's blast radius, and the sole gate on rendering the duration bound as a reducer
    # (``claimsVocab.pauseQualifier``). Not a kernel-signature key.
    "auto_expiry",
    # The observation height and pin scope (``harness._stamp_observation_height``) are world state, not bytecode
    # properties.
    "block_number",
    "block_source",
)


def code_plane_details(details: dict[str, Any] | None) -> dict[str, Any] | None:
    if not details:
        return details
    return {k: v for k, v in details.items() if k not in DEPLOYMENT_PLANE_KEYS}


def deployment_plane_details(details: dict[str, Any] | None) -> dict[str, Any]:
    """Only the per-deployment keys: what an audited hit lifts from its fresh probe so the rewritten row keeps this
    deployment's own qualifiers.
    """
    if not details:
        return {}
    return {k: v for k, v in details.items() if k in DEPLOYMENT_PLANE_KEYS}


def kernel_signature(verdict: str, details: dict[str, Any] | None) -> tuple[Any, ...]:
    """The comparable kernel identity (verdict plus structural witness), order-stable."""
    d = details or {}
    return (verdict, *(d.get(k) for k in _KERNEL_SIGNATURE_KEYS))


def kernel_signature_is_comparable(details: dict[str, Any] | None) -> bool:
    """Whether a signature carries any structural key, i.e. whether comparing it can falsify anything.

    Many rows (all ``authority_change``, many ``freeze_pause``) carry none, so two ``unknown`` signatures compare equal
    trivially. Such a hit mustn't be trusted; the caller re-probes and publishes its own result
    (``effects_worker._resolve_item``).
    """
    d = details or {}
    return any(k in d for k in _KERNEL_SIGNATURE_KEYS)


def kernel_verdicts_agree(
    cached_verdict: str,
    cached_details: dict[str, Any] | None,
    fresh_verdict: str,
    fresh_details: dict[str, Any] | None,
) -> bool:
    """Whether a cached kernel verdict and a fresh re-simulation agree.

    ``False`` is a caught collision: the caller writes ``unknown`` and files a discrepancy. Necessary but not
    sufficient; also check :func:`kernel_signature_is_comparable`.
    """
    return kernel_signature(cached_verdict, cached_details) == kernel_signature(fresh_verdict, fresh_details)


def record_effect_verdict(
    session: Session,
    *,
    chain_id: int,
    contract_address: str,
    effect_class: str,
    verdict: str,
    tier: str,
    function_id: int | None = None,
    selector: str | None = None,
    behavior_hash: str | None = None,
    concrete_destination: str | None = None,
    current_check_passed: bool | None = None,
    observed_residue: dict[str, Any] | None = None,
    witness: dict[str, Any] | None = None,
    witness_from_cache: bool = False,
    transcript_ptr: str | None = None,
) -> None:
    """Upsert one deployment's state-plane residue: concrete destination, target impl, Tier-0 current check, and
    value reach (``observed_residue``). Keyed ``(chain_id, contract_address, selector, effect_class)``; empty
    selector for fallback/receive.

    ``witness_from_cache`` says the witness came from the code-plane cache, so its missing deployment-plane keys say
    nothing; the stored row's are kept (same code and verdict) rather than erased, since e.g. absent ``input_seeded``
    means "no seeding needed". Fresh-probe writes overwrite.
    """
    # A concurrent policy pass can replace the function row; persist unlinked rather than FK-fail the job.
    if (
        function_id is not None
        and session.execute(select(EffectiveFunction.id).where(EffectiveFunction.id == function_id)).first() is None
    ):
        function_id = None

    def _upsert(fid: int | None):
        stmt = pg_insert(EffectVerdict).values(
            function_id=fid,
            chain_id=chain_id,
            contract_address=contract_address.lower(),
            selector=(selector or ""),
            effect_class=effect_class,
            behavior_hash=behavior_hash,
            verdict=verdict,
            tier=tier,
            concrete_destination=concrete_destination,
            current_check_passed=current_check_passed,
            # Explicit SQL NULL: a Python ``None`` becomes jsonb ``null``, a value that breaks the merge and "no
            # residue" reads.
            observed_residue=observed_residue if observed_residue is not None else null(),
            witness=witness,
            transcript_ptr=transcript_ptr,
        )
        existing = EffectVerdict.__table__.c

        # Residue is code-relative; don't carry a pre-upgrade destination across a behavior_hash change.
        same_code = stmt.excluded.behavior_hash.is_not_distinct_from(existing.behavior_hash)
        # Residue is only true while its verdict is; an orphaned ``concrete_destination`` would also suppress
        # re-observation forever.
        same_verdict = stmt.excluded.verdict.is_not_distinct_from(existing.verdict)
        residue_still_stands = and_(same_code, same_verdict)

        def keep_residue(incoming, stored):
            """An absent incoming value means this write observed nothing, not that nothing exists (cache hits carry
            none), so keep the stored value while the verdict is unchanged.
            """
            return case((incoming.is_not(None), incoming), (residue_still_stands, stored), else_=None)

        def merge_residue(incoming, stored):
            """``observed_residue`` is a bag written by different paths, so merge key-wise.

            A changed verdict or hash drops the observations but keeps :data:`RESIDUE_BOOKKEEPING_KEYS`. ``_object``
            normalizes jsonb ``null``, since ``object || null`` makes an array.
            """
            empty = text("'{}'::jsonb")

            def _object(col):
                return func.coalesce(func.nullif(col, text("'null'::jsonb")), empty)

            def _bookkeeping(col):
                picked = func.jsonb_build_object()
                for key in RESIDUE_BOOKKEEPING_KEYS:
                    value = col.op("->")(key)
                    picked = picked.op("||")(
                        case((value.is_not(None), func.jsonb_build_object(key, value)), else_=empty)
                    )
                return picked

            merged = _object(stored).op("||")(_object(incoming))
            flipped = _bookkeeping(_object(stored)).op("||")(_object(incoming))
            return func.nullif(case((residue_still_stands, merged), else_=flipped), empty)

        def merge_witness(incoming, stored):
            """Cache-served rewrites only: keep the stored deployment-plane keys while code and verdict are unchanged
            (incoming keys win), since their absence is a contractual statement the hit never earned.
            """
            empty = text("'{}'::jsonb")

            def _object(col):
                return func.coalesce(func.nullif(col, text("'null'::jsonb")), empty)

            picked = func.jsonb_build_object()
            for key in DEPLOYMENT_PLANE_KEYS:
                value = _object(stored).op("->")(key)
                picked = picked.op("||")(case((value.is_not(None), func.jsonb_build_object(key, value)), else_=empty))
            merged = func.nullif(picked.op("||")(_object(incoming)), empty)
            incoming_present = func.nullif(_object(incoming), empty).is_not(None)
            return case(
                (and_(residue_still_stands, incoming_present), merged),
                # A hit from a NULL-details row asserts only the same verdict; the stored evidence stands.
                (residue_still_stands, stored),
                else_=incoming,
            )

        return stmt.on_conflict_do_update(
            constraint="uq_effect_verdicts_identity",
            set_={
                # The FK is ON DELETE SET NULL, so a stored non-NULL id is live; keep it.
                "function_id": func.coalesce(stmt.excluded.function_id, existing.function_id),
                # Current resolution facts always take the latest.
                "behavior_hash": stmt.excluded.behavior_hash,
                "verdict": stmt.excluded.verdict,
                "tier": stmt.excluded.tier,
                "concrete_destination": keep_residue(stmt.excluded.concrete_destination, existing.concrete_destination),
                "current_check_passed": keep_residue(stmt.excluded.current_check_passed, existing.current_check_passed),
                "observed_residue": merge_residue(stmt.excluded.observed_residue, existing.observed_residue),
                # Evidence moves with its verdict (a proven witness beside ``unknown`` would contradict), except
                # cache-served rewrites of the same verdict keep deployment-plane keys (``merge_witness``).
                "witness": (
                    merge_witness(stmt.excluded.witness, existing.witness)
                    if witness_from_cache
                    else stmt.excluded.witness
                ),
                "transcript_ptr": stmt.excluded.transcript_ptr,
                "updated_at": text("NOW()"),
            },
        )

    try:
        with session.begin_nested():
            session.execute(_upsert(function_id))
    except IntegrityError as exc:
        # The row vanished mid-insert; the savepoint keeps the session usable; retry unlinked.
        if "effect_verdicts_function_id_fkey" not in str(exc.orig):
            raise
        with session.begin_nested():
            session.execute(_upsert(None))
        # Only reported once the unlinked write actually landed.
        context = {
            "chain_id": chain_id,
            "contract_address": contract_address.lower(),
            "selector": selector or "",
            "effect_class": effect_class,
            "function_id": function_id,
        }
        record_degraded(
            phase="effect_verdict_unlink",
            exc=EffectVerdictUnlinked("function row vanished between the existence check and the insert"),
            context=context,
        )
        # The frontend can't attribute it until a later pass relinks it.
        logger.warning(
            "effect verdict written unlinked: function row vanished mid-job",
            extra=context,
        )
    session.flush()
