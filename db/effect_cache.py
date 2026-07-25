"""Effect-verdict cache read/write with kernel-vs-projection scope + §7 self-audit.

The persistence layer Phase 3 wires selection → harness → verdicts onto. Mirrors
``db/contract_materializations.py``: schema-version invalidation, an advisory-lock
coalesce on writes, and cross-job / cross-chain-twin reuse. Verdicts are small
(a ``details`` JSONB witness + a ``transcript_ptr`` artifact key), so there is no
blob-storage split — the multi-MB concern that shapes the materialization cache
does not apply here.

Two scopes (EFFECTS_RESOLUTION_SPEC §7 / inv. 3):

* **kernel** — function-local (latch-flip, gate-mutation, code-change, supply
  sign, destination *shape*). Keyed on the resolved-function behavioral hash;
  ``contract_surface_hash`` is the empty sentinel. Transfers across every
  deployment sharing the hash, cross-chain twins included.
* **projection** — contract-scoped (pause blast radius, authorization delta).
  Keyed ADDITIONALLY on the whole-contract surface hash, because the same mixin
  kernel yields different blast radii on different surfaces.

Concrete values (the exact destination, the exact impl, the current-check
result) are NEVER cache keys (inv. 12) — they are per-deployment state-plane
residue and live in ``effect_verdicts``.

The §7 self-audit lives here (``kernel_verdicts_agree`` + the ``audit_*``
bookkeeping) because it is a cache-integrity concern: the first time two
functions share a kernel hash, the second sighting re-simulates and asserts the
kernel verdicts match before the free hit is *trusted*. A hashing bug that
collided two distinct behaviors is caught here instead of silently propagating a
wrong verdict across deployments.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, func, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import EffectBehaviorCache, EffectiveFunction, EffectVerdict

logger = logging.getLogger(__name__)

# Bump to invalidate every stored verdict when the recipe/verdict output shape
# changes. Deliberately independent of a git SHA (mirrors
# ``ANALYSIS_SCHEMA_VERSION``): an unrelated deploy must not cold-miss the whole
# behavioral cache.
# v2: pause probes seed token preconditions (balance/allowance/shares/owner
# slots, read-back verified). A v1 ``unknown`` row for a surface whose entry
# points were precondition-blind would otherwise cache-hit forever and mask the
# widened observed radius.
# v3: Tier-1 value_out/supply probes retry with the caller's INPUT ASSET seeded
# (read-back verified). Every deposit-backed conversion previously cached an
# ``unknown`` from a precondition revert; those rows would otherwise hit forever
# and keep the whole ``supply.mint`` backing witness empty.
EFFECT_CACHE_SCHEMA_VERSION = 3

# ``contract_surface_hash`` sentinel for kernel rows. A sentinel rather than
# NULL keeps the identity UniqueConstraint portable (no NULLS-NOT-DISTINCT dep) —
# matches the model's ``server_default=""``.
KERNEL_SURFACE_SENTINEL = ""

# Self-audit outcomes stamped on a kernel row.
AUDIT_PASSED = "passed"
AUDIT_FAILED = "failed"


def _lock_key(behavior_hash: str, effect_class: str, scope: str, surface: str, gate_ref: str) -> str:
    return f"effect:{behavior_hash}:{effect_class}:{scope}:{surface}:{gate_ref}"


def _advisory_lock(session: Session, key: str) -> None:
    """Serialize concurrent writers for one cache identity (mirrors the
    materialization cache's ``pg_advisory_xact_lock``). ``hashtext`` is built into
    Postgres and folds the composite key into the 64-bit lock space."""
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
    """Return the current-version cached verdict for this identity, or ``None``.

    A row stamped with a stale ``analysis_schema_version`` reads as a miss so a
    bumped recipe re-simulates rather than transferring a verdict computed under
    different rules — exactly the materialization cache's version gate.
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
    """Bulk form of :func:`find_cached_verdict` for a whole job's plan set.

    ``identities`` is any iterable of
    ``(behavior_hash, effect_class, scope, contract_surface_hash, gate_ref)``
    tuples. Returns a dict keyed by the *normalized* identity (kernel scope maps
    the surface to :data:`KERNEL_SURFACE_SENTINEL`, exactly as the single-row
    form does) whose value is the current-version cached row, if any.

    Semantics match the single-row lookup precisely: the same 5-field identity,
    the same ``analysis_schema_version`` gate (a stale-version row is a miss),
    the same kernel surface-sentinel normalization. The identity UniqueConstraint
    plus the version filter guarantee at most one row per key — so this returns
    the same row the per-plan ``SELECT`` would, in ONE composite ``IN`` query
    instead of N.
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
    """Write (or refresh) a code-plane verdict row under an advisory lock.

    The row is code-plane ONLY (inv. 11): no concrete values enter ``details``.
    Verdicts are gate-relative (inv. 12): ``gate_ref`` names the gate structure,
    never an address. A concurrent sibling writing the same identity coalesces on
    the unique constraint rather than duplicating.
    """
    surface = contract_surface_hash if scope != "kernel" else KERNEL_SURFACE_SENTINEL
    _advisory_lock(session, _lock_key(behavior_hash, effect_class, scope, surface, gate_ref))
    now = datetime.now(timezone.utc)
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
    # No residue guard is needed here (unlike ``record_effect_verdict``): this row
    # is code-plane only, and the worker writes it exclusively on a cache MISS —
    # every rewrite IS a fresh simulation, so each field must take the new value.
    set_ = {
        "verdict": stmt.excluded.verdict,
        "tier": stmt.excluded.tier,
        "transcript_ptr": stmt.excluded.transcript_ptr,
        "details": stmt.excluded.details,
        "analysis_schema_version": stmt.excluded.analysis_schema_version,
        "updated_at": stmt.excluded.updated_at,
    }
    # Only advance audit bookkeeping when this write carries an audit result;
    # a plain refresh must not wipe a prior passed/failed audit.
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
    """Stamp the §7 self-audit result on a kernel row. ``peer_hash`` records the
    surface whose re-simulation was compared, so a later reader can see which
    pair was cross-checked."""
    row.audit_status = AUDIT_PASSED if passed else AUDIT_FAILED
    row.audit_peer_hash = peer_hash
    row.audited_at = datetime.now(timezone.utc)
    session.flush()


def bump_hit(session: Session, row: EffectBehaviorCache) -> None:
    """Count a trusted cache hit (supports the optional every-Nth re-audit)."""
    row.hit_count = (row.hit_count or 0) + 1
    session.flush()


# ---------------------------------------------------------------------------
# §7 self-audit — kernel-verdict agreement
# ---------------------------------------------------------------------------

# The code-plane structural fields that DEFINE a kernel verdict. Two functions
# sharing a behavioral hash must agree on these; a disagreement means the hash
# collided two distinct behaviors (a hashing bug) and the cache must NOT be
# trusted. Concrete/state-plane keys (destination, impl) are deliberately absent —
# they are per-deployment and are EXPECTED to differ.
_KERNEL_SIGNATURE_KEYS = (
    "latch_flip",
    "gate_mutation",
    "upgradeable",
    "supply_delta_sign",
    "destination_shape",
)


def kernel_signature(verdict: str, details: dict[str, Any] | None) -> tuple[Any, ...]:
    """The comparable kernel identity: the verdict plus its structural witness.
    Order-stable so two calls on equal inputs compare equal."""
    d = details or {}
    return (verdict, *(d.get(k) for k in _KERNEL_SIGNATURE_KEYS))


def kernel_verdicts_agree(
    cached_verdict: str,
    cached_details: dict[str, Any] | None,
    fresh_verdict: str,
    fresh_details: dict[str, Any] | None,
) -> bool:
    """Do a cached kernel verdict and a freshly re-simulated one agree (§7)?

    The self-audit trusts a free cache hit only when this returns ``True``. A
    ``False`` is a caught hash collision: the caller withholds (writes
    ``unknown`` + files a discrepancy) instead of propagating the cached verdict.
    """
    return kernel_signature(cached_verdict, cached_details) == kernel_signature(fresh_verdict, fresh_details)


# ---------------------------------------------------------------------------
# effect_verdicts — per-deployment state-plane residue (never the cache)
# ---------------------------------------------------------------------------


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
    witness: dict[str, Any] | None = None,
    transcript_ptr: str | None = None,
) -> None:
    """Upsert the per contract-function state-plane residue for one deployment.

    This is where the concrete values live — the exact destination address, the
    exact target impl, the Tier-0 current-state check — NEVER the
    ``effect_behavior_cache`` (inv. 3). Keyed on the deployment coordinates
    ``(chain_id, contract_address, selector, effect_class)``; the empty-string
    ``selector`` sentinel keeps the identity constraint portable for
    fallback/receive functions.
    """
    # A candidate's function row can be replaced (delete+recreate, new id) by a
    # concurrent policy pass between selection and this write. The verdict must
    # still persist — unlinked — rather than FK-violate and roll back the whole
    # job's witnesses.
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
            witness=witness,
            transcript_ptr=transcript_ptr,
        )
        existing = EffectVerdict.__table__.c

        # Did this write resolve the SAME code as the stored row? Residue is
        # per-deployment but code-relative: it describes what THIS bytecode does
        # at this address. Carrying it across a behavior_hash change would let a
        # pre-upgrade destination masquerade as the new implementation's.
        same_code = stmt.excluded.behavior_hash.is_not_distinct_from(existing.behavior_hash)

        def keep_residue(incoming, stored):
            """State-plane residue: an absent incoming value means *this* write had
            no state-plane observation, NOT that none exists. A cache-HIT resolution
            structurally carries none (inv. 3 — the code-plane cache holds no
            concrete values), so an unconditional overwrite would erase the
            first-sighting observation on every subsequent hit."""
            return case((incoming.is_not(None), incoming), (same_code, stored), else_=None)

        return stmt.on_conflict_do_update(
            constraint="uq_effect_verdicts_identity",
            set_={
                # Linkage, not a fact about this resolution: the FK-vanished guard
                # above nulls ``fid`` when the function row was replaced mid-job.
                # The FK is ON DELETE SET NULL, so a stored non-NULL id is always
                # live — keep it rather than orphaning the row from the frontend.
                "function_id": func.coalesce(stmt.excluded.function_id, existing.function_id),
                # Current resolution facts — always the latest, even downgrades.
                "behavior_hash": stmt.excluded.behavior_hash,
                "verdict": stmt.excluded.verdict,
                "tier": stmt.excluded.tier,
                # State-plane residue — preserved across observation-less rewrites.
                "concrete_destination": keep_residue(stmt.excluded.concrete_destination, existing.concrete_destination),
                "current_check_passed": keep_residue(stmt.excluded.current_check_passed, existing.current_check_passed),
                # Evidence FOR the verdict above, so it moves with it: preserving a
                # "proven" witness next to a downgraded ``unknown`` verdict would
                # publish a contradiction. Deliberately not residue-preserved.
                "witness": stmt.excluded.witness,
                "transcript_ptr": stmt.excluded.transcript_ptr,
                "updated_at": text("NOW()"),
            },
        )

    try:
        with session.begin_nested():
            session.execute(_upsert(function_id))
    except IntegrityError as exc:
        # The row vanished between the existence check and the insert — the
        # savepoint keeps the job session writable; retry unlinked.
        if "effect_verdicts_function_id_fkey" not in str(exc.orig):
            raise
        with session.begin_nested():
            session.execute(_upsert(None))
    session.flush()
