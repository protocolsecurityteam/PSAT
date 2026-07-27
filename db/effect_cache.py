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

from sqlalchemy import and_, case, func, null, select, text, tuple_
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
# v4: the verdict OUTPUT SHAPE changed in four ways that make a v3 row unsafe to
# serve. (a) A burn whose ``totalSupply`` wrapped was published as
# ``supply_delta_sign: mint`` with the §5a witnessed-dilution payload — the
# strongest claim this stage makes, on a call that destroyed units — and those
# rows were written under v3, so without a bump the poisoned verdict is returned
# verbatim and never rewritten (a disagreeing re-probe only marks it
# AUDIT_FAILED, and a failed row is still served). (b) ``destination_shape`` was
# ~95% ``unknown`` because its proof branch was unreachable; it now resolves.
# (c) ``freeze_pause`` rows carry the ``observation`` discriminator every other
# class already carried. (d) Seeded holder balances are capped at the token's own
# supply, so a seeded verdict was reached from different fork state.
# v5: the input-token hints feeding the seeded retry now resolve a library-wrapped
# token receiver to its real getter (was a Slither temporary that seeded the wrong
# token or nothing), so a v4 row was reached from a different seeded fork state and
# must not be served to the new probe.
# v6: the storage read path now resolves DB-recorded keys carrying a foreign
# environment prefix. Before it, ``hydrate_predicate_trees`` returned None for
# 75/75 materializations and ``get_source_files`` returned 0 files for every job
# — so every v5 row was probed against an empty predicate-tree / empty-source
# analysis state, i.e. a different seeded fork state than the same probe reaches
# now. Serving those rows would keep the pre-fix verdict forever.
# v7: §6 candidate ordering was a function of float rounding noise, not of the
# data — 8 PYTHONHASHSEED values produced 8 different candidate orders and 129 of
# 443 rows changed rank, because the value-at-stake sum ran over a ``set`` in
# binary float and one ulp routed equal-value candidates around the ``function_id``
# tiebreak. Order decides which candidates a ``resource_cap`` run reaches, so a v6
# row records what a probe queue built from rounding noise happened to visit; it
# is not the row the now-deterministic queue produces.
# v8: the ``exec.arbitrary`` witness now names a destination/calldata parameter
# only where the call IR puts that parameter in that operand position, and says
# ``state_var`` / ``call_argument`` / ``not_determined`` where it does not. The
# old names came from an arbitrary member of a read-set intersection over
# identity-hashed Slither objects, so they were wrong on both functions where a
# choice existed and varied with allocation order between processes. The executor
# probe builds its inner call from those two slots, so a v7 row records a call
# synthesized around a parameter that is not the destination — a different probe
# input, not merely a different label.
# v9: the same witness now answers ``not_determined`` where the destination or
# payload reaches the call through a name the function body defines more than
# once. Under v8 those resolved through whichever defining IR came first in
# source order and were published as one of the two PROOF states — a caller-
# chosen destination reported as ``state_var`` (proven absent) or as the wrong
# parameter's name. The executor probe builds its inner call from those slots and
# a non-``param`` kind takes it down the ABI-uniqueness path instead, so a v8 row
# on such a function records a verdict reached from a different synthesized call.
# Measured: every one of the 28 witnesses the production compilation units mint is
# byte-identical across the change, so this bump covers the shapes the corpus
# proves changed, not any row observed here.
# v10: a ``computed`` predicate-tree operand now carries ``derived_from`` — the
# origins that reached it through the arguments of the computation that produced
# it. A ``keccak256``/``abi.encode`` used to collapse them into a digest, so a
# hash-commitment gate arrived at the leaf builder with every parameter it
# commits already destroyed (Teller ``refundDeposit`` bound ``nonce`` and nothing
# else; ``receiver`` and four more committed parameters were unrecoverable). The
# probe reads the tree to decide what a gate constrains, so a v9 row records a
# verdict reached from a strictly smaller constraint set than the same probe
# now sees. Measured on the 88 production compilation units: the effect
# artifacts are byte-identical on 87, and on ``EtherFiOracle.unpublishReport``
# the sink *order* moved, which renumbers the ``sinkN`` ids a v9 row references.
# Order there is Slither's ``list(set(vars_written))`` over identity-hashed
# objects, so it tracks allocation addresses; the (kind, target, selector,
# origin) multiset is identical.
# v11: the ``flow.out``/``value_router`` and ``exec.arbitrary`` witnesses now
# carry a three-state destination-constraint verdict (``target_constraint`` /
# ``destination_constraint``): whether a MANDATORY revert gate between entry and
# sink references the destination parameter. A ``param`` destination was
# previously published as one undifferentiated fact and read downstream as
# "the caller can send this anywhere"; on the local artifacts 4 of 80 param
# destinations carry a proven gate and 18 more are not determined, and 7 of the
# 20 ``exec.arbitrary`` sites carry one. The probe selects and shapes its inner
# call from the destination witness, so a v10 row records a verdict reached
# without knowing whether the destination it synthesised was reachable at all —
# a different probe input, not merely a different label.
# v12: ``exec.arbitrary`` is no longer minted where the destination is PROVEN to
# be a state variable. The claim asserts a caller-supplied target and
# ``state_var`` is the proof that the caller does not supply one, so a v11 row on
# such a function carries a claim whose witness states its own negation — and
# the executor probe builds its inner call from that witness, so it synthesised a
# call around a destination the caller cannot reach. ``not_determined`` still
# mints (an open question is not a proof of absence), so this covers only the
# rows where the two contradict.
# Between v12 and v13, recorded late (an as-committed R5 violation, noted for
# the audit trail): the A5 commit introduced the ``rate_limit.consume`` claim
# class — a zero-severity-weight FACT witness carrying the ``refillRate``/
# ``capacity`` discriminators — onto 10 local functions with no bump. The v13
# argument below applies to it verbatim: the probe's candidate selection and
# its synthesized call both read the claim set, so until the enrollment-
# transparency restoration under the v17 entry, a cached row on those functions
# was reached with this class absent from the set (the same 12-13 rows that
# restoration names). No retroactive bump is needed for correctness on this
# branch — every pre-branch row predates v11 and the branch's own bumps already
# invalidate it — but the class introduction itself belongs in this ledger,
# and the branch-scoped tier-0 gate cannot record it after the fact (its R5
# check fires only on ``services/effects/*`` paths).
# v13: the new ``delegatecall.execute`` claim class. A function whose foreign-code
# execution was previously carried only by the legacy ``delegatecall_execution``
# label now publishes a witness naming where that code comes from
# (``storage_setter`` with its writer, ``indeterminate`` for a caller-keyed
# mapping element). The probe's candidate selection and its synthesized call both
# read the claim set, so a v12 row was reached with this class absent from it.
# v14: ``unconstrained_proven`` in the destination-constraint verdict now
# requires the leaf projection to be checkably complete (expression/parameter
# cross-check, keyed-collection reads, parameter_names presence), a computed
# operand always blocks the negative proof (L-24), and a proven OZ-timelock /
# Safe exec entry publishes the standard's own commitment for every parameter.
# A v13 row can carry a positive proof of absence minted from a lossy
# projection's silence — measured on the local artifacts: 4 of 32 such proofs
# were false (two timelock ``execute`` destinations that are hash-committed,
# a merkle-drop ``account`` the ``verify`` leaf touches, a Teller ``to`` gated
# by ``beforeTransferData[to].denyTo``) — and the probe shapes its call from
# that verdict, so those rows must not be served to the new probe.
# v15: every ``constrained`` destination verdict now carries ``pins`` — the
# three-state answer to whether the guard PINS the parameter (True allowlist /
# commitment, False denylist / ordering bound, None external revert surface
# whose set semantics are another contract's). A v14 row's ``constrained`` was
# one undifferentiated state that consumers rendered as "gated", which on the
# local artifacts silently promoted 4/4 blacklist-checked flow destinations
# (EtherFiRedemptionManager.redeem*) into pinned ones; the probe reads the
# verdict to decide whether a synthesized destination can be reached at all,
# so a row minted without the discriminator must not be served to the probe
# that now expects it.
# v16: the ``exec.arbitrary`` taint fragment now answers over EVERY candidate
# call op instead of the first one in body order, so the v12 suppression's
# ``state_var`` is a function-wide proof rather than a first-op fact. Under v15
# a body holding a storage-destination op ahead of a genuine
# ``target.call(data)`` — the Safe/Zodiac transaction-guard idiom — published
# NO claim and no ``arbitrary_external_call`` label, and its statement-swapped
# twin published both; the probe's candidate selection and its synthesized call
# read the claim set, so a v15 row on such a function was reached with the
# function's highest-severity claim absent for a reason that was statement
# order, not evidence.
# v17: a multi-site ``delegatecall.execute`` destination whose sites agree on a
# kind now publishes the UNION of every site's evidence (plural ``variables``,
# merged ``writer_signatures``) instead of the first site's record. A v16 row on
# a two-module body carries one module's writer set presented as the whole
# answer — an ungated second writer invisible behind a gated first — and the
# probe reads the claim witness, so such a row was reached from a witness that
# understates who can replace the executing code.
#
# Still v17 — enrollment transparency (a restoration, not a new analysis):
# ``rate_limit.consume`` and ``delegatecall.execute`` are now TRANSPARENT to the
# probe's candidate selection (``services/effects/selection.py:
# _enrolled_families``): a function whose only claims are these fact classes
# stays the §6 blank full-synthesis candidate it is today, instead of silently
# leaving the candidate set the moment the claims plane mints the new ids (13
# local rows: LRTSquaredAdmin.depositToStrategy and the 12 EtherFiNodesManager
# rate-limited queue/consolidation functions). No bump: for those rows the
# candidate shape the probe sees — full synthesis, ``restrict_families=None`` —
# is byte-identical before and after the fact claims are minted, so a cached
# verdict remains an answer to the same probe; every other row's claim set and
# probe input are untouched.
# v18: exec-mode destination-constraint transparency is now EARNED per call op —
# an identity enters the transparency set only when IR proves that op's own
# destination parameter-rooted, and is withheld when any fixed- or unresolved-
# destination op shares it — instead of covering every body external call. A
# v17 row on a Safe/Zodiac transaction-guard body (a mandatory nonview guard
# call vetting the caller-supplied target before the arbitrary call) carries
# ``destination_constraint: unconstrained_proven`` minted from the swallowed
# guard leaf, byte-identical to a genuinely guardless function; the same walk
# now answers ``not_determined``. The probe shapes its synthesized call from
# that verdict, so such a row was reached from a proof of absence the walk can
# no longer mint. Measured: 0 of the local DB's recomputable exec/delegatecall
# rows flip (none carries a swallowed nonview guard leaf — a lower bound, not
# a population claim); the two corpus guard-idiom rows are the realised flips.
EFFECT_CACHE_SCHEMA_VERSION = 18

# ``contract_surface_hash`` sentinel for kernel rows. A sentinel rather than
# NULL keeps the identity UniqueConstraint portable (no NULLS-NOT-DISTINCT dep) —
# matches the model's ``server_default=""``.
KERNEL_SURFACE_SENTINEL = ""

# Self-audit outcomes stamped on a kernel row.
AUDIT_PASSED = "passed"
AUDIT_FAILED = "failed"

# ``observed_residue`` keys that are BOOKKEEPING about probing, not observations
# of the contract. Everything else in the bag describes what a verdict saw, so a
# verdict flip correctly drops it; these describe how many times this deployment
# has already been re-probed, which is just as true after the flip. Losing them
# resets a cap that exists to stop an unreproducible behavior from re-probing on
# every job forever, so they survive the flip that clears the observations.
RESIDUE_BOOKKEEPING_KEYS = ("destination_probe_attempts",)


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


def find_verdict_residue_batch(
    session: Session,
    *,
    chain_id: int,
    identities: "Any",
) -> dict[tuple[str, str, str], tuple[str | None, bool | None, dict[str, Any] | None]]:
    """State-plane residue already persisted for a set of deployment identities.

    ``identities`` is any iterable of ``(contract_address, selector,
    effect_class)``. Returns ``{identity: (concrete_destination,
    current_check_passed, observed_residue)}`` for the rows that exist — a key
    absent from the result has no verdict row at all, which is also "no residue".

    Read-only and batched (one composite ``IN``) because the caller asks it once
    per job about every cache HIT: a hit carries no state-plane observation of
    its own (inv. 3), so this is how the worker learns whether THIS deployment
    ever got one, without a round-trip per plan.
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
#
# ``reason`` also rides ``details`` (``ObservedEffect.witness_payload``) and is
# deliberately NOT here: it is a strictly finer partition of the same verdict, and
# an unknown's reason can legitimately differ between two sightings of one
# behavior (a precondition revert here, a clean non-observation there) without any
# hash having collided. Comparing it would stamp AUDIT_FAILED — which poisons the
# key permanently — on a transient disagreement. An allowlist, not a diff, is also
# why a new witness key never needs a schema-version bump.
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
    observed_residue: dict[str, Any] | None = None,
    witness: dict[str, Any] | None = None,
    transcript_ptr: str | None = None,
) -> None:
    """Upsert the per contract-function state-plane residue for one deployment.

    This is where the concrete values live — the exact destination address, the
    exact target impl, the Tier-0 current-state check, and (in
    ``observed_residue``) the §5b value-reach holders/USD — NEVER the
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
            # Explicit SQL NULL: a JSONB column turns a Python ``None`` into the
            # jsonb scalar ``null``, which is a VALUE — it would defeat both the
            # merge above and the "no residue" reading everywhere downstream.
            observed_residue=observed_residue if observed_residue is not None else null(),
            witness=witness,
            transcript_ptr=transcript_ptr,
        )
        existing = EffectVerdict.__table__.c

        # Did this write resolve the SAME code as the stored row? Residue is
        # per-deployment but code-relative: it describes what THIS bytecode does
        # at this address. Carrying it across a behavior_hash change would let a
        # pre-upgrade destination masquerade as the new implementation's.
        same_code = stmt.excluded.behavior_hash.is_not_distinct_from(existing.behavior_hash)
        # ...and the same ANSWER? Residue is the concrete detail OF a verdict, so
        # it is only still true while that verdict is. A proven value-move
        # rewritten as ``unknown`` keeps neither its witness nor its transcript
        # (below) precisely so a proven witness never sits beside a downgraded
        # verdict; an orphaned ``concrete_destination`` is that same contradiction
        # in another column, and ``find_verdict_residue_batch`` reads it, so the
        # orphan also permanently suppresses re-observation.
        same_verdict = stmt.excluded.verdict.is_not_distinct_from(existing.verdict)
        residue_still_stands = and_(same_code, same_verdict)

        def keep_residue(incoming, stored):
            """State-plane residue: an absent incoming value means *this* write had
            no state-plane observation, NOT that none exists. A cache-HIT resolution
            structurally carries none (inv. 3 — the code-plane cache holds no
            concrete values), so an unconditional overwrite would erase the
            first-sighting observation on every subsequent hit — but only while the
            verdict it describes is unchanged."""
            return case((incoming.is_not(None), incoming), (residue_still_stands, stored), else_=None)

        def merge_residue(incoming, stored):
            """``observed_residue`` is a BAG of independent residue facts (§5b
            reach, re-probe bookkeeping) written by different paths, so absent
            keys must survive an incoming write that carries only some of them —
            a key-wise ``keep_residue``. Same lifecycle: a changed verdict or a
            changed behavior hash drops the whole bag.

            ``_object`` is not defensive padding: a JSONB column renders a Python
            ``None`` as the jsonb scalar ``null`` rather than SQL NULL, and
            ``jsonb_object || jsonb_null`` concatenates into a two-element ARRAY
            instead of merging. Both sides are normalized to an object first.

            The flip branch is NOT a plain overwrite: the observation keys must go
            (they described the old verdict) but :data:`RESIDUE_BOOKKEEPING_KEYS`
            must not, or a verdict that flips hands the re-probe bound a fresh
            budget and an unreproducible deployment re-probes forever."""
            empty = text("'{}'::jsonb")

            def _object(col):
                return func.coalesce(func.nullif(col, text("'null'::jsonb")), empty)

            def _bookkeeping(col):
                """Only the bookkeeping keys of ``col``, as an object."""
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
                "observed_residue": merge_residue(stmt.excluded.observed_residue, existing.observed_residue),
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
