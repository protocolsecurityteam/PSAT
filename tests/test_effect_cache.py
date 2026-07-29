"""Effect-verdict cache: kernel-vs-projection scope, self-audit, state-plane
residue, version invalidation.

DB-backed (real Postgres), offline-safe. Mirrors the materialization-cache test
conventions."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import effect_cache  # noqa: E402
from db.effect_cache import (  # noqa: E402
    EFFECT_CACHE_SCHEMA_VERSION,
    KERNEL_SURFACE_SENTINEL,
    find_cached_verdict,
    kernel_verdicts_agree,
    mark_audited,
    record_effect_verdict,
    upsert_cached_verdict,
)
from db.models import Contract, EffectBehaviorCache, EffectiveFunction, EffectVerdict  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402

KERNEL = "kernel"
PROJECTION = "projection"


@pytest.fixture()
def clean_effects(db_session):
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.commit()


# ---------------------------------------------------------------------------
# kernel vs projection scoping
# ---------------------------------------------------------------------------


@requires_postgres
def test_kernel_row_uses_empty_surface_sentinel(clean_effects):
    session = clean_effects
    row = upsert_cached_verdict(
        session,
        behavior_hash="bh_kernel",
        effect_class="supply",
        scope=KERNEL,
        verdict="proven",
        tier="tier1",
        details={"supply_delta_sign": "mint"},
    )
    assert row.contract_surface_hash == KERNEL_SURFACE_SENTINEL
    # A kernel lookup ignores the caller-passed surface (kernel is function-local).
    hit = find_cached_verdict(
        session, behavior_hash="bh_kernel", effect_class="supply", scope=KERNEL, contract_surface_hash="ignored"
    )
    assert hit is not None and hit.id == row.id


@requires_postgres
def test_projection_keys_on_surface_two_surfaces_two_rows(clean_effects):
    """A projection transfers ONLY on whole-contract identity: two different
    surfaces get two rows; the same kernel hash on surface A is a MISS on B."""
    session = clean_effects
    upsert_cached_verdict(
        session,
        behavior_hash="bh_proj",
        effect_class="freeze_pause",
        scope=PROJECTION,
        contract_surface_hash="surfaceA",
        verdict="proven",
        tier="tier2",
        details={"latch_flip": True},
    )
    # Same kernel hash, DIFFERENT surface → miss (projection doesn't transfer).
    assert (
        find_cached_verdict(
            session,
            behavior_hash="bh_proj",
            effect_class="freeze_pause",
            scope=PROJECTION,
            contract_surface_hash="surfaceB",
        )
        is None
    )
    # Same surface → hit.
    assert (
        find_cached_verdict(
            session,
            behavior_hash="bh_proj",
            effect_class="freeze_pause",
            scope=PROJECTION,
            contract_surface_hash="surfaceA",
        )
        is not None
    )


@requires_postgres
def test_kernel_transfers_across_surfaces_one_row(clean_effects):
    """A kernel keyed on the function hash is a single row two deployments share —
    the free cross-deployment / cross-chain-twin hit."""
    session = clean_effects
    upsert_cached_verdict(
        session,
        behavior_hash="bh_shared",
        effect_class="supply",
        scope=KERNEL,
        verdict="proven",
        tier="tier1",
    )
    # A second deployment (any surface) resolves the same kernel row.
    hit = find_cached_verdict(session, behavior_hash="bh_shared", effect_class="supply", scope=KERNEL)
    assert hit is not None
    assert session.query(EffectBehaviorCache).count() == 1


# ---------------------------------------------------------------------------
# self-audit
# ---------------------------------------------------------------------------


def test_kernel_verdicts_agree_ignores_concrete_values():
    # Same kernel signature, DIFFERENT concrete destination → still agree.
    assert kernel_verdicts_agree(
        "proven",
        {"supply_delta_sign": "mint", "destination": "0xaaa"},
        "proven",
        {"supply_delta_sign": "mint", "destination": "0xbbb"},
    )
    # Different structural sign → disagree (a real collision).
    assert not kernel_verdicts_agree("proven", {"supply_delta_sign": "mint"}, "proven", {"supply_delta_sign": "burn"})
    # Different verdict → disagree.
    assert not kernel_verdicts_agree("proven", {"latch_flip": True}, "unknown", {"latch_flip": True})


@requires_postgres
def test_mark_audited_stamps_result(clean_effects):
    session = clean_effects
    row = upsert_cached_verdict(
        session, behavior_hash="bh_a", effect_class="supply", scope=KERNEL, verdict="proven", tier="tier1"
    )
    assert row.audit_status is None
    mark_audited(session, row, passed=True, peer_hash="surfaceX")
    assert row.audit_status == effect_cache.AUDIT_PASSED
    assert row.audit_peer_hash == "surfaceX"
    assert row.audited_at is not None


# ---------------------------------------------------------------------------
# version invalidation (mirrors ContractMaterialization)
# ---------------------------------------------------------------------------


@requires_postgres
def test_stale_schema_version_reads_as_miss(clean_effects):
    session = clean_effects
    row = upsert_cached_verdict(
        session, behavior_hash="bh_v", effect_class="supply", scope=KERNEL, verdict="proven", tier="tier1"
    )
    row.analysis_schema_version = EFFECT_CACHE_SCHEMA_VERSION + 1
    session.flush()
    assert find_cached_verdict(session, behavior_hash="bh_v", effect_class="supply", scope=KERNEL) is None


# ---------------------------------------------------------------------------
# effect_verdicts — state-plane residue (never the cache)
# ---------------------------------------------------------------------------


@requires_postgres
def test_record_effect_verdict_upserts_state_plane(clean_effects):
    session = clean_effects
    record_effect_verdict(
        session,
        chain_id=1,
        contract_address="0x" + "11" * 20,
        selector="0x40c10f19",
        effect_class="value_out",
        behavior_hash="bh_state",
        verdict="proven",
        tier="tier1",
        concrete_destination="0x" + "cd" * 20,
        witness={"destination_shape": "immutable_fixed"},
    )
    row = session.query(EffectVerdict).one()
    assert row.concrete_destination == "0x" + "cd" * 20
    assert row.witness["destination_shape"] == "immutable_fixed"
    # Idempotent on the deployment-coordinate key.
    record_effect_verdict(
        session,
        chain_id=1,
        contract_address="0x" + "11" * 20,
        selector="0x40c10f19",
        effect_class="value_out",
        behavior_hash="bh_state",
        verdict="unknown",
        tier="tier1",
    )
    session.expire_all()
    assert session.query(EffectVerdict).count() == 1
    assert session.query(EffectVerdict).one().verdict == "unknown"


# ---------------------------------------------------------------------------
# Stale function_id tolerance: a policy row replace mid-run must not be able to
# fail the verdict write (identity is the deployment coordinates; function_id is
# a convenience join).
# ---------------------------------------------------------------------------


def _seed_function_row(session, address: str, selector: str) -> int:
    contract = Contract(address=address, chain="ethereum", is_proxy=False)
    session.add(contract)
    session.flush()
    ef = EffectiveFunction(
        contract_id=contract.id,
        deployment_address=address,
        function_name="pause",
        selector=selector,
        abi_signature="pause()",
        effect_labels=[],
        authority_public=False,
    )
    session.add(ef)
    session.flush()
    return ef.id


@requires_postgres
def test_record_effect_verdict_stale_function_id_writes_null(clean_effects):
    session = clean_effects
    address = "0x" + "22" * 20
    fn_id = _seed_function_row(session, address, "0x8456cb59")
    # Simulate a concurrent policy row replace: the selected id vanishes.
    session.query(EffectiveFunction).filter(EffectiveFunction.id == fn_id).delete(synchronize_session=False)
    session.flush()
    record_effect_verdict(
        session,
        chain_id=1,
        contract_address=address,
        selector="0x8456cb59",
        effect_class="freeze_pause",
        verdict="proven",
        tier="tier2",
        function_id=fn_id,
        witness={"latch_flip": True},
    )
    session.commit()
    row = session.query(EffectVerdict).one()
    assert row.function_id is None
    assert row.verdict == "proven"
    assert row.witness == {"latch_flip": True}


@requires_postgres
def test_stale_function_id_does_not_poison_sibling_verdicts(clean_effects):
    """One stale id in a job's worklist must not lose the other candidates'
    verdicts — the whole-job session stays writable and commits both rows."""
    session = clean_effects
    live_addr = "0x" + "33" * 20
    stale_addr = "0x" + "44" * 20
    live_id = _seed_function_row(session, live_addr, "0x8456cb59")
    stale_id = _seed_function_row(session, stale_addr, "0x8456cb59")
    session.query(EffectiveFunction).filter(EffectiveFunction.id == stale_id).delete(synchronize_session=False)
    session.flush()
    for addr, fid in ((stale_addr, stale_id), (live_addr, live_id)):
        record_effect_verdict(
            session,
            chain_id=1,
            contract_address=addr,
            selector="0x8456cb59",
            effect_class="freeze_pause",
            verdict="proven",
            tier="tier2",
            function_id=fid,
        )
    session.commit()
    rows = {r.contract_address: r for r in session.query(EffectVerdict).all()}
    assert len(rows) == 2
    assert rows[live_addr].function_id == live_id
    assert rows[stale_addr].function_id is None


# ---------------------------------------------------------------------------
# State-plane residue survives observation-less rewrites (the cache-HIT shape).
#
# The code-plane cache structurally carries no concrete values, so every
# cache-HIT resolution re-writes its verdict row with ``concrete_destination=None``.
# An unconditional SET erased the cold first-sighting observation on every hit.
# ---------------------------------------------------------------------------

RESIDUE_ADDR = "0x" + "55" * 20
DEST = "0x" + "de" * 20


def _write(session, **kw):
    base: dict[str, Any] = {
        "chain_id": 1,
        "contract_address": RESIDUE_ADDR,
        "selector": "0x40c10f19",
        "effect_class": "value_out",
        "behavior_hash": "bh_residue",
        "verdict": "proven",
        "tier": "tier1",
    }
    base.update(kw)
    record_effect_verdict(session, **base)
    session.commit()
    session.expire_all()
    return session.query(EffectVerdict).one()


@requires_postgres
def test_cache_hit_rewrite_preserves_state_plane_residue(clean_effects):
    """The exact live-DB failure: a cold write captures the destination, a later
    cache-HIT job re-writes the SAME verdict carrying none, and the residue must
    survive — while the resolution facts still track the newest write."""
    session = clean_effects
    _write(session, concrete_destination=DEST, current_check_passed=True, witness={"destination_shape": "param"})

    row = _write(session, tier="tier0", concrete_destination=None, current_check_passed=None)

    assert row.concrete_destination == DEST
    assert row.current_check_passed is True
    assert row.verdict == "proven"
    assert row.tier == "tier0"


@requires_postgres
def test_downgraded_verdict_drops_the_residue_that_justified_it(clean_effects):
    """Residue must not outlive the evidence for it. The witness and transcript
    are already overwritten on a downgrade precisely so a *proven* witness never
    sits beside an ``unknown`` verdict; an orphaned ``concrete_destination`` is
    the same contradiction in another column — and ``find_verdict_residue_batch``
    reads it, so the orphan would also suppress re-observation forever."""
    session = clean_effects
    _write(
        session,
        concrete_destination=DEST,
        current_check_passed=True,
        observed_residue={"observed_reach_value_usd": 5_000_000.0},
        witness={"destination_shape": "param"},
    )

    row = _write(session, verdict="unknown", concrete_destination=None, current_check_passed=None)

    assert row.verdict == "unknown"
    assert row.concrete_destination is None
    assert row.current_check_passed is None
    assert row.observed_residue is None
    assert row.witness is None


@requires_postgres
def test_observed_residue_merges_key_wise_across_observation_less_rewrites(clean_effects):
    """``observed_residue`` is a bag of independent residue facts written by
    different paths (downstream value-reach on a cold probe, re-probe bookkeeping on a hit), so
    a write carrying only some keys must leave the others standing."""
    session = clean_effects
    _write(session, observed_residue={"observed_reach_value_usd": 42.0, "observed_reach_holders": ["0xaa"]})

    row = _write(session, observed_residue={"destination_probe_attempts": 1})

    assert row.observed_residue == {
        "observed_reach_value_usd": 42.0,
        "observed_reach_holders": ["0xaa"],
        "destination_probe_attempts": 1,
    }
    # A fresh observation of the same key still wins.
    row = _write(session, observed_residue={"observed_reach_value_usd": 7.0})
    assert row.observed_residue["observed_reach_value_usd"] == 7.0
    assert row.observed_residue["destination_probe_attempts"] == 1


@requires_postgres
def test_probe_bookkeeping_survives_a_verdict_flip(clean_effects):
    """A verdict flip must clear the OBSERVATIONS (they described the old answer)
    without refunding the re-probe budget.

    ``destination_probe_attempts`` is not an observation of the contract — it is
    how many times this deployment has already been re-probed, which stays true
    across a flip. Dropping the whole bag reset the ≤2 cap, so a behavior that is
    proven in the cache but unreproducible HERE flips its way to an unbounded
    number of Tier-1 probes: two per flip, on every job, forever."""
    session = clean_effects
    _write(
        session,
        observed_residue={"destination_probe_attempts": 2, "observed_reach_value_usd": 42.0},
        concrete_destination=DEST,
    )

    row = _write(session, verdict="unknown", observed_residue=None, concrete_destination=None)

    assert row.verdict == "unknown"
    # The observation is gone (it justified the old verdict) ...
    assert "observed_reach_value_usd" not in (row.observed_residue or {})
    assert row.concrete_destination is None
    # ... and the bound the observation was probed under is not refunded.
    assert row.observed_residue == {"destination_probe_attempts": 2}

    # A flip back does not resurrect the observation either.
    row = _write(session, verdict="proven", observed_residue=None)
    assert row.observed_residue == {"destination_probe_attempts": 2}


@requires_postgres
def test_a_flip_with_a_fresh_attempt_count_takes_the_new_one(clean_effects):
    session = clean_effects
    _write(session, observed_residue={"destination_probe_attempts": 1, "observed_reach_holders": ["0xaa"]})
    row = _write(session, verdict="unknown", observed_residue={"destination_probe_attempts": 2})
    assert row.observed_residue == {"destination_probe_attempts": 2}


@requires_postgres
def test_a_code_change_also_keeps_the_probe_bookkeeping(clean_effects):
    """A new behavior hash drops the residue for the same reason a flip does; the
    attempt count is still about this DEPLOYMENT's probe spend, not the code."""
    session = clean_effects
    _write(session, observed_residue={"destination_probe_attempts": 2, "observed_reach_value_usd": 1.0})
    row = _write(session, behavior_hash="other-hash", observed_residue=None)
    assert row.observed_residue == {"destination_probe_attempts": 2}


@requires_postgres
def test_fresh_observation_overwrites_stale_residue(clean_effects):
    """Preservation is only for the absent case — a real new observation wins."""
    session = clean_effects
    _write(session, concrete_destination=DEST, current_check_passed=True)
    other = "0x" + "ab" * 20
    row = _write(session, concrete_destination=other, current_check_passed=False)
    assert row.concrete_destination == other
    assert row.current_check_passed is False


@requires_postgres
def test_behavior_hash_change_drops_stale_residue(clean_effects):
    """Residue is code-relative: an upgraded implementation must not inherit the
    previous one's observed destination just because the address is unchanged."""
    session = clean_effects
    _write(
        session,
        concrete_destination=DEST,
        current_check_passed=True,
        observed_residue={"observed_reach_value_usd": 9.0},
    )
    row = _write(session, behavior_hash="bh_after_upgrade", concrete_destination=None, current_check_passed=None)
    assert row.behavior_hash == "bh_after_upgrade"
    assert row.concrete_destination is None
    assert row.current_check_passed is None
    assert row.observed_residue is None


@requires_postgres
def test_witness_and_transcript_track_the_verdict(clean_effects):
    """Evidence is NOT residue-preserved: a downgrade to ``unknown`` must not keep
    publishing the witness that proved the previous verdict."""
    session = clean_effects
    _write(session, witness={"destination_shape": "param"}, transcript_ptr="job-a::t1")
    row = _write(session, verdict="unknown", witness=None, transcript_ptr=None)
    assert row.witness is None
    assert row.transcript_ptr is None


@requires_postgres
def test_function_id_link_survives_an_unresolved_rewrite(clean_effects):
    """The FK is ON DELETE SET NULL, so a stored non-NULL id is always live. A
    write that could not resolve one must not orphan the row."""
    session = clean_effects
    addr = "0x" + "66" * 20
    fn_id = _seed_function_row(session, addr, "0x8456cb59")
    for fid in (fn_id, None):
        record_effect_verdict(
            session,
            chain_id=1,
            contract_address=addr,
            selector="0x8456cb59",
            effect_class="freeze_pause",
            verdict="proven",
            tier="tier2",
            function_id=fid,
        )
    session.commit()
    session.expire_all()
    assert session.query(EffectVerdict).one().function_id == fn_id


# ---------------------------------------------------------------------------
# The code/deployment plane split, and the self-audit floor
# ---------------------------------------------------------------------------


@requires_postgres
def test_a_cache_row_never_stores_a_per_deployment_observation(clean_effects):
    """Cache scope enforced at the WRITE. Every key in ``DEPLOYMENT_PLANE_KEYS`` is an
    observation of ONE deployment's fork state, and this row is served to every other
    deployment sharing the bytecode — so a hit used to hand deployment B deployment A's
    blast radius, A's pre-pause succeeding set and A's seeding qualifiers as B's own
    witness. Measured before the split: 74 of 150 local cache rows carried at least one
    (29 freeze_pause, 21 supply, 20 value_out, 4 more).

    They are ABSENT on the served row — absent, not ``null`` and not ``false`` — so a
    consumer reads "no observation of my own" instead of another contract's number."""
    session = clean_effects
    row = effect_cache.upsert_cached_verdict(
        session,
        behavior_hash="bh_plane",
        effect_class="freeze_pause",
        scope="projection",
        contract_surface_hash="surface_x",
        verdict="proven",
        tier="tier2",
        details={
            "latch_flip": True,
            "observation": "executed",
            "duration_bound_seconds": 2592000,
            "duration_bound_source": "guard_constant",
            # per-deployment — must not survive the write
            "observed_blast_radius": ["transfer(address,uint256)"],
            "pre_pause_succeeding": ["transfer(address,uint256)"],
            "scored_denominator": ["transfer(address,uint256)"],
            "input_seeded": True,
            "contract_balance_seeded": True,
            "backing": {"inflow_observed": True},
            "pause_effective": True,
            "auto_expiry": True,
        },
    )
    stored = row.details or {}
    for key in effect_cache.DEPLOYMENT_PLANE_KEYS:
        assert key not in stored, key
    # ...and the code-plane witness the cache exists to carry is intact.
    assert stored["latch_flip"] is True
    assert stored["duration_bound_seconds"] == 2592000
    assert stored["duration_bound_source"] == "guard_constant"
    assert stored["observation"] == "executed"


def test_a_zero_key_signature_is_not_comparable():
    """49 of 150 cache rows are ``authority_change`` with ``verdict='unknown'`` and none
    of the five allowlisted structural keys, so their signature is
    ``('unknown', None, None, None, None, None)`` on both sides and ``kernel_verdicts_
    agree`` returns True unconditionally. Agreement there is the string ``unknown``
    compared with itself."""
    thin = {"observation": "executed", "reason": "no_authorization_delta_observed"}
    assert effect_cache.kernel_verdicts_agree("unknown", thin, "unknown", thin) is True
    assert effect_cache.kernel_signature_is_comparable(thin) is False
    assert effect_cache.kernel_signature_is_comparable(None) is False
    assert effect_cache.kernel_signature_is_comparable({}) is False
    # One structural key is the floor, and each of the five clears it on its own.
    for key in ("latch_flip", "gate_mutation", "upgradeable", "supply_delta_sign", "destination_shape"):
        assert effect_cache.kernel_signature_is_comparable({**thin, key: None}) is True, key


# ---------------------------------------------------------------------------
# Cache-served witness rewrites (``witness_from_cache``): a self-hit must not
# erase the producing write's deployment-plane qualifiers.
#
# The realized shape (PR-161 effect_verdicts id 146): a proven ``supply_burn``
# whose transcript records ``input_seeded: true`` was rewritten by its own cache
# hit with the code-plane payload, and absence of ``input_seeded`` contractually
# means "no seeding was needed" — the published claim asserted an unseeded live
# burn its own transcript refutes.
# ---------------------------------------------------------------------------

FULL_WITNESS: dict[str, Any] = {
    "reason": "supply_burn",
    "observation": "executed",
    "supply_delta_sign": "burn",
    "input_seeded": True,
    "contract_balance_seeded": True,
    "backing": {"inflow_observed": False, "minted": False, "input_seeded": True, "contract_balance_seeded": False},
}
# What the cache serves for the same behavior: the code-plane projection.
STRIPPED_WITNESS = {k: v for k, v in FULL_WITNESS.items() if k not in effect_cache.DEPLOYMENT_PLANE_KEYS}


def _write_burn(session, **kw):
    base: dict[str, Any] = {
        "chain_id": 1,
        "contract_address": "0x" + "77" * 20,
        "selector": "0xee7a7c04",
        "effect_class": "supply",
        "behavior_hash": "bh_selfhit",
        "verdict": "proven",
        "tier": "tier1",
    }
    base.update(kw)
    record_effect_verdict(session, **base)
    session.commit()
    session.expire_all()
    return session.query(EffectVerdict).one()


@requires_postgres
def test_cache_served_rewrite_preserves_deployment_plane_witness(clean_effects):
    """The verdict-146 shape: producing write carries the seed qualifiers, the
    self-hit rewrite carries the stripped cache payload — every deployment-plane
    key must survive, and the code-plane keys still track the newest write."""
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, witness=dict(STRIPPED_WITNESS), witness_from_cache=True)
    assert row.witness["input_seeded"] is True
    assert row.witness["contract_balance_seeded"] is True
    assert row.witness["backing"] == FULL_WITNESS["backing"]
    assert row.witness["supply_delta_sign"] == "burn"
    assert row.witness["observation"] == "executed"


@requires_postgres
def test_cache_served_rewrite_keeps_freeze_pause_observations(clean_effects):
    """The companion evidence-destruction shape (PR-161 ids 14/16/22/26/206/207):
    an unknown freeze_pause row loses ``pre_pause_succeeding`` /
    ``observed_blast_radius`` / ``scored_denominator`` to its own self-hit."""
    session = clean_effects
    full = {
        "reason": "no_blast_radius_observed",
        "observation": "executed",
        "pause_effective": True,
        "pre_pause_succeeding": ["transfer(address,uint256)"],
        "observed_blast_radius": [],
        "scored_denominator": ["transfer(address,uint256)"],
        # Empty blast radius -> the expiry warp never ran; the stored JSON null
        # ("not probed") must survive the self-hit as null, not become absent.
        "auto_expiry": None,
    }
    stripped = {k: v for k, v in full.items() if k not in effect_cache.DEPLOYMENT_PLANE_KEYS}
    _write_burn(session, effect_class="freeze_pause", verdict="unknown", witness=full)
    row = _write_burn(
        session, effect_class="freeze_pause", verdict="unknown", witness=stripped, witness_from_cache=True
    )
    for key in (
        "pre_pause_succeeding",
        "observed_blast_radius",
        "scored_denominator",
        "pause_effective",
        "auto_expiry",
    ):
        assert row.witness[key] == full[key], key


@requires_postgres
def test_cache_served_rewrite_lets_a_present_incoming_key_win(clean_effects):
    """Incoming keys win where present: a payload that DOES carry a deployment-plane
    key (the audited-hit enrichment) overrides the stored value instead of being
    shadowed by it."""
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, witness={**STRIPPED_WITNESS, "input_seeded": False}, witness_from_cache=True)
    assert row.witness["input_seeded"] is False
    # Keys the incoming payload does not carry still survive.
    assert row.witness["contract_balance_seeded"] is True


@requires_postgres
def test_cache_served_rewrite_never_resurrects_across_a_verdict_change(clean_effects):
    """The adverse branch: evidence moves with the verdict. A downgrade served from
    the cache must not carry the proven write's qualifiers forward."""
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(
        session,
        verdict="unknown",
        witness={"reason": "no_supply_delta", "observation": "executed"},
        witness_from_cache=True,
    )
    assert "input_seeded" not in row.witness
    assert "backing" not in row.witness
    assert row.witness["reason"] == "no_supply_delta"


@requires_postgres
def test_cache_served_rewrite_never_resurrects_across_a_code_change(clean_effects):
    """Same lifecycle as residue: a changed behavior hash means different code, and
    the old deployment-plane observation does not describe it."""
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, behavior_hash="bh_upgraded", witness=dict(STRIPPED_WITNESS), witness_from_cache=True)
    assert "input_seeded" not in row.witness
    assert "contract_balance_seeded" not in row.witness
    assert "backing" not in row.witness


@requires_postgres
def test_cache_served_null_payload_keeps_the_stored_witness(clean_effects):
    """A hit served from a NULL-details cache row asserts the same verdict of the
    same code and nothing else — the stored evidence still describes it."""
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, witness=None, witness_from_cache=True)
    assert row.witness == FULL_WITNESS


@requires_postgres
def test_absence_of_seeding_survives_a_hit_rewrite_as_absence(clean_effects):
    """The earned negative stays earned: a verdict whose producing probe needed no
    seeding publishes ABSENT qualifiers, and a self-hit must not fabricate any."""
    session = clean_effects
    unseeded = {"reason": "supply_burn", "observation": "executed", "supply_delta_sign": "burn"}
    _write_burn(session, witness=dict(unseeded))
    row = _write_burn(session, witness=dict(unseeded), witness_from_cache=True)
    assert row.witness == unseeded
    for key in effect_cache.DEPLOYMENT_PLANE_KEYS:
        assert key not in row.witness, key


@requires_postgres
def test_fresh_probe_rewrite_still_overwrites_unconditionally(clean_effects):
    """The default (fresh-probe) path is untouched: there an absent key IS the
    current measurement — a re-probe that needed no seeding must publish that."""
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, witness=dict(STRIPPED_WITNESS))
    assert "input_seeded" not in row.witness
    assert "contract_balance_seeded" not in row.witness
    assert "backing" not in row.witness
