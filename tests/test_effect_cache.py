"""Effect-verdict cache: kernel-vs-projection scope, self-audit, state-plane
residue, version invalidation (EFFECTS_RESOLUTION_SPEC §7 / inv. 3, 12).

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
# kernel vs projection scoping (inv. 3)
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
# self-audit (§7)
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
# The code-plane cache structurally carries no concrete values (inv. 3), so every
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
    different paths (§5b reach on a cold probe, re-probe bookkeeping on a hit), so
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
