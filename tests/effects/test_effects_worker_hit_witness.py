"""Cache-hit witness integrity at the worker seam (``_resolve_item``).

The self-hit clobber, replayed at the layer that armed it: the code-plane cache
stores a payload ``code_plane_details`` stripped of every deployment-plane
qualifier, and each hit path used to hand that stripped payload straight to
``record_effect_verdict`` — which overwrote the producing verdict's own witness
with it. Absence of ``input_seeded`` contractually means "no seeding was
needed" (``claims_bridge._observed_summary``), so the realized row (PR-161
``effect_verdicts`` id 146, eETH ``burnShares``) published a proven unseeded
live burn while its own transcript records ``input_seeded: true`` and the
unseeded probe reverting.

DB-backed (real Postgres), offline-safe.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import effect_cache  # noqa: E402
from db.effect_cache import record_effect_verdict, upsert_cached_verdict  # noqa: E402
from db.models import EffectBehaviorCache, EffectVerdict  # noqa: E402
from services.effects import claims_bridge  # noqa: E402
from services.effects.harness import ObservedEffect  # noqa: E402
from services.effects.selection import Candidate  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402
from workers.effects_worker import EffectsWorker, _Counters, _Item  # noqa: E402

ADDR = "0x" + "ac" * 20
SELECTOR = "0xee7a7c04"
BEHAVIOR_HASH = "bh_hit_witness"

# The producing probe's full payload: proven burn, reached only with seeding.
FRESH_DETAILS: dict[str, Any] = {
    "observation": "executed",
    "supply_delta_sign": "burn",
    "input_seeded": True,
}


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


def _candidate() -> Candidate:
    return Candidate(
        function_id=1,
        contract_id=1,
        contract_address=ADDR,
        selector=SELECTOR,
        function_name="burnShares(address,uint256)",
        authority_public=False,
        principal_addresses=("0x" + "a0" * 20,),
        membership_exact=True,
    )


def _cache_row(
    session,
    *,
    details: dict[str, Any] | None,
    audit_status: str | None = None,
    effect_class: str = "supply",
) -> EffectBehaviorCache:
    return upsert_cached_verdict(
        session,
        behavior_hash=BEHAVIOR_HASH,
        effect_class=effect_class,
        scope="kernel",
        verdict="proven",
        tier="tier1",
        transcript_ptr="job-cold::t1",
        details=details,
        audit_status=audit_status,
    )


def _item(
    cached: EffectBehaviorCache,
    *,
    needs_audit: bool,
    probed: ObservedEffect | None = None,
    effect_class: str = "supply",
) -> _Item:
    return _Item(
        candidate=_candidate(),
        effect_class=effect_class,
        scope="kernel",
        gate_ref="",
        behavior_hash=BEHAVIOR_HASH,
        surface_hash="sh",
        run=lambda: probed,
        cached=cached,
        needs_audit=needs_audit,
        probed=probed,
    )


def _resolve(session, it: _Item):
    worker = object.__new__(EffectsWorker)
    return EffectsWorker._resolve_item(worker, session, it, _Counters())


@requires_postgres
def test_audited_hit_reattaches_the_fresh_probes_seed_qualifiers(clean_effects):
    """The verdict-146 replay: the audit re-simulated THIS deployment and its
    probe seeded again — the served details must carry that measurement, not the
    cache's structural absence."""
    session = clean_effects
    cached = _cache_row(session, details=effect_cache.code_plane_details(dict(FRESH_DETAILS)))
    fresh = ObservedEffect(
        effect_class="supply",
        verdict="proven",
        tier="tier1",
        reason="supply_burn",
        details=dict(FRESH_DETAILS),
    )
    verdict, tier, ptr, details, concrete, disc, witness_from_cache = _resolve(
        session, _item(cached, needs_audit=True, probed=fresh)
    )
    assert (verdict, tier, ptr) == ("proven", "tier1", "job-cold::t1")
    assert details is not None and details["input_seeded"] is True
    assert details["supply_delta_sign"] == "burn"
    # A fresh measurement was attached, so the write is NOT cache-shaped: an
    # absent key here is this run's own observation.
    assert witness_from_cache is False
    assert disc is None


@requires_postgres
def test_audited_hit_with_an_unseeded_fresh_probe_publishes_absence(clean_effects):
    """The other direction stays earned: a fresh audit probe that needed no
    seeding publishes ABSENT qualifiers even if a prior payload carried them."""
    session = clean_effects
    cached = _cache_row(session, details={"observation": "executed", "supply_delta_sign": "burn"})
    fresh = ObservedEffect(
        effect_class="supply",
        verdict="proven",
        tier="tier1",
        reason="supply_burn",
        details={"observation": "executed", "supply_delta_sign": "burn"},
    )
    _, _, _, details, _, _, witness_from_cache = _resolve(session, _item(cached, needs_audit=True, probed=fresh))
    assert details is not None
    for key in effect_cache.DEPLOYMENT_PLANE_KEYS:
        assert key not in details, key
    assert witness_from_cache is False


@requires_postgres
def test_audited_hit_attaches_the_fresh_probes_auto_expiry(clean_effects):
    """The rendered freeze pair must come from ONE observation. ``auto_expiry``
    is a subset predicate over this fork's own blast radius, and it is the sole
    gate on rendering the duration bound as a severity reducer
    (``claimsVocab.pauseQualifier``) — so the audited hit's published witness
    must carry the fresh probe's answer next to the fresh probe's freeze scope,
    never the cache's answer beside an enlarged scope it was not measured on."""
    session = clean_effects
    cold = {
        "observation": "executed",
        "latch_flip": True,
        "pause_effective": True,
        "pre_pause_succeeding": ["a()"],
        "observed_blast_radius": ["a()"],
        "scored_denominator": ["a()", "b()"],
        "auto_expiry": True,
        "duration_bound_seconds": 2592000,
        "duration_bound_source": "guard_constant",
    }
    cached = _cache_row(session, details=effect_cache.code_plane_details(dict(cold)), effect_class="freeze_pause")
    # The write-side strip already kept the expiry answer off the cache row.
    assert cached.details is not None and "auto_expiry" not in cached.details
    fresh = ObservedEffect(
        effect_class="freeze_pause",
        verdict="proven",
        tier="tier1",
        reason="pause_froze_entry_points",
        details={
            **cold,
            "pre_pause_succeeding": ["a()", "b()"],
            "observed_blast_radius": ["a()", "b()"],
            "auto_expiry": False,
        },
    )
    _, _, _, details, _, disc, witness_from_cache = _resolve(
        session, _item(cached, needs_audit=True, probed=fresh, effect_class="freeze_pause")
    )
    assert disc is None
    assert details is not None
    assert details["observed_blast_radius"] == ["a()", "b()"]
    assert details["auto_expiry"] is False
    assert witness_from_cache is False


@requires_postgres
def test_plain_hit_declares_its_witness_cache_shaped(clean_effects):
    """No re-simulation happened, so the flag tells the verdict upsert that the
    payload's missing deployment-plane keys are structural, not measured."""
    session = clean_effects
    cached = _cache_row(
        session,
        details={"observation": "executed", "supply_delta_sign": "burn"},
        audit_status=effect_cache.AUDIT_PASSED,
    )
    verdict, tier, ptr, details, concrete, disc, witness_from_cache = _resolve(
        session, _item(cached, needs_audit=False)
    )
    assert (verdict, tier) == ("proven", "tier1")
    assert details == {"observation": "executed", "supply_delta_sign": "burn"}
    assert witness_from_cache is True
    assert disc is None


@requires_postgres
def test_plain_hit_launders_a_stale_deployment_plane_key(clean_effects):
    """A same-version row minted before a key joined ``DEPLOYMENT_PLANE_KEYS``
    (``pause_effective``) must not republish it as this deployment's own."""
    session = clean_effects
    cached = _cache_row(
        session,
        details={"observation": "executed", "supply_delta_sign": "burn"},
        audit_status=effect_cache.AUDIT_PASSED,
    )
    # Simulate the stale row: the write-side strip did not know the keys yet.
    cached.details = {**(cached.details or {}), "pause_effective": True, "auto_expiry": True}
    session.flush()
    _, _, _, details, _, _, _ = _resolve(session, _item(cached, needs_audit=False))
    assert details is not None and "pause_effective" not in details
    assert "auto_expiry" not in details


@requires_postgres
def test_self_hit_round_trip_keeps_the_claim_qualifier(clean_effects):
    """End to end across the two fixed layers: producing write → plain self-hit
    rewrite → minted claim. The published claim must still carry the synthesis
    qualifier the transcript recorded."""
    session = clean_effects
    common: dict[str, Any] = {
        "chain_id": 1,
        "contract_address": ADDR,
        "selector": SELECTOR,
        "effect_class": "supply",
        "behavior_hash": BEHAVIOR_HASH,
        "verdict": "proven",
        "tier": "tier1",
    }
    # Cold run: the probe seeded, and said so.
    record_effect_verdict(session, witness={"reason": "supply_burn", **FRESH_DETAILS}, **common)
    # Later run: plain self-hit serves the code-plane payload.
    cached = _cache_row(
        session,
        details=effect_cache.code_plane_details({"reason": "supply_burn", **FRESH_DETAILS}),
        audit_status=effect_cache.AUDIT_PASSED,
    )
    _, _, _, details, _, _, witness_from_cache = _resolve(session, _item(cached, needs_audit=False))
    record_effect_verdict(session, witness=details or None, witness_from_cache=witness_from_cache, **common)
    session.commit()
    session.expire_all()
    row = session.query(EffectVerdict).one()
    assert row.witness["input_seeded"] is True
    claim = claims_bridge.verdict_to_claim(row)
    assert claim is not None and claim["claim_id"] == "supply.burn"
    assert claim["witness"]["observed"]["input_seeded"] is True
