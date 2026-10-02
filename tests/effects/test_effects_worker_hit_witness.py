"""The cache stores a payload stripped of deployment-plane qualifiers, and each hit used to overwrite the producing
verdict's witness with it; PR-161 verdict 146 then published a seeded burn as unseeded.
"""

from __future__ import annotations

from typing import Any

from db import effect_cache
from db.effect_cache import record_effect_verdict, upsert_cached_verdict
from db.models import EffectBehaviorCache, EffectVerdict
from services.effects import claims_bridge
from services.effects.harness import ObservedEffect
from services.effects.selection import Candidate
from tests.cache_helpers import requires_postgres
from tests.support.effects_worker_harness import clean_effects  # noqa: F401  (fixture, registered by import)
from workers.effects_worker import EffectsWorker, _Counters, _Item

ADDR = "0x" + "ac" * 20
SELECTOR = "0xee7a7c04"
BEHAVIOR_HASH = "bh_hit_witness"

FRESH_DETAILS: dict[str, Any] = {
    "observation": "executed",
    "supply_delta_sign": "burn",
    "input_seeded": True,
}


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
    """The audit re-simulated this deployment, so the served details carry that measurement."""
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
    # This run's own observation, not a cache-shaped write.
    assert witness_from_cache is False
    assert disc is None


@requires_postgres
def test_self_hit_round_trip_keeps_the_claim_qualifier(clean_effects):
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
    record_effect_verdict(session, witness={"reason": "supply_burn", **FRESH_DETAILS}, **common)
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
