"""Effect-verdict cache: kernel-vs-projection scope, self-audit, state-plane
residue, version invalidation (EFFECTS_RESOLUTION_SPEC §7 / inv. 3, 12).

DB-backed (real Postgres), offline-safe. Mirrors the materialization-cache test
conventions."""

from __future__ import annotations

import sys
from pathlib import Path

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
from db.models import EffectBehaviorCache, EffectVerdict  # noqa: E402
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
