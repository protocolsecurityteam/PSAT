from __future__ import annotations

from typing import Any

import pytest

from db import effect_cache
from db.effect_cache import (
    EFFECT_CACHE_SCHEMA_VERSION,
    KERNEL_SURFACE_SENTINEL,
    find_cached_verdict,
    kernel_verdicts_agree,
    record_effect_verdict,
    upsert_cached_verdict,
)
from db.models import Contract, EffectBehaviorCache, EffectiveFunction, EffectVerdict
from tests.cache_helpers import requires_postgres
from tests.support.effects_worker_harness import clean_effects  # noqa: F401  (fixture, registered by import)

KERNEL = "kernel"
PROJECTION = "projection"


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
    # A kernel is function-local.
    hit = find_cached_verdict(
        session, behavior_hash="bh_kernel", effect_class="supply", scope=KERNEL, contract_surface_hash="ignored"
    )
    assert hit is not None and hit.id == row.id


@requires_postgres
def test_projection_keys_on_surface_two_surfaces_two_rows(clean_effects):
    """A projection transfers only on whole-contract identity."""
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
    """The free cross-deployment / cross-chain-twin hit."""
    session = clean_effects
    upsert_cached_verdict(
        session,
        behavior_hash="bh_shared",
        effect_class="supply",
        scope=KERNEL,
        verdict="proven",
        tier="tier1",
    )
    hit = find_cached_verdict(session, behavior_hash="bh_shared", effect_class="supply", scope=KERNEL)
    assert hit is not None
    assert session.query(EffectBehaviorCache).count() == 1


def test_kernel_verdicts_agree_ignores_concrete_values():
    assert kernel_verdicts_agree(
        "proven",
        {"supply_delta_sign": "mint", "destination": "0xaaa"},
        "proven",
        {"supply_delta_sign": "mint", "destination": "0xbbb"},
    )
    assert not kernel_verdicts_agree("proven", {"supply_delta_sign": "mint"}, "proven", {"supply_delta_sign": "burn"})
    assert not kernel_verdicts_agree("proven", {"latch_flip": True}, "unknown", {"latch_flip": True})


@requires_postgres
def test_stale_schema_version_reads_as_miss(clean_effects):
    session = clean_effects
    row = upsert_cached_verdict(
        session, behavior_hash="bh_v", effect_class="supply", scope=KERNEL, verdict="proven", tier="tier1"
    )
    row.analysis_schema_version = EFFECT_CACHE_SCHEMA_VERSION + 1
    session.flush()
    assert find_cached_verdict(session, behavior_hash="bh_v", effect_class="supply", scope=KERNEL) is None


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


# Identity is the deployment coordinates; function_id is a convenience join, so a replace mid-run must not fail the
# write.


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
def test_fk_vanish_fallback_warns_and_records_degraded(clean_effects, caplog):
    """The FK-violation fallback inside the check-insert window is a known orphaned-row bug class."""
    import logging

    from sqlalchemy import delete

    from utils.logging import degraded_errors_var

    session = clean_effects
    address = "0x" + "55" * 20
    fn_id = _seed_function_row(session, address, "0x8456cb59")
    session.commit()

    injected = {"done": False}
    orig_execute = session.execute

    def execute_then_delete(statement, *args, **kwargs):
        result = orig_execute(statement, *args, **kwargs)
        if not injected["done"] and "effective_functions" in str(statement).lower():
            injected["done"] = True
            orig_execute(delete(EffectiveFunction).where(EffectiveFunction.id == fn_id))
        return result

    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    session.execute = execute_then_delete
    try:
        with caplog.at_level(logging.WARNING, logger="db.effect_cache"):
            record_effect_verdict(
                session,
                chain_id=1,
                contract_address=address,
                selector="0x8456cb59",
                effect_class="freeze_pause",
                verdict="proven",
                tier="tier2",
                function_id=fn_id,
            )
    finally:
        del session.execute
        degraded_errors_var.reset(token)
    session.commit()

    assert injected["done"], "FK-vanish injection never fired — the test would be vacuous"
    row = session.query(EffectVerdict).one()
    assert row.function_id is None and row.verdict == "proven"
    rec = next(r for r in caplog.records if r.name == "db.effect_cache")
    assert rec.levelno == logging.WARNING
    assert rec.function_id == fn_id
    assert rec.contract_address == address
    assert [e.phase for e in accumulator] == ["effect_verdict_unlink"]
    # The IntegrityError's str() would be the upsert SQL.
    assert accumulator[0].exc_type.endswith(".EffectVerdictUnlinked")
    assert "vanished" in accumulator[0].message and "INSERT" not in accumulator[0].message


@requires_postgres
def test_stale_function_id_does_not_poison_sibling_verdicts(clean_effects):
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


# Cache hits carry no concrete values; an unconditional SET erased the cold first-sighting observation.

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
    session = clean_effects
    _write(session, concrete_destination=DEST, current_check_passed=True, witness={"destination_shape": "param"})

    row = _write(session, tier="tier0", concrete_destination=None, current_check_passed=None)

    assert row.concrete_destination == DEST
    assert row.current_check_passed is True
    assert row.verdict == "proven"
    assert row.tier == "tier0"


@requires_postgres
def test_downgraded_verdict_drops_the_residue_that_justified_it(clean_effects):
    """``find_verdict_residue_batch`` would read orphaned residue and suppress re-observation forever."""
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
    """Different paths write different keys."""
    session = clean_effects
    _write(session, observed_residue={"observed_reach_value_usd": 42.0, "observed_reach_holders": ["0xaa"]})

    row = _write(session, observed_residue={"destination_probe_attempts": 1})

    assert row.observed_residue == {
        "observed_reach_value_usd": 42.0,
        "observed_reach_holders": ["0xaa"],
        "destination_probe_attempts": 1,
    }
    row = _write(session, observed_residue={"observed_reach_value_usd": 7.0})
    assert row.observed_residue["observed_reach_value_usd"] == 7.0
    assert row.observed_residue["destination_probe_attempts"] == 1


@requires_postgres
def test_probe_bookkeeping_survives_a_verdict_flip(clean_effects):
    """Resetting the attempt count would reset the <=2 cap and allow unbounded Tier-1 probes."""
    session = clean_effects
    _write(
        session,
        observed_residue={"destination_probe_attempts": 2, "observed_reach_value_usd": 42.0},
        concrete_destination=DEST,
    )

    row = _write(session, verdict="unknown", observed_residue=None, concrete_destination=None)

    assert row.verdict == "unknown"
    assert "observed_reach_value_usd" not in (row.observed_residue or {})
    assert row.concrete_destination is None
    assert row.observed_residue == {"destination_probe_attempts": 2}

    row = _write(session, verdict="proven", observed_residue=None)
    assert row.observed_residue == {"destination_probe_attempts": 2}


@requires_postgres
@pytest.mark.parametrize(
    ("first_residue", "rewrite", "expected"),
    [
        pytest.param(
            {"destination_probe_attempts": 1, "observed_reach_holders": ["0xaa"]},
            {"verdict": "unknown", "observed_residue": {"destination_probe_attempts": 2}},
            {"destination_probe_attempts": 2},
            id="flip_with_a_fresh_attempt_count_takes_the_new_one",
        ),
        # The attempt count is about this deployment's probe spend, not the code.
        pytest.param(
            {"destination_probe_attempts": 2, "observed_reach_value_usd": 1.0},
            {"behavior_hash": "other-hash", "observed_residue": None},
            {"destination_probe_attempts": 2},
            id="code_change_keeps_the_probe_bookkeeping",
        ),
    ],
)
def test_probe_bookkeeping_across_rewrites(clean_effects, first_residue, rewrite, expected):
    session = clean_effects
    _write(session, observed_residue=first_residue)
    row = _write(session, **rewrite)
    assert row.observed_residue == expected


@requires_postgres
def test_fresh_observation_overwrites_stale_residue(clean_effects):
    session = clean_effects
    _write(session, concrete_destination=DEST, current_check_passed=True)
    other = "0x" + "ab" * 20
    row = _write(session, concrete_destination=other, current_check_passed=False)
    assert row.concrete_destination == other
    assert row.current_check_passed is False


@requires_postgres
def test_behavior_hash_change_drops_stale_residue(clean_effects):
    """An upgraded implementation must not inherit the previous one's observed destination."""
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
    session = clean_effects
    _write(session, witness={"destination_shape": "param"}, transcript_ptr="job-a::t1")
    row = _write(session, verdict="unknown", witness=None, transcript_ptr=None)
    assert row.witness is None
    assert row.transcript_ptr is None


@requires_postgres
def test_function_id_link_survives_an_unresolved_rewrite(clean_effects):
    """The FK is ON DELETE SET NULL, so a stored id is always live."""
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


@requires_postgres
def test_a_cache_row_never_stores_a_per_deployment_observation(clean_effects):
    """The row is served to every bytecode twin, so per-deployment observations must be absent (not null) on it."""
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
    assert stored["latch_flip"] is True
    assert stored["duration_bound_seconds"] == 2592000
    assert stored["duration_bound_source"] == "guard_constant"
    assert stored["observation"] == "executed"


def test_a_zero_key_signature_is_not_comparable():
    """With none of the structural keys, ``unknown`` compared with itself and always agreed."""
    thin = {"observation": "executed", "reason": "no_authorization_delta_observed"}
    assert effect_cache.kernel_verdicts_agree("unknown", thin, "unknown", thin) is True
    assert effect_cache.kernel_signature_is_comparable(thin) is False
    assert effect_cache.kernel_signature_is_comparable(None) is False
    assert effect_cache.kernel_signature_is_comparable({}) is False
    for key in ("latch_flip", "gate_mutation", "upgradeable", "supply_delta_sign", "destination_shape"):
        assert effect_cache.kernel_signature_is_comparable({**thin, key: None}) is True, key


# A self-hit must not erase the producing write's deployment-plane qualifiers (PR-161 verdict 146 published a claim its
# own transcript contradicted).

FULL_WITNESS: dict[str, Any] = {
    "reason": "supply_burn",
    "observation": "executed",
    "supply_delta_sign": "burn",
    "input_seeded": True,
    "contract_balance_seeded": True,
    "backing": {"inflow_observed": False, "minted": False, "input_seeded": True, "contract_balance_seeded": False},
}
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
    """PR-161: an unknown freeze_pause row lost its observations to its own self-hit."""
    session = clean_effects
    full = {
        "reason": "no_blast_radius_observed",
        "observation": "executed",
        "pause_effective": True,
        "pre_pause_succeeding": ["transfer(address,uint256)"],
        "observed_blast_radius": [],
        "scored_denominator": ["transfer(address,uint256)"],
        # A stored JSON null ("not probed") survives the self-hit as null, not absent.
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
@pytest.mark.parametrize(
    ("rewrite", "absent", "present"),
    [
        # Evidence moves with the verdict.
        pytest.param(
            {"verdict": "unknown", "witness": {"reason": "no_supply_delta", "observation": "executed"}},
            ("input_seeded", "backing"),
            {"reason": "no_supply_delta"},
            id="verdict_change",
        ),
        pytest.param(
            {"behavior_hash": "bh_upgraded", "witness": dict(STRIPPED_WITNESS)},
            ("input_seeded", "contract_balance_seeded", "backing"),
            {},
            id="code_change",
        ),
    ],
)
def test_cache_served_rewrite_never_resurrects(clean_effects, rewrite, absent, present):
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, witness_from_cache=True, **rewrite)
    for key in absent:
        assert key not in row.witness, key
    for key, value in present.items():
        assert row.witness[key] == value


@requires_postgres
def test_cache_served_null_payload_keeps_the_stored_witness(clean_effects):
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, witness=None, witness_from_cache=True)
    assert row.witness == FULL_WITNESS


@requires_postgres
def test_absence_of_seeding_survives_a_hit_rewrite_as_absence(clean_effects):
    """A self-hit must not fabricate seeding qualifiers."""
    session = clean_effects
    unseeded = {"reason": "supply_burn", "observation": "executed", "supply_delta_sign": "burn"}
    _write_burn(session, witness=dict(unseeded))
    row = _write_burn(session, witness=dict(unseeded), witness_from_cache=True)
    assert row.witness == unseeded
    for key in effect_cache.DEPLOYMENT_PLANE_KEYS:
        assert key not in row.witness, key


@requires_postgres
def test_fresh_probe_rewrite_still_overwrites_unconditionally(clean_effects):
    """On the fresh-probe path an absent key is the current measurement."""
    session = clean_effects
    _write_burn(session, witness=dict(FULL_WITNESS))
    row = _write_burn(session, witness=dict(STRIPPED_WITNESS))
    assert "input_seeded" not in row.witness
    assert "contract_balance_seeded" not in row.witness
    assert "backing" not in row.witness
