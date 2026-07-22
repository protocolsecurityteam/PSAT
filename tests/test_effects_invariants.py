"""§10 implementation-invariant sweep (EFFECTS_RESOLUTION_SPEC).

One explicit test per invariant 1–16, each CLOSING the invariant with an
assertion or recorded evidence — mirroring the MULTICHAIN_INVARIANTS inv-test
precedent (``tests/test_multichain_*``). Offline/hermetic; the DB-touching cases
carry ``@requires_postgres``.
"""

from __future__ import annotations

import inspect
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import effect_cache  # noqa: E402
from db.effect_cache import (  # noqa: E402
    KERNEL_SURFACE_SENTINEL,
    find_cached_verdict,
    kernel_verdicts_agree,
    upsert_cached_verdict,
)
from db.models import (  # noqa: E402
    Contract,
    EffectBehaviorCache,
    EffectiveFunction,
    EffectVerdict,
    JobStage,
    Protocol,
)
from services.effects import anvil, recipes  # noqa: E402
from services.effects.config import (  # noqa: E402
    EFFECT_CLASS_CODE_UPGRADE,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
    effects_stage_enabled,
)
from services.effects.discrepancies import file_new_idiom_candidate, route_discrepancy  # noqa: E402
from services.effects.hashing import resolved_function_hash  # noqa: E402
from services.effects.preflight import (  # noqa: E402
    InMemoryCapabilityStore,
    probe_simulate_support,
    require_simulate_or_fallback,
)
from services.effects.selection import AuthorityGraph, select_candidates  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402

# Shared structural doubles + scripted stubs from the harness tests.
from tests.test_effects_harness import CTX, RecordingStore, ScriptedSimulate, ok, transfer_log, uint_ret  # noqa: E402
from tests.test_effects_hashing import _fn, _ir, _node, _var  # noqa: E402
from workers.base import _resolve_job_concurrency  # noqa: E402
from workers.effects_worker import EffectsWorker  # noqa: E402

CONTRACT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20
SENTINEL = "0x" + "ee" * 20


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
# inv. 1 — no name drives an effect; every verdict traces to a witness.
# ---------------------------------------------------------------------------


def test_inv1_no_name_drives_effect():
    # Two structurally-identical functions with DIFFERENT names hash equal —
    # the identity is structural, never the name.
    a = _fn("A.wildlyDifferentName()", nodes=[_node("EXPRESSION", [_ir("Assignment", lvalue=_var("StateVariable"))])])
    b = _fn("B.f()", nodes=[_node("EXPRESSION", [_ir("Assignment", lvalue=_var("StateVariable"))])])
    assert resolved_function_hash(a) == resolved_function_hash(b)
    # And a positive verdict carries a replayable transcript (an observed witness).
    from services.effects.simulate import SimResult

    res = SimResult(
        calls=(ok(uint_ret(1)), ok(logs=[transfer_log(CONTRACT, "0x" + "00" * 20, PRINCIPAL, 1)]), ok(uint_ret(2)))
    )
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        token_address=CONTRACT,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19",
        simulate_supported=True,
    )
    assert eff.transcript is not None and eff.is_proven


# ---------------------------------------------------------------------------
# inv. 2 — dedup key is the RESOLVED function, never a name/file hash.
# ---------------------------------------------------------------------------


def test_inv2_override_and_mixin_hash_apart():
    latch = _var("StateVariable", "_pausedUntil")
    sender = _var("SolidityVariableComposed", "msg.sender")
    admin = _var("StateVariable", "admin")
    guardian = _var("StateVariable", "guardian")
    mixin = _fn("Base.pauseUntil(uint256)", nodes=[_node("EXPRESSION", [_ir("Assignment", lvalue=latch)])])
    override = _fn(
        "Strict.pauseUntil(uint256)",
        nodes=[
            _node("EXPRESSION", [_ir("Binary", read=[sender, admin, guardian])]),
            _node("EXPRESSION", [_ir("Assignment", lvalue=latch)]),
        ],
    )
    assert resolved_function_hash(mixin) != resolved_function_hash(override)


# ---------------------------------------------------------------------------
# inv. 3 — cache scope matches verdict scope; concrete values never keys.
# ---------------------------------------------------------------------------


@requires_postgres
def test_inv3_cache_scope_matches_verdict_scope(clean_effects):
    session = clean_effects
    # Kernel row: empty surface sentinel; a kernel lookup ignores surface.
    upsert_cached_verdict(
        session, behavior_hash="h", effect_class="supply", scope="kernel", verdict="proven", tier="tier1"
    )
    krow = find_cached_verdict(session, behavior_hash="h", effect_class="supply", scope="kernel")
    assert krow is not None and krow.contract_surface_hash == KERNEL_SURFACE_SENTINEL
    # Projection: same hash on two surfaces → two rows (surface IS part of key).
    upsert_cached_verdict(
        session,
        behavior_hash="h",
        effect_class="freeze_pause",
        scope="projection",
        contract_surface_hash="sX",
        verdict="proven",
        tier="tier2",
    )
    assert (
        find_cached_verdict(
            session, behavior_hash="h", effect_class="freeze_pause", scope="projection", contract_surface_hash="sY"
        )
        is None
    )
    # Concrete values are not columns of the cache identity (no address column).
    cols = {c.name for c in EffectBehaviorCache.__table__.columns}
    assert "concrete_destination" not in cols and "contract_address" not in cols


# ---------------------------------------------------------------------------
# inv. 4 — value ORDERS, never gates; a resource cap logs what it drops.
# ---------------------------------------------------------------------------


@requires_postgres
def test_inv4_value_never_gates_cap_logs_drops(clean_effects, caplog):
    session = clean_effects
    proto = Protocol(name=f"inv4-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    for i in range(3):
        c = Contract(protocol_id=proto.id, address="0x" + f"{i:02x}" * 20, chain="ethereum", is_proxy=False)
        session.add(c)
        session.flush()
        session.add(
            EffectiveFunction(
                contract_id=c.id,
                function_name=f"f{i}",
                selector=f"0x0000000{i}",
                authority_public=False,
                effect_targets=["slot0"],
            )
        )
    session.commit()

    # No value gate: all three blank+gated+facts functions survive (value 0).
    assert len(select_candidates(session, proto.id)) == 3
    # The ONLY cutoff — a resource cap — logs exactly what it dropped (inv. 4).
    import logging as _logging

    with caplog.at_level(_logging.WARNING):
        kept = select_candidates(session, proto.id, resource_cap=1)
    assert len(kept) == 1
    assert "resource cap hit" in caplog.text and "dropped 2 candidate" in caplog.text


# ---------------------------------------------------------------------------
# inv. 5 — transitive reach, not direct balance, drives ordering.
# ---------------------------------------------------------------------------


def test_inv5_transitive_reach_beats_direct_balance():
    safe = "0x" + "5a" * 20
    vault = "0x" + "7a" * 20
    graph = AuthorityGraph()
    graph._add_control(safe, vault)  # the $33k Safe controls the $3.2B vault
    graph.balance[safe] = 33_000.0
    graph.balance[vault] = 3_200_000_000.0
    # Reach from the Safe includes the full downstream vault value (upper bound).
    assert graph.reachable_value({safe}) == pytest.approx(3_200_033_000.0)
    # Its transitive reach dwarfs its direct balance — the ordering signal.
    assert graph.reachable_value({safe}) > graph.balance[safe]


# ---------------------------------------------------------------------------
# inv. 6 — fail-closed both sides.
# ---------------------------------------------------------------------------


def test_inv6_nonobservation_is_unknown_not_proven_absent():
    from services.effects.simulate import SimResult

    eff = recipes.value_out(
        simulate=ScriptedSimulate(SimResult(calls=(ok(),))),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_UNKNOWN  # never a proven-absent


# ---------------------------------------------------------------------------
# inv. 7 — read-only, keyless: no mainnet writes.
# ---------------------------------------------------------------------------


def test_inv7_readonly_keyless():
    from services.effects.simulate import SimResult

    sim = ScriptedSimulate(SimResult(calls=(ok(),)), SimResult(calls=(ok(),)))
    recipes.value_out(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x00000000",
        simulate_supported=True,
        sentinel_address=SENTINEL,
        sentinel_calldata="0x00000000",
    )
    # Every issued call carries zero ETH value (read-only probing, no transfer).
    for calls, _tag, _ov in sim.blocks:
        for c in calls:
            assert c.value == 0
    # The real fork transport defaults to NON-forking (no mainnet-write path).
    assert inspect.signature(anvil.SubprocessAnvil.__init__).parameters["fork_url"].default is None


# ---------------------------------------------------------------------------
# inv. 8 — every verdict tiered and replayable from its transcript.
# ---------------------------------------------------------------------------


def test_inv8_verdict_tiered_and_replayable():
    from services.effects.simulate import SimResult

    store = RecordingStore()
    eff = recipes.supply(
        simulate=ScriptedSimulate(
            SimResult(
                calls=(
                    ok(uint_ret(1)),
                    ok(logs=[transfer_log(CONTRACT, "0x" + "00" * 20, PRINCIPAL, 1)]),
                    ok(uint_ret(3)),
                )
            )
        ),
        store=store,
        ctx=CTX,
        token_address=CONTRACT,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19",
        simulate_supported=True,
    )
    assert eff.tier and eff.transcript_ptr is not None
    tr = store.stored[-1]
    assert {"tier", "block_number", "hardfork", "calls", "results"} <= set(tr)


# ---------------------------------------------------------------------------
# inv. 9 — both planes retained (static universals + simulation existentials).
# ---------------------------------------------------------------------------


def test_inv9_both_planes_retained():
    # Simulation adds an existential witness; static's §9 disagreement routing
    # (both directions) exists so static's vocabulary can grow WITHOUT retiring it.
    assert callable(route_discrepancy) and callable(file_new_idiom_candidate)
    # Selection is driven by STATIC facts (blank-claim set), not simulation.
    src = inspect.getsource(select_candidates)
    assert "claims" in inspect.getsource(sys.modules["services.effects.selection"])
    assert "resource_cap" in src


# ---------------------------------------------------------------------------
# inv. 10 — duration/bound facts read from source constants, never hardcoded.
# ---------------------------------------------------------------------------


def test_inv10_duration_bound_from_source_constant():
    class _T:
        def hardfork(self):
            return "prague"

        def versions(self):
            return {"anvil": "x", "foundry": "x"}

        def snapshot(self):
            return "1"

        def revert(self, snapshot_id):
            return True

        def impersonate(self, address):
            pass

        def stop_impersonate(self, address):
            pass

        def increase_time(self, seconds):
            pass

        def mine(self):
            pass

        def call(self, tx):
            from utils.rpc import EthCallResult

            # Every entry point succeeds pre-pause; the paused one reverts after.
            paused = getattr(self, "_paused", False)
            return EthCallResult(not paused, "0x", None if not paused else "0xdead", None)

        def send(self, tx):
            self._paused = True
            return "0xhash"

    src_read_duration = 4242  # a duration READ from the contract's source constant
    eff = anvil.pause_recipe(
        transport=_T(),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata="0x8456cb59",
        entry_points=[anvil.EntryPoint(key="deposit", calldata="0xd0e30db0")],
        predicted_guard_set=["deposit"],
        max_pause_duration=src_read_duration,
    )
    # The bound in the witness is exactly the source-read value — not a constant.
    assert eff.details["duration_bound_seconds"] == src_read_duration
    # No hardcoded duration literal lives in the recipe.
    assert "MAX_PAUSE_DURATION =" not in inspect.getsource(anvil)


# ---------------------------------------------------------------------------
# inv. 11 — own stage between policy and coverage; cache is code-plane only.
# ---------------------------------------------------------------------------


def test_inv11_stage_placement_and_codeplane_cache():
    order = [s.value for s in JobStage]
    assert order.index("policy") < order.index("effects") < order.index("coverage")
    # The cache carries NO state-plane concrete columns (code-plane only).
    cache_cols = {c.name for c in EffectBehaviorCache.__table__.columns}
    assert {"behavior_hash", "effect_class", "scope", "gate_ref", "verdict", "tier", "transcript_ptr"} <= cache_cols
    assert "concrete_destination" not in cache_cols


# ---------------------------------------------------------------------------
# inv. 12 — verdicts are gate-relative; gate_ref names structure, not an address.
# ---------------------------------------------------------------------------


@requires_postgres
def test_inv12_verdicts_gate_relative(clean_effects):
    session = clean_effects
    row = upsert_cached_verdict(
        session,
        behavior_hash="hg",
        effect_class="code_upgrade",
        scope="kernel",
        gate_ref="proxy:uups",  # a STRUCTURE descriptor, never an address
        verdict="proven",
        tier="tier0",
    )
    assert row.gate_ref == "proxy:uups"
    assert not row.gate_ref.startswith("0x")
    # The cache schema has no principal/address column — binding is at read time.
    assert "principal" not in {c.name for c in EffectBehaviorCache.__table__.columns}


# ---------------------------------------------------------------------------
# inv. 13 — Tier 0 is historical: indexed event needs a current-state check.
# ---------------------------------------------------------------------------


def test_inv13_tier0_needs_current_state_check():
    proven_now = recipes.code_upgrade(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x",
        sentinel_address=SENTINEL,
        sentinel_override=None,
        impl_before=None,
        indexed_upgrade=True,
        current_impl_nonzero=True,
    )
    unknown_hist = recipes.code_upgrade(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x",
        sentinel_address=SENTINEL,
        sentinel_override=None,
        impl_before=None,
        indexed_upgrade=True,
        current_impl_nonzero=False,
    )
    assert proven_now.verdict == VERDICT_PROVEN and proven_now.effect_class == EFFECT_CLASS_CODE_UPGRADE
    assert unknown_hist.verdict == VERDICT_UNKNOWN  # history alone never proves present capability


# ---------------------------------------------------------------------------
# inv. 14 — capabilities are probed, not assumed.
# ---------------------------------------------------------------------------


def test_inv14_capabilities_probed_not_assumed():
    store = InMemoryCapabilityStore()
    # Unprobed chain is fail-closed (never assumed supported).
    assert require_simulate_or_fallback(store, 999) is False
    from services.effects.simulate import SimResult

    assert probe_simulate_support(ScriptedSimulate(SimResult(calls=(ok(),))), 1, store) is True
    assert store.get_simulate_support(1) is True


# ---------------------------------------------------------------------------
# inv. 15 — fail-forward stage, transition-gated flag.
# ---------------------------------------------------------------------------


def test_inv15_fail_forward_and_flag_gates_transition(monkeypatch):
    # The effects stage advances to coverage on failure (never failed_terminal).
    assert EffectsWorker.next_stage == JobStage.coverage
    src = inspect.getsource(EffectsWorker._finalize_terminal_failure)
    assert "advance_job" in src and "failed_terminal" not in src.split('"""')[-1]
    # Flag gates the transition itself.
    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)
    assert effects_stage_enabled() is False
    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    assert effects_stage_enabled() is True


# ---------------------------------------------------------------------------
# inv. 16 — single-flight fork: PSAT_EFFECTS_JOB_CONCURRENCY defaults to 1.
# ---------------------------------------------------------------------------


def test_inv16_single_flight_fork_default(monkeypatch):
    monkeypatch.delenv("PSAT_EFFECTS_JOB_CONCURRENCY", raising=False)
    monkeypatch.delenv("PSAT_JOB_CONCURRENCY", raising=False)
    assert _resolve_job_concurrency("effects") == 1


# The self-audit helper closes inv. 3's "first shared-hash pair self-audited"
# clause with a pure comparison (the worker path is covered in
# test_effects_worker_integration).
def test_inv3_self_audit_helper_catches_collision():
    assert kernel_verdicts_agree("proven", {"supply_delta_sign": "mint"}, "proven", {"supply_delta_sign": "mint"})
    assert not kernel_verdicts_agree("proven", {"supply_delta_sign": "mint"}, "proven", {"supply_delta_sign": "burn"})


def test_audit_constants_exist():
    assert effect_cache.AUDIT_PASSED == "passed" and effect_cache.AUDIT_FAILED == "failed"
