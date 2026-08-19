"""Implementation-invariant sweep for the effects stage.

One explicit test per invariant, each CLOSING the invariant with an assertion or
recorded evidence — the same one-test-per-rule pattern the multichain suite uses
(``tests/test_multichain_*``). Each section header below states the rule its test
pins. Offline/hermetic; the DB-touching cases carry ``@requires_postgres``.
"""

from __future__ import annotations

import inspect
import uuid
from decimal import Decimal

import pytest

from db import effect_cache
from db.effect_cache import (
    KERNEL_SURFACE_SENTINEL,
    find_cached_verdict,
    kernel_verdicts_agree,
    upsert_cached_verdict,
)
from db.models import (
    Contract,
    EffectBehaviorCache,
    EffectiveFunction,
    EffectVerdict,
    JobStage,
    Protocol,
)
from services.effects import anvil, recipes
from services.effects.config import (
    effects_stage_enabled,
)
from services.effects.hashing import resolved_function_hash
from services.effects.preflight import (
    InMemoryCapabilityStore,
    probe_simulate_support,
)
from services.effects.selection import AuthorityGraph, select_candidates
from tests.cache_helpers import requires_postgres
from tests.support.effects_ir import _fn, _ir, _node, _var

# Shared structural doubles + scripted stubs from the harness tests.
from tests.support.effects_stubs import CTX, RecordingStore, ScriptedSimulate, ok, transfer_log, uint_ret
from workers.base import _resolve_job_concurrency
from workers.effects_worker import EffectsWorker

pytestmark = pytest.mark.anvil

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
# No name drives an effect; every verdict traces to a witness.
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
# Cache scope matches verdict scope; concrete values are never keys.
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
# Value ORDERS, never gates; a resource cap logs what it drops.
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
    # The ONLY cutoff — a resource cap — logs exactly what it dropped.
    import logging as _logging

    with caplog.at_level(_logging.WARNING):
        kept = select_candidates(session, proto.id, resource_cap=1)
    assert len(kept) == 1
    assert "resource cap hit" in caplog.text and "dropped 2 candidate" in caplog.text


# ---------------------------------------------------------------------------
# Transitive reach, not direct balance, drives ordering.
# ---------------------------------------------------------------------------


def test_inv5_transitive_reach_beats_direct_balance():
    safe = "0x" + "5a" * 20
    vault = "0x" + "7a" * 20
    graph = AuthorityGraph()
    graph._add_control(safe, vault)  # the $33k Safe controls the $3.2B vault
    graph.balance[safe] = Decimal("33000.00")
    graph.balance[vault] = Decimal("3200000000.00")
    # Reach from the Safe includes the full downstream vault value (upper bound).
    # Exact, not approx: `Decimal == pytest.approx(float)` cannot fail — it
    # returns True on agreement and raises TypeError otherwise.
    assert graph.reachable_value({safe}) == Decimal("3200033000.00")
    # Its transitive reach dwarfs its direct balance — the ordering signal.
    assert graph.reachable_value({safe}) > graph.balance[safe]


# ---------------------------------------------------------------------------
# Read-only and keyless: no mainnet writes.
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
# Every verdict is tiered and replayable from its transcript.
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
# Duration/bound facts are read from source constants, never hardcoded.
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

        def set_balance(self, address, value):
            pass

        def set_storage_at(self, address, slot, value):
            pass

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
        duration_bound_source="guard_constant",
    )
    # The bound in the witness is exactly the source-read value — not a constant.
    assert eff.details["duration_bound_seconds"] == src_read_duration
    # ...and it names the evidence that produced it, so a consumer can tell a read
    # bound from an unread one.
    assert eff.details["duration_bound_source"] == "guard_constant"
    # No hardcoded duration literal lives in the recipe.
    assert "MAX_PAUSE_DURATION =" not in inspect.getsource(anvil)


# ---------------------------------------------------------------------------
# Own stage between policy and coverage; the cache is code-plane only.
# ---------------------------------------------------------------------------


def test_inv11_stage_placement_and_codeplane_cache():
    order = [s.value for s in JobStage]
    assert order.index("policy") < order.index("effects") < order.index("coverage")
    # The cache carries NO state-plane concrete columns (code-plane only).
    cache_cols = {c.name for c in EffectBehaviorCache.__table__.columns}
    assert {"behavior_hash", "effect_class", "scope", "gate_ref", "verdict", "tier", "transcript_ptr"} <= cache_cols
    assert "concrete_destination" not in cache_cols


# ---------------------------------------------------------------------------
# Verdicts are gate-relative; gate_ref names structure, not an address.
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
# Capabilities are probed, not assumed.
# ---------------------------------------------------------------------------


def test_inv14_capabilities_probed_not_assumed():
    store = InMemoryCapabilityStore()
    # An unprobed chain records nothing — never a support claim.
    assert store.get_simulate_support(999) is None
    from services.effects.simulate import SimResult

    assert probe_simulate_support(ScriptedSimulate(SimResult(calls=(ok(),))), 1, store) is True
    assert store.get_simulate_support(1) is True


# ---------------------------------------------------------------------------
# Fail-forward stage, transition-gated flag.
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
# Single-flight fork: PSAT_EFFECTS_JOB_CONCURRENCY defaults to 1.
# ---------------------------------------------------------------------------


def test_inv16_single_flight_fork_default(monkeypatch):
    monkeypatch.delenv("PSAT_EFFECTS_JOB_CONCURRENCY", raising=False)
    monkeypatch.delenv("PSAT_JOB_CONCURRENCY", raising=False)
    assert _resolve_job_concurrency("effects") == 1


# The self-audit helper closes the cache-scope rule's "first shared-hash pair
# self-audited" clause with a pure comparison (the worker path is covered in
# test_effects_worker_integration).
def test_inv3_self_audit_helper_catches_collision():
    assert kernel_verdicts_agree("proven", {"supply_delta_sign": "mint"}, "proven", {"supply_delta_sign": "mint"})
    assert not kernel_verdicts_agree("proven", {"supply_delta_sign": "mint"}, "proven", {"supply_delta_sign": "burn"})


def test_audit_constants_exist():
    assert effect_cache.AUDIT_PASSED == "passed" and effect_cache.AUDIT_FAILED == "failed"
