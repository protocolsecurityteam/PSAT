"""``effect_behavior_cache`` is keyed on code alone and republished to every twin, so per-deployment reach must never
enter it. Drives the real worker on real rows, since a mock can't show a value crossing deployments.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock

import pytest

from db.models import (
    Contract,
    EffectBehaviorCache,
    EffectiveFunction,
    EffectsPlanMarker,
    EffectVerdict,
    Protocol,
)
from db.queue import create_job
from services.effects import anvil, claims_bridge
from services.effects.anvil import EntryPoint
from services.effects.config import EFFECT_CLASS_VALUE_OUT, SCOPE_KERNEL, VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.orchestrator import ProbePlan
from services.effects.selection import AssetHolding, Candidate
from services.effects.simulate import SimCallResult, SimResult
from tests.cache_helpers import requires_postgres
from tests.support.effects_stubs import RecordingStore, ok, transfer_log
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.logging import degraded_errors_var, stage_metrics_var
from workers.effects_worker import EffectsWorker, _Seams

# B shares A's bytecode and inherits the verdict, not A's holders or USD.
CONTRACT_A = "0x" + "a1" * 20
CONTRACT_B = "0x" + "b2" * 20
HOLDER = "0x" + "aa" * 20
RECIPIENT = "0x" + "ab" * 20
TOKEN = "0x" + "cc" * 20
PRINCIPAL = "0x" + "22" * 20
SELECTOR = "0x2e1a7d4d"
BEHAVIOR_HASH = "kernel_hash_shared"
REACH_USD = 5_000_000.0
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


@pytest.fixture()
def clean_effects(db_session):
    for model in (EffectVerdict, EffectBehaviorCache, EffectsPlanMarker):
        db_session.query(model).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    for model in (EffectVerdict, EffectBehaviorCache, EffectsPlanMarker):
        db_session.query(model).delete()
    db_session.commit()


def _protocol(session, addresses: list[str]):
    proto = Protocol(name=f"effects-leak-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    fn_ids: dict[str, int] = {}
    contract_ids: dict[str, int] = {}
    for addr in addresses:
        c = Contract(protocol_id=proto.id, address=addr, chain="ethereum", is_proxy=False)
        session.add(c)
        session.flush()
        contract_ids[addr] = c.id
        fn = EffectiveFunction(
            contract_id=c.id,
            function_name="withdraw",
            selector=SELECTOR,
            authority_public=False,
            effect_targets=["slot0"],
        )
        session.add(fn)
        session.flush()
        fn_ids[addr] = fn.id
    session.commit()
    return proto.id, fn_ids, contract_ids


def _candidate(address: str, function_id: int, contract_id: int) -> Candidate:
    return Candidate(
        function_id=function_id,
        contract_id=contract_id,
        contract_address=address,
        selector=SELECTOR,
        function_name="withdraw",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
        value_at_stake_usd=Decimal("1"),
    )


def _seams(session, chain_id: int = 1) -> _Seams:
    from services.effects.preflight import InMemoryCapabilityStore

    store = InMemoryCapabilityStore()
    store.set_simulate_support(chain_id, True)
    return _Seams(
        simulate=MagicMock(return_value=SimResult(calls=(SimCallResult(True, "0x", None),))),
        transcript_store=lambda tr: None,
        capability_store=store,
        chain_id=chain_id,
    )


def _run(worker, session, job) -> dict:
    metrics: dict = {}
    etok = degraded_errors_var.set([])
    mtok = stage_metrics_var.set(metrics)
    try:
        worker.process(session, job)
    finally:
        degraded_errors_var.reset(etok)
        stage_metrics_var.reset(mtok)
    return metrics


def _real_value_out_plan(address: str):
    """The reach fields come from production code rather than a hand-built dict."""

    def run():
        from services.effects import recipes

        base = SimResult(
            calls=(
                ok(
                    logs=[
                        transfer_log(TOKEN, address, RECIPIENT, 3),  # the acting contract's own outflow
                        transfer_log(TOKEN, HOLDER, RECIPIENT, 9),  # a downstream value-holder drained too
                    ]
                ),
            )
        )

        def simulate(_calls, _tag, _ov):
            return base

        return recipes.value_out(
            simulate=simulate,
            store=RecordingStore(),
            ctx=CTX,
            contract_address=address,
            principal=PRINCIPAL,
            calldata="0x2e1a7d4d",
            simulate_supported=True,
            value_holders=(AssetHolding(HOLDER, TOKEN, REACH_USD),),
            acting_balance_usd=1.0,
        )

    return ProbePlan(effect_class=EFFECT_CLASS_VALUE_OUT, scope=SCOPE_KERNEL, run=run, gate_ref="role:X")


def _prober(runs: list[str]):
    def prober(_session, cand, _ctx):
        runs.append(cand.contract_address)
        return [_real_value_out_plan(cand.contract_address)]

    return prober


def _make_job(session, protocol_id: int, name: str, address: str):
    job = create_job(session, {"address": address, "name": name})
    job.protocol_id = protocol_id
    session.commit()
    return job


def _run_for(session, pid, fns, cids, address, name, monkeypatch, runs):
    cand = _candidate(address, fns[address], cids[address])
    monkeypatch.setattr("workers.effects_worker.select_candidates", lambda *a, **k: [cand])
    job = _make_job(session, pid, name, address)
    worker = EffectsWorker(
        prober=_prober(runs),
        hash_resolver=lambda s, c: (BEHAVIOR_HASH, "surface"),
        seams=_seams(session),
    )
    return _run(worker, session, job)


def _flat_values(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _flat_values(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _flat_values(v)
    else:
        yield obj


# Any other number is a per-execution measurement; the cache republishes ``details`` verbatim.
_CODE_PLANE_INT_KEYS = {
    # Read from this bytecode's own guard constants.
    "duration_bound_seconds",
    # A constant of the probe, not the deployment.
    "identities",
}


def _plane_violations(details: dict[str, Any] | None) -> list[Any]:
    """Every recipe float is a USD or amount figure."""
    bad: list[Any] = []

    def walk(node: Any, key: str | None) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, str(k))
            return
        if isinstance(node, (list, tuple)):
            for v in node:
                walk(v, key)
            return
        if isinstance(node, bool):
            return
        if isinstance(node, float):
            bad.append((key, node))
        elif isinstance(node, int) and key not in _CODE_PLANE_INT_KEYS:
            bad.append((key, node))
        elif isinstance(node, str) and node.startswith("0x") and len(node) == 42:
            bad.append((key, node))

    walk(details or {}, None)
    return bad


def test_no_tier1_recipe_puts_per_deployment_data_in_cacheable_details():
    """``details`` is the only recipe output entering the code-keyed cache, so every Tier-1 recipe must keep
    per-deployment data in ``concrete``.
    """
    from services.effects import recipes

    zero = "0x" + "00" * 20
    asset = "0x" + "77" * 20
    store = RecordingStore()

    value_out_base = SimResult(
        calls=(ok(logs=[transfer_log(TOKEN, CONTRACT_A, RECIPIENT, 3), transfer_log(TOKEN, HOLDER, RECIPIENT, 9)]),)
    )
    value_out_sentinel = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT_A, "0x" + "ee" * 20, 3)]),))
    scripted = iter((value_out_base, value_out_sentinel))
    v = recipes.value_out(
        simulate=lambda *_a: next(scripted),
        store=store,
        ctx=CTX,
        contract_address=CONTRACT_A,
        principal=PRINCIPAL,
        calldata="0x2e1a7d4d",
        simulate_supported=True,
        sentinel_address="0x" + "ee" * 20,
        sentinel_calldata="0x2e1a7d4d" + "ee" * 32,
        value_holders=(AssetHolding(HOLDER, TOKEN, REACH_USD),),
        acting_balance_usd=1.0,
    )

    supply_block = SimResult(
        calls=(
            ok("0x" + (1000).to_bytes(32, "big").hex()),
            ok(logs=[transfer_log(asset, PRINCIPAL, CONTRACT_A, 5), transfer_log(CONTRACT_A, zero, RECIPIENT, 5)]),
            ok("0x" + (1500).to_bytes(32, "big").hex()),
        )
    )
    s = recipes.supply(
        simulate=lambda *_a: supply_block,
        store=store,
        ctx=CTX,
        token_address=CONTRACT_A,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=True,
    )

    upgrade_post = SimResult(
        calls=(ok(),),
        storage={CONTRACT_A.lower(): {recipes.EIP1967_IMPL_SLOT: "0x" + ("ee" * 20).rjust(64, "0")}},
    )
    u = recipes.code_upgrade(
        simulate=lambda *_a: upgrade_post,
        store=store,
        ctx=CTX,
        proxy_address=CONTRACT_A,
        principal=PRINCIPAL,
        upgrade_calldata="0x3659cfe6" + "ee" * 32,
        sentinel_address="0x" + "ee" * 20,
        sentinel_override={"code": "0x00"},
        impl_before="0x" + "dd" * 20,
    )

    rejected = SimCallResult(False, "0x", "0xdeadbeef", ())
    randoms = ["0x" + "31" * 20, "0x" + "32" * 20]
    a = recipes.authority_change(
        simulate=lambda *_a: SimResult(calls=(rejected, rejected, ok(), ok(), ok())),
        store=store,
        ctx=CTX,
        contract_address=CONTRACT_A,
        principal=PRINCIPAL,
        mutate_calldata="0x2f2ff15d" + "00" * 64,
        probe_calldata="0x8456cb59",
        randoms=randoms,
    )

    from tests.support.effects_stubs import GUARDED, PAUSE, StubAnvil

    p = anvil.pause_recipe(
        transport=StubAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=3600),
        store=store,
        ctx=CTX,
        contract_address=CONTRACT_A,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=[EntryPoint(key="foo", calldata=GUARDED), EntryPoint(key="ping", calldata="0xffffffff")],
        predicted_guard_set=["foo"],
        max_pause_duration=3600,
    )

    for eff in (v, s, u, a, p):
        assert _plane_violations(eff.details) == [], f"{eff.effect_class}: {_plane_violations(eff.details)}"
    assert v.concrete["observed_reach_holders"] == [HOLDER.lower()]
    assert u.concrete["impl_before"] == "0x" + "dd" * 20
    assert s.concrete["backing_inflow_transfers"] == 1
    assert s.details["backing"]["inflow_observed"] is True
    assert a.details["gate_mutation"] is True
    assert p.details["observed_blast_radius"] == ["foo"]


@requires_postgres
def test_reach_never_reaches_the_code_plane_cache(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns, cids = _protocol(session, [CONTRACT_A])
    _run_for(session, pid, fns, cids, CONTRACT_A, "leak-a", monkeypatch, [])
    session.expire_all()

    cached = session.query(EffectBehaviorCache).one()
    body = str(cached.details)
    assert HOLDER.lower() not in body.lower()
    assert RECIPIENT.lower() not in body.lower()
    assert str(REACH_USD) not in body
    assert not any(k.startswith(("observed_reach", "reach_")) for k in (cached.details or {}))
    # The proving execution is one deployment's observation too.
    assert PROVING_EXECUTION_KEY not in (cached.details or {})
    assert PRINCIPAL.lower() not in body.lower()
    assert (cached.details or {})["value_moved"] is True

    row = session.query(EffectVerdict).one()
    residue = dict(row.observed_residue or {})
    execution = residue.pop(PROVING_EXECUTION_KEY)
    assert residue == {
        "observed_reach_value_usd": REACH_USD,
        "observed_reach_holders": [HOLDER.lower()],
        "reach_determined": True,
        "observed_reach_assets": [TOKEN.lower()],
        "reach_tvl_check": "skipped_no_tvl",
    }
    assert execution["caller"] == PRINCIPAL.lower()
    assert execution["target"] == CONTRACT_A.lower()


@requires_postgres
def test_cache_hit_never_inherits_another_deployments_reach(clean_effects, monkeypatch):
    session = clean_effects
    pid, fns, cids = _protocol(session, [CONTRACT_A, CONTRACT_B])
    runs: list[str] = []
    _run_for(session, pid, fns, cids, CONTRACT_A, "leak-a", monkeypatch, runs)
    session.expire_all()
    assert session.query(EffectBehaviorCache).count() == 1

    metrics = _run_for(session, pid, fns, cids, CONTRACT_B, "leak-b", monkeypatch, runs)
    session.expire_all()

    assert metrics["cache_hits_kernel"] == 1
    rows = {r.contract_address: r for r in session.query(EffectVerdict).all()}
    b = rows[CONTRACT_B.lower()]
    assert b.verdict == VERDICT_PROVEN
    assert (b.witness or {})["value_moved"] is True
    assert HOLDER.lower() not in str(b.witness).lower()
    assert str(REACH_USD) not in str(b.witness)
    residue: dict[str, Any] = b.observed_residue or {}
    assert "observed_reach_holders" not in residue
    assert "observed_reach_value_usd" not in residue
    assert rows[CONTRACT_A.lower()].observed_residue["observed_reach_holders"] == [HOLDER.lower()]


@requires_postgres
def test_minted_claim_surfaces_reach_only_for_the_observing_deployment(clean_effects, monkeypatch):
    """The claim is what the frontend publishes."""
    session = clean_effects
    pid, fns, cids = _protocol(session, [CONTRACT_A, CONTRACT_B])
    runs: list[str] = []
    _run_for(session, pid, fns, cids, CONTRACT_A, "leak-claim-a", monkeypatch, runs)
    _run_for(session, pid, fns, cids, CONTRACT_B, "leak-claim-b", monkeypatch, runs)
    session.expire_all()

    rows = {r.contract_address: r for r in session.query(EffectVerdict).all()}
    claim_a = claims_bridge.verdict_to_claim(rows[CONTRACT_A.lower()])
    claim_b = claims_bridge.verdict_to_claim(rows[CONTRACT_B.lower()])
    assert claim_a is not None and claim_b is not None
    assert claim_a["witness"]["observed"]["observed_reach_holders"] == [HOLDER.lower()]
    assert claim_a["witness"]["observed"]["observed_reach_value_usd"] == REACH_USD
    observed_b = claim_b["witness"].get("observed", {})
    assert "observed_reach_holders" not in observed_b
    assert "observed_reach_value_usd" not in observed_b


@requires_postgres
def test_reach_survives_a_later_observation_less_rewrite(clean_effects, monkeypatch):
    """The residue column is preserved across an observation-less rewrite, like the destination."""
    session = clean_effects
    pid, fns, cids = _protocol(session, [CONTRACT_A])
    runs: list[str] = []
    _run_for(session, pid, fns, cids, CONTRACT_A, "leak-keep-1", monkeypatch, runs)
    _run_for(session, pid, fns, cids, CONTRACT_A, "leak-keep-2", monkeypatch, runs)
    session.expire_all()

    row = session.query(EffectVerdict).one()
    assert row.observed_residue["observed_reach_holders"] == [HOLDER.lower()]
    assert row.observed_residue["observed_reach_value_usd"] == REACH_USD
