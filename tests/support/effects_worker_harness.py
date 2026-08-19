"""Effects-worker orchestration harness: the stubbed seams, the injectable prober
and the row builders the worker integration tests drive.

Extracted verbatim from ``test_effects_worker_integration``; ``test_effects_stage``
imported all of it cross-module, including the ``clean_effects`` fixture.
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
    EffectVerdict,
    Protocol,
)
from db.queue import create_job, store_artifact
from services.effects.config import EFFECT_CLASS_SUPPLY, SCOPE_KERNEL
from services.effects.orchestrator import ProbePlan
from services.effects.selection import Candidate
from services.effects.simulate import SimCallResult, SimResult
from utils.logging import degraded_errors_var, stage_metrics_var
from workers.effects_worker import _Seams

CONTRACT_A = "0x" + "a1" * 20
CONTRACT_B = "0x" + "b2" * 20
CONTRACT_C = "0x" + "c3" * 20
PRINCIPAL = "0x" + "22" * 20


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


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


def _protocol_with_functions(session, addresses: list[str]) -> tuple[int, dict[str, int]]:
    """Create a protocol + one contract & effective-function per address. Returns
    ``(protocol_id, {address: function_id})`` so candidates can reference real
    ``effective_functions.id`` rows (the ``effect_verdicts`` FK)."""
    proto = Protocol(name=f"effects-it-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    fn_ids: dict[str, int] = {}
    for addr in addresses:
        c = Contract(protocol_id=proto.id, address=addr, chain="ethereum", is_proxy=False)
        session.add(c)
        session.flush()
        fn = EffectiveFunction(
            contract_id=c.id,
            function_name="f",
            selector="0x40c10f19",
            authority_public=False,
            effect_targets=["slot0"],
        )
        session.add(fn)
        session.flush()
        fn_ids[addr] = fn.id
    session.commit()
    return proto.id, fn_ids


def _make_job(session, protocol_id: int, name: str, address: str = CONTRACT_A):
    """A job stamped with ``protocol_id`` so the worker's selection guard passes
    (a contract job with no protocol has nothing to simulate)."""
    job = create_job(session, {"address": address, "name": name})
    job.protocol_id = protocol_id
    session.commit()
    return job


def _candidate(address: str, function_id: int, contract_id: int = 0) -> Candidate:
    return Candidate(
        function_id=function_id,
        contract_id=contract_id,
        contract_address=address,
        selector="0x40c10f19",
        function_name="f",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
        value_at_stake_usd=Decimal("1"),
    )


def _transcript_store(session, job):
    """A REAL transcript store (artifact-backed) so ``transcript_ptr`` resolves."""
    seq = {"n": 0}

    def store(tr: dict[str, Any]) -> str:
        name = f"effect_transcript_{seq['n']}"
        seq["n"] += 1
        store_artifact(session, job.id, name, data=tr)
        return f"{job.id}::{name}"

    return store


def _run(worker, session, job) -> tuple[list, dict]:
    """Run ``process`` under bound warning-channel + metrics accumulators (as
    ``BaseWorker._execute_job`` would), returning (stage_errors, metrics)."""
    errors: list = []
    metrics: dict = {}
    etok = degraded_errors_var.set(errors)
    mtok = stage_metrics_var.set(metrics)
    try:
        worker.process(session, job)
    finally:
        degraded_errors_var.reset(etok)
        stage_metrics_var.reset(mtok)
    return errors, metrics


class _Prober:
    """Injectable prober: one plan per candidate whose ``run`` returns a canned
    ObservedEffect from ``factory(candidate)``. Records which candidates ran so
    'no re-sim' is checkable."""

    def __init__(self, factory, *, effect_class=EFFECT_CLASS_SUPPLY, scope=SCOPE_KERNEL, gate_ref="role:MINTER"):
        self.factory = factory
        self.effect_class = effect_class
        self.scope = scope
        self.gate_ref = gate_ref
        self.runs: list[int] = []

    def __call__(self, session, cand, ctx):
        def run():
            self.runs.append(cand.function_id)
            return self.factory(cand, ctx)

        return [ProbePlan(effect_class=self.effect_class, scope=self.scope, run=run, gate_ref=self.gate_ref)]


def _seams(session, job, *, simulate=None):
    from services.effects.preflight import InMemoryCapabilityStore

    sim = (
        simulate
        if simulate is not None
        else MagicMock(return_value=SimResult(calls=(SimCallResult(True, "0x", None),)))
    )
    store = InMemoryCapabilityStore()
    store.set_simulate_support(1, True)
    return _Seams(
        simulate=sim,
        transcript_store=_transcript_store(session, job),
        capability_store=store,
        chain_id=1,
    )
