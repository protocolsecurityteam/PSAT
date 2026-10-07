"""A function claimed ``pause.set`` is still fork-probed for the freeze family.

A static claim names the latch; only the fork witnesses which entry points it freezes. Dropping the row as "already
explained" left a fresh analysis with no observed ``pause.set`` and no ``pause_effective`` for etherfi ``pauseUntil``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from db.models import FunctionPrincipal
from db.queue import create_job, store_artifact
from services.effects import calldata as cd
from services.effects.config import EFFECT_CLASS_FREEZE_PAUSE, EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT
from services.effects.orchestrator import ProbeContext, default_prober
from services.effects.selection import _enrolled_families, select_candidates
from tests.conftest import requires_postgres
from tests.support.effects_builders import _contract, _fn, _protocol
from tests.support.effects_stubs import RecordingStore

LATCH = "PAUSABLE_UNTIL_STORAGE_SLOT"
PAUSE_UNTIL = "pauseUntil()"
DEPOSIT = "deposit()"
PRINCIPAL = "0x" + "2a" * 20


def _pause_claim(tier: str, **witness: Any) -> dict[str, Any]:
    return {
        "claim_id": "pause.set",
        "tier": tier,
        "witness": {
            "kind": "pause_flag",
            "polarity": "set",
            "flags": [{"var": LATCH, "member": "pausedUntil", "latch": "timestamp"}],
            **witness,
        },
    }


def _claim(claim_id: str, tier: str = "standard_exact") -> dict[str, Any]:
    return {"claim_id": claim_id, "tier": tier, "witness": {}}


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        pytest.param([_pause_claim("idiom_structural")], {EFFECT_CLASS_FREEZE_PAUSE}, id="static_idiom"),
        pytest.param([_pause_claim("standard_exact")], {EFFECT_CLASS_FREEZE_PAUSE}, id="static_standard"),
        # A re-analysis re-probes an observed claim rather than freezing its witness.
        pytest.param(
            [_pause_claim("behavioral_observed", static_tier="idiom_structural")],
            {EFFECT_CLASS_FREEZE_PAUSE},
            id="observed",
        ),
        pytest.param(
            [_pause_claim("idiom_structural"), _claim("flow.out")],
            {EFFECT_CLASS_FREEZE_PAUSE, EFFECT_CLASS_VALUE_OUT},
            id="with_flow",
        ),
        # The pause recipe only witnesses freezes; an unpause stays explained by its static claim.
        pytest.param([_claim("pause.unset", "idiom_structural")], set(), id="unset_only"),
        pytest.param([_claim("supply.mint")], {EFFECT_CLASS_SUPPLY}, id="unrelated_family"),
    ],
)
def test_a_pause_set_claim_enrolls_the_freeze_family(claims, expected):
    assert _enrolled_families(claims) == frozenset(expected)


def _seed(session) -> tuple[int, int]:
    proto = _protocol(session, "static-pause-proto")
    address = "0x" + "5e" * 20
    job = create_job(session, {"address": address, "name": "PausableUntilLike"})
    contract = _contract(session, proto.id, address, chain="ethereum", job_id=job.id)
    latch_write = {
        "var": LATCH,
        "declared_type": "bytes32",
        "member_path": [],
        "granularity": "var",
        "hygiene_class": "storage_location_pseudo",
        "origin": "body",
    }
    store_artifact(
        session,
        job.id,
        "effects",
        data={
            "functions": {
                PAUSE_UNTIL: {
                    "function": PAUSE_UNTIL,
                    "selector": cd._selector_of(PAUSE_UNTIL),
                    "abi_signature": PAUSE_UNTIL,
                    "state_writes": [latch_write],
                    "sinks": [],
                    "value_flows": [],
                    "effect_labels": [],
                    "state_changing": True,
                    "parameter_names": [],
                },
                DEPOSIT: {
                    "function": DEPOSIT,
                    "selector": cd._selector_of(DEPOSIT),
                    "abi_signature": DEPOSIT,
                    "state_writes": [],
                    "sinks": [],
                    "value_flows": [],
                    "effect_labels": [],
                    "state_changing": True,
                    "parameter_names": [],
                },
            }
        },
    )
    deposit_gate = {
        "op": "AND",
        "operand_absorption": "recorded",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "operator": "lt",
                    "operands": [
                        {"source": "state_variable", "state_variable_name": LATCH, "member_path": ["pausedUntil"]},
                        {"source": "block_context", "block_context_kind": "timestamp"},
                    ],
                },
            }
        ],
    }
    owner_gate = {
        "op": "AND",
        "operand_absorption": "recorded",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "authority_role": "caller_authority",
                    "operands": [{"source": "state_variable", "state_variable_name": "owner"}],
                },
            }
        ],
    }
    store_artifact(session, job.id, "predicate_trees", data={"trees": {PAUSE_UNTIL: owner_gate, DEPOSIT: deposit_gate}})
    pause_until = _fn(
        session,
        contract.id,
        name="pauseUntil",
        selector=cd._selector_of(PAUSE_UNTIL),
        claims=[_pause_claim("idiom_structural")],
        state_changing=True,
        state_writes=[latch_write],
        sinks=[{"kind": "state_write", "target": LATCH, "origin": "body"}],
    )
    _fn(
        session,
        contract.id,
        name="deposit",
        selector=cd._selector_of(DEPOSIT),
        state_changing=True,
        state_writes=[],
        sinks=[],
    )
    session.add(FunctionPrincipal(function_id=pause_until.id, address=PRINCIPAL))
    session.commit()
    return proto.id, pause_until.id


@requires_postgres
def test_a_static_pause_set_reaches_the_freeze_probe(db_session):
    protocol_id, function_id = _seed(db_session)

    candidate = next(c for c in select_candidates(db_session, protocol_id) if c.function_id == function_id)
    assert candidate.restrict_families == frozenset({EFFECT_CLASS_FREEZE_PAUSE})

    inputs = cd.synthesize(db_session, candidate)
    assert inputs.pause is not None
    assert inputs.value_out is None and inputs.supply is None and inputs.authority is None
    # The claim's latch member names the gate that reads it.
    assert inputs.pause.predicted_guard_set == (DEPOSIT,)
    assert inputs.pause.principal == PRINCIPAL

    ctx = ProbeContext(
        chain_id=1,
        block=21_000_000,
        hardfork="prague",
        simulate=MagicMock(),
        simulate_supported=True,
        transcript_store=RecordingStore(),
        anvil_factory=MagicMock(),
    )
    plans = default_prober(db_session, candidate, ctx)
    assert [plan.effect_class for plan in plans] == [EFFECT_CLASS_FREEZE_PAUSE]
