"""The fail-safe oracle, metamorphic: every verdict-oracle probe a test module registers (``PROBES``) is decided again
under each injected fault, and the faulted verdict is never bolder than the clean one (``_oracle.never_bolder``:
never more open, never a smaller complete list, never complete where the clean run was not), and whatever it claims
beyond the clean verdict holds on the chain (``_oracle.chain_sound``: a holder only it lists passes ``eth_call`` from
its own address, an "open now" at a witness of its own passes for all five strangers). The faults: every followed
callee mis-lowered (as "nobody", always reverting; as "false", returning false; as "everyone", returning true), every
storage read failing, every ``eth_call`` failing, every log history cut in half, and each budget constant at zero
and at a small value. The clean verdicts themselves are checked against the chain by the modules that register
them."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import services.logic.decide as decide_module
import services.logic.holders as holders_module
import services.logic.lower as lower_module
import services.logic.verdict as verdict_module
from services.logic.lower import Lowerer
from services.logic.terms import FALSE, TRUE
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

_HERE = Path(__file__).parent
MODULES = sorted(p.stem for p in _HERE.glob("test_*.py") if p.stem != "test_failsafe")

# Each budget constant, by the modules that read it, with the small value tried beside zero (a size can't be zero).
BUDGETS = {
    "DECISION_WORK": ((decide_module,), 0.5),
    "READS_PER_FUNCTION": ((verdict_module,), 3),
    "CONFIRM_READS": ((verdict_module,), 1),
    "UNPROVEN_CANDIDATES": ((decide_module,), 1),
    "UNPROVEN_READS": ((decide_module,), 2),
    "UNPROVEN_BATCH": ((decide_module,), 1),
    "_EXECUTED_CANDIDATES": ((decide_module, verdict_module), 1),
    "_PRIOR_WRITERS": ((verdict_module,), 1),
    "ARRANGE_WORK": ((verdict_module,), 0.5),
    "LOG_CALLS": ((decide_module,), 1),
    "LOG_ROWS": ((decide_module,), 1),
    "VALUE_STEPS": ((lower_module,), 50),
    "UNROLL_BUDGET": ((lower_module,), 4),
    "_CHAIN_ROUNDS": ((decide_module,), 1),
    "_SCREEN_WORK": ((decide_module,), 0.5),
    "_CANDIDATE_BATCH": ((decide_module,), 1),
    "_STORED_ROWS": ((holders_module,), 1),
    "_WALK_STEPS": ((holders_module,), 1),
    "_BINDINGS": ((holders_module,), 1),
}
_SIZES = {"UNPROVEN_BATCH", "_CANDIDATE_BATCH"}
# A followed callee's lowering replaced by (success condition, the value it returns).
CALLEE_FAULTS = {"callee_nobody": (FALSE, FALSE), "callee_false": (TRUE, FALSE), "callee_everyone": (TRUE, TRUE)}
FAULTS = [
    *CALLEE_FAULTS,
    "storage",
    "calls",
    "logs",
    *(
        f"{name}={value}"
        for name, (_, small) in BUDGETS.items()
        for value in ((small,) if name in _SIZES else (0, small))
    ),
]


def _registered():
    out = []
    for module in MODULES:
        probes = getattr(importlib.import_module(f"tests.logic.{module}"), "PROBES", ())
        for i, probe in enumerate(probes):
            for contract, function, others in probe.functions:
                name = f"{module[5:]}-{i}-{contract}.{function}-{'+'.join(others) or 'alone'}"
                for fault in FAULTS:
                    out.append(pytest.param(module, i, contract, function, tuple(others), fault, id=f"{name}-{fault}"))
    return out


PROBED = _registered()
_CLEAN: dict = {}


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    cache: dict = {}

    def get(module: str, index: int):
        if (module, index) not in cache:
            probe = importlib.import_module(f"tests.logic.{module}").PROBES[index]
            d = O.deployment(*anvil, probe.source, probe.version)
            probe.setup(d)
            cache[(module, index)] = d
        return cache[(module, index)]

    return get


def _inject(fault: str, monkeypatch, d, contract: str):
    """Apply ``fault``; the chain to decide on."""
    if fault in CALLEE_FAULTS:
        pc, answer = CALLEE_FAULTS[fault]
        called = Lowerer.called

        def misread(self, function, args, view):
            if getattr(getattr(function, "contract", None), "name", contract) != contract:
                return pc, (answer,)
            return called(self, function, args, view)

        monkeypatch.setattr(Lowerer, "called", misread)
        return None
    if fault in ("storage", "calls", "logs"):
        return O.Faulty(d, **{fault: True})
    name, value = fault.split("=")
    modules, _ = BUDGETS[name]
    for module in modules:
        if hasattr(module, name):
            monkeypatch.setattr(module, name, type(getattr(module, name))(float(value)))
    return None


@pytest.mark.parametrize(("module", "index", "contract", "function", "others", "fault"), PROBED)
def test_a_fault_never_makes_a_verdict_bolder(deployed, monkeypatch, module, index, contract, function, others, fault):
    d = deployed(module, index)
    key = (module, index, contract, function, others)
    if key not in _CLEAN:
        _forget(d)
        _CLEAN[key] = O.verdict(d, contract, function, *others)
    clean = _CLEAN[key]
    chain = _inject(fault, monkeypatch, d, contract)
    _forget(d)  # nothing a run lowered under one fault is kept for the next
    try:
        faulted = O.verdict(d, contract, function, *others, chain=chain)
    finally:
        _forget(d)
    O.never_bolder(clean, faulted)
    O.chain_sound(d, contract, function, faulted, clean)


def _forget(d) -> None:
    """Drop what the engine remembers on the Slither contracts (``_psat_*``: stores, logged answers, scope facts)."""
    for c in [*d.slither.values(), *getattr(getattr(d, "legacy", None), "slither", {}).values()]:
        for k in [k for k in c.__dict__ if k.startswith("_psat_")]:
            del c.__dict__[k]


def test_the_sweep_covers_every_registering_module():
    # A module whose probes the sweep doesn't see is checked for nothing here.
    registering = {p.values[0] for p in PROBED}
    expected = {m for m in MODULES if hasattr(importlib.import_module(f"tests.logic.{m}"), "PROBES")}
    assert registering == expected and len(registering) >= 15, sorted(expected - registering)
    assert len(PROBED) >= 150 * len(FAULTS), len(PROBED)
