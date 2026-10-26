"""The fail-safe oracle, metamorphic: every verdict-oracle probe a test module registers (``PROBES``) is decided again
under each injected fault, and the faulted verdict is never bolder than the clean one (``_oracle.never_bolder``:
never more open, never a smaller complete list, never complete where the clean run was not), and whatever it claims
beyond the clean verdict holds on the chain (``_oracle.chain_sound``: a holder only it lists passes ``eth_call`` from
its own address, an "open now" at a witness of its own passes for all five strangers).

The faults: every followed callee mis-lowered (as "nobody", always reverting; as "false", returning false; as
"everyone", returning true), every storage read failing, every ``eth_call`` failing, every log history cut in half,
and each budget constant at a tight value. The budgets the decision has always been swept on run over every probe
(``BUDGETS``); the rest of the module constants that bound work run over a seeded sample of probes, with one probe
known to be cut by each among them (``SAMPLED``). A fault that only reorders, batches or steers work must leave every
verdict exactly as it was (``INVARIANT``); any other must change some verdict somewhere in the registry, or it tests
nothing (``test_every_fault_changes_some_verdict``), save the few no registered probe yet reaches (``UNREACHED``, each
saying why). The clean verdicts themselves are checked against the chain by the modules that register them."""

from __future__ import annotations

import importlib
import random
import zlib
from pathlib import Path

import pytest

import services.logic.decide as decide_module
import services.logic.holders as holders_module
import services.logic.logged as logged_module
import services.logic.lower as lower_module
import services.logic.snapshot as snapshot_module
import services.logic.verdict as verdict_module
from services.logic.lower import Lowerer
from services.logic.terms import FALSE, TRUE
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

_HERE = Path(__file__).parent
MODULES = sorted(p.stem for p in _HERE.glob("test_*.py") if p.stem != "test_failsafe")

D, V, H, L, S, W = decide_module, verdict_module, holders_module, logged_module, snapshot_module, lower_module

# Each budget constant swept over every probe, by the modules that read it, with its tight values.
BUDGETS = {
    "DECISION_WORK": ((D,), (0, 0.5)),
    "READS_PER_FUNCTION": ((V,), (0, 3)),
    "CONFIRM_READS": ((V,), (0, 1)),
    "UNPROVEN_CANDIDATES": ((D,), (0, 1)),
    "UNPROVEN_READS": ((D,), (0, 2)),
    "UNPROVEN_BATCH": ((D,), (1,)),  # a size: never zero
    "_EXECUTED_CANDIDATES": ((D, V), (0, 1)),
    "_PRIOR_WRITERS": ((V,), (0, 1)),
    "ARRANGE_WORK": ((V,), (0, 0.5)),
    "LOG_CALLS": ((D,), (0,)),  # one window spans anvil's whole history: a cap of one cuts no scan
    "LOG_ROWS": ((D,), (0, 1)),
    "VALUE_STEPS": ((W,), (0,)),  # no registered lowering spends 50 value steps
    "UNROLL_BUDGET": ((W,), (0, 4)),
    "_CHAIN_ROUNDS": ((D,), (0, 1)),
    "_SCREEN_WORK": ((D,), (0, 0.5)),
    "_CANDIDATE_BATCH": ((D,), (1,)),  # a size
    "_STORED_ROWS": ((H,), (0, 1)),
    "_WALK_STEPS": ((H,), (0, 1)),
    "_BINDINGS": ((H,), (0, 1)),
}
# The other constants that bound work, swept over a sample of probes: (modules that read it, tight value).
SAMPLED = {
    "_EARLY_GUESSES": ((D,), 1),
    "LOG_WINDOW": ((D,), 16),
    "LOG_SECONDS": ((D, V), 0.0),  # read by name into ``verdict``: set where it is read
    "LOG_TOTAL_SECONDS": ((D, V), 0.0),
    "LOG_BATCH": ((D,), 1),
    "SNAPSHOT_SLOTS": ((D,), 1),
    "SNAPSHOT_PAGE": ((D,), 1),
    "CREATION_PROBES": ((D,), 1),
    "_LOCATED": ((D,), 1),
    "_SNAPSHOT_TRIES": ((D,), 1),
    "_RESOLVE_SLOTS": ((D,), 1),
    "_MAX_WHEN": ((D,), 1),
    "_GATHER_GUESSES": ((D,), 1),
    "_SEARCH_BATCH": ((D,), 1),
    "_SOLVER_GIVE_UPS": ((D,), 1),
    "_CALLEE_DEPTH": ((D,), 1),
    "IDENTITY_DEPTH": ((D, V), 1),
    "DECISION_SECONDS": ((D,), 0.0),
    "NODE_WORK": ((D, V), 1.0),  # a cost per node: tight is large
    "RLIMIT_PER_WORK": ((D,), 1),
    "QUESTION_WORK": ((D,), 100.0),  # a cost per question: tight is large
    "SOLVER_RLIMIT": ((D,), 1),
    "_MAX_OWNED_KEYS": ((D,), 1),
    "_HELD_ADDRESSES": ((D,), 1),
    "_SHARE": ((D,), 0.01),
    "_MIN_SHARE": ((D,), 0.0),
    "_FREE_SAT_MS": ((D,), 1),
    "_STORED_BYTES": ((D,), 1),
    "_MAX_LATCH_STATES": ((V,), 1),
    "_WALK": ((V,), 1),  # every JUMPDEST a jump target: more code read as reachable
    "_REACH_ROUNDS": ((V,), 1),
    "_ARRANGE_DEPTH": ((V,), 0),
    "_ARRANGE_ATOMS": ((V,), 1),
    "READ_CAP_SHARE": ((V,), 0.0001),  # with a read cap supplied (``PSAT_LOGIC_READ_CAP``), else it reads nothing
    "_PROPOSITIONAL_MS": ((L,), 1),
    "_PROPOSITIONAL_SECONDS": ((L,), 0.0),
    "_SPENT": ((S,), 1),
    "_ARRAY_ITEMS": ((S,), 1),
    "_ARRAY_SLOTS": ((S,), 1),
    "_CONSTANT_SPAN": ((S,), 1),
    "_DEPTH": ((S,), 0),
    "MAX_DEPTH": ((W,), 1),
    "MAX_UNROLL": ((W,), 1),
    "MAX_SYMBOLIC_UNROLL": ((W,), 0),
    "MAX_ARRAY_ITEMS": ((W,), 1),
}
_SAMPLE = 20  # probes per sampled constant, seeded by its name
# A probe each sampled constant is known to cut (module, index, contract, function), always in its sample: the
# vacuity guard then needn't scan the registry for it. Measured 2026-10-24; a stale one costs only that scan.
KNOWN_CUT = {
    "_EARLY_GUESSES": ("test_abi_encode_types", 1, "Seeded", "wN8neg"),
    "LOG_SECONDS": ("test_arranged", 2, "Roles", "grantRole"),
    "LOG_TOTAL_SECONDS": ("test_arranged", 2, "Roles", "grantRole"),
    "_MAX_WHEN": ("test_abi_encode_types", 0, "C", "signedSmallNot"),
    "_SEARCH_BATCH": ("test_callee_frame", 0, "C", "paid"),
    "_CALLEE_DEPTH": ("test_pool_shapes", 0, "Pool", "deposit"),
    "IDENTITY_DEPTH": ("test_callee_depth", 0, "Guarded3", "act"),
    "DECISION_SECONDS": ("test_abi_encode_types", 0, "C", "addr"),
    "NODE_WORK": ("test_actions", 0, "Vault", "deposit"),
    "RLIMIT_PER_WORK": ("test_actions", 0, "Minter", "mint"),
    "QUESTION_WORK": ("test_abi_encode_types", 0, "C", "addr"),
    "SOLVER_RLIMIT": ("test_budget_bites", 0, "Flagged", "act"),
    "_REACH_ROUNDS": ("test_governance", 0, "Migrated", "migrate"),
    "_ARRANGE_ATOMS": ("test_arranged", 0, "C", "withdrawFor"),
    "READ_CAP_SHARE": ("test_abi_encode_types", 0, "C", "addr"),
    "MAX_DEPTH": ("test_pool_shapes", 0, "GPv2Answering", "supply"),
    "MAX_UNROLL": ("test_review_probes", 3, "C", "floop"),
    "MAX_ARRAY_ITEMS": ("test_pool_shapes", 0, "Router", "transferIn"),
    "_WALK": ("test_origin_scan", 0, "C", "adminOr"),
}
# Faults that only reorder, batch, page, remember or steer work: every verdict must come out exactly as it was.
INVARIANT = {
    "_CANDIDATE_BATCH=1",
    "_SCREEN_WORK=0",
    "_SCREEN_WORK=0.5",
    "UNPROVEN_BATCH=1",
    "_BINDINGS=0",
    "_BINDINGS=1",
    "LOG_WINDOW=16",
    "LOG_BATCH=1",
    "SNAPSHOT_PAGE=1",
    "CREATION_PROBES=1",
    "_LOCATED=1",
    "_GATHER_GUESSES=1",
}
# Faults no registered probe's decision reaches yet (measured 2026-10-24: they change no verdict): swept for soundness
# all the same, but not asked to change one. Each is owed a probe.
_DUMP = "a storage dump is planned only for unlisted lookups a stranger fails; no registered verdict rests on one"
UNREACHED = {
    "SNAPSHOT_SLOTS=1": _DUMP,
    "_SNAPSHOT_TRIES=1": _DUMP,
    "_RESOLVE_SLOTS=1": _DUMP,
    "_SPENT=1": _DUMP,
    "_ARRAY_ITEMS=1": _DUMP,
    "_ARRAY_SLOTS=1": _DUMP,
    "_CONSTANT_SPAN=1": _DUMP,
    "_DEPTH=0": _DUMP,
    "_SOLVER_GIVE_UPS=1": "z3 settles every registered question before giving up on it",
    "_MAX_OWNED_KEYS=1": "the key that lets each registered candidate through is the first its history names",
    "_HELD_ADDRESSES=1": "no registered probe has the caller pick an address to be called",
    "_SHARE=0.01": "a candidate's share floors at _MIN_SHARE, more than any registered candidate spends",
    "_MIN_SHARE=0.0": "a candidate's share is half what is left, more than any registered candidate spends",
    "_FREE_SAT_MS=1": "every registered freed-atom question is settled before z3's clock is read",
    "_PROPOSITIONAL_MS=1": "every registered implication between path conditions is shown structurally first",
    "_PROPOSITIONAL_SECONDS=0.0": "every registered implication between path conditions is shown structurally first",
    "_STORED_BYTES=1": "no registered probe reads a long bytes value back from storage",
    "_MAX_LATCH_STATES=1": "no registered latching question has more than one reachable state to follow",
    "_ARRANGE_DEPTH=0": "no registered arrangement needs a writer's own guard arranged in turn",
    "MAX_SYMBOLIC_UNROLL=0": "no registered verdict rests on an argument-bounded loop's unrolled iterations",
}
# A followed callee's lowering replaced by (success condition, the value it returns).
CALLEE_FAULTS = {"callee_nobody": (FALSE, FALSE), "callee_false": (TRUE, FALSE), "callee_everyone": (TRUE, TRUE)}
FAULTS = [
    *CALLEE_FAULTS,
    "storage",
    "calls",
    "logs",
    *(f"{name}={value}" for name, (_, values) in BUDGETS.items() for value in values),
]
SAMPLED_FAULTS = [f"{name}={value}" for name, (_, value) in SAMPLED.items()]


def _probes() -> list[tuple]:
    out = []
    for module in MODULES:
        for i, probe in enumerate(getattr(importlib.import_module(f"tests.logic.{module}"), "PROBES", ())):
            out += [(module, i, contract, function, tuple(others)) for contract, function, others in probe.functions]
    return out


def _param(key: tuple, fault: str):
    module, i, contract, function, others = key
    name = f"{module[5:]}-{i}-{contract}.{function}-{'+'.join(others) or 'alone'}"
    return pytest.param(*key, fault, id=f"{name}-{fault}")


def _sample(keys: list[tuple], fault: str) -> list[tuple]:
    chosen = random.Random(zlib.crc32(fault.encode())).sample(keys, min(_SAMPLE, len(keys)))
    cut = KNOWN_CUT.get(fault.split("=")[0])
    return chosen + [k for k in keys if cut is not None and k[:4] == cut and k not in chosen][:1]


def _registered():
    keys = _probes()
    out = [_param(key, fault) for key in keys for fault in FAULTS]
    return out + [_param(key, fault) for fault in SAMPLED_FAULTS for key in _sample(keys, fault)]


PROBED = _registered()
_CLEAN: dict = {}
_CHANGED: dict[str, set] = {}  # fault -> probes whose verdict it changed
_RAN: dict[str, set] = {}  # fault -> probes decided under it


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
    modules = BUDGETS[name][0] if name in BUDGETS else SAMPLED[name][0]
    if name == "READ_CAP_SHARE":
        monkeypatch.setenv("PSAT_LOGIC_READ_CAP", "100000")
    for module in modules:
        monkeypatch.setattr(module, name, type(getattr(module, name))(float(value)))
    return None


def _sig(v) -> tuple:
    """Everything a verdict says but its witnesses (one passing call among the many that may be found)."""
    return (v.openness, v.allowed, v.complete, frozenset(v.principals), frozenset(v.signers),
            tuple(sorted(v.conditions.items())), frozenset(v.undecided), v.gaps, v.requires,
            tuple(signature for signature, _ in v.after))  # fmt: skip


def _decided(d, key: tuple, monkeypatch, fault: str):
    """The clean verdict (decided again once the chain has moved on: a deadline counts blocks) and the faulted one."""
    module, index, contract, function, others = key
    block = int(rpc(d.url, "eth_blockNumber", []), 16)
    if _CLEAN.get(key, (None,))[0] != block:
        _forget(d)
        _CLEAN[key] = (block, O.verdict(d, contract, function, *others))
    clean = _CLEAN[key][1]
    with monkeypatch.context() as patch:
        chain = _inject(fault, patch, d, contract)
        _forget(d)  # nothing a run lowered under one fault is kept for the next
        try:
            faulted = O.verdict(d, contract, function, *others, chain=chain)
        finally:
            _forget(d)
    _RAN.setdefault(fault, set()).add(key)
    if _sig(faulted) != _sig(clean):
        _CHANGED.setdefault(fault, set()).add(key)
    return clean, faulted


@pytest.mark.parametrize(("module", "index", "contract", "function", "others", "fault"), PROBED)
def test_a_fault_never_makes_a_verdict_bolder(deployed, monkeypatch, module, index, contract, function, others, fault):
    d = deployed(module, index)
    clean, faulted = _decided(d, (module, index, contract, function, others), monkeypatch, fault)
    O.never_bolder(clean, faulted)
    O.chain_sound(d, contract, function, faulted, clean)
    if fault in INVARIANT:
        assert _sig(faulted) == _sig(clean), (fault, clean, faulted)


def test_every_fault_changes_some_verdict(deployed, monkeypatch):
    # Otherwise the property above holds vacuously for it. What the sweep didn't decide (a fault whose sample cut
    # nothing, or a run that deselected it) is decided here, probe by probe, until one verdict changes.
    keys = _probes()
    vacuous = []
    for fault in [*FAULTS, *SAMPLED_FAULTS]:
        if fault in INVARIANT or fault in UNREACHED:
            continue
        for key in keys:
            if _CHANGED.get(fault):
                break
            if key not in _RAN.get(fault, set()):
                _decided(deployed(*key[:2]), key, monkeypatch, fault)
        if not _CHANGED.get(fault):
            vacuous.append(fault)
    assert not vacuous, vacuous


def test_the_unreached_faults_still_cut_nothing(deployed, monkeypatch):
    # Once one of them changes a verdict, it belongs with the faults that must (and its probe is no longer owed).
    for fault in UNREACHED:
        assert fault in SAMPLED_FAULTS, fault
        assert not _CHANGED.get(fault), (fault, sorted(_CHANGED[fault]))


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


def test_every_constant_that_bounds_work_is_swept():
    # A budget the sweep leaves out may let a verdict through bolder under it, unseen.
    swept = set(BUDGETS) | set(SAMPLED)
    for module in (D, V, H, L, S, W):
        for name, value in vars(module).items():
            if name.isupper() or (name.startswith("_") and name[1:].isupper()):
                if isinstance(value, (int, float)) and not isinstance(value, bool) and name not in _NOT_BUDGETS:
                    assert name in swept, (module.__name__, name)


# Numbers that bound no work: a stranger's address, word sizes, the read's own constants, the clock's floor, sizes
# the protocol fixes.
_NOT_BUDGETS = {
    "FRESH", "_LOWEST_SENDER", "_W", "WORD", "_MAX_CALLDATA", "LOG_MIN_WINDOW", "_ORIGIN_OP", "_EPOCH",
    "_SIZE_CAP", "_MEMORY_SPAN", "_FREE_MEMORY", "SKIP_SELF_SCOPED",
}  # fmt: skip
