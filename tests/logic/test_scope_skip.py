"""The self-scope skip (``PSAT_LOGIC_SCOPE_SKIP=1``, ``decide.SKIP_SELF_SCOPED``) tested on its own, whatever the
scope label says: the label is unverified (``SCOPE.md``), so the worst a wrong one may do is lose holders into a
list never complete, saying ``self_scoped``. With skipping on, (a) a function the chain lets a stranger through is
never reported restricted: every stranger's own call is run before skipping; (b) a skipped row is never complete
and always says ``self_scoped`` and its gate; (c) an admin function the classifier is forced to call self-scoped
comes out no more open and with no confident list than with skipping off (``_oracle.never_bolder``); the fail-safe
sweep runs the whole registry with skipping on, and with every function forced self-scoped, as two more faults
(``test_failsafe``). (e) ``scripts/logic_run_passes.py`` counts skipped rows apart and prints each whose prod
holders' replayed calls go through. Each verdict is checked against ``eth_call`` on anvil (``_oracle.check``)."""

from __future__ import annotations

import json

import pytest

import services.logic.verdict as verdict_module
from scripts.logic_run_passes import main as run_passes
from services.logic import decide
from services.logic.lower import Lowerer
from services.logic.scope import Scope
from services.logic.terms import CALLER, const, mk_and, mk_cmp
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Reg { function ok(address who) external pure returns (bool) { who; return true; } }

contract C {
    address owner;
    Reg reg;
    mapping(address => bool) allowed;
    mapping(address => uint256) bal;
    uint256 fee;
    event Allowed(address indexed who);
    constructor(address r) { owner = msg.sender; reg = Reg(r); }
    function allow(address w) external { require(msg.sender == owner); allowed[w] = true; emit Allowed(w); }
    // Allowlisted senders move their own balance: self-scoped by its shape.
    function send(address to, uint256 d) external { require(allowed[msg.sender]); bal[msg.sender] -= d; bal[to] += d; }
    // Admin: the owner alone.
    function setFee(uint256 x) external { require(msg.sender == owner); fee = x; }
    // Anyone: ``reg.ok`` answers true for every caller.
    function poke(uint256 a) external { require(reg.ok(msg.sender)); bal[msg.sender] += a; }
    function deposit(uint256 a) external { bal[msg.sender] += a; }
}
"""

MEMBER, ADMIN = O.ACCOUNTS[2], O.ACCOUNTS[3]


def _setup(d):
    d.deploy("Reg")
    d.deploy("C", ("address",), (d.at["Reg"],))
    assert O.transact(d, "C", "allow(address)", ("address",), (MEMBER,))


PROBES = [O.Probe(SOURCE, _setup, (("C", "send", ()), ("C", "setFee", ()), ("C", "poke", ("Reg",))))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _forget(d):
    for contract in d.slither.values():
        for key in [k for k in contract.__dict__ if k.startswith("_psat_")]:
            del contract.__dict__[key]


def _decided(d, name, *others, skip=False, self_scoped=False, monkeypatch=None):
    with monkeypatch.context() as patch:
        patch.setattr(decide, "SKIP_SELF_SCOPED", skip)
        if self_scoped:
            patch.setattr(verdict_module, "classify", lambda *a, **k: Scope("self"))
        _forget(d)
        try:
            return O.verdict(d, "C", name, *others)
        finally:
            _forget(d)


def _skipped(v) -> bool:
    return "self_scoped" in v.gaps


@pytest.mark.parametrize("forced", [False, True], ids=["classified", "forced_self"])
def test_a_skipped_row_is_never_complete_and_names_its_gate(d, monkeypatch, forced):
    clean = _decided(d, "send", monkeypatch=monkeypatch)
    v = _decided(d, "send", skip=True, self_scoped=forced, monkeypatch=monkeypatch)
    O.check(d, "C", "send", v, samples=({"to": MEMBER, "d": 0},), known=(MEMBER,), open_at=False)
    O.never_bolder(clean, v)
    if forced or v.scope == "self":
        assert v.openness == "restricted" and not v.complete and _skipped(v) and v.gate, v
        assert not v.principals and not v.conditions, v
    # Skipping off (the default): the allowlisted member is listed.
    assert clean.openness == "restricted" and MEMBER in O.listed(clean) and not _skipped(clean), clean


def test_an_admin_function_mislabelled_self_scoped_only_loses_its_holders(d, monkeypatch):
    clean = _decided(d, "setFee", monkeypatch=monkeypatch)
    assert clean.openness == "restricted" and clean.complete and set(clean.principals) == {O.OWNER}, clean
    v = _decided(d, "setFee", skip=True, self_scoped=True, monkeypatch=monkeypatch)
    O.check(d, "C", "setFee", v, samples=({"x": 1},), known=(O.OWNER,), open_at=False)
    O.never_bolder(clean, v)
    assert v.openness == "restricted" and not v.complete and _skipped(v) and v.gate, v


def test_a_function_strangers_pass_is_never_skipped_into_restricted(d, monkeypatch):
    for name, others in (("deposit", ()), ("poke", ("Reg",))):
        v = _decided(d, name, *others, skip=True, self_scoped=True, monkeypatch=monkeypatch)
        O.check(d, "C", name, v)
        assert v.openness == "open" and not _skipped(v), v


def test_a_formula_refusing_strangers_the_chain_lets_through_is_never_skipped_into_restricted(d, monkeypatch):
    # ``deposit`` mis-lowered as an admin check (``msg.sender == ADMIN`` added): the formula refuses every stranger,
    # the holders' builder names the admin, and the label says self-scoped. The chain lets every stranger through,
    # so skipping, which would answer restricted on the formula alone, runs their calls first.
    success = Lowerer.success

    def admin_only(self, fn):
        formula = success(self, fn)
        return mk_and([formula, mk_cmp("eq", CALLER, const(ADMIN, "address"))]) if fn.name == "deposit" else formula

    monkeypatch.setattr(Lowerer, "success", admin_only)
    v = _decided(d, "deposit", skip=True, self_scoped=True, monkeypatch=monkeypatch)
    assert O.strangers_passing(d, "C", O.function(d, "C", "deposit"), {"a": 1}) == {True}
    assert v.openness != "restricted" and not v.complete, v
    assert v.gaps == ("self_scoped", "self_scoped_ran"), v


def test_skipping_stays_off_by_default():
    assert decide.SKIP_SELF_SCOPED is False


def _row(**fields):
    return {"contract": "C", "address": "0x" + "c" * 40, "function": "f()", "lego": "restricted", **fields}


def _run(tmp_path, capsys, old, new, *flags):
    (tmp_path / "corpus_x_old_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in old))
    (tmp_path / "corpus_x_new_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in new))
    code = run_passes(
        ["--old", str(tmp_path / "corpus_x_old_s1.jsonl"), "--new", str(tmp_path / "corpus_x_new_s1.jsonl"), *flags]
    )
    return code, capsys.readouterr().out


HOLDER = "0x" + "a" * 40


def test_the_pass_script_counts_skipped_rows_and_shows_those_a_prod_holder_passes(tmp_path, capsys):
    skipped = dict(lego_scope="self", lego_gaps=["self_scoped"], lego_complete=False)
    old = [_row(lego_scope="self", lego_principals=[HOLDER], checks={HOLDER: True}), _row(function="g()")]
    new = [_row(**skipped, checks={HOLDER: True}), _row(function="g()", **skipped, checks={HOLDER: False})]
    code, out = _run(tmp_path, capsys, old, new, "--scope-skip")
    assert "skipped self-scoped rows: 2" in out, out
    assert "skipped rows a prod holder's replay passes: 1" in out and f"f() @ 0x{'c' * 40}: {HOLDER}" in out, out
    assert code == 0, out  # with --scope-skip, holders a skipped row stopped listing are expected
    code, out = _run(tmp_path, capsys, old, new)
    assert code == 1 and "(b) lost 1 replay-confirmed holder" in out, out


def test_the_pass_script_says_nothing_skipped_where_nothing_was(tmp_path, capsys):
    code, out = _run(tmp_path, capsys, [_row()], [_row()])
    assert code == 0 and "skipped self-scoped rows: 0" in out and "skipped rows a prod holder's replay passes: 0" in out
