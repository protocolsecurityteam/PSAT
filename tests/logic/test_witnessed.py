"""Witnessed open and proven open are two claims (``Verdict.witnessed``). "Open" unqualified says every unconfigured
address passes, and is said only where the formula's form shows it (``decide._alike_for_strangers``: the caller only
as a mapping key or one side of an equality, no callee handed it, nothing reading ``tx.origin``) and nothing was
sampled to reach it. An open resting on the five strangers' calls run on the chain, or on the formula evaluated at
those five addresses where its form doesn't make every unconfigured address alike, is ``witnessed``: a gate letting
nine in ten addresses through passes five strangers. The sample never promotes to the proof: ``report``,
``deployment`` and ``scripts/logic_run_passes.py`` carry the flag, and the fail-safe sweep ranks proven above
witnessed (``_oracle.never_bolder``). Each verdict is checked against ``eth_call`` on anvil (``_oracle.check``), a
proved open at 24 further addresses the engine never samples (``_oracle.UNSEEN``)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts.logic_run_passes import main as run_passes
from services.logic.decide import _STRANGERS
from services.logic.report import openness_label
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Reg {
    mapping(address => bool) public banned;
    function ok(address who) external view returns (bool) { return !banned[who]; }
}

contract Sink { uint256 n; function poke() external { n++; } }

contract C {
    address owner;
    Reg reg;
    Sink sink;
    mapping(address => bool) blocked;
    mapping(address => uint256) bal;
    uint256 total;
    constructor(address r, address s) { owner = msg.sender; reg = Reg(r); sink = Sink(s); }
    // Half of all addresses: the five strangers differ in their low bit.
    function parity(uint256 x) external { require(uint160(msg.sender) % 2 == 0); total += x; }
    // Nine in ten: every one of the five strangers passes, an address that is a multiple of ten doesn't.
    function ninety(uint256 x) external { require(uint160(msg.sender) % 10 != 0); total += x; }
    // An ordering of addresses: the five strangers sit above it, the zero-prefixed don't.
    function above(uint256 x) external { require(msg.sender > address(0x1000)); total += x; }
    function free(uint256 x) external { total += x; }
    function notBlocked(uint256 x) external { require(!blocked[msg.sender]); total += x; }
    function notOwner(uint256 x) external { require(msg.sender != owner && x > 0); total += x; }
    function pay() external payable { require(msg.value > 0); total += msg.value; }
    function ownerOnly(uint256 x) external { require(msg.sender == owner); total += x; }
    // Open on a callee's answer for the caller: its code, not the formula, says everyone passes.
    function viaReg(uint256 x) external { require(reg.ok(msg.sender)); total += x; }
    // Open on an action not handed the caller.
    function bump() external { sink.poke(); total += 1; }
    // Open after a deposit of each stranger's own.
    function deposit(uint256 a) external { require(a > 0); bal[msg.sender] += a; }
    function withdrawAll() external { uint256 b = bal[msg.sender]; require(b > 0); bal[msg.sender] = 0; total += b; }
    // Every stranger's own account passes; a contract a stranger calls through never does.
    function fromAccount(uint256 x) external { require(msg.sender == tx.origin); total += x; }
    function fromAccountWide(uint256 x) external {
        require(uint256(uint160(msg.sender)) == uint160(tx.origin));
        total += x;
    }
}

contract Relay {
    function go(C c) external { c.fromAccount(1); }
}
"""


def _setup(d):
    d.deploy("Reg")
    d.deploy("Sink")
    d.deploy("C", ("address", "address"), (d.at["Reg"], d.at["Sink"]))
    d.deploy("Relay")


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        tuple(
            ("C", n, f)
            for n, f in [
                ("parity", ()),
                ("ninety", ()),
                ("above", ()),
                ("free", ()),
                ("notBlocked", ()),
                ("notOwner", ()),
                ("pay", ()),
                ("ownerOnly", ()),
                ("viaReg", ("Reg",)),
                ("viaReg", ()),
                ("bump", ("Sink",)),
                ("withdrawAll", ()),
            ]
        ),
    )
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_the_strangers_low_bits_differ():
    # What the parity probe relies on: one stranger is even, the rest odd; none a multiple of ten.
    assert {s % 2 for s in _STRANGERS} == {0, 1}
    assert all(s % 10 for s in _STRANGERS)


def test_a_gate_admitting_half_is_never_open(d):
    fn = O.function(d, "C", "parity")
    assert O.strangers_passing(d, "C", fn, {"x": 1}) == {True, False}
    v = O.check(d, "C", "parity", O.verdict(d, "C", "parity"), samples=({"x": 1},), open_at=False)
    assert v.openness == "not_determined", v


@pytest.mark.parametrize("name", ["ninety", "above"])
def test_a_gate_every_stranger_passes_by_its_arithmetic_is_only_witnessed(d, name):
    fn = O.function(d, "C", name)
    assert O.strangers_passing(d, "C", fn, {"x": 1}) == {True}
    assert not O.passes(d, "C", fn, {"x": 1}, sender=0x500)  # below 0x1000, a multiple of ten: refused
    v = O.check(d, "C", name, O.verdict(d, "C", name), open_at={"x": 1}, open_proven=False)
    assert v.openness == "open" and v.allowed == "now" and v.witnessed, v
    assert openness_label(v) == "open_witnessed"


@pytest.mark.parametrize("name", ["fromAccount", "fromAccountWide"])
def test_the_caller_against_the_origin_is_never_alike_for_every_address(d, name):
    # ``msg.sender == tx.origin`` holds for each stranger calling from its own account, never for a contract it
    # calls through: an address that is a contract is refused. Before, an identity compared with any identity
    # counted as alike for every address and the open was proven.
    assert not O.passes(d, "Relay", O.function(d, "Relay", "go"), {"c": d.at["C"]}, sender=O.STRANGERS[0])
    v = O.check(d, "C", name, O.verdict(d, "C", name), open_at={"x": 1}, open_proven=False)
    assert v.openness != "open" or v.witnessed, v


@pytest.mark.parametrize("name", ["free", "notBlocked", "notOwner", "pay"])
def test_an_open_the_formula_shows_for_every_address_is_proven(d, name):
    v = O.check(d, "C", name, O.verdict(d, "C", name), open_proven=True)
    assert v.openness == "open" and v.allowed == "now" and not v.witnessed, v
    assert openness_label(v) == "open"


@pytest.mark.parametrize(
    ("name", "others"), [("viaReg", ("Reg",)), ("viaReg", ()), ("bump", ("Sink",)), ("withdrawAll", ())]
)
def test_an_open_resting_on_callee_code_an_action_or_a_call_first_is_witnessed(d, name, others):
    v = O.check(d, "C", name, O.verdict(d, "C", name, *others), open_proven=False)
    assert v.openness == "open" and v.witnessed, v
    if name == "withdrawAll":
        assert [s for s, _ in v.after] == ["deposit(uint256)"], v


def test_a_restricted_verdict_is_never_witnessed(d):
    v = O.check(d, "C", "ownerOnly", O.verdict(d, "C", "ownerOnly"), samples=({"x": 1},), open_at=False)
    assert v.openness == "restricted" and not v.witnessed and openness_label(v) == "restricted", v


def _v(openness, witnessed=False, allowed="now", complete=True):
    return SimpleNamespace(
        openness=openness,
        witnessed=witnessed,
        allowed=allowed,
        complete=complete,
        principals=frozenset(),
        signers=frozenset(),
        conditions={},
    )


def test_the_sweep_ranks_proven_above_witnessed():
    proven, witnessed, undetermined = _v("open"), _v("open", True), _v("not_determined", complete=False)
    O.never_bolder(proven, witnessed)  # a fault may cost the proof
    O.never_bolder(witnessed, undetermined)
    with pytest.raises(AssertionError):
        O.never_bolder(witnessed, proven)  # never gain it
    with pytest.raises(AssertionError):
        O.never_bolder(undetermined, witnessed)


def _row(**fields):
    return {"contract": "C", "address": "0x" + "c" * 40, "function": "f()", "lego": "open", **fields}


def _run(tmp_path, capsys, old, new, *flags):
    (tmp_path / "corpus_x_old_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in old))
    (tmp_path / "corpus_x_new_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in new))
    code = run_passes(
        ["--old", str(tmp_path / "corpus_x_old_s1.jsonl"), "--new", str(tmp_path / "corpus_x_new_s1.jsonl"), *flags]
    )
    return code, capsys.readouterr().out


@pytest.mark.parametrize("flag", ["--faulty", "--budget-only"])
def test_a_run_turning_a_witnessed_open_proven_fails(tmp_path, capsys, flag):
    code, out = _run(tmp_path, capsys, [_row(lego_witnessed=True)], [_row(lego_witnessed=False)], flag)
    assert code == 1 and "witnessed open" in out and "proven" in out, out


@pytest.mark.parametrize("flag", ["--faulty", "--budget-only"])
def test_a_run_turning_a_proven_open_witnessed_is_a_confidence_only_move(tmp_path, capsys, flag):
    code, out = _run(tmp_path, capsys, [_row(lego_witnessed=False)], [_row(lego_witnessed=True)], flag)
    assert code == 0 and "confidence-only moves: 1" in out and "open proven -> witnessed" in out, out


def test_a_run_that_didnt_record_the_flag_says_nothing_either_way(tmp_path, capsys):
    code, out = _run(tmp_path, capsys, [_row()], [_row(lego_witnessed=False)], "--budget-only")
    assert code == 0 and "confidence-only moves: 0" in out, out
