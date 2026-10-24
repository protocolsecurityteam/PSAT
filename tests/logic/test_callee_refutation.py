"""A followed callee's code never refutes on its own (``Evaluator.truth``, ``solve``): a failure or an unsatisfiable
question resting on a callee's code standing in for a call is asked again without it, each view call a value tied to
what the chain answers at the inputs the models reach. What still fails was refuted by the chain; a model the chain's
answers agree with is a pass; anything else is unknown, named ``callee_code_refutation``, never complete. So however a
callee is mis-lowered, the verdict is never a confident list missing a stranger the chain lets through. Each probe
lowers the callee wrongly on purpose (its code read as "nobody") and checks the verdict against ``eth_call`` on
anvil."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from services.logic.lower import Lowerer
from services.logic.terms import FALSE, TRUE, reset_terms
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

SOURCE = """
pragma solidity 0.8.27;

contract L {
    function ok(uint256 v) external pure returns (bool) { return v == 3; }
    function pick(uint256 w) external pure returns (bool) { return w == 1; }
    function never(uint256 w) external pure returns (bool) { w; return false; }
}
contract C {
    L public l;
    address public owner;
    uint256 public x;
    constructor(L z) { l = z; owner = msg.sender; }
    // A stranger passing v = 3 gets through.
    function any(uint256 v) external { require(l.ok(v) || msg.sender == owner); x = v; }
    // A stranger passing v > 5 gets through: the call's input is 1 or 2, whatever v is.
    function picked(uint256 v) external { require(l.pick(v > 5 ? 1 : 2) || msg.sender == owner); x = v; }
    // Only the owner: the call fails at both inputs it can be handed.
    function none(uint256 v) external { require(l.never(v > 5 ? 1 : 2) || msg.sender == owner); x = v; }
}

contract G {
    address public owner;
    address public admin2;
    constructor(address o, address a) { owner = o; admin2 = a; }
    function ok(address who) external view returns (bool) { return who == admin2 || who == owner; }
    function ok2(address who, uint256 v) external view returns (bool) { v; return who == owner; }
}
contract D {
    G public g;
    uint256 public x;
    constructor(G z) { g = z; }
    // The owner and the second admin pass; a stranger doesn't.
    function m() external { require(g.ok(msg.sender)); x = 1; }
    function k() external { require(g.ok2(msg.sender, 5)); x = 1; }
    function kv(uint256 v) external { require(g.ok2(msg.sender, v)); x = v; }
}
"""
ADMIN2 = 0xA2 << 144  # above the sentinels: an address that sends

STRANGER = "0x" + "00" * 19 + "aa"


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("L")
    d.deploy("C", ("address",), (d.at["L"],))
    return d


@pytest.fixture
def wrong(monkeypatch):
    """L's code lowered as "nobody": returns false, whatever it is handed."""
    called = Lowerer.called

    def misread(self, function, args, view):
        if getattr(getattr(function, "contract", None), "name", None) == "L":
            return TRUE, (FALSE,)
        return called(self, function, args, view)

    monkeypatch.setattr(Lowerer, "called", misread)


def _verdict(d, name):
    reset_terms()
    c = d.slither["C"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    return function_verdict(c, fn, d.at["C"], d.chain(), d.contracts("C", "L"))[0]


def _passes(d, name, v, sender=STRANGER) -> bool:
    data = "0x" + (keccak(text=f"{name}(uint256)")[:4] + encode(["uint256"], [v])).hex()
    try:
        rpc(d.url, "eth_call", [{"from": sender, "to": "0x%040x" % d.at["C"], "data": data}, "latest"])
        return True
    except RuntimeError:
        return False


def test_a_mis_lowered_callee_never_makes_a_confident_list_missing_a_stranger(d, wrong):
    assert _passes(d, "any", 3)
    verdict = _verdict(d, "any")
    assert not (verdict.openness == "restricted" and verdict.complete), verdict
    if verdict.openness != "open":
        assert "callee_code_refutation" in verdict.gaps
        assert int(ACCOUNT0, 16) in verdict.principals


def test_a_mis_lowered_callee_s_refusal_the_chain_contradicts_is_a_pass(d, wrong):
    # The call's input is 1 or 2 whatever v is: the chain answers both, and v > 5 passes.
    assert _passes(d, "picked", 6)
    verdict = _verdict(d, "picked")
    assert verdict.openness == "open", verdict
    assert list(verdict.witnesses.values())[0]["v"] > 5


@pytest.mark.parametrize("misread", [False, True])
def test_a_refusal_the_chain_answers_at_every_input_is_complete(d, monkeypatch, misread):
    if misread:
        called = Lowerer.called
        monkeypatch.setattr(
            Lowerer,
            "called",
            lambda self, function, args, view: (
                (TRUE, (FALSE,)) if function.contract.name == "L" else called(self, function, args, view)
            ),
        )
    assert not any(_passes(d, "none", v) for v in (0, 6))
    verdict = _verdict(d, "none")
    assert verdict.openness == "restricted" and verdict.complete, verdict
    assert verdict.principals == {int(ACCOUNT0, 16)}


@pytest.fixture(scope="module")
def dg(d):
    g = d.deploy("G", ("address", "address"), (int(ACCOUNT0, 16), ADMIN2))
    d.deploy("D", ("address",), (g,))
    return d


def _g_reads(monkeypatch, value):
    """G's checks lowered as reading alike for everyone: ``value`` (true or false), whatever they are handed."""
    called = Lowerer.called

    def misread(self, function, args, view):
        if getattr(getattr(function, "contract", None), "name", None) == "G":
            return TRUE, (value,)
        return called(self, function, args, view)

    monkeypatch.setattr(Lowerer, "called", misread)


def _d_verdict(d, name):
    reset_terms()
    c = d.slither["D"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    return function_verdict(c, fn, d.at["D"], d.chain(), d.contracts("D", "G"))[0]


def _d_passes(d, signature, types=(), values=(), sender=STRANGER) -> bool:
    data = "0x" + (keccak(text=signature)[:4] + encode(list(types), list(values))).hex()
    try:
        rpc(d.url, "eth_call", [{"from": sender, "to": "0x%040x" % d.at["D"], "data": data}, "latest"])
        return True
    except RuntimeError:
        return False


@pytest.mark.parametrize("value", [FALSE, TRUE], ids=["nobody", "everyone"])
@pytest.mark.parametrize(("name", "signature"), [("m", "ok(address)"), ("k", "ok2(address,uint256)")])
def test_callee_code_reading_alike_for_everyone_never_proves_nobody(dg, monkeypatch, value, name, signature):
    # G's code, mis-lowered, never uses the caller it is handed: "nobody is singled out" would rest on it alone. The
    # chain refuses a stranger and lets the owner through, so the list is never a complete "nobody".
    _g_reads(monkeypatch, value)
    assert _d_passes(dg, f"{name}()", sender=ACCOUNT0) and not _d_passes(dg, f"{name}()")
    verdict = _d_verdict(dg, name)
    assert verdict.openness != "open" and not verdict.complete, verdict
    assert f"callee_unsingled:{signature}" in verdict.gaps


def test_callee_code_naming_the_wrong_holder_never_makes_a_complete_list(dg, monkeypatch):
    # G's check mis-lowered as "the caller is address 1": a list resting on it would be a confident "nobody" while
    # the chain lets the owner through. It names whom it names as likely, never all.
    from services.logic.terms import const, mk_cmp

    called = Lowerer.called

    def misread(self, function, args, view):
        if getattr(getattr(function, "contract", None), "name", None) == "G":
            return TRUE, (mk_cmp("eq", args[0], const(1, "address")),)
        return called(self, function, args, view)

    monkeypatch.setattr(Lowerer, "called", misread)
    assert _d_passes(dg, "m()", sender=ACCOUNT0)
    verdict = _d_verdict(dg, "m")
    assert not verdict.complete and "callee_code_list:ok(address)" in verdict.gaps


def test_a_callee_list_names_whom_the_chain_lets_through_but_is_never_complete_on_its_code(dg):
    # Correctly lowered, G's code names the owner and the second admin, each confirmed by the chain; that they are
    # all rests on G's code alone, so the list isn't complete.
    assert _d_passes(dg, "m()", sender="0x%040x" % ADMIN2)
    verdict = _d_verdict(dg, "m")
    assert verdict.openness == "restricted" and verdict.principals == {int(ACCOUNT0, 16), ADMIN2}
    assert not verdict.complete and "callee_code_list:ok(address)" in verdict.gaps


def test_a_pass_resting_on_callee_code_over_an_argument_not_known_whole_is_never_open(dg, monkeypatch):
    # ``ok2(msg.sender, v)`` with ``v`` left to choose: G's code (mis-lowered: everyone) answers a call whose input
    # isn't known whole. Asked again with no callee code at all, that call is unknown: never a pass, never open.
    _g_reads(monkeypatch, TRUE)
    assert not any(_d_passes(dg, "kv(uint256)", ["uint256"], [v]) for v in (0, 3, 2**200))
    verdict = _d_verdict(dg, "kv")
    assert verdict.openness != "open", verdict
    assert "callee_code_pass" in verdict.gaps


def test_a_pass_confirmed_again_never_lets_callee_code_answer_a_call_not_known_whole(dg, monkeypatch):
    # ``confirmed``: a guess G's code lets through, asked again of the chain, with the call's input still not known
    # whole (``v`` unassigned): unknown, not the code's pass again.
    from services.logic.decide import UNK, Evaluator, World, confirmed
    from services.logic.lower import parameter

    _g_reads(monkeypatch, TRUE)
    reset_terms()
    c = dg.slither["D"]
    fn = next(f for f in c.functions_entry_points if f.name == "kv")
    formula = Lowerer(c).success(fn)
    world = World(dg.chain(), dg.at["D"], int.from_bytes(keccak(text=fn.solidity_signature)[:4], "big"))
    world.contracts = dg.contracts("D", "G")
    lowered = {}

    def callee(call, address=None):
        if call not in lowered:
            target = dg.slither["G"].get_function_from_signature(call[2])
            pc, ret = Lowerer(dg.slither["G"], this=call[1]).called(target, list(call[3]), call[4])
            lowered[call] = (pc, ret)
        return lowered[call]

    world.callee = callee
    world.parameters = (parameter(fn.parameters[0], 0),)
    stranger = int(STRANGER, 16)
    ev = Evaluator(world, {"caller": stranger, "signer": stranger})
    assert ev.ranked(formula) is True and ev.coded[0]
    assert confirmed(ev, formula, None, True) is UNK


def test_what_a_detached_block_looked_up_about_a_callee_is_put_back(dg, monkeypatch):
    # The verdict's callbacks remember where a call goes (and how it is bound to its caller) in the world, which a
    # block that must leave no trace (``detached``, the candidates' screen) puts back: an address it couldn't read,
    # the chain being offline there, is read afresh after it, never left unknown.
    import services.logic.verdict as verdict_module
    from services.logic.decide import detached
    from services.logic.terms import mk, subterms

    found: list = []
    real = verdict_module.decide

    def spy(formula, world, cover):
        call = next(c for c in subterms(formula, "call") if c[2] == "ok(address)")
        other = mk("call", mk("conv", "address", call[1]), call[2], call[3], call[4])
        world.chain._memo.pop(("s", dg.at["D"], 0), None)  # where ``g`` is stored: not read yet
        with detached(world):
            found.append(world.callee(other))  # offline: the address unread
        found.append(world.callee(other))
        return real(formula, world, cover)

    monkeypatch.setattr(verdict_module, "decide", spy)
    _d_verdict(dg, "m")
    assert found[0] is None and found[1] is not None


def test_what_the_chain_answers_one_asker_is_never_taken_for_another():
    # A call made by followed code (its asker the callee making it, here one the caller picks) answered by the chain
    # for one asker says nothing of what it answers another: the lemma ties the answer to the asker too, so a model
    # with another asker is asked again rather than refuted.
    from services.logic.decide import Chain, Evaluator, World, _solve
    from services.logic.terms import const, mk, mk_and, mk_cmp, mk_not

    target, picked = 0x7A << 152, 0xB0B << 148

    class _Chain(Chain):
        def __init__(self):
            super().__init__(lambda method, params: None, 1)

        def call(self, address, data, sender, overrides=None):
            return (1 if sender == picked else 0).to_bytes(32, "big")

        def code(self, address):
            return b"\x60"

    reset_terms()
    asker = mk("arg", "asker", "address")
    call = mk("call", const(target, "address"), "allowed()", (), True, asker)
    # The asker is the caller's to pick, as the formula reads it elsewhere too.
    formula = mk_and([mk_cmp("eq", call, const(1)), mk_not(mk_cmp("eq", asker, const(0, "address")))])
    world = World(_Chain(), this=0xC0 << 152, selector=0)
    stranger = int(STRANGER, 16)
    ground = Evaluator(world, {"caller": stranger, "signer": stranger})
    ground.code_first = ground.callee_code = False
    assert _solve(formula, ground, chain_calls=True) is not None
