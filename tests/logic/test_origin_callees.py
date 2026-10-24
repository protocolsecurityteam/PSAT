"""A callee sees the caller's ``tx.origin``, and the chain answers a call with this contract as the origin: a callee
whose code may read it is never taken at the chain's word. Followed, it is inlined with its own success condition,
which only proposes: a holder it names is listed once the whole call, run on the chain from that address, goes
through, and the list never rests on its word (never complete, ``inlined_callee:<signature>``). Otherwise the call
stays an unknown named for why. Each verdict is checked against ``eth_call`` on anvil (``_oracle.check``): the admin
listed passes from its own address (the origin too), no stranger does."""

from __future__ import annotations

import pytest

from services.logic.decide import Verdict
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Guard {
    address public admin;
    constructor(address a) { admin = a; }
    function originOk() external view returns (bool) { return tx.origin == admin; }
    function originReq() external view returns (bool) { require(tx.origin == admin); return true; }
    function originReqArg(uint256 x) external view returns (bool) { x; require(tx.origin == admin); return true; }
    function originVoid(uint256 x) external view { x; require(tx.origin == admin); }
    function onlyEoa() external view returns (bool) { return tx.origin == msg.sender; }
    function capFor() external view returns (uint256) { require(tx.origin == admin); return 100; }
}

contract C {
    address admin;
    Guard guard;
    mapping(address => bool) blocked;
    uint256 total;
    constructor(address a, address g) { admin = a; guard = Guard(g); }
    function p9(uint256 x) external { x; require(guard.originOk()); total += 1; }
    function p9e(uint256 x) external { x; require(guard.onlyEoa()); total += 1; }
    function p9r(uint256 x) external { x; require(guard.originReq()); total += 1; }
    function p9v(uint256 x) external { guard.originVoid(x); total += 1; }
    function q1(uint256 x) external { uint256 cap = guard.capFor(); require(x <= cap); total += 1; }
    function q3(uint256 x) external { require(guard.originReqArg(x)); total += 1; }
    function q4(uint256 x) external { require(guard.originReq() && !blocked[msg.sender]); total += x; }
}
"""

ADMIN = int("ab" * 20, 16)


ADMIN = O.ACCOUNTS[1]
X = ({"x": 0}, {"x": 1}, {"x": 100})
NAMES = ("p9", "p9e", "p9r", "p9v", "q1", "q3", "q4")


def _setup(d):
    d.deploy("Guard", ("address",), (ADMIN,))
    d.deploy("C", ("address", "address"), (ADMIN, d.at["Guard"]))


PROBES = [O.Probe(SOURCE, _setup, tuple(("C", n, f) for n in NAMES for f in (("Guard",), ())))]


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _verdict(d, name, followed=True, chain=None) -> Verdict:
    return O.verdict(d, "C", name, *(("Guard",) if followed else ()), chain=chain)


@pytest.mark.parametrize(
    ("name", "signature"),
    [
        ("p9", "originOk()"),
        ("p9r", "originReq()"),
        ("p9v", "originVoid(uint256)"),
        ("q1", "capFor()"),
        ("q3", "originReqArg(uint256)"),
        ("q4", "originReq()"),
    ],
)
def test_a_followed_callee_checking_the_origin_lists_its_admin(deployed, name, signature):
    # The admin, whose own call goes through on the chain; the inlined code's list is never complete on its word.
    v = O.check(deployed, "C", name, _verdict(deployed, name), samples=X, open_at=False)
    assert not v.complete and set(v.principals) == {ADMIN}
    assert f"inlined_callee:{signature}" in v.gaps


@pytest.mark.parametrize(("name", "signature"), [("p9", "originOk()"), ("q1", "capFor()"), ("p9e", "onlyEoa()")])
def test_code_not_followed_that_reads_the_origin_is_never_taken_at_the_chains_word(deployed, name, signature):
    v = O.check(deployed, "C", name, _verdict(deployed, name, followed=False), samples=X, open_at=False)
    O.sound(v, {ADMIN} if name != "p9e" else set())
    assert v.openness == "not_determined"
    assert f"origin:{signature}" in v.gaps


def test_no_contract_is_a_transactions_origin(deployed):
    # tx.origin == msg.sender inside the guard: msg.sender is this contract, so nobody ever passes. The inlined code
    # says so; nothing the chain answers shows it is all, so nobody is listed and the list isn't complete.
    v = O.check(deployed, "C", "p9e", _verdict(deployed, "p9e"), samples=X, open_at=False)
    assert not v.complete and v.principals == set()
    assert "inlined_callee:onlyEoa()" in v.gaps
    p9e = O.function(deployed, "C", "p9e")
    for who in {*O.ACCOUNTS, *O.STRANGERS}:
        assert not O.passes(deployed, "C", p9e, {"x": 0}, sender=who)


def test_an_unread_callee_address_is_a_gap_not_a_silent_skip(deployed):
    left = [1]
    guard_slot = (deployed.at["C"], 1)

    def first_read(method, params):  # that storage word's first read fails as a node error
        if left[0] and (int(params[0], 16), int(params[1], 16)) == guard_slot:
            left[0] -= 1
            return True
        return False

    clean = _verdict(deployed, "p9v")
    v = _verdict(deployed, "p9v", chain=O.Faulty(deployed, storage=first_read))
    assert v.openness == "not_determined"
    assert "read_failed:call_target:originVoid(uint256)" in v.gaps
    O.never_bolder(clean, v)


def test_runtime_code_is_walked_by_opcode():
    from services.logic.verdict import _runtime_reach

    assert _runtime_reach(bytes([0x60, 0x32, 0x00])) is None  # 0x32 as PUSH1 data
    assert _runtime_reach(bytes([0x32, 0x00])) == "origin"
    assert _runtime_reach(bytes([0x5B, 0xFA, 0x00])) == "unfollowed"
    metadata = bytes([0xA1, 0x64]) + b"ipfs" + bytes([0x42, 0x32, 0xF1])
    assert _runtime_reach(bytes([0x00]) + metadata + len(metadata).to_bytes(2, "big")) is None  # never run
    # A tail that only looks like a size pointing at a map byte, no metadata key in it: all of it is code.
    assert _runtime_reach(bytes([0xA1, 0x32, 0x00, 0x00, 0x03])) == "origin"


def test_every_verdict_reports_how_it_is_allowed(monkeypatch):
    import services.logic.deployment as deployment

    class _Fn:
        view = pure = is_constructor = False
        solidity_signature = "f()"
        entry_point = object()
        name = "f"

    class _Contract:
        functions_entry_points = [_Fn()]
        state_variables: list = []

    class _Builds:
        def __init__(self, *args):
            pass

        def get(self, address):
            return _Contract()

        def code_address(self, address):
            return address

    conditional = Verdict("restricted", frozenset(), False, gaps=("conditional:unknown:x",), allowed="conditional")
    monkeypatch.setattr(deployment, "Builds", _Builds)
    monkeypatch.setattr(deployment, "IndexedChain", lambda *args, **kwargs: None)
    monkeypatch.setattr(deployment, "function_verdict", lambda *args, **kwargs: (conditional, None))
    out = deployment.deployment_verdicts(None, "0x" + "11" * 20, 1, "http://127.0.0.1:9", block=1)
    assert out["functions"]["f()"]["allowed"] == "conditional"
    undecided = Verdict("not_determined", frozenset(), False, gaps=("now_unknown",))
    monkeypatch.setattr(deployment, "function_verdict", lambda *args, **kwargs: (undecided, None))
    out = deployment.deployment_verdicts(None, "0x" + "11" * 20, 1, "http://127.0.0.1:9", block=1)
    assert out["functions"]["f()"]["allowed"] is None


def _guard_reads(monkeypatch, value):
    """Guard's ``originOk`` lowered wrongly, still reading the origin (so it is inlined): ``value`` of the origin."""
    from services.logic.lower import Lowerer
    from services.logic.terms import TRUE

    called = Lowerer.called

    def misread(self, function, args, view):
        if getattr(function, "name", None) == "originOk":
            return TRUE, (value,)
        return called(self, function, args, view)

    monkeypatch.setattr(Lowerer, "called", misread)


def test_inlined_code_letting_everyone_through_opens_nothing_the_chain_refuses(deployed, monkeypatch):
    # Mis-lowered as "any origin but address 1": a stranger passes on its word, and the chain refuses it.
    from services.logic.terms import ORIGIN, const, mk_cmp, mk_not

    clean = _verdict(deployed, "p9")
    _guard_reads(monkeypatch, mk_not(mk_cmp("eq", ORIGIN, const(1, "address"))))
    v = O.check(deployed, "C", "p9", _verdict(deployed, "p9"), samples=X, open_at=False)
    assert "inlined_callee:originOk()" in v.gaps
    O.never_bolder(clean, v)


def test_inlined_code_letting_nobody_through_is_never_a_complete_nobody(deployed, monkeypatch):
    # Mis-lowered as "the origin is address 1": nobody, on its word, while the chain lets the admin through.
    from services.logic.terms import ORIGIN, const, mk_cmp

    clean = _verdict(deployed, "p9")
    _guard_reads(monkeypatch, mk_cmp("eq", ORIGIN, const(1, "address")))
    v = O.check(deployed, "C", "p9", _verdict(deployed, "p9"), samples=X)
    assert not v.complete, v
    assert "inlined_callee:originOk()" in v.gaps
    O.never_bolder(clean, v)
