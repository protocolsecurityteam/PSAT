"""A callee sees the caller's ``tx.origin``, and the chain answers a call with this contract as the origin: a callee
whose code may read it is never taken at the chain's word. Followed, it is inlined with its own success condition;
otherwise the call stays an unknown named for why. Each against what the chain does on anvil."""

from __future__ import annotations

import pytest

from services.logic.decide import Chain, Verdict
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import rpc

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


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    guard = d.deploy("Guard", ("address",), (ADMIN,))
    d.deploy("C", ("address", "address"), (ADMIN, guard))
    return d


def _chain(d, flaky: tuple[int, int] | None = None) -> Chain:
    """``d``'s chain; ``flaky`` (address, slot): that storage word's first read fails as a node error."""
    block = int(rpc(d.url, "eth_blockNumber", []), 16)
    left = [1 if flaky else 0]

    def read(method, params):
        if left[0] and method == "eth_getStorageAt" and (int(params[0], 16), int(params[1], 16)) == flaky:
            left[0] -= 1
            raise RuntimeError("upstream timeout")
        return rpc(d.url, method, params)

    def batch(calls):
        out = []
        for method, params in calls:
            try:
                out.append(read(method, params))
            except RuntimeError:
                out.append(None)
        return out

    return Chain(read, block, batch)


def _verdict(d, name, followed=True, flaky=None) -> Verdict:
    from services.logic.terms import reset_terms

    reset_terms()
    contract = d.slither["C"]
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    contracts = d.contracts("C", "Guard") if followed else d.contracts("C")
    return function_verdict(contract, fn, d.at["C"], _chain(d, flaky), contracts)[0]


@pytest.mark.parametrize("name", ["p9", "p9r", "p9v", "q1", "q3", "q4"])
def test_a_followed_callee_checking_the_origin_lists_its_admin(deployed, name):
    verdict = _verdict(deployed, name)
    assert verdict.openness == "restricted" and verdict.complete
    assert verdict.principals == {ADMIN}


@pytest.mark.parametrize(("name", "signature"), [("p9", "originOk()"), ("q1", "capFor()"), ("p9e", "onlyEoa()")])
def test_code_not_followed_that_reads_the_origin_is_never_taken_at_the_chains_word(deployed, name, signature):
    verdict = _verdict(deployed, name, followed=False)
    assert verdict.openness == "not_determined"
    assert f"origin:{signature}" in verdict.gaps


def test_no_contract_is_a_transactions_origin(deployed):
    # tx.origin == msg.sender inside the guard: msg.sender is this contract, so nobody ever passes.
    verdict = _verdict(deployed, "p9e")
    assert verdict.openness == "restricted" and verdict.complete
    assert verdict.principals == set()


def test_an_unread_callee_address_is_a_gap_not_a_silent_skip(deployed):
    verdict = _verdict(deployed, "p9v", flaky=(deployed.at["C"], 1))
    assert verdict.openness == "not_determined"
    assert "read_failed:call_target:originVoid(uint256)" in verdict.gaps


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
