"""What the second pass on the core may never do: open a function on a failed read or a spent budget, set aside a
callee that reads ``tx.origin`` (the caller's in every callee), pass off "open on conditions" as open, or read a
memory word it lost track of as the same for everyone. Each against what the chain does on anvil."""

from __future__ import annotations

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """
pragma solidity 0.8.27;

contract Guard {
    address public admin;
    bool public flag;
    constructor(address a) { admin = a; }
    function ok(uint256 x) external view returns (bool) { x; return tx.origin == admin; }
    function okOr(uint256 x) external view returns (bool) { return tx.origin == admin || gasleft() == x; }
    function paused(uint256 x) external view returns (bool) { x; return true; }
    function flagged(uint256 x) external view returns (bool) { return flag && gasleft() > x; }
}

contract C {
    address admin;
    Guard guard;
    mapping(address => bool) isAdmin;
    uint256 total;
    constructor(address a, address g) { admin = a; guard = Guard(g); isAdmin[a] = true; }
    function viaOrigin(uint256 x) external { require(guard.ok(x)); total += x; }
    function viaOriginOr(uint256 x) external { require(guard.okOr(x)); total += x; }
    function viaPause(uint256 x) external { require(!guard.paused(x)); total += x; }
    function viaFlag(uint256 x) external { require(guard.flagged(x)); total += x; }
    function viaMem(uint256 x) external {
        address who;
        assembly { let p := mload(0x40) mstore(add(p, mul(x, 0)), caller()) who := mload(add(p, mul(x, 0))) }
        require(isAdmin[who]);
        total += 1;
    }
}
"""

ADMIN = 0xAB << 152 | int("ab" * 19, 16)


def _deployed(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    guard = d.deploy("Guard", ("address",), (ADMIN,))
    d.deploy("C", ("address", "address"), (ADMIN, guard))
    return d


def _chain(d, failing: int | None = None) -> Chain:
    """``d``'s chain, with every storage read of ``failing`` answered by a node error."""
    block = int(rpc(d.url, "eth_blockNumber", []), 16)

    def read(method, params):
        if failing is not None and method == "eth_getStorageAt" and int(params[0], 16) == failing:
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


def _verdict(d, name, followed=True, failing=None):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = d.slither["C"]
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    contracts = d.contracts("C", "Guard") if followed else d.contracts("C")
    return function_verdict(contract, fn, d.at["C"], _chain(d, failing), contracts)[0]


def test_a_failed_read_in_a_followed_callee_never_opens_it(anvil):  # noqa: F811
    d = _deployed(anvil)
    verdict = _verdict(d, "viaFlag", failing=d.at["Guard"])
    assert verdict.openness == "not_determined"
    assert "read_failed:storage:flag" in verdict.gaps
    assert _verdict(d, "viaFlag").openness == "restricted"  # read whole: nobody, the flag being unset


def test_a_spent_read_budget_never_opens_it(anvil, monkeypatch):  # noqa: F811
    import services.logic.verdict as verdict_module

    d = _deployed(anvil)
    monkeypatch.setattr(verdict_module, "READS_PER_FUNCTION", 1)
    assert _verdict(d, "viaFlag").openness == "not_determined"


def test_a_followed_callee_reading_the_origin_singles_out_its_admin(anvil):  # noqa: F811
    d = _deployed(anvil)
    verdict = _verdict(d, "viaOrigin")
    assert verdict.openness == "restricted" and verdict.complete
    assert verdict.principals == {ADMIN}
    assert _verdict(d, "viaOriginOr").openness != "open"


def test_an_unfollowed_callee_is_never_taken_free_of_the_origin(anvil):  # noqa: F811
    d = _deployed(anvil)
    for name, signature in (("viaOrigin", "ok(uint256)"), ("viaOriginOr", "okOr(uint256)")):
        verdict = _verdict(d, name, followed=False)
        assert verdict.openness == "not_determined"
        assert f"unfollowed:{signature}" in verdict.gaps


def test_open_on_an_unsettled_condition_is_never_plain_open(anvil):  # noqa: F811
    d = _deployed(anvil)
    verdict = _verdict(d, "viaPause", followed=False)  # paused() is always true: everyone reverts on the chain
    assert not (verdict.openness == "open" and verdict.allowed == "now")


def test_a_memory_word_lost_track_of_may_be_the_caller(anvil):  # noqa: F811
    d = _deployed(anvil)
    assert _verdict(d, "viaMem").openness == "not_determined"
