"""A followed callee's code that the lowering gets wrong never makes a verdict bolder than the chain allows. These
are natural mis-lowerings, no fault injected: a ``tx.origin`` read through a Solidity local declared twice and named
in assembly (lowered ``unknown:shadowed:o``, no ``origin`` term), a Yul ``call`` into code that always reverts read
as a success (A52), and a check made by a call in assembly whose outcome the lowering assumes. Each verdict is
checked against ``eth_call`` on anvil (``_oracle.check``): no stranger the chain refuses is let through, now or
later, and every holder listed passes from its own address."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = r"""
pragma solidity 0.8.27;

contract Rev {}

contract Guard {
    address public admin;
    constructor(address a) { admin = a; }
    // The origin through a local declared twice and read in assembly: its lowering shows no ``tx.origin``.
    function ok() external view returns (bool r) {
        { address o = address(0); o; }
        { address o = tx.origin; address ad = admin; assembly { r := eq(o, ad) } }
    }
}

// Lets through only an address whose low bit is set.
contract Odd {
    fallback() external { require(abi.decode(msg.data, (uint256)) & 1 == 1); }
}

contract Bits {
    address odd;
    constructor(address o) { odd = o; }
    // Refuses a caller ``Odd`` refuses, by a call in assembly: its lowering shows no use of ``who``.
    function check(address who) external view returns (bool) {
        address o = odd;
        assembly { mstore(0, who) let ok := staticcall(gas(), o, 0, 32, 0, 0) if iszero(ok) { revert(0, 0) } }
        return true;
    }
}

contract Supply {
    address admin;
    address rev;
    mapping(address => bool) controllers;
    constructor(address r) { admin = msg.sender; rev = r; }
    function addController(address who) external { require(msg.sender == admin); controllers[who] = true; }
    // An unlisted sender is refused by a call into code that always reverts (A52 reads it as a success).
    function canMint(address sender, uint256 amount) external {
        amount;
        if (!controllers[sender]) {
            address r = rev;
            assembly { let ok := call(gas(), r, 0, 0, 0, 0, 0) if iszero(ok) { revert(0, 0) } }
        }
    }
}

contract C {
    Guard guard;
    Bits bits;
    Supply supply;
    uint256 total;
    constructor(address g, address b, address s) { guard = Guard(g); bits = Bits(b); supply = Supply(s); }
    function shadowOrigin(uint256 x) external { x; require(guard.ok()); total += 1; }
    function lowBit(uint256 x) external { x; require(bits.check(msg.sender)); total += 1; }
    function mint(uint256 amount) external { supply.canMint(msg.sender, amount); total += amount; }
}
"""

ADMIN = O.ACCOUNTS[1]
CONTROLLER = O.ACCOUNTS[2]
SAMPLES = ({"x": 0, "amount": 0}, {"x": 1, "amount": 1})


def _setup(d):
    d.deploy("Rev")
    d.deploy("Guard", ("address",), (ADMIN,))
    d.deploy("Odd")
    d.deploy("Bits", ("address",), (d.at["Odd"],))
    d.deploy("Supply", ("address",), (d.at["Rev"],))
    d.deploy("C", ("address", "address", "address"), (d.at["Guard"], d.at["Bits"], d.at["Supply"]))
    assert O.transact(d, "Supply", "addController(address)", ("address",), (CONTROLLER,))


FOLLOWED = {"shadowOrigin": "Guard", "lowBit": "Bits", "mint": "Supply"}
PROBES = [O.Probe(SOURCE, _setup, tuple(("C", n, f) for n, c in FOLLOWED.items() for f in ((c,), ())))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _never_open(d, name, v):
    O.check(d, "C", name, v, samples=SAMPLES, open_at=False)
    assert v.openness != "open", v
    assert not O.nobody(v), v  # someone passes on the chain


@pytest.mark.parametrize("followed", [True, False])
def test_an_origin_read_the_lowering_misses_is_never_open(d, followed):
    # Only the admin, as the transaction's origin, passes. The lowering of ``ok`` shows no ``tx.origin``: its runtime
    # code's ``ORIGIN`` opcode still keeps the call from being read as the same for every caller.
    v = O.verdict(d, "C", "shadowOrigin", *(("Guard",) if followed else ()))
    _never_open(d, "shadowOrigin", v)
    assert O.passes(d, "C", O.function(d, "C", "shadowOrigin"), {"x": 0}, sender=ADMIN)
    assert "origin:ok()" in v.gaps


@pytest.mark.parametrize("followed", [True, False])
def test_a_callee_whose_code_reads_the_caller_alike_is_open_only_if_every_stranger_passes(d, followed):
    # ``check(msg.sender)`` refuses a caller whose low bit is clear; lowered, the call in assembly assumed to succeed,
    # it lets everyone through, reading the caller it is handed alike for all. That rests on the code alone: open
    # only once every stranger's own call goes through on the chain, and one of them does not.
    v = O.verdict(d, "C", "lowBit", *(("Bits",) if followed else ()))
    _never_open(d, "lowBit", v)
    assert O.strangers_passing(d, "C", O.function(d, "C", "lowBit"), {"x": 0}) == {True, False}
    if followed:
        assert "callee_unsingled:check(address)" in v.gaps
