"""Balances only an owner credits are no stranger's to arrange. A stranger's own entry is zero, so a write counts as
bringing it about only where it can leave a zero entry nonzero (``verdict._arrangeable``): a checked decrement of the
caller's own balance (``bal[msg.sender] -= a``) reverts below zero or leaves zero, while an unchecked one (an
``unchecked`` block, or solc before 0.8) wraps into a grant. And a condition on an argument alone (``a > 0``) is never
set aside on its own while the same argument is chosen to meet the rest (``bal >= a`` with ``a = 0``,
``decide._jointly_freed``). Each verdict is checked against ``eth_call`` on anvil (``_oracle.check``): where no
stranger can pass, never "open now"; where one can, by the calls it makes first, it is one of those."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

// Every decrementing withdrawal together (the probe's SRC): none of them can credit a stranger.
contract Bank {
    address owner;
    mapping(address => uint256) bal;
    mapping(address => uint256) claimable;
    uint256 public total;
    constructor() { owner = msg.sender; }
    function credit(address w, uint256 a) external { require(msg.sender == owner); bal[w] += a; }
    function grant(address w, uint256 a) external { require(msg.sender == owner); claimable[w] += a; }
    function withdraw(uint256 a) external { require(a > 0 && bal[msg.sender] >= a); bal[msg.sender] -= a; }
    function withdrawRev(uint256 a) external { require(bal[msg.sender] >= a && a > 0); bal[msg.sender] -= a; }
    function withdrawNe(uint256 a) external { require(a != 0); require(bal[msg.sender] >= a); bal[msg.sender] -= a; }
    function withdrawGt(uint256 a) external { require(a > 0 && bal[msg.sender] > a); bal[msg.sender] -= a; }
    function withdrawHalf(uint256 a) external { require(a >= 2 && bal[msg.sender] >= a); bal[msg.sender] -= a / 2; }
    function withdrawAll() external { uint256 b = bal[msg.sender]; require(b > 0); bal[msg.sender] = 0; total += b; }
    // The vesting shape.
    function claim(uint256 amount) external {
        require(amount > 0 && claimable[msg.sender] >= amount);
        claimable[msg.sender] -= amount;
        total += amount;
    }
}

// SRC2 and SRC3: one withdrawal each.
contract BankAll {
    address owner;
    mapping(address => uint256) bal;
    uint256 public total;
    constructor() { owner = msg.sender; }
    function credit(address w, uint256 a) external { require(msg.sender == owner); bal[w] += a; }
    function withdrawAll() external { uint256 b = bal[msg.sender]; require(b > 0); bal[msg.sender] = 0; total += b; }
}

contract BankRev {
    address owner;
    mapping(address => uint256) bal;
    constructor() { owner = msg.sender; }
    function credit(address w, uint256 a) external { require(msg.sender == owner); bal[w] += a; }
    function withdraw(uint256 a) external { require(bal[msg.sender] >= a && a > 0); bal[msg.sender] -= a; }
}

// An unchecked decrement guarded by the balance still leaves zero; one unguarded wraps a stranger's zero into a
// balance: anyone burning first passes.
contract Wrap {
    address owner;
    mapping(address => uint256) bal;
    constructor() { owner = msg.sender; }
    function credit(address w, uint256 a) external { require(msg.sender == owner); bal[w] += a; }
    function burnSafe(uint256 a) external { require(bal[msg.sender] >= a); unchecked { bal[msg.sender] -= a; } }
    function withdraw(uint256 a) external { require(a > 0 && bal[msg.sender] >= a); bal[msg.sender] -= a; }
}

contract WrapOpen {
    address owner;
    mapping(address => uint256) bal;
    constructor() { owner = msg.sender; }
    function credit(address w, uint256 a) external { require(msg.sender == owner); bal[w] += a; }
    function burn(uint256 a) external { unchecked { bal[msg.sender] -= a; } }
    function withdraw(uint256 a) external { require(a > 0 && bal[msg.sender] >= a); bal[msg.sender] -= a; }
}
"""

# Before 0.8 arithmetic wraps: the same unguarded decrement is a grant, the guarded one is not.
OLD = """
pragma solidity 0.7.1;

contract Old {
    address owner;
    mapping(address => uint256) bal;
    constructor() { owner = msg.sender; }
    function credit(address w, uint256 a) external { require(msg.sender == owner); bal[w] += a; }
    function withdraw(uint256 a) external { require(a > 0 && bal[msg.sender] >= a); bal[msg.sender] -= a; }
}

contract OldBurn {
    address owner;
    mapping(address => uint256) bal;
    constructor() { owner = msg.sender; }
    function credit(address w, uint256 a) external { require(msg.sender == owner); bal[w] += a; }
    function burn(uint256 a) external { bal[msg.sender] -= a; }
    function withdraw(uint256 a) external { require(a > 0 && bal[msg.sender] >= a); bal[msg.sender] -= a; }
}
"""

HOLDER = O.ACCOUNTS[2]
CLOSED = {
    "Bank": ("withdraw", "withdrawRev", "withdrawNe", "withdrawGt", "withdrawHalf", "withdrawAll", "claim"),
    "BankAll": ("withdrawAll",),
    "BankRev": ("withdraw",),
    "Wrap": ("withdraw",),
}
SAMPLES = ({"a": 1, "amount": 1}, {"a": 2, "amount": 2}, {"a": 0, "amount": 0})


def _setup(d):
    for name in ("Bank", "BankAll", "BankRev", "Wrap", "WrapOpen"):
        d.deploy(name)
        assert O.transact(d, name, "credit(address,uint256)", ("address", "uint256"), (HOLDER, 10))
    assert O.transact(d, "Bank", "grant(address,uint256)", ("address", "uint256"), (HOLDER, 10))


def _setup_old(d):
    for name in ("Old", "OldBurn"):
        d.deploy(name)
        assert O.transact(d, name, "credit(address,uint256)", ("address", "uint256"), (HOLDER, 10))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        tuple((c, n, ()) for c, names in CLOSED.items() for n in names) + (("WrapOpen", "withdraw", ()),),
    ),
    O.Probe(OLD, _setup_old, (("Old", "withdraw", ()), ("OldBurn", "withdraw", ())), version="0.7.1"),
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.fixture(scope="module")
def old(anvil):  # noqa: F811
    d = O.deployment(*anvil, OLD, "0.7.1")
    _setup_old(d)
    return d


def _samples(d, contract, name):
    params = {p.name for p in O.function(d, contract, name).parameters}
    return tuple({k: v for k, v in s.items() if k in params} for s in SAMPLES)


@pytest.mark.parametrize(("contract", "name"), [(c, n) for c, names in CLOSED.items() for n in names])
def test_an_owner_credited_balance_is_no_strangers_to_arrange(d, contract, name):
    v = O.verdict(d, contract, name)
    O.check(d, contract, name, v, open_at=False, samples=_samples(d, contract, name))
    assert v.openness != "open", v


def test_an_unchecked_decrement_wraps_into_a_balance_anyone_can_make(d):
    v = O.verdict(d, "WrapOpen", "withdraw")
    O.check(d, "WrapOpen", "withdraw", v, samples=_samples(d, "WrapOpen", "withdraw"))
    # Every stranger burning first passes: open, after that call of its own.
    assert v.openness == "open" and [s for s, _ in v.after] == ["burn(uint256)"], v
    with O.snapshot(d):
        fn = O.function(d, "WrapOpen", "burn")
        for who in O.STRANGERS:
            assert O.transact_data(d, "WrapOpen", O.calldata(fn, {"a": 1}), who)
        assert O.strangers_passing(d, "WrapOpen", O.function(d, "WrapOpen", "withdraw"), {"a": 1}) == {True}


def test_before_0_8_a_guarded_decrement_is_no_grant(old):
    v = O.verdict(old, "Old", "withdraw")
    O.check(old, "Old", "withdraw", v, open_at=False, samples=({"a": 1}, {"a": 0}))
    assert v.openness != "open", v


def test_before_0_8_an_unguarded_decrement_wraps_into_a_grant(old):
    v = O.verdict(old, "OldBurn", "withdraw")
    O.check(old, "OldBurn", "withdraw", v, samples=({"a": 1},))
    assert v.openness == "open" and [s for s, _ in v.after] == ["burn(uint256)"], v
