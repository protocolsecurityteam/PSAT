"""A ``when`` condition is read as it stands ("latched") only when nothing can flip it, and "no code at an address"
only where no code can ever come to be: this contract, or a precompile. A constant or an immutable with no code now
may be where a contract is created later (an address worked out in advance), and a target read from storage (or a
write around or within what a condition reads: a whole struct over the field it checks, an item pushed onto an array
it reads whole) may change: never latched, so a closed condition is never "nobody, ever", and whoever passes once it
opens is still named. A slot no entry point writes is fixed only where no delegatecall of the contract's own and no
proxy in front of it can write it (``verdict._delegating``).

Each probe is deployed on anvil. A holder the verdict names on a condition closed now is confirmed by ``eth_call``
once the condition is opened for real: the owner's write, a stranger's loop, a delegatecall into code that writes
the slot, or code coming to be at the address (``anvil_setCode``, standing in for a contract created there later).
"Nobody, ever" is refuted by nobody, whatever an entry point does."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

interface IPing { function ping() external view returns (uint256); }

contract Ping {
    function ping() external pure returns (uint256) { return 1; }
}

contract C {
    struct Config { bool live; uint64 version; }
    struct Route { address target; uint64 version; }

    address owner;
    Config config;
    uint256 count;
    address[] list;
    address target;
    address[] targets;
    address constant NOWHERE = address(0xdead);
    address fixedAtDeploy;
    mapping(uint256 => bool) flags;
    Route route;
    address fixedPrecompile;
    address immutable gate;

    constructor() {
        owner = msg.sender; fixedAtDeploy = address(0xbeef); fixedPrecompile = address(4); gate = address(0xfeed);
    }

    function setConfig(bool live) external { require(msg.sender == owner); config = Config(live, 1); }
    function add(address item) external { require(msg.sender == owner); list.push(item); }
    function setTarget(address t) external { require(msg.sender == owner); target = t; }
    function addTarget(address t) external { require(msg.sender == owner); targets.push(t); }

    function act() external { require(msg.sender == owner); require(config.live); count += 1; }
    function actOnList() external {
        require(msg.sender == owner);
        address[] memory items = list;
        require(items.length > 0);
        count += 1;
    }
    function pinged() external { require(msg.sender == owner); count += IPing(target).ping(); }
    function pingedEach() external {
        require(msg.sender == owner);
        address[] memory all = targets;
        for (uint256 i; i < all.length; i++) count += IPing(all[i]).ping();
    }
    function setFlags(uint256 n) external { for (uint256 i; i < n; i++) { if (i == 5) flags[0] = true; } }
    function flagged() external { require(msg.sender == owner); require(flags[0]); count += 1; }
    function pingedStored() external { require(msg.sender == owner); count += IPing(fixedAtDeploy).ping(); }
    function codedStored() external {
        require(msg.sender == owner);
        require(fixedPrecompile.code.length > 0);
        count += 1;
    }
    function pingedNowhere() external { require(msg.sender == owner); count += IPing(NOWHERE).ping(); }
    function codedNowhere() external { require(msg.sender == owner); require(NOWHERE.code.length > 0); count += 1; }
    function pingedImmutable() external { require(msg.sender == owner); count += IPing(gate).ping(); }
    function setRoute(address t) external { require(msg.sender == owner); route = Route(t, 1); }
    function pingedRoute() external { require(msg.sender == owner); count += IPing(route.target).ping(); }
    // The identity precompile: no contract is ever created there.
    function codedPrecompile() external {
        require(msg.sender == owner);
        require(address(4).code.length > 0);
        count += 1;
    }
}

// The same contract with an owner-only delegatecall into code the owner names: any slot may be written.
contract CD is C {
    function exec(address t, bytes calldata d) external {
        require(msg.sender == owner);
        (bool ok,) = t.delegatecall(d);
        require(ok);
    }
}

// Code an owner's ``exec`` may run: it writes the slots no entry point of ``C`` writes.
contract Setter is C {
    function set(address p) external { fixedAtDeploy = p; fixedPrecompile = p; }
}
"""
OWNER = O.OWNER


def _setup(d):
    d.deploy("C")
    d.deploy("CD")
    d.deploy("Ping")
    d.deploy("Setter")


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        tuple(
            (c, f, ("Ping",))
            for c in ("C", "CD")
            for f in (
                "act",
                "actOnList",
                "pinged",
                "pingedEach",
                "flagged",
                "pingedStored",
                "codedStored",
                "pingedNowhere",
                "codedNowhere",
                "pingedImmutable",
                "pingedRoute",
                "codedPrecompile",
            )
        ),  # fmt: skip
    )
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _owner(d, contract, signature, types=(), values=()):
    assert O.transact(d, contract, signature, types, values)


def _code_at(address):
    def put(d):
        code = O.rpc(d.url, "eth_getCode", [O.hex20(d.at["Ping"]), "latest"])
        O.rpc(d.url, "anvil_setCode", [O.hex20(address), code])

    return put


def _latched(d, contract, name, holders_after=None):
    v = O.verdict(d, contract, name, "Ping")
    O.check(d, contract, name, v, open_at=False, holders_after=holders_after)
    return v


@pytest.mark.parametrize("contract", ["C", "CD"])
def test_a_field_written_by_a_whole_struct_write_is_not_latched(d, contract):
    # ``config.live`` false: closed now, reopened by ``setConfig(true)``.
    v = _latched(d, contract, "act", lambda d: _owner(d, contract, "setConfig(bool)", ("bool",), (True,)))
    assert v.openness == "restricted" and set(v.principals) == {OWNER} and not O.nobody(v)


@pytest.mark.parametrize("contract", ["C", "CD"])
def test_an_array_read_whole_and_pushed_onto_is_not_latched(d, contract):
    v = _latched(d, contract, "actOnList", lambda d: _owner(d, contract, "add(address)", ("address",), (1,)))
    assert v.openness == "restricted" and set(v.principals) == {OWNER}


def test_a_codeless_target_read_from_writable_storage_is_not_latched(d):
    # ``target`` is zero now (no code: every call reverts), but the owner can point it at code.
    ping = d.at["Ping"]
    v = _latched(d, "C", "pinged", lambda d: _owner(d, "C", "setTarget(address)", ("address",), (ping,)))
    assert set(v.principals) == {OWNER}
    # A field a whole struct write sets.
    v = _latched(d, "C", "pingedRoute", lambda d: _owner(d, "C", "setRoute(address)", ("address",), (ping,)))
    assert set(v.principals) == {OWNER}


def test_a_codeless_item_of_a_stored_list_is_not_latched(d):
    # 0xbeef in the list has no code now; a contract created there later lets the owner through.
    with O.snapshot(d):
        _owner(d, "C", "addTarget(address)", ("address",), (0xBEEF,))
        v = _latched(d, "C", "pingedEach", _code_at(0xBEEF))
        assert set(v.principals) == {OWNER}


@pytest.mark.parametrize("contract", ["C", "CD"])
def test_a_codeless_target_in_storage_no_entry_point_writes_is_not_latched(d, contract):
    # 0xbeef, in a slot nothing of ``C`` writes: not a precompile, so code may come to be there either way.
    v = _latched(d, contract, "pingedStored", _code_at(0xBEEF))
    assert not O.nobody(v)


def test_a_precompile_in_a_slot_nothing_can_write_is_latched(d):
    # No entry point writes ``fixedPrecompile``, ``C`` makes no delegatecall and runs at its own address: the slot
    # is fixed, and no code is ever created at a precompile. Nobody, ever, as on the chain.
    v = _latched(d, "C", "codedStored")
    assert O.nobody(v)


def test_a_precompile_in_a_slot_a_delegatecall_can_write_is_never_nobody_ever(d):
    # ``CD``'s owner can delegatecall code that points the slot elsewhere: never "nobody, ever".
    ping, setter = d.at["Ping"], d.at["Setter"]
    data = O.calldata(O.function(d, "Setter", "set"), {"p": ping})
    v = O.verdict(d, "CD", "codedStored", "Ping")
    assert not O.nobody(v), v
    with O.snapshot(d):
        _owner(d, "CD", "exec(address,bytes)", ("address", "bytes"), (setter, data))
        assert O.passes(d, "CD", O.function(d, "CD", "codedStored"), sender=OWNER)
        O.check(d, "CD", "codedStored", O.verdict(d, "CD", "codedStored", "Ping"))


@pytest.mark.parametrize("contract", ["C", "CD"])
def test_a_flag_only_a_later_loop_iteration_sets_is_not_latched(d, contract):
    # ``setFlags(6)`` sets it in its sixth iteration, whoever calls.
    v = _latched(
        d,
        contract,
        "flagged",
        lambda d: O.transact(d, contract, "setFlags(uint256)", ("uint256",), (6,), O.STRANGERS[0]),
    )
    assert not O.nobody(v)


@pytest.mark.parametrize("name", ["pingedNowhere", "codedNowhere"])
def test_a_codeless_constant_target_is_how_the_condition_reads_now(d, name):
    # No code at a constant now: code may be created there later, and the owner passes then.
    v = _latched(d, "C", name, _code_at(0xDEAD))
    assert not O.nobody(v) and set(v.principals) == {OWNER}


def test_a_codeless_immutable_target_is_never_latched(d):
    # Whose immutable it is and what it holds are set at deployment: an address with no code now is no more fixed
    # than a constant.
    v = _latched(d, "C", "pingedImmutable", _code_at(0xFEED))
    assert not O.nobody(v) and set(v.principals) | set(v.conditions) == {OWNER}


@pytest.mark.parametrize("contract", ["C", "CD"])
def test_no_code_at_a_precompile_stays_latched(d, contract):
    v = _latched(d, contract, "codedPrecompile")  # no contract is ever created there: nobody, ever
    assert O.nobody(v)
