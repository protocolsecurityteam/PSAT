"""Governance shapes whose writes, events and enums the engine has to read right for a list to be whole or a gate to
be open: a legacy storage array's length raised in place or pushed through a storage pointer, a set whose remove
re-indexes the last member, an add whose success is merged apart from its event, an event a library declares, an
enum a contract declares under a file-level enum's name, a loop the arguments steer, and code past what is followed
reached only once a listed entry lets the caller in. Each verdict is checked against ``eth_call`` on anvil
(``_oracle.check``); the enum against the chain at each input (``_oracle.agrees``)."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

LEGACY = """
pragma solidity 0.4.19;

contract Checkpoints {
    struct Checkpoint { uint128 fromBlock; uint128 value; }
    mapping(address => Checkpoint[]) balances;
    mapping(address => address[]) lists;
    uint256 x;

    // MiniMe's ``updateValueAtNow``: the new checkpoint goes past the length, which the reference raises.
    function record(uint128 value) public {
        Checkpoint[] storage checkpoints = balances[msg.sender];
        Checkpoint storage next = checkpoints[checkpoints.length++];
        next.fromBlock = uint128(block.number);
        next.value = value;
    }

    // Lido's ``_addDelegatedAddressFor``: a storage pointer Slither renders as an array literal.
    function add(address to) public {
        address[] storage list = lists[to];
        list.push(msg.sender);
    }

    // Whoever has recorded a checkpoint: any caller, once its own ``record`` raised the length.
    function recorded() public { require(balances[msg.sender].length > 0); x = 1; }

    // Whoever a list names: any caller, once its own ``add`` pushed itself there.
    function listed() public { require(lists[msg.sender].length > 0); x = 2; }
}
"""

SHAPES = """
pragma solidity 0.8.27;

enum State { Unset, Normal, VetoSignalling }

library Registry {
    event Registered(address indexed who);

    function register(mapping(address => uint256) storage self, address who) internal {
        self[who] = 1;
        emit Registered(who);
    }
}

// OpenZeppelin's EnumerableSet, flattened: a remove moves the last member into the gap and re-indexes it there.
contract Committee {
    address owner;
    address[] values;
    mapping(address => uint256) positions;
    mapping(address => uint256) registered;
    uint256 x;
    event MemberAdded(address member);
    event MemberRemoved(address member);

    constructor() { owner = msg.sender; }

    function add(address[] calldata members) external {
        require(msg.sender == owner);
        for (uint256 i; i < members.length; ++i) {
            require(positions[members[i]] == 0);
            values.push(members[i]);
            positions[members[i]] = values.length;
            emit MemberAdded(members[i]);
        }
    }

    function remove(address member) external {
        require(msg.sender == owner);
        uint256 position = positions[member];
        require(position != 0);
        uint256 last = values.length - 1;
        if (position - 1 != last) {
            address moved = values[last];
            values[position - 1] = moved;
            positions[moved] = position;
        }
        values.pop();
        delete positions[member];
        emit MemberRemoved(member);
    }

    function register(address who) external {
        require(msg.sender == owner);
        Registry.register(registered, who);
    }

    function act() external { require(positions[msg.sender] != 0); x = 1; }
    function actRegistered() external { require(registered[msg.sender] == 1); x = 2; }
}

// Lido's ``HashConsensus._addMembers``: the set's ``add`` says whether it added, and the loop refuses a repeat.
contract Checked {
    address owner;
    address[] values;
    mapping(address => uint256) positions;
    uint256 x;
    event MemberAdded(address member);

    constructor() { owner = msg.sender; }

    function _add(address member) internal returns (bool) {
        if (positions[member] != 0) return false;
        values.push(member);
        positions[member] = values.length;
        return true;
    }

    function addAll(address[] calldata members) external {
        require(msg.sender == owner);
        for (uint256 i; i < members.length; ++i) {
            if (!_add(members[i])) revert();
            emit MemberAdded(members[i]);
        }
    }

    function act() external { require(positions[msg.sender] != 0); x = 1; }
}

// A contract's own enum under the file-level enum's name: its members, not the file's.
contract Escrow {
    enum State { NotInitialized, SignallingEscrow, RageQuitEscrow }
    function at(uint8 s) external pure { require(State(s) == State.RageQuitEscrow); }
    function file(uint8 s) external pure { require(uint8(s) == uint8(type(State).max)); }
}

// A proposal's calls, run by whoever asks: the loop turns on what is asked, never on who asks.
contract Uses {
    struct Call { address target; bytes data; }
    mapping(uint256 => Call[]) proposals;

    function run(uint256 id) external {
        Call[] storage calls = proposals[id];
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, ) = calls[i].target.call(calls[i].data);
            require(ok);
        }
    }
}

// Aragon's ACL: a permission's parameters are evaluated (recursively, past what the lowering follows) only for an
// entity holding it; an address no event names is refused before.
contract ACL {
    address owner;
    mapping(bytes32 => bool) permissions;
    event SetPermission(address indexed entity, bool allowed);

    constructor() { owner = msg.sender; }

    function grant(address who) external {
        require(msg.sender == owner);
        permissions[keccak256(abi.encode(who))] = true;
        emit SetPermission(who, true);
    }

    function hasPermission(address who) external view returns (bool) {
        if (!permissions[keccak256(abi.encode(who))]) return false;
        return _evalParams(who, 0);
    }

    function _evalParams(address who, uint256 depth) internal view returns (bool) {
        if (depth > 20) return who != address(0);
        return _evalParams(who, depth + 1);
    }
}

contract Gated {
    ACL acl;
    uint256 x;
    constructor(address a) { acl = ACL(a); }
    function act() external { require(acl.hasPermission(msg.sender)); x = 1; }
}
"""

A1, A2, A3 = O.ACCOUNTS[1], O.ACCOUNTS[2], O.ACCOUNTS[3]


def _setup_legacy(d):
    d.deploy("Checkpoints")


def _setup(d):
    for name in ("Committee", "Checked", "Escrow", "Uses", "ACL"):
        d.deploy(name)
    d.deploy("Gated", ("address",), (d.at["ACL"],))
    assert O.transact(d, "Committee", "add(address[])", ("address[]",), ([A1, A2, A3],))
    assert O.transact(d, "Committee", "remove(address)", ("address",), (A1,))  # A3 moves into A1's place
    assert O.transact(d, "Committee", "register(address)", ("address",), (A2,))
    assert O.transact(d, "Checked", "addAll(address[])", ("address[]",), ([A1, A2],))
    assert O.transact(d, "ACL", "grant(address)", ("address",), (A1,))


PROBES = [
    O.Probe(LEGACY, _setup_legacy, (("Checkpoints", "recorded", ()), ("Checkpoints", "listed", ())), "0.4.19"),
    O.Probe(
        SHAPES,
        _setup,
        (
            ("Committee", "act", ()),
            ("Committee", "actRegistered", ()),
            ("Checked", "act", ()),
            ("Uses", "run", ()),
            ("Gated", "act", ("ACL",)),
        ),
    ),
]


@pytest.fixture(scope="module")
def legacy(anvil):  # noqa: F811
    d = O.deployment(*anvil, LEGACY, "0.4.19")
    _setup_legacy(d)
    return d


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SHAPES)
    _setup(d)
    return d


def _record(d, who):
    assert O.transact(d, "Checkpoints", "record(uint128)", ("uint128",), (1,), who)


def _add(d, who):
    assert O.transact(d, "Checkpoints", "add(address)", ("address",), (who,), who)


@pytest.mark.parametrize(("name", "first"), [("recorded", _record), ("listed", _add)], ids=["length++", "push"])
def test_a_legacy_arrays_length_raised_in_place_or_pushed_is_written(legacy, name, first):
    # ``checkpoints.length++`` and ``list.push`` through a storage pointer write the length the gate reads: never
    # "nobody, ever"; no stranger passes as things stand, and each one passes once its own call made the entry.
    v = O.check(legacy, "Checkpoints", name, O.verdict(legacy, "Checkpoints", name), open_at=False)
    assert not O.nobody(v), v
    fn = O.function(legacy, "Checkpoints", name)
    for who in O.STRANGERS:
        with O.snapshot(legacy):
            first(legacy, who)
            assert O.passes(legacy, "Checkpoints", fn, sender=who)


@pytest.mark.xfail(strict=True, reason="G8: a stranger's own legacy length++/push first call is not found (after)")
@pytest.mark.parametrize(("name", "first"), [("recorded", _record), ("listed", _add)], ids=["length++", "push"])
def test_a_strangers_own_legacy_array_write_opens_what_it_unlocks(legacy, name, first):
    v = O.verdict(legacy, "Checkpoints", name)
    O.check(legacy, "Checkpoints", name, v, open_at={})
    assert v.openness == "open"


def test_a_member_a_remove_reindexes_is_listed_and_the_removed_one_is_not(d):
    # The remove moved A3 into A1's place: A3 is still one its add logged; A1 holds nothing now.
    v = O.check(d, "Committee", "act", O.verdict(d, "Committee", "act"), known=(A1, A2, A3))
    assert v.openness == "restricted" and set(v.principals) == {A2, A3}


def test_an_add_whose_success_merges_apart_from_its_event_is_still_a_whole_list(d):
    v = O.check(d, "Checked", "act", O.verdict(d, "Checked", "act"), known=(A1, A2, A3))
    assert v.openness == "restricted" and v.complete and set(v.principals) == {A1, A2}


def test_an_event_a_library_declares_lists_whom_the_contract_registered(d):
    v = O.check(d, "Committee", "actRegistered", O.verdict(d, "Committee", "actRegistered"), known=(A1, A2, A3))
    assert v.openness == "restricted" and v.complete and set(v.principals) == {A2}


@pytest.mark.parametrize("name", ["at", "file"])
def test_a_contracts_enum_under_a_file_level_enums_name_is_its_own(d, name):
    fn = O.function(d, "Escrow", name)
    for s in range(3):
        formula, engine = O.engine_says(d, fn, [s], "Escrow")
        O.agrees(formula, engine, O.chain_says(d, fn, [s], "Escrow"), (name, s))
        assert engine == (s == 2), (name, s, engine)


def test_a_loop_the_arguments_steer_singles_out_nobody(d):
    # Proposal 0 has no calls: anyone runs it.
    v = O.check(d, "Uses", "run", O.verdict(d, "Uses", "run"), open_at={"id": 0})
    assert v.openness == "open"


def test_code_past_what_is_followed_reached_only_once_a_listed_entry_lets_in_keeps_the_holder(d):
    # Only A1 holds the permission; the parameters are evaluated past what the lowering follows. A1's own call goes
    # through on the chain; no stranger's does.
    v = O.check(d, "Gated", "act", O.verdict(d, "Gated", "act", "ACL"), known=(A1, A2, A3), open_at=False)
    assert v.openness == "restricted" and A1 in v.principals
