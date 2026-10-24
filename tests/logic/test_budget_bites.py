"""Probes where a budget constant the fail-safe sweep sets small has something to cut (``test_failsafe``'s vacuity
guard asks each fault to change some verdict): managers kept per id with only the id logged (``_STORED_ROWS``; their
list was "nobody, ever" while the managers pass, since a write logging its key but not its value was read as listing
both), owners kept as a sentinel-linked list (``_WALK_STEPS``), the stranger's own first call being the last of three
writers (``_PRIOR_WRITERS``), and a callee's answer over two inputs refuting everyone but the owner
(``_CHAIN_ROUNDS``). Each clean verdict is checked against ``eth_call`` on anvil (``_oracle.check``)."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

// Each id's manager, set by the admin, logged by id only: who manages is read from storage, id by id.
contract Managed {
    address admin;
    mapping(uint256 => address) managers;
    uint256 x;
    event ManagerSet(uint256 indexed id);
    constructor() { admin = msg.sender; }
    function setManager(uint256 id, address who) external {
        require(msg.sender == admin);
        managers[id] = who;
        emit ManagerSet(id);
    }
    function act(uint256 id) external { require(managers[id] == msg.sender); x = id; }
}

// Gnosis Safe's owners: a list linked from a sentinel.
contract Owners {
    address constant SENTINEL = address(1);
    mapping(address => address) next;
    uint256 x;
    constructor(address[] memory list) {
        address cur = SENTINEL;
        for (uint256 i; i < list.length; i++) { next[cur] = list[i]; cur = list[i]; }
        next[cur] = SENTINEL;
    }
    function act() external { require(msg.sender != SENTINEL && next[msg.sender] != address(0)); x = 1; }
}

// Several open writers of the caller's entry; only the last leaves what the gate asks (a first call is arranged).
contract Steps {
    mapping(address => uint256) stage;
    uint256 x;
    function w1() external { stage[msg.sender] = 2; }
    function w2() external { stage[msg.sender] = 3; }
    function w4() external { stage[msg.sender] = 1; }
    function act() external { require(stage[msg.sender] == 1); x = 1; }
}

// Lido's delegation: ``unassign`` opens once the stranger's own ``assign`` ran, the last of three writers.
contract Delegation {
    mapping(address => address) delegates;
    mapping(address => address[]) delegated;
    uint256 x;
    function clear() external { delete delegates[msg.sender]; }
    function park(address d) external { require(d != address(0)); delegates[msg.sender] = d; }
    function assign(address d) external {
        require(d != address(0) && d != msg.sender && delegates[msg.sender] == address(0));
        delegates[msg.sender] = d;
        delegated[d].push(msg.sender);
    }
    function unassign() external {
        address d = delegates[msg.sender];
        require(d != address(0));
        address[] storage list = delegated[d];
        require(list[list.length - 1] == msg.sender);
        list.pop();
        delete delegates[msg.sender];
        x = 1;
    }
}

contract Flags {
    bool on;
    function flagged(bool b) external view returns (bool) { return b && on; }
}

// Nobody but the owner, ever: ``flagged`` answers false at both of its inputs, as the chain says.
contract Flagged {
    address owner;
    Flags flags;
    uint256 x;
    constructor(address f) { owner = msg.sender; flags = Flags(f); }
    function act(bool b) external { require(flags.flagged(b) || msg.sender == owner); x = 1; }
}
"""

A1, A2, A3 = O.ACCOUNTS[1], O.ACCOUNTS[2], O.ACCOUNTS[3]


def _setup(d):
    d.deploy("Managed")
    for id_, who in ((1, A1), (2, A1), (3, A2)):
        assert O.transact(d, "Managed", "setManager(uint256,address)", ("uint256", "address"), (id_, who))
    d.deploy("Owners", ("address[]",), ([O.hex20(a) for a in (A1, A2, A3)],))
    d.deploy("Steps")
    d.deploy("Delegation")
    d.deploy("Flags")
    d.deploy("Flagged", ("address",), (d.at["Flags"],))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        (
            ("Managed", "act", ()),
            ("Owners", "act", ()),
            ("Steps", "act", ()),
            ("Delegation", "unassign", ()),
            ("Flagged", "act", ("Flags",)),
        ),
    )
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_managers_stored_by_id_are_listed_with_the_ids_they_manage(d):
    v = O.check(d, "Managed", "act", O.verdict(d, "Managed", "act"), samples=({"id": 1}, {"id": 3}), known=(A3,))
    assert v.openness == "restricted" and set(v.principals) == {A1, A2}


def test_owners_linked_from_a_sentinel_are_listed(d):
    v = O.check(d, "Owners", "act", O.verdict(d, "Owners", "act"), known=(A1, A2, A3))
    assert v.openness == "restricted" and set(v.principals) == {A1, A2, A3}


def test_an_entry_the_strangers_own_call_sets_is_open_to_it(d):
    def staged(d, who):
        assert O.transact(d, "Steps", "w4()", sender=who)

    v = O.check(d, "Steps", "act", O.verdict(d, "Steps", "act"), arrange=staged, open_at={})
    assert v.openness == "open"


def test_the_last_of_several_writers_is_the_strangers_own_first_call(d):
    v = O.check(d, "Delegation", "unassign", O.verdict(d, "Delegation", "unassign"))
    assert v.openness == "open" and [s for s, _ in v.after] == ["assign(address)"]


def test_a_callee_answer_over_two_inputs_refutes_everyone_but_the_owner(d):
    samples = ({"b": False}, {"b": True})
    v = O.check(d, "Flagged", "act", O.verdict(d, "Flagged", "act", "Flags"), samples=samples, known=(A1, A2, A3))
    assert v.openness == "restricted" and O.OWNER in v.principals
