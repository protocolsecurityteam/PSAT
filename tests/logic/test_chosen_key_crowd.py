"""A crowd of managers kept in namespaced storage, each at an id the caller picks (``ops[id].manager == msg.sender``),
every write logged with its id: the list is read entry by entry from storage. Each probe pairs that gate with
another entry point whose lowering used to lose track of its storage writes, which left every lookup of the contract
unproven to be logged and the managers unlisted (Lido's CSModule after its v3 upgrade):

* a storage pointer moved within a loop (``Op storage o = $.ops[ids[i]]``);
* a part of storage handed to an internal function on one branch of a loop body (the reference unset on the other);
* a ``continue`` in a loop whose body opens with a tuple declaration;
* an assembly ``sstore`` at a hash of 96 bytes chosen by branch (never a mapping's entry).

Every manager listed passes ``eth_call`` with its witness id (``_oracle.check``); a list said complete leaves out no
manager. With fewer reads than entries, the entries left unread are counted, exactly: listed and untested together
are all of them, none left undecided."""

from __future__ import annotations

import pytest

import services.logic.verdict as verdict_module
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

CROWD = 300

_COMMON = """
    struct Op { address manager; uint32 count; }
    struct Store { mapping(uint256 => Op) ops; uint256 n; }
    bytes32 constant LOC = 0x6c0757dc3e6b28b2580c03fd9e96c274acf4f99d91fbec9b418fa1d70604ff00;
    address admin;
    uint256 x;
    event OpAdded(uint256 indexed id, address manager);
    constructor() { admin = msg.sender; }
    function _s() internal pure returns (Store storage $) { assembly { $.slot := LOC } }
    function add(address[] calldata managers) external {
        require(msg.sender == admin);
        Store storage $ = _s();
        for (uint256 i; i < managers.length; i++) {
            uint256 id = $.n++;
            $.ops[id].manager = managers[i];
            emit OpAdded(id, managers[i]);
        }
    }
    function act(uint256 id) external { require(_s().ops[id].manager == msg.sender); x = id; }
"""

SOURCE = (
    """
pragma solidity 0.8.27;

contract Moved {"""
    + _COMMON
    + """
    function bump(uint256[] calldata ids) external {
        Store storage $ = _s();
        for (uint256 i; i < ids.length; i++) {
            Op storage o = $.ops[ids[i]];
            o.count += 1;
        }
    }
}

contract Handed {"""
    + _COMMON
    + """
    function _inc(Op storage o) internal { o.count += 1; }
    function bump(uint256[] calldata ids) external {
        Store storage $ = _s();
        for (uint256 i; i < ids.length; i++) {
            if (ids[i] % 2 == 0) _inc($.ops[ids[i]]);
        }
    }
}

contract Continued {"""
    + _COMMON
    + """
    function bump(uint256[] calldata ids) external {
        Store storage $ = _s();
        for (uint256 i; i < ids.length; i++) {
            (uint256 id, uint256 step) = (ids[i], ids[i] % 3);
            if (step == 0) continue;
            $.ops[id].count += uint32(step);
        }
    }
}

contract Keyed {"""
    + _COMMON
    + """
    bytes32 constant SEED = keccak256("keys");
    function save(uint256 id, uint256 index, bool first, uint256 word) external {
        require(msg.sender == admin);
        bytes32 at = first
            ? keccak256(abi.encodePacked(SEED, id, index))
            : keccak256(abi.encodePacked(SEED, id, index + 1));
        assembly { sstore(add(at, 1), word) }
    }
}
"""
)

CONTRACTS = ("Moved", "Handed", "Continued", "Keyed")


def manager(i: int) -> int:
    return 0x5EED0000000000000000000000000000000000 + i + 1


def _setup(d, crowd: int = CROWD):
    for name in CONTRACTS:
        d.deploy(name)
        managers = [O.hex20(manager(i)) for i in range(crowd)]
        assert O.transact(d, name, "add(address[])", ("address[]",), (managers,))


PROBES = [O.Probe(SOURCE, lambda d: _setup(d, 12), tuple((name, "act", ()) for name in CONTRACTS))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.mark.parametrize("name", CONTRACTS)
def test_every_manager_of_a_crowd_is_listed(d, name):
    v = O.check(d, name, "act", O.verdict(d, name, "act"), samples=({"id": 0}, {"id": 7}), known=(manager(CROWD),))
    assert v.openness == "restricted" and v.complete, v
    assert set(v.principals) == {manager(i) for i in range(CROWD)}
    assert v.witnesses[manager(7)] == {"id": 7}


@pytest.mark.parametrize("reads", (60, 400))
def test_entries_past_the_read_budget_are_counted_untested(d, monkeypatch, reads):
    monkeypatch.setattr(verdict_module, "READS_PER_FUNCTION", reads)
    v = O.check(d, "Moved", "act", O.verdict(d, "Moved", "act"), samples=({"id": 0},))
    assert v.openness == "restricted" and not v.complete, v
    untested = [int(g.split(":")[1]) for g in v.gaps if g.startswith("untested_candidates:")]
    assert len(untested) == 1, v.gaps
    truth = {manager(i) for i in range(CROWD)}
    assert set(v.principals) <= truth and v.principals
    # Every entry read is decided; every one left unread is counted: listed and untested are all of them.
    assert not v.undecided and len(set(v.principals)) + untested[0] == CROWD, v.gaps
