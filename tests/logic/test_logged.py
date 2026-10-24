"""A lookup is listed whole by its events only when every write that can set an entry logs the entry's keys. Each
probe is deployed on anvil, its entries written by real transactions, and each verdict checked against ``eth_call``
(``_oracle.check``): a complete list leaves out nobody who passes, an unlogged write leaves it partial."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

H1, H2, H3 = O.ACCOUNTS[1:4]
DEAD = 0xDEAD
DATA = b"\x12\x34"

SOURCE = """
pragma solidity 0.8.27;

contract L {
    address owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    mapping(address => bytes32) roles;
    mapping(address => bool) silent;
    mapping(address => bool) elsewhere;
    mapping(bytes32 => uint256) scheduled;
    mapping(bytes32 => uint256) byId;
    event RoleSet(address indexed who, uint8 role, bool on);
    event Marked(address who);
    event Scheduled(bytes32 indexed id, address caller, bytes data);
    event Queued(bytes32 indexed id);
    event RawSet(address indexed holder, uint256 role);

    // solmate ``RolesAuthority``: a bitmask, set and cleared, logged either way.
    function setRole(address who, uint8 role, bool on) external onlyOwner {
        if (on) roles[who] |= bytes32(uint256(1) << role);
        else roles[who] &= ~bytes32(uint256(1) << role);
        emit RoleSet(who, role, on);
    }

    // Clearing needs no event: whoever it drops stays listed, and is asked about for nothing.
    function dropAll(address who) external onlyOwner { delete roles[who]; }

    function setSilent(address who) external onlyOwner { silent[who] = true; }

    // The event is on the other branch from the write.
    function setElsewhere(address who, bool on) external onlyOwner {
        if (on) elsewhere[who] = true;
        else emit Marked(who);
    }

    // OpenZeppelin ``AccessManager.schedule``: keyed by a hash of who scheduled it, logged with its parts.
    function schedule(bytes calldata data) external onlyOwner {
        scheduled[keccak256(abi.encode(msg.sender, data))] = block.timestamp;
        emit Scheduled(keccak256(abi.encode(msg.sender, data)), msg.sender, data);
    }

    // Logged by the hash alone: the id is listed, never who it stands for.
    function queue(bytes calldata data) external onlyOwner {
        byId[keccak256(abi.encode(msg.sender, data))] = block.timestamp;
        emit Queued(keccak256(abi.encode(msg.sender, data)));
    }

    // Solady-style roles: a raw slot hashed from a seed, the role and the holder.
    function setRaw(address holder, uint256 role) external onlyOwner {
        assembly {
            let free := mload(0x40)
            mstore(0x00, 0x1234)
            mstore(0x20, role)
            mstore(0x40, holder)
            sstore(keccak256(0x00, 0x60), 1)
            mstore(0x40, free)
        }
        emit RawSet(holder, role);
    }

    function hasRaw(uint256 role) external view {
        uint256 held;
        assembly {
            let free := mload(0x40)
            mstore(0x00, 0x1234)
            mstore(0x20, role)
            mstore(0x40, caller())
            held := sload(keccak256(0x00, 0x60))
            mstore(0x40, free)
        }
        require(held != 0);
    }

    function gated() external view { require(roles[msg.sender] & bytes32(uint256(1)) != 0); }
    function gatedSilent() external view { require(silent[msg.sender]); }
    function gatedElsewhere() external view { require(elsewhere[msg.sender]); }
    function gatedScheduled(bytes calldata data) external view {
        require(scheduled[keccak256(abi.encode(msg.sender, data))] != 0);
    }
    function gatedById(bytes calldata data) external view {
        require(byId[keccak256(abi.encode(msg.sender, data))] != 0);
    }
}
"""


SHADOWED = """
pragma solidity 0.8.27;

contract Shadowed {
    mapping(address => bool) members;
    event Added(address who);

    function add(address who) external {
        require(msg.sender == address(0xdead));
        members[who] = true;
        emit Added(who);
    }

    function isMember() external view { require(members[msg.sender]); }

    // The same entry, written by assembly where the compiler keeps it, and logged by nothing.
    function slip(address who) external {
        require(msg.sender == address(0xdead));
        assembly {
            mstore(0x00, who)
            mstore(0x20, members.slot)
            sstore(keccak256(0x00, 0x40), 1)
        }
    }
}
"""


NOTED = """
pragma solidity 0.8.27;

contract Noted {
    mapping(address => uint256) wards;

    // MakerDAO's ``note``: an anonymous event written in assembly, the selector and the arguments as its topics.
    modifier note() {
        _;
        assembly {
            let mark := mload(0x40)
            log4(mark, 0, shl(224, shr(224, calldataload(0))), calldataload(4), calldataload(36), calldataload(68))
        }
    }

    modifier auth() {
        require(wards[msg.sender] == 1);
        _;
    }

    constructor(address a) { wards[a] = 1; }

    function rely(address usr) external note auth { wards[usr] = 1; }
    function deny(address usr) external note auth { wards[usr] = 0; }
}
"""


def _setup(d):
    d.deploy("L")
    t = O.transact
    assert t(d, "L", "setRole(address,uint8,bool)", ("address", "uint8", "bool"), (H1, 0, True))
    assert t(d, "L", "setRole(address,uint8,bool)", ("address", "uint8", "bool"), (H2, 0, True))
    assert t(d, "L", "setRole(address,uint8,bool)", ("address", "uint8", "bool"), (H2, 0, False))
    assert t(d, "L", "setSilent(address)", ("address",), (H1,))
    assert t(d, "L", "setElsewhere(address,bool)", ("address", "bool"), (H1, True))
    assert t(d, "L", "schedule(bytes)", ("bytes",), (DATA,))
    assert t(d, "L", "queue(bytes)", ("bytes",), (DATA,))
    assert t(d, "L", "setRaw(address,uint256)", ("address", "uint256"), (H3, 7))
    d.deploy("Shadowed")
    assert t(d, "Shadowed", "add(address)", ("address",), (H1,), sender=DEAD)
    assert t(d, "Shadowed", "slip(address)", ("address",), (H2,), sender=DEAD)
    d.deploy("Noted", ("address",), (O.OWNER,))
    assert t(d, "Noted", "rely(address)", ("address",), (H1,))


PROBES = [
    O.Probe(
        SOURCE + SHADOWED.split("\n", 2)[2] + NOTED.split("\n", 2)[2],
        _setup,
        (("L", "gated", ()), ("L", "gatedSilent", ()), ("L", "gatedElsewhere", ()), ("L", "gatedScheduled", ()),
         ("L", "gatedById", ()), ("L", "hasRaw", ()), ("Shadowed", "isMember", ()), ("Noted", "rely", ())),
    )
]  # fmt: skip


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, PROBES[0].source)
    _setup(d)
    return d


def test_a_bitmask_set_and_cleared_under_one_event_is_listed(d):
    v = O.check(d, "L", "gated", O.verdict(d, "L", "gated"))
    assert v.complete and set(v.principals) == {H1}  # H2's role was set and cleared, both logged


def test_a_write_no_event_names_is_not_listed(d):
    v = O.check(d, "L", "gatedSilent", O.verdict(d, "L", "gatedSilent"))
    assert v.openness == "restricted" and not v.complete
    assert O.passes(d, "L", O.function(d, "L", "gatedSilent"), sender=H1)


def test_an_event_on_another_path_than_the_write_does_not_list_it(d):
    v = O.check(d, "L", "gatedElsewhere", O.verdict(d, "L", "gatedElsewhere"))
    assert v.openness == "restricted" and not v.complete


def test_a_key_hashed_from_the_caller_is_listed_by_an_event_that_names_its_parts(d):
    v = O.check(d, "L", "gatedScheduled", O.verdict(d, "L", "gatedScheduled"), samples=({"data": DATA},))
    O.sound(v, {O.OWNER})  # listing the scheduler from its event's parts is not reached on a real history yet
    assert O.passes(d, "L", O.function(d, "L", "gatedScheduled"), {"data": DATA}, sender=O.OWNER)


def test_a_key_hashed_from_the_caller_is_not_listed_by_its_hash_alone(d):
    v = O.check(d, "L", "gatedById", O.verdict(d, "L", "gatedById"), samples=({"data": DATA},))
    assert not v.complete
    assert O.passes(d, "L", O.function(d, "L", "gatedById"), {"data": DATA}, sender=O.OWNER)


def test_a_raw_slot_hashed_from_the_holder_is_listed_by_an_event_that_names_its_parts(d):
    v = O.check(d, "L", "hasRaw", O.verdict(d, "L", "hasRaw"), samples=({"role": 7},))
    O.sound(v, {H3})  # likewise for the raw slot: never more than the holder, never complete without it
    assert O.passes(d, "L", O.function(d, "L", "hasRaw"), {"role": 7}, sender=H3)


def test_assembly_writing_where_an_entry_may_be_leaves_the_lookup_unlisted(d):
    v = O.check(d, "Shadowed", "isMember", O.verdict(d, "Shadowed", "isMember"))
    assert not v.complete
    assert O.passes(d, "Shadowed", O.function(d, "Shadowed", "isMember"), sender=H2)  # written by the assembly


def test_an_assembly_event_keyed_by_the_selector_logs_the_arguments_it_carries(d):
    v = O.check(d, "Noted", "rely", O.verdict(d, "Noted", "rely"))
    assert H1 in v.principals  # relied through the noted call
    assert O.passes(d, "Noted", O.function(d, "Noted", "rely"), sender=O.OWNER)
    assert O.OWNER in v.principals or not v.complete  # the constructor's ward no event names
