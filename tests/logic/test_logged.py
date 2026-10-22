"""A lookup is listed whole by its events only when every write that can set an entry logs the entry's keys."""

from __future__ import annotations

import pytest

from services.logic.logged import logged, logged_raw
from services.logic.terms import reset_terms
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic.test_arranged import THIS, _Fresh

SOURCE = """
pragma solidity 0.8.27;

contract L {
    address owner;
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
            mstore(0x00, 0x1234)
            mstore(0x20, role)
            mstore(0x40, holder)
            sstore(keccak256(0x00, 0x60), 1)
        }
        emit RawSet(holder, role);
    }

    function hasRaw(uint256 role) external view {
        uint256 held;
        assembly {
            mstore(0x00, 0x1234)
            mstore(0x20, role)
            mstore(0x40, caller())
            held := sload(keccak256(0x00, 0x60))
        }
        require(held != 0);
    }

    function gated() external view { require(roles[msg.sender] & bytes32(uint256(1)) != 0); }
    function gatedSilent() external view { require(silent[msg.sender]); }
    function gatedScheduled(bytes calldata data) external view {
        require(scheduled[keccak256(abi.encode(msg.sender, data))] != 0);
    }
    function gatedById(bytes calldata data) external view {
        require(byId[keccak256(abi.encode(msg.sender, data))] != 0);
    }
}
"""


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("logged") / "L.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "L")


def _verdict(contract, name):
    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(contract, fn, THIS, _Fresh(), {THIS: contract})
    return verdict


def test_a_bitmask_set_and_cleared_under_one_event_is_listed(contract):
    reset_terms()
    assert logged(contract, "roles", 1, (), False) == {("RoleSet", 3)}
    assert _verdict(contract, "gated").complete


def test_a_write_no_event_names_is_not_listed(contract):
    reset_terms()
    assert logged(contract, "silent", 1, (), False) is None
    verdict = _verdict(contract, "gatedSilent")
    assert verdict.openness == "restricted" and not verdict.complete


def test_an_event_on_another_path_than_the_write_does_not_list_it(contract):
    reset_terms()
    assert logged(contract, "elsewhere", 1, (), False) is None


def test_a_key_hashed_from_the_caller_is_listed_by_an_event_that_names_its_parts(contract):
    reset_terms()
    assert logged(contract, "scheduled", 1, (), True) == {("Scheduled", 3)}
    assert _verdict(contract, "gatedScheduled").complete


def test_a_key_hashed_from_the_caller_is_not_listed_by_its_hash_alone(contract):
    reset_terms()
    assert logged(contract, "byId", 1, (), False) == {("Queued", 1)}  # the ids are listed
    assert logged(contract, "byId", 1, (), True) is None  # who they stand for is not
    assert not _verdict(contract, "gatedById").complete


def test_a_raw_slot_hashed_from_the_holder_is_listed_by_an_event_that_names_its_parts(contract):
    reset_terms()
    from services.logic.terms import CALLER, const, mk

    slot = mk(
        "hash", "keccak256", (mk("enc", "abi.encodePacked", (const(0x1234), mk("arg", "role", "uint256"), CALLER)),)
    )
    assert logged_raw(contract, slot) == {("RawSet", 2)}


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


def test_assembly_writing_where_an_entry_may_be_leaves_the_lookup_unlisted(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("shadowed") / "S.sol"
    path.write_text(SHADOWED)
    shadowed = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Shadowed")
    reset_terms()
    assert logged(shadowed, "members", 1, (), False) is None


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

    function rely(address usr) external note auth { wards[usr] = 1; }
    function deny(address usr) external note auth { wards[usr] = 0; }
}
"""


def test_an_assembly_event_keyed_by_the_selector_logs_the_arguments_it_carries(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from eth_utils.crypto import keccak
    from slither import Slither

    path = tmp_path_factory.mktemp("noted") / "N.sol"
    path.write_text(NOTED)
    noted = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Noted")
    reset_terms()
    rely = int.from_bytes(keccak(text="rely(address)")[:4], "big")
    assert logged(noted, "wards", 1, (), False) == {("topic0", rely << 224, 3)}  # deny only clears
