"""Whether code may read ``tx.origin`` (or delegate) is read off the instructions a run can reach from offset 0
(``verdict._opcodes``), never off every byte: data the code never jumps into (a revert string, the code of a contract
it deploys, the compiler's metadata) holds bytes that decode as ``ORIGIN`` (0x32, ASCII ``2``). Reachability follows
the constants pushed and moved on the stack to each jump; a jump to anything else makes every ``JUMPDEST`` a target,
so the walk never misses reachable code. Hand-assembled code pins each rule; compiled contracts check it on solc's
own output, and the engine's verdict on a callee whose only ``ORIGIN`` byte is in a contract it deploys is checked
against ``eth_call`` on anvil (``_oracle.check``)."""

from __future__ import annotations

import pytest

from services.logic.verdict import _opcodes, _runtime_code
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

ORIGIN, INVALID, STOP, JUMP, JUMPI, JUMPDEST = 0x32, 0xFE, 0x00, 0x56, 0x57, 0x5B
PUSH1, POP, DUP1, SWAP1, MSTORE, MLOAD, CALLDATALOAD = 0x60, 0x50, 0x80, 0x90, 0x52, 0x51, 0x35


def code(*parts: int | bytes) -> bytes:
    return b"".join(bytes([p]) if isinstance(p, int) else p for p in parts)


def test_data_after_the_code_is_not_read_as_code():
    # ``STOP`` then a revert string's bytes ("x2y"): never reached.
    assert ORIGIN not in _opcodes(code(PUSH1, 1, POP, STOP, b"x2y"))
    assert ORIGIN not in _opcodes(code(PUSH1, 1, POP, INVALID, b"\x32\x32"))


def test_origin_in_a_branch_is_read():
    # 0 PUSH1 1, 2 PUSH1 7, 4 JUMPI, 5 STOP, 6 STOP, 7 JUMPDEST, 8 ORIGIN.
    assert ORIGIN in _opcodes(code(PUSH1, 1, PUSH1, 7, JUMPI, STOP, STOP, JUMPDEST, ORIGIN, STOP))
    # Straight-line, before any halt.
    assert ORIGIN in _opcodes(code(ORIGIN, POP, STOP))


def test_a_return_address_moved_on_the_stack_is_followed():
    # A label pushed at 0 and jumped to later, from the stack: 0 PUSH1 8, 2 PUSH1 6, 4 JUMP, 5 STOP, 6 JUMPDEST,
    # 7 JUMP (to 8), 8 JUMPDEST, 9 ORIGIN.
    assert ORIGIN in _opcodes(code(PUSH1, 8, PUSH1, 6, JUMP, STOP, JUMPDEST, JUMP, JUMPDEST, ORIGIN, STOP))
    # The label moved under another word by SWAP and DUP before the jump reaches it.
    assert ORIGIN in _opcodes(code(PUSH1, 9, PUSH1, 0, SWAP1, DUP1, SWAP1, POP, JUMP, JUMPDEST, ORIGIN, STOP))


def test_a_computed_jump_makes_every_jumpdest_reachable():
    # The target comes from call data: every JUMPDEST may be jumped to, the one before ORIGIN past a STOP too.
    assert ORIGIN in _opcodes(code(PUSH1, 0, CALLDATALOAD, JUMP, STOP, JUMPDEST, ORIGIN, STOP))
    # A target stored in memory and loaded back is computed too.
    assert ORIGIN in _opcodes(code(PUSH1, 9, PUSH1, 0, MSTORE, PUSH1, 0, MLOAD, JUMP, JUMPDEST, ORIGIN, STOP))


def test_a_dead_region_after_invalid_is_unreachable_only_where_nothing_can_jump_into_it():
    dead = code(JUMPDEST, ORIGIN, STOP)
    # Only constant jumps (to 6), none to the dead JUMPDEST at 8: unreachable.
    assert ORIGIN not in _opcodes(code(PUSH1, 1, PUSH1, 6, JUMPI, INVALID, JUMPDEST, INVALID) + dead)
    # A computed jump anywhere: it may land there.
    assert ORIGIN in _opcodes(code(PUSH1, 1, PUSH1, 0, CALLDATALOAD, JUMPI, INVALID) + dead)
    # A constant jump to it: reachable.
    assert ORIGIN in _opcodes(code(PUSH1, 1, PUSH1, 7, JUMPI, INVALID, INVALID, JUMPDEST, ORIGIN, STOP))


def test_metadata_is_data():
    body = code(PUSH1, 1, POP, STOP)
    bzzr0 = bytes.fromhex("a165627a7a72305820") + b"\x32" * 32 + bytes.fromhex("0029")
    ipfs = bytes.fromhex("a2646970667358221220") + b"\x32" * 32 + bytes.fromhex("64736f6c6343") + b"\x00\x08\x1b"
    ipfs += len(ipfs).to_bytes(2, "big")
    for meta in (bzzr0, ipfs):
        assert ORIGIN not in _opcodes(body + meta)
        assert ORIGIN not in _opcodes(body + INVALID.to_bytes(1, "big") + meta + meta)  # a deployed child's, twice


def test_only_a_whole_metadata_map_is_stripped():
    # A computed jump makes every JUMPDEST a target, one inside the trailer (offset 14) too. A real map is data and
    # stripped; a trailer one byte off a whole map is not, so the JUMPDEST ORIGIN it holds counts.
    body = code(PUSH1, 0, CALLDATALOAD, JUMP, STOP)
    meta = bytes.fromhex("a165627a7a72305820") + b"\x5b\x32" + b"\x00" * 30
    assert ORIGIN not in _opcodes(body + meta + len(meta).to_bytes(2, "big"))
    for bad in (meta + b"\x00", meta[:-1], b"\xa2" + meta[1:], meta.replace(b"bzzr0", b"bzzr9")):
        assert ORIGIN in _opcodes(body + bad + len(bad).to_bytes(2, "big")), bad.hex()


SOURCE = """
pragma solidity 0.8.27;

contract Child {
    address public who;
    constructor() { who = tx.origin; }
    function origin() external view returns (address) { return tx.origin; }
}

contract Factory {
    Child public last;
    function ok() external view returns (bool) { return address(last) != address(1); }
    function no() external pure returns (bool) { return false; }
    function noView() external view returns (bool) { return address(this) == address(1); }
    function make() external { last = new Child(); }
}

contract Messages {
    uint256 public x;
    function set(uint256 v) external {
        require(v != 0, "value 2 must be 22 or 222, see section 2.2 of the 2022 spec, page 222");
        require(v < 2**200, "2222222222222222222222222222222222222222222222222222222222222222222222");
        x = v;
    }
}

contract Reader {
    function origin() external view returns (address) { return tx.origin; }
}

contract C {
    Factory f;
    address admin;
    uint256 public total;
    constructor(address a, address b) { f = Factory(a); admin = b; }
    function act(uint256 x) external { x; require(f.ok()); total += 1; }
    function adminOr(uint256 x) external { x; require(msg.sender == admin || f.no()); total += 1; }
    function adminOrView(uint256 x) external { x; require(msg.sender == admin || f.noView()); total += 1; }
}
"""


ADMIN = O.ACCOUNTS[1]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _setup(d):
    d.deploy("Factory")
    d.deploy("C", ("address", "address"), (d.at["Factory"], ADMIN))
    d.deploy("Messages")
    d.deploy("Reader")


PROBES = [
    O.Probe(SOURCE, _setup, tuple(("C", n, f) for n in ("act", "adminOr", "adminOrView") for f in (("Factory",), ())))
]


def test_compiled_code_reads_origin_only_where_its_source_does(d):
    assert ORIGIN in _opcodes(_runtime_code(d.slither["Child"]))
    assert ORIGIN in _opcodes(_runtime_code(d.slither["Reader"]))
    # The factory's runtime code holds the child's whole creation code as data.
    factory = _runtime_code(d.slither["Factory"])
    assert ORIGIN in factory and ORIGIN not in _opcodes(factory)
    assert ORIGIN not in _opcodes(_runtime_code(d.slither["Messages"]))


@pytest.mark.parametrize("name", ["adminOr", "adminOrView"])
@pytest.mark.parametrize("others", [("Factory",), ()])
def test_a_callee_deploying_code_that_reads_the_origin_is_read_alike_for_every_caller(d, name, others):
    # ``f.no()`` answers false for everyone: the factory's only ``ORIGIN`` byte is in the child's code, never run by
    # it. Before, the factory counted as reading the origin, the call was trusted for no caller, and the verdict was
    # not determined (``origin:no()``); the admin alone passes.
    v = O.verdict(d, "C", name, *others)
    O.check(d, "C", name, v, open_at=False, samples=({"x": 1},))
    assert v.openness == "restricted" and v.complete and set(v.principals) == {ADMIN}, v


def test_a_callee_whose_answer_is_alike_for_everyone_stays_open(d):
    for others in (("Factory",), ()):
        v = O.verdict(d, "C", "act", *others)
        O.check(d, "C", "act", v, open_at={"x": 1})
