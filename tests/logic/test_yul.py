"""Legacy inline assembly (Solidity before 0.6) read as code (``yul.py``): straight-line Yul is followed like any other
code, so its storage writes are known; Yul it doesn't follow that may write storage leaves the writes unrecorded."""

from __future__ import annotations

import pytest

from services.logic.yul import Unsupported, parse
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


@pytest.mark.parametrize("text", ["if x { sstore(0, 1) }", "for {} lt(i, 3) {} { i := add(i, 1) }", "switch x"])
def test_control_flow_is_not_followed(text):
    with pytest.raises(Unsupported):
        parse(text)


SOURCE = """
pragma solidity 0.4.24;

// Lido's NodeOperatorsRegistry shape: an operator's keys kept at raw slots past a hash, written in assembly; the
// operators themselves in a mapping every write to which is logged.
contract Keys {
    struct Operator { address reward; uint64 count; }
    mapping(uint256 => Operator) operators;
    address admin;
    bytes32 constant KEYS = keccak256("keys");
    event OperatorAdded(uint256 id, address reward);
    event RewardSet(uint256 indexed id, address reward);

    function add(uint256 id, address reward) external {
        require(msg.sender == admin);
        operators[id].reward = reward;
        emit OperatorAdded(id, reward);
    }

    function setReward(uint256 id, address reward) external {
        require(msg.sender == operators[id].reward);
        operators[id].reward = reward;
        emit RewardSet(id, reward);
    }

    function addKey(uint256 id, bytes32 key) external {
        require(msg.sender == operators[id].reward);
        uint256 at = uint256(keccak256(abi.encodePacked(KEYS, id, uint256(operators[id].count))));
        assembly {
            sstore(at, key)
            sstore(add(at, 1), shl(128, key))
        }
        operators[id].count += 1;
    }
}

contract Branchy {
    mapping(uint256 => address) owners;
    event OwnerSet(uint256 indexed id, address owner);

    function set(uint256 id, address owner) external {
        require(msg.sender == owners[id]);
        owners[id] = owner;
        emit OwnerSet(id, owner);
    }

    function poke(uint256 slot) external {
        assembly {
            if gt(slot, 3) { sstore(slot, caller) }
        }
    }
}
"""


ARITHMETIC = """
pragma solidity 0.4.19;

// Straight-line legacy assembly: each word operation, ``let`` and a nested block, read by ``yul.py``.
contract A {
    function y_add(uint a, uint b, uint w) public pure { uint r; assembly { r := add(a, b) } require(r == w); }
    function y_sub(uint a, uint b, uint w) public pure { uint r; assembly { r := sub(a, b) } require(r == w); }
    function y_mul(uint a, uint b, uint w) public pure { uint r; assembly { r := mul(a, b) } require(r == w); }
    function y_div(uint a, uint b, uint w) public pure { uint r; assembly { r := div(a, b) } require(r == w); }
    function y_mod(uint a, uint b, uint w) public pure { uint r; assembly { r := mod(a, b) } require(r == w); }
    function y_exp(uint a, uint b, uint w) public pure { uint r; assembly { r := exp(a, b) } require(r == w); }
    function y_and(uint a, uint b, uint w) public pure { uint r; assembly { r := and(a, b) } require(r == w); }
    function y_or(uint a, uint b, uint w) public pure { uint r; assembly { r := or(a, b) } require(r == w); }
    function y_xor(uint a, uint b, uint w) public pure { uint r; assembly { r := xor(a, b) } require(r == w); }
    function y_lt(uint a, uint b, uint w) public pure { uint r; assembly { r := lt(a, b) } require(r == w); }
    function y_gt(uint a, uint b, uint w) public pure { uint r; assembly { r := gt(a, b) } require(r == w); }
    function y_eq(uint a, uint b, uint w) public pure { uint r; assembly { r := eq(a, b) } require(r == w); }
    function y_iszero(uint a, uint b, uint w) public pure { uint r; assembly { r := iszero(a) } require(r == w); }
    function y_not(uint a, uint b, uint w) public pure { uint r; assembly { r := not(a) } require(r == w); }
    function y_let(uint256 a, uint256 b, uint256 want) public pure {
        uint256 r;
        assembly { let t := mul(a, 2) { let u := add(t, b) r := u } }
        require(r == want);
    }
}
"""
_W = 2**256
_OPS = {
    "add": lambda a, b: (a + b) % _W, "sub": lambda a, b: (a - b) % _W, "mul": lambda a, b: (a * b) % _W,
    "div": lambda a, b: a // b if b else 0, "mod": lambda a, b: a % b if b else 0, "exp": lambda a, b: pow(a, b, _W),
    "and": lambda a, b: a & b, "or": lambda a, b: a | b, "xor": lambda a, b: a ^ b, "lt": lambda a, b: int(a < b),
    "gt": lambda a, b: int(a > b), "eq": lambda a, b: int(a == b), "iszero": lambda a, b: int(a == 0),
    "not": lambda a, b: _W - 1 - a, "let": lambda a, b: (2 * a + b) % _W,
}  # fmt: skip
_PAIRS = [(7, 3), (3, 7), (0, 0), (_W - 1, 2), (2, 255)]


@pytest.fixture(scope="module")
def arithmetic(anvil):  # noqa: F811
    d = O.deployment(*anvil, ARITHMETIC, "0.4.19")
    d.deploy("A")
    return d


@pytest.mark.parametrize("op", sorted(_OPS))
def test_legacy_assembly_arithmetic_is_the_evm_s(arithmetic, op):
    # The legacy reader's word operations, evaluated, against ``eth_call``: the hand-computed word passes, one more
    # doesn't, and the formula says the same at both.
    fn = O.function(arithmetic, "A", f"y_{op}")
    for a, b in _PAIRS:
        want = _OPS[op](a, b)
        for w, expected in ((want, True), ((want + 1) % _W, False)):
            chain = O.chain_says(arithmetic, fn, [a, b, w], "A")
            formula, engine = O.engine_says(arithmetic, fn, [a, b, w], "A")
            assert chain is expected, (op, a, b, w)
            assert engine == chain, (op, a, b, w, engine, formula)
