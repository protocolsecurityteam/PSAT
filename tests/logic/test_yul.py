"""Legacy inline assembly (Solidity before 0.6) read as code (``yul.py``): straight-line Yul is followed like any other
code, so its storage writes are known; Yul it doesn't follow that may write storage leaves the writes unrecorded."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.logic.yul import Assign, Call, Effect, Name, Number, Unsupported, parse
from tests.fuzz.authority import solc_path


def test_straight_line_yul_parses_into_statements():
    parsed = parse(
        """{
            let ofs := add(add(keys, 0x20), mul(i, 48)) // one key
            sstore(slot, mload(ofs))
            i := add(i, 1)
        }"""
    )
    assert parsed == [
        Assign(
            ("ofs",), Call("add", (Call("add", (Name("keys"), Number(0x20))), Call("mul", (Name("i"), Number(48)))))
        ),
        Effect(Call("sstore", (Name("slot"), Call("mload", (Name("ofs"),))))),
        Assign(("i",), Call("add", (Name("i"), Number(1)))),
    ]


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


def _solc_0424() -> Path | None:
    found = solc_path("0.4.24")
    svm = Path.home() / ".svm/0.4.24/solc-0.4.24"
    return found or (svm if svm.exists() else None)


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = _solc_0424()
    if solc is None:
        pytest.skip("solc 0.4.24 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("yul") / "Y.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def test_assembly_writing_past_a_hash_leaves_the_mapping_logged(built):
    from services.logic.logged import logged, written_by
    from services.logic.terms import reset_terms

    reset_terms()
    keys = built["Keys"]
    assert logged(keys, "operators", 1, ("reward",), False, True) == {("OperatorAdded", 2), ("RewardSet", 2)}
    assert {s["event_signature"] for s in written_by(keys, "operators", ("reward",))} == {
        "OperatorAdded(uint256,address)",
        "RewardSet(uint256,address)",
    }


def test_assembly_that_may_write_anywhere_leaves_nothing_logged(built):
    from services.logic.logged import logged
    from services.logic.terms import reset_terms

    reset_terms()
    assert logged(built["Branchy"], "owners", 1, (), False) is None
