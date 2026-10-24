"""``caller == E[k...]`` with keys the caller picks: whoever is stored there for some keys, the keys quantified away
rather than guessed one by one, and the choice reported as a condition on the arguments."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O

SOURCE = """
pragma solidity 0.8.27;

contract Ops {
    struct Op { address manager; uint256 x; }
    mapping(uint256 => Op) ops;
    address admin;
    event OpSet(uint256 indexed id, address manager);

    function setOp(uint256 id, address m) external {
        require(msg.sender == admin);
        ops[id].manager = m;
        emit OpSet(id, m);
    }
    function act(uint256 id) external { require(ops[id].manager == msg.sender); }
}

// The same, with a setter that logs nothing.
contract OpsQuiet {
    struct Op { address manager; uint256 x; }
    mapping(uint256 => Op) ops;
    address admin;
    event OpSet(uint256 indexed id, address manager);

    function setOp(uint256 id, address m) external {
        require(msg.sender == admin);
        ops[id].manager = m;
        emit OpSet(id, m);
    }
    function quietSet(uint256 id, address m) external { require(msg.sender == admin); ops[id].manager = m; }
    function act(uint256 id) external { require(ops[id].manager == msg.sender); }
}

contract Grid {
    mapping(uint256 => mapping(uint256 => address)) ops;
    address admin;
    event OpSet(uint256 indexed a, uint256 indexed b, address manager);

    function setOp(uint256 a, uint256 b, address m) external {
        require(msg.sender == admin);
        ops[a][b] = m;
        emit OpSet(a, b, m);
    }
    function act(uint256 a, uint256 b) external { require(ops[a][b] == msg.sender); }
}

contract GridQuiet {
    mapping(uint256 => mapping(uint256 => address)) ops;
    address admin;
    event OpSet(uint256 indexed a, uint256 indexed b, address manager);

    function setOp(uint256 a, uint256 b, address m) external {
        require(msg.sender == admin);
        ops[a][b] = m;
        emit OpSet(a, b, m);
    }
    function quietSet(uint256 a, uint256 b, address m) external { require(msg.sender == admin); ops[a][b] = m; }
    function act(uint256 a, uint256 b) external { require(ops[a][b] == msg.sender); }
}
"""

AT, ADMIN = 0xA1 << 140, 0xB2 << 140
MANAGERS = (0xC3 << 140, 0xD4 << 140, 0xE5 << 140)


def _topic(signature: str) -> int:
    return int.from_bytes(keccak(signature.encode()), "big")


class _Deployed(Chain):
    def __init__(self, words: dict, logged: list):
        self.words, self.logged = {1: ADMIN, **words}, logged
        super().__init__(self._answer, 100, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get(int(params[1], 16), 0))
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\\x60" if address == AT else b""

    def logs(self, address, topics):
        return self.logged if address == AT else []


def _by_id():
    words = {O.slot(i + 1, 0): m for i, m in enumerate(MANAGERS)}
    return _Deployed(words, [([_topic("OpSet(uint256,address)"), i + 1], [m]) for i, m in enumerate(MANAGERS)])


def _by_cell():
    words = {O.slot(7, O.slot(i + 1, 0)): m for i, m in enumerate(MANAGERS)}
    signature = "OpSet(uint256,uint256,address)"
    return _Deployed(words, [([_topic(signature), i + 1, 7], [m]) for i, m in enumerate(MANAGERS)])


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("chosen") / "C.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(built, name, chain):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built[name]
    fn = next(f for f in contract.functions_entry_points if f.name == "act")
    return function_verdict(contract, fn, AT, chain, {AT: contract})[0]


def test_every_operator_any_id_names_is_listed(built):
    verdict = _verdict(built, "Ops", _by_id())
    assert verdict.openness == "restricted" and verdict.complete
    assert verdict.principals == set(MANAGERS)
    assert ("arguments", "id") in verdict.condition_terms


def test_an_unlogged_writer_leaves_the_same_operators_unproven(built):
    verdict = _verdict(built, "OpsQuiet", _by_id())
    assert verdict.openness == "restricted" and not verdict.complete
    assert verdict.principals == set(MANAGERS)
    assert verdict.gaps == ("storage:ops",)


def test_keys_chosen_two_deep_are_quantified_away(built):
    verdict = _verdict(built, "Grid", _by_cell())
    assert verdict.openness == "restricted" and verdict.complete
    assert verdict.principals == set(MANAGERS)
    assert verdict.witnesses[MANAGERS[0]] == {"a": 1, "b": 7}
    assert {("arguments", "a"), ("arguments", "b")} <= set(verdict.condition_terms)


def test_two_deep_with_an_unlogged_writer_lists_them_unproven(built):
    verdict = _verdict(built, "GridQuiet", _by_cell())
    assert verdict.openness == "restricted" and not verdict.complete
    assert verdict.principals == set(MANAGERS)
    assert verdict.gaps == ("storage:ops",)
