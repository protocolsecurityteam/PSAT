"""Entries written in a library on a ``storage`` pointer, logged by the library's events: what lets those events say
whose entry each one is (Lido CSM's ``NodeOperatorOps``, its operators in namespaced storage at slot 0)."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

struct Operator { address manager; uint32 added; }

library Ops {
    event OperatorAdded(uint256 indexed id, address indexed manager);
    event ManagerChanged(uint256 indexed id, address oldManager, address newManager);

    function create(mapping(uint256 => Operator) storage ops, uint256 id, address manager, address from) external {
        address chosen = manager == address(0) ? from : manager;
        ops[id].manager = chosen;
        emit OperatorAdded(id, chosen);
    }

    function change(mapping(uint256 => Operator) storage ops, uint256 id, address to) external {
        address old = ops[id].manager;
        if (to != old) {
            ops[id].manager = to;
            emit ManagerChanged(id, old, to);
        }
    }
}

contract Module {
    struct Layout { mapping(uint256 => Operator) ops; uint256 count; address admin; }
    bytes32 constant KEYS = keccak256("keys");

    function _layout() internal pure returns (Layout storage $) {
        assembly { $.slot := 0 }
    }

    function addOperator(address manager) external {
        Layout storage $ = _layout();
        require(msg.sender == $.admin);
        Ops.create($.ops, $.count, manager, msg.sender);
        $.count++;
    }

    function changeManager(uint256 id, address to) external {
        require(to != address(0) && _layout().ops[id].manager == msg.sender);
        Ops.change(_layout().ops, id, to);
    }

    function addKeys(uint256 id, uint256 count, bytes calldata keys) external {
        Operator storage no = _layout().ops[id];
        require(no.manager != address(0) && no.manager == msg.sender);
        require(count > 0 && keys.length == count * 48 && no.added + count <= type(uint32).max);
        uint256 start = no.added;
        for (uint256 i; i < count; ++i) {
            bytes32 slot = _keySlot(id, start + i);
            assembly { sstore(slot, 1) }
        }
        no.added = uint32(start + count);
    }

    function _keySlot(uint256 id, uint256 index) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(KEYS, id, index));
    }
}
"""

AT = 0xA1 << 140
ADMIN, FIRST, SECOND, THEN = 0xB2 << 140, 0xC3 << 140, 0xD4 << 140, 0xE5 << 140
_ADDED = int.from_bytes(keccak(b"OperatorAdded(uint256,address)"), "big")
_CHANGED = int.from_bytes(keccak(b"ManagerChanged(uint256,address,address)"), "big")


def _entry(key: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + (0).to_bytes(32, "big")), "big")


class _Deployed(Chain):
    """Operator 0 created for ``FIRST``, operator 1 for ``SECOND``, who handed it to ``THEN``."""

    def __init__(self):
        managers = {_entry(0): FIRST, _entry(1): THEN}
        self.words = {**managers, 1: 2, 2: ADMIN}
        batch = lambda calls: [self._safe(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch)

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
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        if address != AT:
            return []
        return [
            ([_ADDED, 0, FIRST], []),
            ([_ADDED, 1, SECOND], []),
            ([_CHANGED, 1], [SECOND, THEN]),
        ]


@pytest.fixture(scope="module")
def module(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("library_writers") / "M.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Module")


@pytest.mark.parametrize("name", ["addKeys", "changeManager"])
def test_each_operators_manager_is_listed_from_the_librarys_events(module, name):
    # ``changeManager`` writes the very entry the managers' checks read: who passes them changes, so it is shared.
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in module.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(module, fn, AT, _Deployed(), {AT: module})
    assert verdict.openness == "restricted" and verdict.scope == "shared"
    assert verdict.principals | set(verdict.conditions) == {FIRST, THEN}
    assert verdict.complete
