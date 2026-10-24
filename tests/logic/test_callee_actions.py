"""A state-changing call handed the caller is read for whether it returns: its callee's checks on the caller list who
may pass, never its return value (Maple's ``processRedeem(shares, owner, msg.sender)``)."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O

SOURCE = """
pragma solidity 0.8.27;

contract Manager {
    mapping(address => bool) allowed;
    event Allowed(address indexed who);

    function allow(address who) external {
        require(allowed[msg.sender]);
        allowed[who] = true;
        emit Allowed(who);
    }

    function process(address who) external returns (uint256) {
        require(allowed[who]);
        return 1;
    }
}

contract Pool {
    Manager manager;

    function redeem() external {
        manager.process(msg.sender);
    }
}

contract Registry {
    event Granted(address indexed who);

    function grant(address who) external {
        assembly {
            mstore(0, 7)
            mstore(32, caller())
            if iszero(sload(keccak256(0, 64))) { revert(0, 0) }
            mstore(32, who)
            sstore(keccak256(0, 64), 1)
        }
        emit Granted(who);
    }

    function onlyGranted(address who) external {
        assembly {
            mstore(0, 7)
            mstore(32, who)
            if iszero(sload(keccak256(0, 64))) { revert(0, 0) }
            sstore(1, add(sload(1), 1))
        }
    }
}

contract Guarded {
    Registry registry;
    bool paused;

    function pause() external {
        registry.onlyGranted(msg.sender);
        paused = true;
    }
}
"""

POOL, MANAGER, GUARDED, REGISTRY = 0xA1 << 140, 0xA2 << 140, 0xA3 << 140, 0xA4 << 140
ALLOWED, OTHER = 0xB1 << 152, 0xB2 << 152
_ALLOWED = int.from_bytes(keccak(b"Allowed(address)"), "big")
_GRANTED = int.from_bytes(keccak(b"Granted(address)"), "big")


class _Deployed(Chain):
    """The pool's manager at ``MANAGER``, which allowed ``ALLOWED`` and logged it."""

    def __init__(self):
        self.words = {
            (POOL, 0): MANAGER,
            (MANAGER, O.slot(ALLOWED, 0)): 1,
            (GUARDED, 0): REGISTRY,
            (REGISTRY, O.slot(7, ALLOWED)): 1,
        }
        batch = lambda calls: [self._safe(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch)

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get((int(params[0], 16), int(params[1], 16)), 0))
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address in (POOL, MANAGER, GUARDED, REGISTRY) else b""

    def logs(self, address, topics):
        return {MANAGER: [([_ALLOWED, ALLOWED], [])], REGISTRY: [([_GRANTED, ALLOWED], [])]}.get(address, [])

    def all_log_words(self, address):
        return {w for topics, data in self.logs(address, None) for w in (*topics[1:], *data)}


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("callee_actions") / "P.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def test_an_action_that_checks_the_caller_lists_whom_its_callee_lets_through(built):
    from services.logic.terms import reset_terms

    reset_terms()
    pool = built["Pool"]
    fn = next(f for f in pool.functions_entry_points if f.name == "redeem")
    verdict, _ = function_verdict(pool, fn, POOL, _Deployed(), {POOL: pool, MANAGER: built["Manager"]})
    # Whether a stranger is refused there stays unknown (who may be allowed goes unread); the list does not.
    assert ALLOWED in verdict.principals
    assert OTHER not in verdict.principals


def test_a_check_its_callee_keeps_in_an_assembly_slot_lists_whom_the_callee_logged(built):
    from services.logic.terms import reset_terms

    reset_terms()
    guarded = built["Guarded"]
    fn = next(f for f in guarded.functions_entry_points if f.name == "pause")
    contracts = {GUARDED: guarded, REGISTRY: built["Registry"]}
    verdict, _ = function_verdict(guarded, fn, GUARDED, _Deployed(), contracts)
    assert ALLOWED in verdict.principals
    assert OTHER not in verdict.principals
