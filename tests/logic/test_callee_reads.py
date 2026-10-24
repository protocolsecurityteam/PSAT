"""A check another contract makes, lowered into the caller's terms, whatever order the chain reads arrive in."""

from __future__ import annotations

import pytest
from eth_utils.crypto import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

contract Permissions {
    address admin;

    function allowed(address who) external view returns (bool) {
        return who == admin;
    }
}

contract Manager {
    Permissions permissions;

    // The identity reaches ``allowed`` through a condition: a call coverage doesn't follow, first lowered while the
    // decision is gathering its reads.
    function canCall(address who, uint256 x) external view returns (bool) {
        return permissions.allowed(x > 0 ? who : address(0));
    }
}

contract C {
    Manager manager;

    function f(uint256 x) external view {
        require(manager.canCall(msg.sender, x));
    }
}
"""

THIS, MANAGER, PERMISSIONS, OWNER = 0xC0DE << 100, 0x3A9A << 100, 0x9E53 << 100, 0x0E1E << 100


class _Batched(Chain):
    """Storage answered only through batches: a single read during ``gather`` is deferred, as on a real node."""

    STORAGE = {(THIS, 0): MANAGER, (MANAGER, 0): PERMISSIONS, (PERMISSIONS, 0): OWNER}

    def __init__(self):
        super().__init__(self._single, 1, self._batch)

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.STORAGE.get((int(params[0], 16), int(params[1], 16)), 0))
        if method == "eth_getCode":
            return "0x60" if int(params[0], 16) in (THIS, MANAGER, PERMISSIONS) else "0x"
        if method == "eth_getLogs":
            return []
        if method == "eth_call":
            return self._call(int(params[0]["to"], 16), bytes.fromhex(params[0]["data"][2:]))
        raise RuntimeError("execution reverted")

    def _call(self, to, data):
        """The two view functions, answered as their code would."""
        words = [int.from_bytes(data[4 + 32 * i : 36 + 32 * i], "big") for i in range((len(data) - 4) // 32)]
        if to == PERMISSIONS and data[:4] == keccak(text="allowed(address)")[:4]:
            return "0x" + format(int(words[0] == OWNER), "064x")
        if to == MANAGER and data[:4] == keccak(text="canCall(address,uint256)")[:4]:
            return "0x" + format(int(words[0] == OWNER and words[1] > 0), "064x")
        raise RuntimeError("execution reverted")

    def _single(self, method, params):
        return self._answer(method, params)

    def _batch(self, calls):
        return [self._answer(method, params) for method, params in calls]

    def code(self, address):
        return b"\x60" if address in (THIS, MANAGER, PERMISSIONS) else b""

    def logs(self, address, topics):
        return []


@pytest.fixture(scope="module")
def contracts(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("callee") / "C.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def test_a_callee_first_reached_while_reads_wait_for_a_batch_is_still_followed(contracts):
    c = contracts["C"]
    fn = next(f for f in c.functions_entry_points if f.name == "f")
    deployed = {THIS: c, MANAGER: contracts["Manager"], PERMISSIONS: contracts["Permissions"]}
    verdict, _ = function_verdict(c, fn, THIS, _Batched(), deployed)
    assert verdict.principals == {OWNER}
    # That a stranger fails over every ``x`` only the callees' code shows, which never refutes on its own.
    assert verdict.openness == "not_determined" and "callee_code_refutation" in verdict.gaps
