"""Lists built from the identity checks themselves (``holders``): every holder a role's logged history names, read
whole, however many; and an address set that excludes some rather than naming any is no list."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O

SOURCE = """
pragma solidity 0.8.27;

contract Roles {
    mapping(bytes32 => mapping(address => bool)) roles;
    mapping(address => bool) blocked;
    bytes32 constant MINTER = keccak256("MINTER");
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event Blocked(address indexed account);

    function grant(bytes32 role, address who) external {
        require(roles[0][msg.sender]);
        roles[role][who] = true;
        emit RoleGranted(role, who);
    }

    function revoke(bytes32 role, address who) external {
        require(roles[0][msg.sender]);
        roles[role][who] = false;
        emit RoleRevoked(role, who);
    }

    function block(address who) external {
        require(roles[0][msg.sender]);
        blocked[who] = true;
        emit Blocked(who);
    }

    function mint() external view {
        require(roles[MINTER][msg.sender] && !blocked[msg.sender]);
    }

    function transfer() external view {
        require(!blocked[msg.sender]);
    }
}
"""

AT = 0xA1 << 140
_MINTER = int.from_bytes(keccak(b"MINTER"), "big")
_GRANTED = int.from_bytes(keccak(b"RoleGranted(bytes32,address)"), "big")
_REVOKED = int.from_bytes(keccak(b"RoleRevoked(bytes32,address)"), "big")
_BLOCKED = int.from_bytes(keccak(b"Blocked(address)"), "big")
MINTERS = [(0xB0 << 150) + i for i in range(300)]
REVOKED, BLOCKED = MINTERS[7], MINTERS[11]
_TRANSFER = keccak(b"transfer()")[:4].hex()


class _Deployed(Chain):
    """300 minters granted, one revoked since, one blocked."""

    def __init__(self):
        self.words = {O.slot(m, O.slot(_MINTER, 0)): 1 for m in MINTERS if m != REVOKED}
        self.words[O.slot(BLOCKED, 1)] = 1
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
        call = params[0] if method == "eth_call" else {}
        if int(call.get("to", "0x0"), 16) == AT and call.get("data", "").startswith("0x" + _TRANSFER):
            # ``transfer()`` as deployed: it returns for whoever is not blocked.
            if int(call["from"], 16) != BLOCKED and not self.words.get(O.slot(int(call["from"], 16), 1)):
                return "0x"
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        if address != AT:
            return []
        return [
            *(([_GRANTED, _MINTER, m], []) for m in MINTERS),
            ([_REVOKED, _MINTER, REVOKED], []),
            ([_BLOCKED, BLOCKED], []),
        ]


@pytest.fixture(scope="module")
def roles(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("holders") / "R.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Roles")


def _verdict(roles, name):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in roles.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(roles, fn, AT, _Deployed(), {AT: roles})
    return verdict


def test_every_minter_the_history_names_is_listed_and_read_however_many(roles):
    verdict = _verdict(roles, "mint")
    assert verdict.openness == "restricted"
    assert verdict.principals == set(MINTERS) - {REVOKED, BLOCKED}
    assert verdict.complete


def test_a_blocklist_alone_lists_nobody(roles):
    assert _verdict(roles, "transfer").openness == "open"
