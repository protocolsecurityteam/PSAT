"""Lists built from the identity checks themselves (``holders``): every holder a role's logged history names, read
whole, however many; and an address set that excludes some rather than naming any is no list."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.holders import ANYONE, NOBODY, Who, _join, _meet
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

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


def _slot(key: int, base: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


class _Deployed(Chain):
    """300 minters granted, one revoked since, one blocked."""

    def __init__(self):
        self.words = {_slot(m, _slot(_MINTER, 0)): 1 for m in MINTERS if m != REVOKED}
        self.words[_slot(BLOCKED, 1)] = 1
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


def test_sets_combine_as_the_checks_do():
    a, b = Who({1: ({},), 2: ({},)}), Who({2: ({},), 3: ({},)})
    assert _meet(a, b).members == {2: ({},)}
    assert set(_join(a, b).members) == {1, 2, 3}
    everyone_but_2 = Who(None, frozenset({2}))
    assert _meet(a, everyone_but_2).members == {1: ({},)}
    joined = _join(a, everyone_but_2)
    assert joined.members is None and joined.excluded == frozenset() and joined.hints == {1, 2}
    assert _meet(ANYONE, NOBODY).members == {}
    bound = _meet(Who({1: ({"k": 5}, {"k": 6})}), Who({1: ({"k": 6},)}))
    assert bound.members == {1: ({"k": 6},)}
    # Held at one key in one lookup and at another in the next, under the same argument: no call satisfies both.
    assert _meet(Who({1: ({"k": 5},)}), Who({1: ({"k": 6},)})).members == {}
    assert _meet(Who({1: ({"k": 5},)}), Who({1: ({},)})).members == {1: ({"k": 5},)}
