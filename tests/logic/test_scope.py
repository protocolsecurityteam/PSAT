"""Effect scope (``SCOPE.md``): a function whose writes stay in the caller's own positions reports its gate as a
condition instead of enumerating who holds it; anything that also writes a global, mints, or grants keeps full
enumeration."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

contract Token {
    mapping(address => uint256) balances;
    mapping(address => bool) allowed;
    uint256 moved;
    uint256 supply;
    mapping(bytes32 => mapping(address => bool)) roles;
    uint256 locked = 1;
    address owner;
    mapping(uint256 => address) owners;
    mapping(uint256 => address) approvals;
    mapping(address => mapping(address => bool)) operators;
    event Allowed(address indexed who, bool ok);
    event RoleGranted(bytes32 indexed role, address indexed who);

    function allow(address who, bool ok) external {
        require(msg.sender == owner);
        allowed[who] = ok;
        emit Allowed(who, ok);
    }

    function transfer(address to, uint256 amount) external {
        require(allowed[msg.sender]);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function transferCounted(address to, uint256 amount) external {
        require(allowed[msg.sender]);
        balances[msg.sender] -= amount;
        balances[to] += amount;
        moved += amount;
    }

    function mint(address to, uint256 amount) external {
        require(allowed[msg.sender]);
        balances[to] += amount;
        supply += amount;
    }

    function grant(bytes32 role, address who) external {
        require(roles[0][msg.sender]);
        roles[role][who] = true;
        emit RoleGranted(role, who);
    }

    function transferLocked(address to, uint256 amount) external {
        require(locked == 1);
        locked = 2;
        require(allowed[msg.sender]);
        balances[msg.sender] -= amount;
        balances[to] += amount;
        locked = 1;
    }

    function approve(address to, uint256 id) external {
        address holder = owners[id];
        require(msg.sender == holder || operators[holder][msg.sender]);
        approvals[id] = to;
    }
}
"""

AT = 0xA1 << 140
ALLOWED = [0xB1 << 140, 0xB2 << 140]
ADMIN = 0xAD << 140
_ALLOWED = int.from_bytes(keccak(b"Allowed(address,bool)"), "big")
_GRANTED = int.from_bytes(keccak(b"RoleGranted(bytes32,address)"), "big")


def _slot(key: int, base: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


class _Deployed(Chain):
    """Two allowlisted senders, an admin holding role 0, the lock at rest."""

    def __init__(self):
        self.words = {_slot(a, 1): 1 for a in ALLOWED}
        self.words[_slot(ADMIN, _slot(0, 4))] = 1
        self.words[5] = 1
        self.read_logs: list = []
        super().__init__(self._answer, 100, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get(int(params[1], 16), 0) if int(params[0], 16) == AT else 0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        self.read_logs.append(topics)
        if address != AT:
            return []
        return [
            *(([_ALLOWED, a], [1]) for a in ALLOWED),
            ([_GRANTED, 0, ADMIN], []),
        ]


@pytest.fixture(scope="module")
def token(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("scope") / "T.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Token")


def _verdict(token, name, chain=None):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in token.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(token, fn, AT, chain or _Deployed(), {AT: token})
    return verdict


def test_a_transfer_behind_an_allowlist_is_self_scoped_and_reports_its_gate(token):
    chain = _Deployed()
    verdict = _verdict(token, "transfer", chain)
    assert verdict.scope == "self"
    assert set(verdict.scope_writes) == {("own", "balances"), ("credit", "balances")}
    assert verdict.openness == "restricted" and not verdict.complete
    assert verdict.gaps == ("self_scoped",)
    assert any("allowed[caller]" in g for g in verdict.gate)
    assert verdict.principals == frozenset()
    assert chain.read_logs == []  # no holder history read: nobody enumerated


def test_the_same_transfer_counting_into_a_global_is_shared_and_enumerated(token):
    verdict = _verdict(token, "transferCounted")
    assert verdict.scope == "shared" and ("shared", "moved") in verdict.scope_writes
    assert verdict.openness == "restricted" and verdict.complete
    assert verdict.principals == set(ALLOWED)


def test_minting_is_shared_and_enumerated(token):
    verdict = _verdict(token, "mint")
    assert verdict.scope == "shared"
    assert {("shared", "balances"), ("shared", "supply")} <= set(verdict.scope_writes)
    assert verdict.principals == set(ALLOWED) and verdict.complete


def test_a_role_grant_is_shared_and_enumerated(token):
    verdict = _verdict(token, "grant")
    assert verdict.scope == "shared" and ("shared", "roles") in verdict.scope_writes
    assert verdict.principals == {ADMIN} and verdict.complete


def test_a_lock_set_and_reset_leaves_a_transfer_self_scoped(token):
    verdict = _verdict(token, "transferLocked")
    assert verdict.scope == "self" and ("unchanged", "locked") in verdict.scope_writes
    assert verdict.gaps == ("self_scoped",)


def test_approving_for_a_token_one_holds_or_operates_is_self_scoped(token):
    verdict = _verdict(token, "approve")
    assert verdict.scope == "self" and verdict.scope_writes == (("authorized", "approvals"),)
    assert verdict.openness == "restricted" and verdict.gaps == ("self_scoped",)
