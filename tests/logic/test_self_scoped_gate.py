"""A function the scope classifier calls self-scoped (an unverified label, off by default: ``SCOPE.md``) still says
who can pass: with skipping on, nobody when the list of holders is shown empty; with skipping off (the default) its
holders are enumerated as for any function."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic import decide
from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

// Allowlisted senders move their own balance, only to receivers an admin accepts.
contract Gated {
    address admin;
    mapping(address => bool) allowed;
    mapping(address => bool) accepts;
    mapping(address => uint256) balances;
    event Allowed(address indexed who);

    function allow(address who) external {
        require(msg.sender == admin);
        allowed[who] = true;
        emit Allowed(who);
    }

    function accept(address who) external {
        require(msg.sender == admin);
        accepts[who] = true;
    }

    function send(address to, uint256 d) external {
        require(allowed[msg.sender] && accepts[to]);
        balances[msg.sender] -= d;
        balances[to] += d;
    }
}
"""

AT = 0xA1 << 152
SENDER, RECEIVER = 0xB1 << 152, 0xB2 << 152
_ALLOWED = int.from_bytes(keccak(b"Allowed(address)"), "big")


def _slot(key: int, base: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


class _Deployed(Chain):
    """``senders`` allowlisted (and logged); ``RECEIVER`` accepted."""

    def __init__(self, senders: list):
        self.senders = senders
        self.words = {_slot(who, 1): 1 for who in senders}
        self.words[_slot(RECEIVER, 2)] = 1
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
        return [([_ALLOWED, who], []) for who in self.senders] if address == AT else []


@pytest.fixture(scope="module")
def gated(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("gated") / "G.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Gated")


def _verdict(contract, chain):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "send")
    verdict, _ = function_verdict(contract, fn, AT, chain, {AT: contract})
    return verdict


def test_with_nobody_ever_allowlisted_nobody_can_send(gated, monkeypatch):
    monkeypatch.setattr(decide, "SKIP_SELF_SCOPED", True)
    verdict = _verdict(gated, _Deployed([]))
    assert verdict.openness == "restricted" and verdict.complete and not verdict.principals


def test_by_default_a_self_scoped_function_is_still_enumerated(gated):
    assert decide.SKIP_SELF_SCOPED is False
    verdict = _verdict(gated, _Deployed([SENDER]))
    assert "self_scoped" not in verdict.gaps and verdict.principals == {SENDER}
