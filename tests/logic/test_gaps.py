"""Every not_determined verdict says why: the unknown term, the read that failed, or the budget."""

from __future__ import annotations

import pytest

from services.logic.decide import Chain, Verdict
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

interface IOracle { function ready() external view returns (bool); }

contract C {
    IOracle oracle;
    uint256 epoch;
    bool flagged;

    function flip() external { flagged = !flagged; }
    function guarded() external { require(!flagged); }
    function polled() external { require(oracle.ready()); }
}
"""

AT, ORACLE = 0xA1 << 140, 0xB7 << 140


class _Flaky(Chain):
    """Slot 0 holds the oracle; every other read, the flag's slot 2 too, and every call fail as a node's error."""

    def __init__(self):
        super().__init__(self._answer, 100, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[1], 16) == 0:
            return hex(ORACLE)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("upstream timeout")

    def code(self, address):
        return b"\\x60" if address in (AT, ORACLE) else b""

    def logs(self, address, topics):
        return []


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("gaps") / "C.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "C")


def _verdict(contract, name):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    return function_verdict(contract, fn, AT, _Flaky(), {AT: contract})[0]


def test_an_unread_flag_is_named(contract):
    verdict = _verdict(contract, "guarded")
    assert verdict.openness == "not_determined"
    assert "read_failed:storage:flagged" in verdict.gaps


def test_an_unanswered_call_is_named(contract):
    verdict = _verdict(contract, "polled")
    assert verdict.openness == "not_determined"
    assert "read_failed:call:ready()" in verdict.gaps


def test_a_not_determined_verdict_without_a_reason_is_refused():
    with pytest.raises(ValueError):
        Verdict("not_determined", frozenset(), False)
