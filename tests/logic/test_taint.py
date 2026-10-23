"""The success formula split by who calls: what depends on the caller's identity, and what every caller faces alike."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.taint import split, tainted
from services.logic.terms import CALLER, THIS, const, mk, mk_and, mk_cmp, mk_not, unknown
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

X = mk("arg", "x", "uint256")
HUB = mk("load", THIS, "hub", ())


def _call(*args):
    return mk("call", HUB, "math(uint256)", tuple(args), True)


def test_a_call_depends_on_the_caller_only_through_what_it_is_handed():
    assert not tainted(mk_cmp("lt", const(0), _call(X)))
    assert tainted(mk_cmp("lt", const(0), _call(CALLER)))
    assert tainted(mk("ok", _call(mk("load", THIS, "shares", (("k", CALLER),))), 1))
    assert not tainted(mk("item", _call(X), 1))


def test_storage_depends_on_the_caller_through_its_keys():
    assert tainted(mk("load", THIS, "roles", (("k", CALLER),)))
    assert not tainted(mk("load", THIS, "roles", (("k", X),)))


def test_an_unknown_depends_on_the_caller_unless_the_lowering_marked_it_alike_for_everyone():
    assert tainted(unknown("loop:3"))
    assert tainted(unknown("unanalysed:C.f"))
    assert not tainted(unknown("loop:3:nobody"))
    assert not tainted(mk("opaque", "loop:3:anyone", ()))
    assert tainted(mk("opaque", "loop:3", (CALLER,)))


def test_what_is_not_shown_free_of_the_caller_depends_on_it():
    assert tainted(mk("opaque", "mload(uint256)", (mk("op", "add", (const(128), X)),)))
    assert tainted(mk("delegate", HUB))  # the code it runs sees this caller
    assert tainted(mk("sref", 1, "f"))  # a kind this module doesn't know
    assert not tainted(mk("opaque", "gasleft()", ()))
    assert not tainted(mk("balance", THIS))


def test_the_top_level_conjunction_splits_into_core_and_conditions():
    role = mk("load", THIS, "roles", (("k", CALLER),))
    business = mk_cmp("lt", const(0), _call(X))
    paused = mk_not(mk("load", THIS, "paused", ()))
    core, free = split(mk_and([role, business, paused]))
    assert core == (role,)
    assert set(free) == {business, paused}


SOURCE = """
pragma solidity 0.8.27;

interface IHub { function math(uint256 x) external view returns (uint256); }

contract C {
    IHub hub;
    mapping(address => bool) roles;
    address admin;
    event Granted(address indexed who);

    function grant(address who) external { require(msg.sender == admin); roles[who] = true; emit Granted(who); }
    function gated(uint256 x) external { require(hub.math(x) > 0); require(roles[msg.sender]); }
}
"""

AT, HUB_AT, ADMIN, HOLDER = 0xA1 << 140, 0xB7 << 140, 0xB2 << 140, 0xC3 << 140
GRANTED = int.from_bytes(keccak(b"Granted(address)"), "big")


class _Deployed(Chain):
    def __init__(self, words):
        self.words = words
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
        return b"\\x60" if address in (AT, HUB_AT) else b""

    def logs(self, address, topics):
        return [([GRANTED, HOLDER], [])] if address == AT else []


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("taint") / "C.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "C")


def test_a_verdict_reports_its_core_and_the_conditions_beside_it(contract):
    from services.logic.terms import reset_terms

    reset_terms()
    role = int.from_bytes(keccak(HOLDER.to_bytes(32, "big") + (1).to_bytes(32, "big")), "big")
    fn = next(f for f in contract.functions_entry_points if f.name == "gated")
    verdict, _ = function_verdict(contract, fn, AT, _Deployed({0: HUB_AT, 2: ADMIN, role: 1}), {AT: contract})
    assert verdict.core == ("roles[caller]",)
    # The call returning at all, and what it returns.
    assert set(verdict.condition_terms) == {
        ("business", "0 lt hub.math(uint256)(x)"),
        ("business", "hub.math(uint256)(x)"),
    }


def test_conditions_that_read_alike_keep_their_own_unknowns():
    from services.logic.decide import _business

    def deep(label):
        t = unknown(label)
        for _ in range(7):
            t = mk("op", "add", (t, X))
        return mk_cmp("lt", const(0), t)

    labels = {text for _, text in _business((deep("a:nobody"), deep("b:nobody")))}
    assert {"unknown:a:nobody", "unknown:b:nobody"} <= labels
