"""The success formula split by who calls: what depends on the caller's identity, and what every caller faces alike."""

from __future__ import annotations

from services.logic.taint import tainted
from services.logic.terms import CALLER, THIS, const, mk, unknown

X = mk("arg", "x", "uint256")
HUB = mk("load", THIS, "hub", ())


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
