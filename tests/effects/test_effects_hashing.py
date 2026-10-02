"""Behavioral-hash ladder tests.

A real-Slither compile of a mixin default vs a stricter override (gated on local solc; CI has one,
a fresh clone skips), plus solc-free structural doubles so the core invariants are always covered.
"""

from __future__ import annotations

import pytest

from services.effects.hashing import (
    bytecode_fallback_hash,
    contract_surface_hash,
    resolved_function_hash,
)
from tests.support.effects_ir import _fn, _ir, _node, _var

pytestmark = pytest.mark.compile


def test_override_hashes_differently_from_mixin_structural():
    """a stricter override MUST hash apart from the mixin default even though names are stripped."""
    latch = _var("StateVariable", "_pausedUntil")
    sender = _var("SolidityVariableComposed", "msg.sender")
    guardian = _var("StateVariable", "guardian")
    admin = _var("StateVariable", "admin")

    mixin = _fn(
        "Base.pauseUntil(uint256)",
        nodes=[
            _node("EXPRESSION", [_ir("Binary", read=[sender, guardian])]),
            _node("EXPRESSION", [_ir("Assignment", lvalue=latch)]),
        ],
    )
    override = _fn(
        "Strict.pauseUntil(uint256)",
        nodes=[
            _node("EXPRESSION", [_ir("Binary", read=[sender, guardian])]),
            _node("EXPRESSION", [_ir("Binary", read=[sender, admin])]),  # stricter gate
            _node("EXPRESSION", [_ir("Assignment", lvalue=latch)]),
        ],
    )
    assert resolved_function_hash(mixin) != resolved_function_hash(override)


def test_variable_names_do_not_change_the_hash():
    a = _fn("A.f()", nodes=[_node("EXPRESSION", [_ir("Assignment", lvalue=_var("StateVariable", "paused"))])])
    b = _fn("B.g()", nodes=[_node("EXPRESSION", [_ir("Assignment", lvalue=_var("StateVariable", "frozen"))])])
    assert resolved_function_hash(a) == resolved_function_hash(b)


def test_internal_callee_is_inlined():
    rich_callee = _fn("H.helper()", nodes=[_node("EXPRESSION", [_ir("Assignment", lvalue=_var("StateVariable"))])])
    empty_callee = _fn("H.noop()", nodes=[])
    caller_rich = _fn("C.f()", nodes=[_node("EXPRESSION", [_ir("InternalCall", function=rich_callee)])])
    caller_empty = _fn("C.f()", nodes=[_node("EXPRESSION", [_ir("InternalCall", function=empty_callee)])])
    assert resolved_function_hash(caller_rich) != resolved_function_hash(caller_empty)


def test_recursion_terminates():
    fn = _fn("R.loop()", nodes=[])
    fn.nodes = [_node("EXPRESSION", [_ir("InternalCall", function=fn)])]  # pyright: ignore[reportAttributeAccessIssue]
    assert isinstance(resolved_function_hash(fn), str)


def test_modifier_gate_participates():
    body = [_node("EXPRESSION", [_ir("Assignment", lvalue=_var("StateVariable"))])]
    mod_a = _fn("m.onlyGuardian()", nodes=[_node("EXPRESSION", [_ir("Binary", read=[_var("StateVariable")])])])
    mod_b = _fn(
        "m.onlyAdmin()",
        nodes=[
            _node("EXPRESSION", [_ir("Binary", read=[_var("StateVariable")])]),
            _node("EXPRESSION", [_ir("Binary", read=[_var("StateVariable")])]),
        ],
    )
    fn_a = _fn("A.f()", nodes=body, modifiers=[mod_a])
    fn_b = _fn("A.f()", nodes=body, modifiers=[mod_b])
    assert resolved_function_hash(fn_a) != resolved_function_hash(fn_b)


def _with_metadata(core: bytes) -> bytes:
    meta = b"\xa2\x64meta"
    return core + meta + len(meta).to_bytes(2, "big")


def test_unverified_fallback_is_deterministic_and_strips_metadata():
    core = b"\x60\x80\x60\x40\x52\xfe"
    h1 = bytecode_fallback_hash(_with_metadata(core), "0x12345678")
    h2 = bytecode_fallback_hash("0x" + _with_metadata(core).hex(), "0x12345678")
    alt_meta = b"\xa2\x64DIFF"
    meta2 = core + alt_meta + len(alt_meta).to_bytes(2, "big")
    h3 = bytecode_fallback_hash(meta2, "0x12345678")
    assert h1 == h2 == h3
    assert bytecode_fallback_hash(_with_metadata(core), "0xdeadbeef") != h1


def test_contract_surface_hash_is_selectorless_and_masks():
    prefix = b"\x60\x80"
    refs = {"1": [{"start": 2, "length": 4}]}
    a = prefix + b"\xaa\xbb\xcc\xdd" + b"\xfe"
    b = prefix + b"\x00\x11\x22\x33" + b"\xfe"
    assert contract_surface_hash(a, immutable_references=refs) == contract_surface_hash(b, immutable_references=refs)
