"""Behavioral-hash ladder tests.

A real-Slither compile of a mixin default vs a stricter override (gated on local solc; CI has one,
a fresh clone skips), plus solc-free structural doubles so the core invariants are always covered.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from services.effects.hashing import (
    bytecode_fallback_hash,
    contract_surface_hash,
    resolved_function_hash,
)
from tests.support.effects_ir import _fn, _ir, _node, _var
from tests.support.solc import _solc_086

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


def test_immutable_masking_recovers_a_hit():
    prefix = b"\x60\x80"
    suffix = b"\xfe"
    imm_a = b"\x11" * 32
    imm_b = b"\x22" * 32
    code_a = prefix + imm_a + suffix
    code_b = prefix + imm_b + suffix
    refs = {"7": [{"start": len(prefix), "length": 32}]}

    assert bytecode_fallback_hash(code_a, "0xaa") != bytecode_fallback_hash(code_b, "0xaa")
    assert bytecode_fallback_hash(code_a, "0xaa", immutable_references=refs) == bytecode_fallback_hash(
        code_b, "0xaa", immutable_references=refs
    )


def test_masking_never_merges_a_gated_deployment_with_an_ungated_one():
    """``gate:none`` covers proven-ungated and not-lowerable functions, so masking must erase the compared address
    but keep the comparison.
    """
    body = bytes.fromhex("6001600155")  # the guarded action: sstore(1, 1)

    # CALLER, PUSH20 <owner>, EQ, PUSH1 dest, JUMPI, REVERT, JUMPDEST
    def _gated(owner: bytes) -> bytes:
        return bytes.fromhex("33") + bytes.fromhex("73") + owner + bytes.fromhex("14601a575ffd5b") + body

    owner_offset = 2  # after CALLER + the PUSH20 opcode
    refs = {"1": [{"start": owner_offset, "length": 20}]}
    gated_a = _gated(b"\xaa" * 20)
    gated_b = _gated(b"\xbb" * 20)
    selector = "0xdeadbeef"

    assert bytecode_fallback_hash(gated_a, selector, immutable_references=refs) == bytecode_fallback_hash(
        gated_b, selector, immutable_references=refs
    )
    # A ``gate:none`` row can never transfer onto a gated deployment.
    assert bytecode_fallback_hash(gated_a, selector, immutable_references=refs) != bytecode_fallback_hash(
        body, selector, immutable_references=refs
    )
    assert bytecode_fallback_hash(gated_a, selector) != bytecode_fallback_hash(body, selector)


def test_contract_surface_hash_is_selectorless_and_masks():
    prefix = b"\x60\x80"
    refs = {"1": [{"start": 2, "length": 4}]}
    a = prefix + b"\xaa\xbb\xcc\xdd" + b"\xfe"
    b = prefix + b"\x00\x11\x22\x33" + b"\xfe"
    assert contract_surface_hash(a, immutable_references=refs) == contract_surface_hash(b, immutable_references=refs)


def test_override_vs_mixin_resolved_hashes_differ_real_slither(tmp_path: Path):
    """On real IR: the mixin `pauseUntil` default and a stricter override MUST hash apart
    (the exact weETH hazard: same name, same inherited file, different gate)."""
    from slither.slither import Slither

    src = textwrap.dedent(
        """
        pragma solidity ^0.8.26;
        contract Base {
            uint256 internal _pausedUntil;
            address internal guardian;
            modifier onlyGuardian() { require(msg.sender == guardian); _; }
            function pauseUntil(uint256 t) public virtual onlyGuardian {
                _pausedUntil = t;
            }
        }
        contract Strict is Base {
            address internal admin;
            function pauseUntil(uint256 t) public override onlyGuardian {
                require(msg.sender == admin);
                _pausedUntil = t;
            }
        }
        """
    ).strip()
    f = tmp_path / "P.sol"
    f.write_text(src + "\n")
    sl = Slither(str(f), solc=_solc_086())

    base = next(c for c in sl.contracts if c.name == "Base")
    strict = next(c for c in sl.contracts if c.name == "Strict")
    base_fn = base.get_function_from_signature("pauseUntil(uint256)")
    strict_fn = strict.get_function_from_signature("pauseUntil(uint256)")
    assert base_fn is not None and strict_fn is not None

    assert resolved_function_hash(base_fn) != resolved_function_hash(strict_fn)
