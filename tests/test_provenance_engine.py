"""Unit tests for ``ProvenanceEngine`` over Slither IR.

Each fixture is a tiny Solidity contract; we run Slither on it, pick a
function, run the engine, and assert provenance for specific SSA
values. We do NOT assert internal SSA naming — Slither's SSA renaming
isn't part of the contract; tests find values by their semantic
position (function parameter / state read / call return).

The fixtures cover the IR opcodes the predicate builder will read in
weeks 2-3:
  - Assignment / TypeConversion / Phi
  - Binary / Unary
  - Index / Member (for mapping/struct access)
  - SolidityCall (ecrecover, keccak256)
  - InternalCall (recursion + parameter binding)
  - HighLevelCall (external bool)

These are the foundation that the predicate builder (week 2) sits on
top of. We don't test the predicate builder here — that's a separate
test suite.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.provenance import (  # noqa: E402
    EMPTY,
    TOP,
    ProvenanceEngine,
    Source,
    is_top,
    union,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _function(sl: Slither, fn_name: str):
    for c in sl.contracts:
        for f in c.functions:
            if f.name == fn_name:
                return f
    raise LookupError(fn_name)


def _has_source_kind(sources, kind: str) -> bool:
    return any(s.kind == kind for s in sources)


def _find_source_with_kind(sources, kind: str) -> Source | None:
    for s in sources:
        if s.kind == kind:
            return s
    return None


# ---------------------------------------------------------------------------
# Pure lattice tests (no Slither needed).
# ---------------------------------------------------------------------------


def test_lattice_union_basic():
    a = frozenset({Source(kind="msg_sender")})
    b = frozenset({Source(kind="parameter", parameter_index=0)})
    out = union(a, b)
    assert _has_source_kind(out, "msg_sender")
    assert _has_source_kind(out, "parameter")
    assert not is_top(out)


def test_lattice_top_absorbs():
    a = frozenset({Source(kind="msg_sender")})
    out = union(a, TOP)
    assert is_top(out)
    out2 = union(TOP, a)
    assert is_top(out2)


def test_lattice_empty_identity():
    a = frozenset({Source(kind="parameter", parameter_index=0)})
    assert union(a, EMPTY) == a
    assert union(EMPTY, a) == a


def test_is_top_singleton_invariant():
    """``is_top`` is O(1) (``_TOP_SOURCE in s`` frozenset lookup),
    which only works if every kind="top" Source equals the bare
    sentinel. The dataclass ``__post_init__`` enforces it. Pin both
    halves so a future change can't quietly tag a "top with metadata"
    and watch ``is_top`` silently miss it.
    """
    import pytest as _pytest

    # 1. The bare sentinel is detected.
    assert is_top(TOP)
    assert is_top(frozenset({Source(kind="top")}))

    # 2. Sets that contain non-top sources aren't.
    assert not is_top(frozenset({Source(kind="parameter", parameter_index=0)}))
    assert not is_top(frozenset())

    # 3. Constructing a Source(kind="top", ...) with any metadata field
    # set is rejected at construction time — that's how the O(1)
    # optimization stays correct in the face of future drift. One
    # rejection assertion per field so a single broken field is named
    # in the failure rather than buried in a parametrize id.
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", parameter_index=0)
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", parameter_name="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", state_variable_name="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", callee="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", callee_args_digest="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", callee_signature="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", callee_selector="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", constant_value="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", value_type="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", computed_kind="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", block_context_kind="x")
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", member_path=("x",))
    with _pytest.raises(ValueError, match="bare sentinel"):
        Source(kind="top", derived_from=frozenset())


def test_source_unknown_kind_raises():
    with pytest.raises(ValueError):
        Source(kind="not_a_real_kind")  # pyright: ignore[reportArgumentType]


# ---------------------------------------------------------------------------
# Slither-driven IR tests.
# ---------------------------------------------------------------------------


def test_parameter_seeded(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(address account, uint256 amount) external {
                account; amount;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # Every parameter should have a `parameter` source with the right index.
    for idx, param in enumerate(fn.parameters):
        assert param.name is not None
        sources = eng.provenance.get(param.name)
        param_src = _find_source_with_kind(sources, "parameter")
        assert param_src is not None, f"parameter {param.name} not seeded"
        assert param_src.parameter_index == idx


def test_assignment_propagates(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f() external view {
                address a = msg.sender;
                a;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # Find the SSA value for `a` — it'll have a name like `a` or `a_1`.
    found = False
    for name, sources in eng.provenance.sources.items():
        if name.startswith("a") and _has_source_kind(sources, "msg_sender"):
            found = True
            break
    assert found, f"no SSA value for `a` got msg_sender source. map={dict(eng.provenance.sources)}"


def test_type_conversion_preserves_source(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f() external view {
                bytes32 b = bytes32(uint256(uint160(msg.sender)));
                b;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # The chain of type conversions should land msg.sender provenance
    # somewhere reachable.
    has_caller = any(_has_source_kind(srcs, "msg_sender") for srcs in eng.provenance.sources.values())
    assert has_caller, "type conversion chain dropped msg_sender source"


def test_binary_combines_operand_sources(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public threshold;
            function f(uint256 amount) external view {
                bool ok = amount > threshold;
                ok;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # The `ok` value should have a `computed` source whose taint
    # includes both parameter and state_variable.
    found_computed = False
    for sources in eng.provenance.sources.values():
        if (
            _has_source_kind(sources, "parameter")
            and _has_source_kind(sources, "state_variable")
            and _has_source_kind(sources, "computed")
        ):
            found_computed = True
            break
    assert found_computed, (
        f"binary op didn't produce computed+parameter+state_variable taint. map={dict(eng.provenance.sources)}"
    )


def test_state_variable_read(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view returns (address) {
                return ownerVar;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    has_state = any(_has_source_kind(srcs, "state_variable") for srcs in eng.provenance.sources.values())
    assert has_state


def test_index_propagates_base_and_key(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public balances;
            function f() external view returns (uint256) {
                return balances[msg.sender];
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # The reference for balances[msg.sender] should carry both
    # state_variable (from the mapping base) and msg_sender (from the key).
    has_state_and_caller = any(
        _has_source_kind(srcs, "state_variable") and _has_source_kind(srcs, "msg_sender")
        for srcs in eng.provenance.sources.values()
    )
    assert has_state_and_caller, f"Index didn't propagate base+key sources. map={dict(eng.provenance.sources)}"


def test_solidity_call_ecrecover_classified_as_signature(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
                return ecrecover(h, v, r, s);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    has_sig = any(_has_source_kind(srcs, "signature_recovery") for srcs in eng.provenance.sources.values())
    assert has_sig, f"ecrecover didn't produce signature_recovery source. map={dict(eng.provenance.sources)}"


def test_solidity_call_keccak_classified_as_computed(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(uint256 x) external pure returns (bytes32) {
                return keccak256(abi.encode(x));
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # keccak256 result should be `computed`, not signature_recovery.
    has_computed = any(_has_source_kind(srcs, "computed") for srcs in eng.provenance.sources.values())
    has_sig = any(_has_source_kind(srcs, "signature_recovery") for srcs in eng.provenance.sources.values())
    assert has_computed
    assert not has_sig, "keccak256 was misclassified as signature_recovery"


def _keccak_sources(eng) -> frozenset[Source]:
    """The source set of the outermost ``keccak256`` result in a run."""
    for srcs in eng.provenance.sources.values():
        for source in srcs:
            if source.kind == "computed" and (source.computed_kind or "").startswith("keccak256"):
                return srcs
    raise AssertionError(f"no keccak256 computed source. map={dict(eng.provenance.sources)}")


def test_keccak_binds_the_parameters_it_commits_through_abi_encode(tmp_path):
    """The un-hedged half of ``..._classified_as_computed``: the hash is
    ``computed``, AND the parameters it commits are still named. Nesting is what
    makes this non-trivial — ``x`` reaches ``keccak256`` only through
    ``abi.encode``, whose own origins have to be spliced in."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            function f(uint256 x, address to) external view returns (bytes32) {
                return keccak256(abi.encode(x, to, owner));
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    keccak = next(
        s for s in _keccak_sources(eng) if s.kind == "computed" and (s.computed_kind or "").startswith("keccak256")
    )
    assert keccak.derived_from is not None, "argument provenance reported as not-determined"
    assert {(o.parameter_index, o.parameter_name) for o in keccak.derived_from if o.kind == "parameter"} == {
        (0, "x"),
        (1, "to"),
    }
    assert {o.state_variable_name for o in keccak.derived_from if o.kind == "state_variable"} == {"owner"}
    # The derivation shape survives alongside the binding — a consumer must still
    # be able to tell a hash commitment from a plain equality against storage.
    assert any(o.kind == "computed" and (o.computed_kind or "").startswith("abi.encode") for o in keccak.derived_from)
    # Members are stored stripped so the projection can never nest.
    assert all(o.derived_from is None for o in keccak.derived_from)


def test_keccak_over_constants_is_determined_empty_not_unknown(tmp_path):
    """The proven-absent state: nothing but constants reached the hash. This
    must be distinguishable from "nobody worked it out" (``None``)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f() external pure returns (bytes32) {
                return keccak256("MINTER_ROLE");
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    keccak = next(s for s in _keccak_sources(eng) if s.kind == "computed")
    assert keccak.derived_from == frozenset()


def test_msg_value_computed_source_reports_not_determined(tmp_path):
    """The third state, live: ``msg.value`` mints a ``computed`` source outside
    the Solidity-call handler, so its argument provenance is genuinely
    unpopulated. It must say ``None``, not ``frozenset()`` — the latter would
    assert that nothing reached it, which is a claim nobody made."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public total;
            function f() external payable {
                total = msg.value;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    computed = [
        s
        for srcs in eng.provenance.sources.values()
        for s in srcs
        if s.kind == "computed" and s.computed_kind == "msg.value"
    ]
    assert computed, f"no msg.value computed source. map={dict(eng.provenance.sources)}"
    assert all(s.derived_from is None for s in computed)


def test_external_call_classified(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IOther {
            function answer() external view returns (uint256);
        }
        contract C {
            IOther public other;
            function f() external view returns (uint256) {
                return other.answer();
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    has_external = any(_has_source_kind(srcs, "external_call") for srcs in eng.provenance.sources.values())
    assert has_external


def test_internal_call_recurses_into_callee(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function _helper(address a) internal view returns (address) {
                return a;
            }
            function f() external view returns (address) {
                return _helper(msg.sender);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # The return of _helper(msg.sender) should land msg_sender provenance.
    has_caller = any(_has_source_kind(srcs, "msg_sender") for srcs in eng.provenance.sources.values())
    assert has_caller, f"internal call didn't propagate msg_sender. map={dict(eng.provenance.sources)}"


def test_internal_call_depth_cap_does_not_crash(tmp_path):
    """Mutual recursion past the depth cap must terminate cleanly.

    Even though Solidity rarely has infinite mutual recursion in
    practice, the engine must guard against it to avoid blowing the
    stack on adversarial fixtures.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function a(address x) internal view returns (address) { return b(x); }
            function b(address x) internal view returns (address) { return a(x); }
            function f() external view returns (address) {
                return a(msg.sender);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn, internal_call_depth=3)
    # Should not raise / loop forever.
    eng.run()
    # We just want termination — don't assert specific provenance.


def test_block_timestamp_classified(tmp_path):
    """``block.timestamp`` is a SolidityVariable. When it appears as
    an operand to a Binary op (the typical require pattern), the
    binary's SSA result carries a ``block_context`` source through
    the operand-union path."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public unlockTime;
            function f() external view returns (bool) {
                return block.timestamp > unlockTime;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    has_block = any(_has_source_kind(srcs, "block_context") for srcs in eng.provenance.sources.values())
    assert has_block, (
        f"binary op with block.timestamp didn't yield block_context source. map={dict(eng.provenance.sources)}"
    )


# ---------------------------------------------------------------------------
# Low-level calls + tuple unpacking.
# ---------------------------------------------------------------------------


def test_low_level_call_classified(tmp_path):
    """``target.call(data)`` produces a tuple lvalue. The tuple's
    provenance must include ``external_call`` AND the destination/args
    taint (both parameters here)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(address target, bytes calldata data) external returns (bool, bytes memory) {
                (bool ok, bytes memory r) = target.call(data);
                return (ok, r);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # Find a value with external_call source AND parameter taint.
    found = False
    for srcs in eng.provenance.sources.values():
        if _has_source_kind(srcs, "external_call") and _has_source_kind(srcs, "parameter"):
            external = _find_source_with_kind(srcs, "external_call")
            assert external is not None
            assert external.callee == "call", f"expected callee='call', got {external.callee!r}"
            found = True
            break
    assert found, f"low_level_call didn't produce external_call+parameter taint. map={dict(eng.provenance.sources)}"


def test_staticcall_classified(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(address target, bytes calldata data) external view returns (bool, bytes memory) {
                return target.staticcall(data);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    found_staticcall = False
    for srcs in eng.provenance.sources.values():
        ext = _find_source_with_kind(srcs, "external_call")
        if ext and ext.callee == "staticcall":
            found_staticcall = True
            break
    assert found_staticcall, f"staticcall not classified with callee='staticcall'. map={dict(eng.provenance.sources)}"


def test_delegatecall_preserves_destination_taint(tmp_path):
    """delegatecall is structurally distinguished by ``callee==
    'delegatecall'``. The destination's provenance must travel
    through into the result so a downstream analyzer can see if the
    target was caller-controlled."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(bytes calldata data) external returns (bool) {
                (bool ok, ) = msg.sender.delegatecall(data);
                return ok;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # The result must carry both external_call(callee=delegatecall)
    # AND msg_sender (because the destination was msg.sender).
    found = False
    for srcs in eng.provenance.sources.values():
        ext = _find_source_with_kind(srcs, "external_call")
        if ext and ext.callee == "delegatecall" and _has_source_kind(srcs, "msg_sender"):
            found = True
            break
    assert found, (
        f"delegatecall with msg.sender destination didn't preserve msg_sender taint. map={dict(eng.provenance.sources)}"
    )


def test_member_records_field_name(tmp_path):
    """``s.field`` should produce a ``computed`` source whose
    ``computed_kind`` is ``member.<field_name>`` AND preserve the
    base's provenance. Critical for the OZ role-mapping pattern:
    ``_roles[role].adminRole`` must surface both the parameter taint
    (so the predicate builder marks it parametric) AND the field name
    (so the builder can recognize the getRoleAdmin shape)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            struct Role { bytes32 adminRole; uint256 nonce; }
            mapping(bytes32 => Role) _roles;
            function f(bytes32 role) external view returns (bytes32) {
                return _roles[role].adminRole;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # We want a value whose source set has BOTH:
    #   - parameter taint (from `role`)
    #   - state_variable taint (from `_roles`)
    #   - computed source with computed_kind == "member.adminRole"
    found = False
    for srcs in eng.provenance.sources.values():
        member = next((s for s in srcs if s.kind == "computed" and (s.computed_kind or "").startswith("member.")), None)
        if member and member.computed_kind == "member.adminRole":
            assert _has_source_kind(srcs, "parameter")
            assert _has_source_kind(srcs, "state_variable")
            found = True
            break
    assert found, (
        f"member access didn't record field name 'adminRole' alongside base taint. map={dict(eng.provenance.sources)}"
    )


def test_env_override_internal_call_depth(monkeypatch):
    """``PSAT_PROVENANCE_INTERNAL_CALL_DEPTH`` env var overrides the
    default recursion depth, so pipeline runs can tune without code
    changes."""
    from importlib import reload

    import services.static.contract_analysis_pipeline.provenance as prov

    monkeypatch.setenv("PSAT_PROVENANCE_INTERNAL_CALL_DEPTH", "9")
    monkeypatch.setenv("PSAT_PROVENANCE_WORKLIST_CAP", "37")
    reload(prov)
    assert prov.DEFAULT_INTERNAL_CALL_DEPTH == 9
    assert prov.DEFAULT_WORKLIST_ITER_CAP == 37
    # Bad values fall back to the hard-coded default.
    monkeypatch.setenv("PSAT_PROVENANCE_INTERNAL_CALL_DEPTH", "not_a_number")
    monkeypatch.setenv("PSAT_PROVENANCE_WORKLIST_CAP", "-1")
    reload(prov)
    assert prov.DEFAULT_INTERNAL_CALL_DEPTH == 4
    assert prov.DEFAULT_WORKLIST_ITER_CAP == 200
    # Clean up — re-import without env vars set.
    monkeypatch.delenv("PSAT_PROVENANCE_INTERNAL_CALL_DEPTH", raising=False)
    monkeypatch.delenv("PSAT_PROVENANCE_WORKLIST_CAP", raising=False)
    reload(prov)


def test_loop_phi_converges_with_loop_carried_taint(tmp_path):
    """A loop-carried variable's provenance must reach a fixed point
    that includes both the entry-block source AND the loop-body
    source. The worklist iterator handles Phi unions; this test
    pins that the result actually converges (no oscillation, no
    saturation to TOP for a clean monotonic increase)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public seed;
            function f(uint256[] calldata vals) external view returns (uint256) {
                uint256 acc = seed;
                for (uint256 i = 0; i < vals.length; i++) {
                    acc = acc + vals[i];
                }
                return acc;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # Some SSA value (the converged `acc`) must carry both
    # state_variable (from `seed`) and parameter (from `vals`) taint.
    found = False
    for srcs in eng.provenance.sources.values():
        if _has_source_kind(srcs, "state_variable") and _has_source_kind(srcs, "parameter"):
            found = True
            break
    assert found, f"loop accumulator didn't converge with both seed+vals taint. map={dict(eng.provenance.sources)}"
    # Negative invariant: the accumulator should NOT have been saturated
    # to TOP. A monotonic union over a finite source set converges
    # cleanly in Slither's bounded SSA.
    seed_sources = eng.provenance.sources
    has_top_in_loop_var = any(is_top(srcs) for srcs in seed_sources.values())
    assert not has_top_in_loop_var, (
        "loop accumulator saturated to TOP — worklist may be oscillating or Phi handler is wrong"
    )


def test_loop_iteration_cap_terminates(tmp_path):
    """Even with a pathologically deep loop body the worklist must
    terminate within the iteration cap. We use a tiny cap to force
    the cap-hit path; the engine must NOT raise or hang."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(uint256 n) external pure returns (uint256) {
                uint256 acc;
                for (uint256 i = 0; i < n; i++) {
                    acc = acc + i;
                }
                return acc;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn, worklist_cap=1)  # force cap hit
    eng.run()  # must terminate, must not raise


def test_sub_engine_memo_collapses_repeated_internal_calls(tmp_path):
    """Per-engine memo on (callee_full_name, frozenset(bindings.items()))
    should make repeat InternalCall handling within ONE run() return a
    cache hit instead of spawning a fresh sub-engine each time. The
    worklist iterates to fixed point and re-visits the same IR nodes
    multiple times — without the memo, each visit re-runs the callee's
    sub-engine which compounds quadratically.

    Memo only fires for InternalCall IRs WITH an lvalue (i.e. helpers
    that return a value). Modifier-style void internal calls take a
    different path. Use a return-value helper here so the memo is
    exercised.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function _resolve(address u) internal view returns (uint256) {
                return uint256(uint160(u));
            }
            function f(address u) external {
                require(_resolve(u) > 0);
                require(_resolve(u) < type(uint128).max);
                x = 1;
            }
        }
        """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # The two `_resolve(u)` call sites have identical bindings; the
    # memo must collapse them so both are served from one cache entry.
    assert eng._sub_engine_memo, (
        "expected _sub_engine_memo to be populated after a value-returning "
        "internal-call run; the optimization path didn't fire"
    )
    # Stability across re-runs: keys must not multiply.
    pre_keys = set(eng._sub_engine_memo.keys())
    eng.run()
    assert set(eng._sub_engine_memo.keys()) == pre_keys, (
        "re-running the same engine introduced new memo keys — bindings may have shifted, breaking memo stability"
    )


def test_leaf_value_source_cache_collapses_repeat_resolutions(tmp_path):
    """Per-engine ``_leaf_value_source_cache`` short-circuits the
    isinstance chain for SolidityVariable / Constant / StateVariable
    after the first resolution. The worklist iterates to fixed point
    so the same operand is re-resolved many times — caching by id
    collapses each unique value to one classification call. Bounded
    lifetime (= engine instance), so no cross-Slither-instance id
    reuse risk.

    Pin: a function with msg.sender + state-var reads + a literal
    constant should populate at least one entry of each leaf kind in
    the cache after a single run().
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public counter;
            function f() external view {
                require(msg.sender == ownerVar);
                require(counter > 100);
            }
        }
        """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    cache_kinds = set()
    for sources in eng._leaf_value_source_cache.values():
        for src in sources:
            cache_kinds.add(src.kind)
    # msg.sender → msg_sender; ownerVar/counter → state_variable;
    # 100 → constant. All three must be present.
    assert "msg_sender" in cache_kinds, cache_kinds
    assert "state_variable" in cache_kinds, cache_kinds
    assert "constant" in cache_kinds, cache_kinds
    # Variables (Local/Temporary/Reference) must NOT be cached —
    # their provenance changes during dataflow convergence.
    for sources in eng._leaf_value_source_cache.values():
        for src in sources:
            assert src.kind not in ("parameter", "local", "temporary", "reference"), (
                f"Variable subtype leaked into leaf cache: {src.kind} ({sources})"
            )


def test_shared_modifier_phi_does_not_pollute_function_parameter(tmp_path):
    """Slither shares a modifier's SSA-IR across every caller, so the
    modifier-entry Phi for a modifier parameter unions ALL call-site
    arguments — one rvalue per function that uses the modifier. When
    the modifier parameter shares a NAME with one of the function's
    parameters (the canonical OZ ``modifier onlyRole(bytes32 role)``
    + ``function revokeRole(bytes32 role, ...)`` shape), iterating
    that Phi in the function's engine would pollute the function's
    parameter provenance with every OTHER caller's argument.

    Pre-fix: on CumulativeMerkleDrop this turned a 5-IR function into
    a 200-iter-cap saturated build (~18 s/fn, 17 min for the contract).
    The bindings of downstream ``_handle_internal_call`` invocations
    kept growing — state variables from other call sites accreting —
    so ``_sub_engine_memo`` keyed on ``(callee, bindings)`` missed
    every iteration and the same sub-engines respawned 200×.

    The fix: ``_iter_nodes`` no longer yields modifier bodies. The
    cross-fn revert path (modifier → helper → ``if (!check) revert``)
    is independently handled by ``RevertDetector`` + ``_build_chain_bindings``,
    so we lose nothing.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) internal _roles;
            bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
            bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR");
            bytes32 public constant PAUSER_ROLE = keccak256("PAUSER");

            modifier onlyRole(bytes32 role) {
                require(_roles[role][msg.sender], "missing role");
                _;
            }

            // Multiple users of the modifier — each contributes an rvalue
            // to the modifier-entry Phi's lvalue named ``role``. Without
            // the fix, processing this Phi inside ``revokeRole``'s engine
            // unions PAUSER_ROLE / OPERATOR_ROLE / DEFAULT_ADMIN_ROLE into
            // ``role``'s provenance, then propagates into downstream
            // ``_grantRole(role, ...)`` bindings.
            function pause() external onlyRole(PAUSER_ROLE) {}
            function setOperator() external onlyRole(OPERATOR_ROLE) {}
            function grantRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
                _roles[role][account] = true;
            }
            function revokeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
                _roles[role][account] = false;
            }
        }
        """,
    )
    fn = _function(sl, "revokeRole")
    eng = ProvenanceEngine(fn)
    eng.run()

    role_sources = eng.provenance.get("role")
    assert role_sources, "expected `role` parameter to be seeded"
    # The function's ``role`` parameter is bound to its caller's
    # argument — never reads a state variable. If we see the modifier-
    # entry Phi's rvalues (PAUSER_ROLE / OPERATOR_ROLE state vars), the
    # bug is back.
    polluted_state_vars = {s.state_variable_name for s in role_sources if s.kind == "state_variable"}
    assert not polluted_state_vars, (
        f"`role`'s provenance was polluted by the modifier-shared Phi: "
        f"state_variable sources leaked in = {polluted_state_vars}. "
        "This is the CumulativeMerkleDrop 782 s build bug — the function's "
        "parameter must NOT pick up rvalues from a modifier-entry Phi shared "
        "across all callers of the modifier."
    )


def test_unpack_propagates_tuple_provenance(tmp_path):
    """After ``(bool ok, ) = target.call(data);``, the unpacked ``ok``
    SSA value inherits the tuple's full provenance set."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(address target, bytes calldata data) external returns (bool) {
                (bool ok, ) = target.call(data);
                return ok;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    # `ok` is unpacked from the tuple; it should carry external_call source.
    has_ok_with_external = any(
        name.startswith("ok") and _has_source_kind(srcs, "external_call")
        for name, srcs in eng.provenance.sources.items()
    )
    assert has_ok_with_external, (
        f"unpacked `ok` didn't inherit external_call source. map={dict(eng.provenance.sources)}"
    )


# ---------------------------------------------------------------------------
# ``callee_args_digest`` is content-stable across processes/seeds.
# ---------------------------------------------------------------------------

_DIGEST_SNIPPET = """
import sys
sys.path.insert(0, {repo!r})
from services.static.contract_analysis_pipeline.provenance import Source, _digest
a = frozenset({{
    Source(kind="parameter", parameter_index=0, parameter_name="who"),
    Source(kind="state_variable", state_variable_name="owner"),
    Source(
        kind="view_call",
        callee="registry",
        callee_signature="hasRole(address,uint256)",
        callee_args_digest=_digest(frozenset({{Source(kind="msg_sender")}})),
    ),
}})
b = frozenset({{Source(kind="parameter", parameter_index=1, parameter_name="amt")}})
print(_digest(a), _digest(b))
"""


def _digests_under_seed(seed: str) -> list[str]:
    import os
    import subprocess

    repo = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ, PYTHONHASHSEED=seed)
    out = subprocess.run(
        [sys.executable, "-c", _DIGEST_SNIPPET.format(repo=repo)],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.split()


def test_callee_args_digest_is_seed_independent():
    """The digest of the same SourceSet is byte-identical under different
    PYTHONHASHSEED values (it is content-derived, not ``hash()``-derived), and
    two different SourceSets still get different digests (the discriminating
    role the field exists for)."""
    run_a = _digests_under_seed("0")
    run_b = _digests_under_seed("12345")
    assert run_a == run_b, f"digest varies with hash seed: {run_a} vs {run_b}"
    assert run_a[0] != run_a[1], "different SourceSets collapsed to one digest"


def test_operand_tie_break_is_seed_independent():
    """Two computed Sources tied on every sort-key field before the digest
    (same kind, no parameter/state/callee identity) must
    resolve to the SAME published operand in every process. Before the fix the
    winner was ordered by a ``hash()``-seeded digest string; 37-46 operand
    slots flickered across 25/88 production units."""
    import os
    import subprocess

    repo = str(Path(__file__).resolve().parents[1])
    snippet = """
import sys
sys.path.insert(0, {repo!r})
from services.static.contract_analysis_pipeline.provenance import ProvenanceMap, Source, _digest
from services.static.contract_analysis_pipeline.predicates import _operand_for_value


class _Fake:
    name = "v_0"


sources = frozenset({{
    Source(
        kind="computed",
        computed_kind="BinaryType.AND",
        callee_args_digest=_digest(frozenset({{Source(kind="parameter", parameter_index=0)}})),
    ),
    Source(
        kind="computed",
        computed_kind="call(uint256,uint256)",
        callee_args_digest=_digest(frozenset({{Source(kind="parameter", parameter_index=1)}})),
    ),
}})
prov = ProvenanceMap(sources={{"v_0": sources}})
print(_operand_for_value(_Fake(), prov)["computed_kind"])
"""
    winners = set()
    for seed in ("0", "1", "31337"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run(
            [sys.executable, "-c", snippet.format(repo=repo)],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        winners.add(out.stdout.strip())
    assert len(winners) == 1, f"operand winner flickers with hash seed: {winners}"
