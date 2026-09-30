"""Provenance is asserted by semantic position (parameter / state read / call return), not Slither's SSA naming."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

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


_SENDER = frozenset({Source(kind="msg_sender")})
_PARAM0 = frozenset({Source(kind="parameter", parameter_index=0)})


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        pytest.param(_SENDER, _PARAM0, _SENDER | _PARAM0, id="union_basic"),
        pytest.param(_SENDER, TOP, TOP, id="top_absorbs_right"),
        pytest.param(TOP, _SENDER, TOP, id="top_absorbs_left"),
        pytest.param(_PARAM0, EMPTY, _PARAM0, id="empty_identity_right"),
        pytest.param(EMPTY, _PARAM0, _PARAM0, id="empty_identity_left"),
    ],
)
def test_lattice_union(left, right, expected):
    out = union(left, right)
    assert out == expected
    assert is_top(out) == is_top(expected)


def test_is_top_singleton_invariant():
    """``is_top`` is O(1) only if every top Source equals the bare sentinel."""
    import pytest as _pytest

    assert is_top(TOP)
    assert is_top(frozenset({Source(kind="top")}))

    assert not is_top(frozenset({Source(kind="parameter", parameter_index=0)}))
    assert not is_top(frozenset())

    # One assertion per field so a broken one is named.
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
    has_computed = any(_has_source_kind(srcs, "computed") for srcs in eng.provenance.sources.values())
    has_sig = any(_has_source_kind(srcs, "signature_recovery") for srcs in eng.provenance.sources.values())
    assert has_computed
    assert not has_sig, "keccak256 was misclassified as signature_recovery"


def _keccak_sources(eng) -> frozenset[Source]:
    for srcs in eng.provenance.sources.values():
        for source in srcs:
            if source.kind == "computed" and (source.computed_kind or "").startswith("keccak256"):
                return srcs
    raise AssertionError(f"no keccak256 computed source. map={dict(eng.provenance.sources)}")


def test_keccak_binds_the_parameters_it_commits_through_abi_encode(tmp_path):
    """``x`` reaches ``keccak256`` only through ``abi.encode``, whose origins must be spliced in."""
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
    assert any(o.kind == "computed" and (o.computed_kind or "").startswith("abi.encode") for o in keccak.derived_from)
    assert all(o.derived_from is None for o in keccak.derived_from)


def test_keccak_over_constants_is_determined_empty_not_unknown(tmp_path):
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
    """``msg.value`` mints its source outside the Solidity-call handler; ``frozenset()`` would claim nothing reached
    it.
    """
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
    has_caller = any(_has_source_kind(srcs, "msg_sender") for srcs in eng.provenance.sources.values())
    assert has_caller, f"internal call didn't propagate msg_sender. map={dict(eng.provenance.sources)}"


def test_internal_call_depth_cap_does_not_crash(tmp_path):
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
    eng.run()


def test_block_timestamp_classified(tmp_path):
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


@pytest.mark.parametrize(
    ("body", "callee", "extra_kinds"),
    [
        pytest.param(
            """
            function f(address target, bytes calldata data) external returns (bool, bytes memory) {
                (bool ok, bytes memory r) = target.call(data);
                return (ok, r);
            }
            """,
            "call",
            ("parameter",),
            id="call",
        ),
        pytest.param(
            """
            function f(address target, bytes calldata data) external view returns (bool, bytes memory) {
                return target.staticcall(data);
            }
            """,
            "staticcall",
            (),
            id="staticcall",
        ),
        pytest.param(
            """
            function f(bytes calldata data) external returns (bool) {
                (bool ok, ) = msg.sender.delegatecall(data);
                return ok;
            }
            """,
            "delegatecall",
            ("msg_sender",),
            id="delegatecall_preserves_destination_taint",
        ),
    ],
)
def test_low_level_call_classified(tmp_path, body, callee, extra_kinds):
    sl = _compile(
        tmp_path,
        "pragma solidity ^0.8.19;\ncontract C {\n" + textwrap.dedent(body) + "\n}\n",
    )
    fn = _function(sl, "f")
    eng = ProvenanceEngine(fn)
    eng.run()
    found = False
    for srcs in eng.provenance.sources.values():
        ext = _find_source_with_kind(srcs, "external_call")
        if ext and ext.callee == callee and all(_has_source_kind(srcs, k) for k in extra_kinds):
            found = True
            break
    assert found, (
        f"{callee} not classified as external_call(callee={callee!r}) with {extra_kinds} taint. "
        f"map={dict(eng.provenance.sources)}"
    )


def test_member_records_field_name(tmp_path):
    """``_roles[role].adminRole`` must surface the parameter taint and the field name for the getRoleAdmin shape."""
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
    from importlib import reload

    import services.static.contract_analysis_pipeline.provenance as prov

    monkeypatch.setenv("PSAT_PROVENANCE_INTERNAL_CALL_DEPTH", "9")
    monkeypatch.setenv("PSAT_PROVENANCE_WORKLIST_CAP", "37")
    reload(prov)
    assert prov.DEFAULT_INTERNAL_CALL_DEPTH == 9
    assert prov.DEFAULT_WORKLIST_ITER_CAP == 37
    monkeypatch.setenv("PSAT_PROVENANCE_INTERNAL_CALL_DEPTH", "not_a_number")
    monkeypatch.setenv("PSAT_PROVENANCE_WORKLIST_CAP", "-1")
    reload(prov)
    assert prov.DEFAULT_INTERNAL_CALL_DEPTH == 4
    assert prov.DEFAULT_WORKLIST_ITER_CAP == 200
    monkeypatch.delenv("PSAT_PROVENANCE_INTERNAL_CALL_DEPTH", raising=False)
    monkeypatch.delenv("PSAT_PROVENANCE_WORKLIST_CAP", raising=False)
    reload(prov)


def test_loop_phi_converges_with_loop_carried_taint(tmp_path):
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
    found = False
    for srcs in eng.provenance.sources.values():
        if _has_source_kind(srcs, "state_variable") and _has_source_kind(srcs, "parameter"):
            found = True
            break
    assert found, f"loop accumulator didn't converge with both seed+vals taint. map={dict(eng.provenance.sources)}"
    seed_sources = eng.provenance.sources
    has_top_in_loop_var = any(is_top(srcs) for srcs in seed_sources.values())
    assert not has_top_in_loop_var, (
        "loop accumulator saturated to TOP — worklist may be oscillating or Phi handler is wrong"
    )


def test_loop_iteration_cap_terminates(tmp_path):
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
    """Without the memo the fixed-point worklist re-runs the callee sub-engine on every revisit.

    Only InternalCalls with an lvalue hit it.
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
    assert eng._sub_engine_memo, (
        "expected _sub_engine_memo to be populated after a value-returning "
        "internal-call run; the optimization path didn't fire"
    )
    pre_keys = set(eng._sub_engine_memo.keys())
    eng.run()
    assert set(eng._sub_engine_memo.keys()) == pre_keys, (
        "re-running the same engine introduced new memo keys — bindings may have shifted, breaking memo stability"
    )


def test_shared_modifier_phi_does_not_pollute_function_parameter(tmp_path):
    """Slither shares a modifier's SSA across callers, so its entry Phi unions every call site's argument.

    On CumulativeMerkleDrop this saturated the 200-iter cap (17 min per contract). ``_iter_nodes`` no longer yields
    modifier bodies; ``RevertDetector`` covers the cross-fn path.
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
    # Seeing PAUSER_ROLE / OPERATOR_ROLE means the bug is back.
    polluted_state_vars = {s.state_variable_name for s in role_sources if s.kind == "state_variable"}
    assert not polluted_state_vars, (
        f"`role`'s provenance was polluted by the modifier-shared Phi: "
        f"state_variable sources leaked in = {polluted_state_vars}. "
        "This is the CumulativeMerkleDrop 782 s build bug — the function's "
        "parameter must NOT pick up rvalues from a modifier-entry Phi shared "
        "across all callers of the modifier."
    )


def test_unpack_propagates_tuple_provenance(tmp_path):
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
    has_ok_with_external = any(
        name.startswith("ok") and _has_source_kind(srcs, "external_call")
        for name, srcs in eng.provenance.sources.items()
    )
    assert has_ok_with_external, (
        f"unpacked `ok` didn't inherit external_call source. map={dict(eng.provenance.sources)}"
    )


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

    repo = str(Path(__file__).resolve().parents[2])
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
    run_a = _digests_under_seed("0")
    run_b = _digests_under_seed("12345")
    assert run_a == run_b, f"digest varies with hash seed: {run_a} vs {run_b}"
    assert run_a[0] != run_a[1], "different SourceSets collapsed to one digest"


def test_operand_tie_break_is_seed_independent():
    """A ``hash()``-seeded tie-break flickered 37-46 operand slots across 25/88 production units."""
    import os
    import subprocess

    repo = str(Path(__file__).resolve().parents[2])
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
