"""Provenance is asserted by semantic position (parameter / state read / call return), not Slither's SSA naming."""

from __future__ import annotations

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
from tests.support.slither_compile import _compile  # noqa: E402


def _function(sl: Slither, fn_name: str):
    for c in sl.contracts:
        for f in c.functions:
            if f.name == fn_name:
                return f
    raise LookupError(fn_name)


def _has_source_kind(sources, kind: str) -> bool:
    return any(s.kind == kind for s in sources)


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
