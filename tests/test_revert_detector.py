"""Tests for ``RevertDetector``.

Covers each of the 8 revert-pattern cases from v4 plan round-2 #8.
For each, we compile a tiny Solidity contract and assert RevertDetector
finds exactly the expected RevertGate(s) with the correct kind +
polarity. The condition_value identity isn't pinned (Slither-version
dependent SSA renaming); we focus on count + kind + polarity.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.revert_detect import (  # noqa: E402
    RevertDetector,
    RevertGate,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _function(sl: Slither, name: str):
    for c in sl.contracts:
        for f in c.functions:
            if f.name == name:
                return f
    raise LookupError(name)


def _gate_kinds(gates: list[RevertGate]) -> list[str]:
    return [g.kind for g in gates]


# ---------------------------------------------------------------------------
# Case 1: require
# ---------------------------------------------------------------------------


def test_require_simple(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view {
                require(msg.sender == ownerVar);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    kinds = _gate_kinds(gates)
    assert "require" in kinds
    req = next(g for g in gates if g.kind == "require")
    assert req.polarity == "allowed_when_true"
    assert req.condition_value is not None


def test_require_with_message(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public threshold;
            function f(uint256 amount) external view {
                require(amount > threshold, "too low");
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert any(g.kind == "require" for g in gates)


# ---------------------------------------------------------------------------
# Case 2: assert
# ---------------------------------------------------------------------------


def test_assert(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(uint256 x) external pure {
                assert(x > 0);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert any(g.kind == "assert" for g in gates)


# ---------------------------------------------------------------------------
# Case 3: if (C) revert
# ---------------------------------------------------------------------------


def test_if_revert_inverts_polarity(tmp_path):
    """``if (bad) revert`` means allowed when bad is false. Polarity
    must be ``allowed_when_false``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view {
                if (msg.sender != ownerVar) revert();
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    if_gates = [g for g in gates if g.kind in ("if_revert", "custom_revert")]
    assert len(if_gates) >= 1, f"expected one if-revert gate, got: {_gate_kinds(gates)}"
    assert if_gates[0].polarity == "allowed_when_false"


def test_if_revert_custom_error(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            error NotOwner();
            function f() external view {
                if (msg.sender != ownerVar) revert NotOwner();
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert any(g.kind in ("custom_revert", "if_revert") for g in gates), _gate_kinds(gates)


# ---------------------------------------------------------------------------
# Case 5: inline assembly conditional revert
# ---------------------------------------------------------------------------


def test_inline_asm_conditional_revert_structurally_parsed(tmp_path):
    """``assembly { if iszero(x) { revert(0,0) } }`` is parsed by
    Slither into structured IF + SolidityCall(revert(uint256,uint256)).
    The detector captures this via the standard if-revert path, so
    the gate kind is ``if_revert`` (not ``inline_asm``) — high-fidelity
    classification."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(uint256 x) external pure {
                assembly {
                    if iszero(x) { revert(0, 0) }
                }
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert any(g.kind == "if_revert" for g in gates), _gate_kinds(gates)


def test_pure_compute_assembly_yields_no_gates(tmp_path):
    """An assembly block doing memory ops with no revert is genuinely
    ungated — RevertDetector returns ``[]``. The opaque marker is
    reserved for assembly that has a textual `revert` we couldn't
    structurally extract; pure compute is fine."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f() external pure returns (uint256 r) {
                assembly {
                    let p := mload(0x40)
                    r := mul(p, 2)
                }
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert gates == []


# ---------------------------------------------------------------------------
# Sanity: function with no revert paths returns no gates.
# ---------------------------------------------------------------------------


def test_no_gates_for_unguarded_function(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f() external {
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert gates == []


# ---------------------------------------------------------------------------
# Multiple sequential gates → multiple RevertGate records.
# ---------------------------------------------------------------------------


def test_two_requires_yields_two_gates(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public threshold;
            function f(uint256 amount) external view {
                require(msg.sender == ownerVar);
                require(amount > threshold);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    require_count = sum(1 for g in gates if g.kind == "require")
    assert require_count == 2, f"expected 2 require gates, got {require_count}: {_gate_kinds(gates)}"


# ---------------------------------------------------------------------------
# Case 6: try/catch revert
# ---------------------------------------------------------------------------


def test_try_catch_with_revert_in_catch_emits_opaque_gate(tmp_path):
    """``try x.foo() {} catch { revert(); }`` reverts iff the
    external call reverts. We can't classify the gate structurally
    without recursing into the called contract, so we emit an
    opaque gate flagged ``opaque_try_catch``. Without this the
    function looks unguarded — strictly worse than reporting
    'we know there's a gate but can't characterize it.'"""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface Helper { function helper() external; }
        contract C {
            Helper public h;
            constructor(address h_) { h = Helper(h_); }
            function caller() external {
                try h.helper() {} catch {
                    revert("oops");
                }
            }
        }
    """,
    )
    fn = _function(sl, "caller")
    gates = RevertDetector(fn).run()
    assert len(gates) == 1
    g = gates[0]
    assert g.kind == "opaque"
    assert g.unsupported_reason == "opaque_try_catch"


def test_try_catch_without_revert_in_catch_emits_no_gate(tmp_path):
    """``try x.foo() {} catch {}`` swallows any revert — the
    function is unguarded by the try/catch. Verifies we don't
    over-emit gates when the catch is empty."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface Helper { function helper() external; }
        contract C {
            Helper public h;
            constructor(address h_) { h = Helper(h_); }
            function caller() external {
                try h.helper() {} catch {}
            }
        }
    """,
    )
    fn = _function(sl, "caller")
    gates = RevertDetector(fn).run()
    assert gates == []


def test_try_catch_with_require_in_catch_also_emits_gate(tmp_path):
    """``catch { require(false); }`` is the same shape as a bare
    revert — also emits an opaque gate."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface Helper { function helper() external; }
        contract C {
            Helper public h;
            constructor(address h_) { h = Helper(h_); }
            function caller() external {
                try h.helper() {} catch {
                    require(false, "oops");
                }
            }
        }
    """,
    )
    fn = _function(sl, "caller")
    gates = RevertDetector(fn).run()
    assert any(g.kind == "opaque" and g.unsupported_reason == "opaque_try_catch" for g in gates)


def test_bare_void_state_var_call_is_semantic_precondition(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IGate {
            function check(address who) external view;
        }
        contract C {
            IGate public gate;
            uint256 public x;
            function f() external {
                gate.check(msg.sender);
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert any(g.kind == "external_call_revert" for g in gates)


# ---------------------------------------------------------------------------
# Bug 1: try/catch wrapping a single external authority-check call should not
# collapse to opaque(opaque_try_catch). Recognising the shape (one
# HighLevelCall whose return drives the body's require/revert) lets the
# downstream pipeline preserve the call selector + target contract, which the
# capability resolver then uses to expand into actual member addresses.
# Currently the analyzer paints any try-with-revert-in-catch as opaque, which
# cascades through `intersect()` as `unsupported`, and EtherFi's
# UUPSUpgradeable.upgradeTo ends up unresolvable on the surface page.
# ---------------------------------------------------------------------------


def test_try_catch_around_external_authority_call_is_not_opaque(tmp_path):
    """``try authority.canCall(...) returns (bool ok) { require(ok); }
    catch { revert; }`` is the OZ AccessManaged / EtherFi RoleRegistry
    upgrade pattern. The body has a single HighLevelCall whose return
    value gates a require — the gate is not opaque, it's an external
    authority check on ``authority.canCall``. Downstream should be able
    to identify the target call and resolve it to the role's holders."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function canCall(address caller, address target, bytes4 sig) external view returns (bool);
        }
        contract C {
            IAuthority public authority;
            constructor(address a) { authority = IAuthority(a); }
            function upgradeTo(address) external {
                try authority.canCall(msg.sender, address(this), msg.sig) returns (bool ok) {
                    require(ok, "not authorized");
                } catch {
                    revert("auth call failed");
                }
            }
        }
    """,
    )
    fn = _function(sl, "upgradeTo")
    gates = RevertDetector(fn).run()
    # We expect at least one gate that is NOT the catch-all opaque marker.
    assert gates, "expected at least one revert gate"
    opaque_only = all(g.kind == "opaque" and g.unsupported_reason == "opaque_try_catch" for g in gates)
    assert not opaque_only, (
        "try/catch wrapping a single authority-check call collapsed to opaque(opaque_try_catch); "
        "expected kind='try_catch_revert' (or similar non-opaque kind) so the call selector + "
        "target are recoverable downstream"
    )
    # And specifically: at least one gate carries the recognised try-catch shape.
    assert any(g.kind == "try_catch_revert" for g in gates), (
        f"no gate with kind='try_catch_revert' found; got kinds={_gate_kinds(gates)}"
    )


# ---------------------------------------------------------------------------
# Custom-error require — ``require(cond, MyError())`` (Solidity >=0.8.26).
# Slither lowers this to a SolidityCall named ``require(bool,error)``. Dropping
# it left the predicate tree empty and the function defaulted to public; it must
# be lifted exactly like ``require(bool)`` / ``require(bool,string)``.
# ---------------------------------------------------------------------------


def _solc_086(version: str = "0.8.27") -> str:
    """Return a >=0.8.26 solc binary path (install on demand), so the custom-error
    require form parses. CI-safe: resolves through solc-select's own store."""
    import solc_select.solc_select as ss

    if version not in ss.installed_versions():
        ss.install_artifacts([version])
    return str(ss.artifact_path(version))


def _compile_086(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f), solc=_solc_086())


def test_require_custom_error_is_lifted(tmp_path):
    """``require(msg.sender == owner, NotOwner())`` must yield a ``require`` gate
    with the caller-equality condition — not an empty gate list."""
    sl = _compile_086(
        tmp_path,
        """
        pragma solidity 0.8.27;
        contract C {
            address public owner;
            error NotOwner();
            function f() external view {
                require(msg.sender == owner, NotOwner());
            }
        }
        """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert any(g.kind == "require" for g in gates), (
        f"custom-error require dropped: expected a 'require' gate, got {_gate_kinds(gates)}"
    )
    req = next(g for g in gates if g.kind == "require")
    assert req.polarity == "allowed_when_true"
    assert req.condition_value is not None


def test_require_custom_error_with_args_is_lifted(tmp_path):
    """The error constructor taking arguments (``MyError(x)``) is the same
    ``require(bool,error)`` SolidityCall shape — also lifted."""
    sl = _compile_086(
        tmp_path,
        """
        pragma solidity 0.8.27;
        contract C {
            address public owner;
            error Unauthorized(address caller);
            function f() external view {
                require(msg.sender == owner, Unauthorized(msg.sender));
            }
        }
        """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert any(g.kind == "require" for g in gates), _gate_kinds(gates)


# ---------------------------------------------------------------------------
# Coverage invariant — a require/assert SolidityCall we walked but did not lift
# into a gate must surface as ``unsupported`` (fail closed), never be silently
# dropped (which defaults the function to public).
# ---------------------------------------------------------------------------


def test_unmodeled_require_fails_closed(tmp_path, monkeypatch):
    """If the structural lifter rejects a require form, the coverage invariant
    emits an ``opaque``/``unsupported`` gate so the tree is non-empty and the
    function resolves gated. Simulated here by forcing ``_ir_is_require`` to
    reject every require — a stand-in for any future unmodeled form."""
    import services.static.contract_analysis_pipeline.revert_detect as rd

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            function f() external view {
                require(msg.sender == owner);
            }
        }
        """,
    )
    fn = _function(sl, "f")

    # Baseline: with the require recognised, there is no unmodeled-gate marker.
    baseline = RevertDetector(fn).run()
    assert not any(g.unsupported_reason == "unmodeled_require_gate" for g in baseline)
    assert any(g.kind == "require" for g in baseline)

    # Reject every require → the walked-but-unlifted require must be caught.
    monkeypatch.setattr(rd, "_ir_is_require", lambda ir: False)
    gates = RevertDetector(fn).run()
    assert any(g.kind == "opaque" and g.unsupported_reason == "unmodeled_require_gate" for g in gates), (
        "an unmodeled require slipped through with no gate — the function would "
        f"default to public; got {_gate_kinds(gates)}"
    )


def test_genuinely_ungated_function_stays_gateless(tmp_path):
    """The coverage invariant must NOT fire on a function with no require/assert
    at all — a genuinely permissionless function still yields zero gates (→ the
    deliberate public default), not a spurious unsupported gate."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public total;
            function f() external view returns (uint256) { return total; }
        }
        """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert gates == [], f"expected no gates for an ungated function, got {_gate_kinds(gates)}"


# ---------------------------------------------------------------------------
# Discarded-result guard helpers: the require lives in a bool-returning
# callee whose result the caller ignores.
# ---------------------------------------------------------------------------


def test_discarded_bool_guard_helper_gate_is_found(tmp_path):
    """``modifier hasRole(r) { _hasRole(r, msg.sender); _; }`` calls a
    bool-returning guard and ignores the bool — the require lives in the
    callee. The lvalue-skip used to drop this gate entirely (every
    EtherFiRedemptionManager admin function defaulted to public)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IRoleRegistry { function hasRole(bytes32 role, address account) external view returns (bool); }
        contract C {
            IRoleRegistry public roleRegistry;
            function _hasRole(bytes32 role, address account) internal view returns (bool) {
                require(roleRegistry.hasRole(role, account), "Unauthorized");
                return true;
            }
            modifier hasRole(bytes32 role) {
                _hasRole(role, msg.sender);
                _;
            }
            function pauseContract() external hasRole(keccak256("PAUSER")) {}
        }
    """,
    )
    fn = _function(sl, "pauseContract")
    gates = RevertDetector(fn).run()
    requires = [g for g in gates if g.kind == "require"]
    assert requires, f"the guard helper's require must be lifted, got kinds={_gate_kinds(gates)}"


def test_consumed_bool_helper_result_is_not_double_walked(tmp_path):
    """``require(_check(msg.sender))`` — the result feeds the caller's own
    require, which the predicate builder lifts; the recursion must not also
    walk the callee and emit a duplicate gate for the same condition."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) public allowed;
            function _check(address who) internal view returns (bool) {
                return allowed[who];
            }
            function f() external view {
                require(_check(msg.sender), "no");
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert _gate_kinds(gates) == ["require"], f"expected the single caller-side require, got {_gate_kinds(gates)}"
