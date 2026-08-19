"""Tests for ``RevertDetector``.

Covers each of the 8 revert-pattern cases.
For each, we compile a tiny Solidity contract and assert RevertDetector
finds exactly the expected RevertGate(s) with the correct kind +
polarity. The condition_value identity isn't pinned (Slither-version
dependent SSA renaming); we focus on count + kind + polarity.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.predicate_evaluator import evaluate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.contract_analysis_pipeline.reentrancy_pause import (  # noqa: E402
    apply_reentrancy_pause_pass,
)
from services.static.contract_analysis_pipeline.revert_detect import (  # noqa: E402
    RevertDetector,
    RevertGate,
)
from services.static.contract_analysis_pipeline.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)

pytestmark = pytest.mark.compile


def _cap_for(sl: Slither, full_name: str, cname: str = "C"):
    """Drive the static→evaluator pipeline (same shape as test_earned_public's
    ``_build_pipeline``/``_cap_for``) and return the CapabilityExpr for one
    function, so a recovered revert gate can be pinned by its final verdict."""
    contract = next(c for c in sl.contracts if c.name == cname)
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    return evaluate_tree(trees[full_name])


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


def _solc_086() -> str:
    """Highest installed solc >=0.8.26, so the custom-error require form
    parses. Resolved from solc-select's LOCAL store only — the offline guard
    blocks the binary download under pytest, so an absent version skips
    rather than installing on demand (the CI workflow preinstalls one;
    locally: ``solc-select install 0.8.27``)."""
    import solc_select.solc_select as ss

    best: tuple[int, int, int] | None = None
    for version in ss.installed_versions():
        try:
            parsed = tuple(int(x) for x in version.split("."))
        except ValueError:
            continue
        if len(parsed) == 3 and (0, 8, 26) <= parsed and parsed[:2] == (0, 8) and (best is None or parsed > best):
            best = parsed
    if best is None:
        pytest.skip("no installed solc >=0.8.26 (run `solc-select install 0.8.27`)")
    return str(ss.artifact_path(".".join(str(x) for x in best)))


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
        pragma solidity ^0.8.26;
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
        pragma solidity ^0.8.26;
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


# ---------------------------------------------------------------------------
# Forwarders: the result is RETURNED, never branched on. Nothing lifts it, so
# the recursion is the only path to the callee's gate (G3 class F).
# ---------------------------------------------------------------------------


def test_returned_helper_result_still_recurses_for_the_gate(tmp_path):
    """``return gatedCallee(...)`` — the RETURN reads the result, so the
    read-anywhere test suppressed the recursion, and the callee's require was
    never walked: the forwarder resolved unguarded."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            mapping(address => uint256) public bal;
            function _gated(uint256 amt) internal returns (uint256) {
                require(msg.sender == owner, "not owner");
                bal[msg.sender] += amt;
                return amt;
            }
            function forward(uint256 amt) external returns (uint256) {
                return _gated(amt);
            }
        }
    """,
    )
    fn = _function(sl, "forward")
    gates = RevertDetector(fn).run()
    assert _gate_kinds(gates) == ["require"], f"the forwarded callee's require must be lifted, got {_gate_kinds(gates)}"
    assert "owner" in (gates[0].expression_text or "")


def test_returned_helper_result_yields_a_caller_authority_leaf(tmp_path):
    """R4 positive case: the recovered gate must reach the evaluator as an
    authority constraint, not merely exist as a ``RevertGate``."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            uint256 public total;
            function _gated(uint256 amt) internal returns (uint256) {
                require(msg.sender == owner, "not owner");
                total += amt;
                return amt;
            }
            function forward(uint256 amt) external returns (uint256) {
                return _gated(amt);
            }
            function open(uint256 amt) external { total += amt; }
        }
    """,
    )
    gated = _cap_for(sl, "forward(uint256)")
    ungated = _cap_for(sl, "open(uint256)")
    # Before the fix both answered ``conditional_universal`` — the forwarder was
    # indistinguishable from the genuinely open function next to it.
    assert gated.kind == "finite_set", f"forwarder must resolve to the owner set, got {gated.kind}"
    assert ungated.kind == "conditional_universal", f"the ungated control must stay open, got {ungated.kind}"


def test_result_reaching_a_condition_transitively_is_not_double_walked(tmp_path):
    """``bool ok = _check(); bool z = ok && other; require(z);`` — the result
    reaches the require only through an intermediate, so the already-lifted
    test has to be a transitive closure, not a one-hop check."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) public allowed;
            bool public other;
            function _check(address who) internal view returns (bool) {
                return allowed[who];
            }
            function f() external view {
                bool ok = _check(msg.sender);
                bool z = ok && other;
                require(z, "no");
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert _gate_kinds(gates) == ["require"], f"expected the single caller-side require, got {_gate_kinds(gates)}"


# ---------------------------------------------------------------------------
# Expression-text memo: instance-scoped (mirrors ``_container_condition_reads``), so it's
# GC'd with the per-function detector and never keys ``id(expr)`` across the
# lifetime of a different Slither parse.
# ---------------------------------------------------------------------------


def test_expression_text_cache_is_instance_scoped(tmp_path):
    """The ``str(expr)`` memo lives on the ``RevertDetector`` instance, not at
    module scope — so two detectors don't share an ``id(expr)`` keyspace and
    the cache can't accrete across a long-lived process."""
    import services.static.contract_analysis_pipeline.revert_detect as rd

    # No process-global memo survives between runs.
    assert not hasattr(rd, "_EXPRESSION_TEXT_CACHE")

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

    d1 = RevertDetector(fn)
    assert d1._expression_text_cache == {}
    d1.run()
    assert d1._expression_text_cache, "str(expr) memo should populate during run()"

    # A fresh detector starts with its own empty memo — no cross-instance reuse
    # of id() keys (the hazard a module-level dict would carry).
    d2 = RevertDetector(fn)
    assert d2._expression_text_cache == {}
    assert d2._expression_text_cache is not d1._expression_text_cache


# ---------------------------------------------------------------------------
# #115: multi-statement guard body — the revert sits >=2 hops below the IF.
# Slither lowers ``if(C){ emit/assign…; revert; }`` into a chain of EXPRESSION
# nodes; the historical one-hop son scan missed the revert and returned ``[]``,
# defaulting the function to public (fail-OPEN). The "exactly one branch always
# reverts" CFG walk recovers exactly one gate.
# ---------------------------------------------------------------------------


def test_multi_statement_emit_then_revert_is_recovered(tmp_path):
    """``if (msg.sender != owner) { emit Denied(...); revert(); }`` — the
    revert is two hops below the IF (after the emit). HEAD returned ``[]`` and
    the function defaulted to public; the walk must recover one if-revert gate
    with allowed_when_false (the guarded branch is the condition-true side)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            event Denied(address caller);
            function f() external {
                if (msg.sender != ownerVar) {
                    emit Denied(msg.sender);
                    revert();
                }
                ownerVar = msg.sender;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    if_gates = [g for g in gates if g.kind in ("if_revert", "custom_revert")]
    assert len(if_gates) == 1, f"expected the recovered guard, got: {_gate_kinds(gates)}"
    assert if_gates[0].polarity == "allowed_when_false"


def test_multi_statement_assign_then_revert_is_recovered(tmp_path):
    """Same shape with an assignment (not an emit) between the IF and a bare
    ``revert()`` — still recovered as exactly one gate."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public n;
            function f() external {
                if (msg.sender != ownerVar) {
                    n = 0;
                    revert();
                }
                n = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert sum(1 for g in gates if g.kind in ("if_revert", "custom_revert")) == 1, _gate_kinds(gates)


def test_revert_after_nested_if_emits_one_outer_gate(tmp_path):
    """Shape A (the prior approach's live fail-open): ``if(outer){ if(flag){
    emit;} revert(); }``. Both inner arms reconverge into the trailing revert,
    so EVERY path leaving the outer-true branch reverts -> the OUTER guard
    always reverts -> exactly one gate. The inner IF reverts on both arms
    (not exactly one) -> no spurious inner gate. (BFS-to-ENDIF would have
    dropped the outer guard = fail-open.)"""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            bool public flag;
            event E(address a);
            function f() external {
                if (msg.sender != ownerVar) {
                    if (flag) { emit E(msg.sender); }
                    revert();
                }
                ownerVar = msg.sender;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert sum(1 for g in gates if g.kind in ("if_revert", "custom_revert")) == 1, _gate_kinds(gates)


def test_revert_inside_nested_if_attributes_to_inner_only(tmp_path):
    """Shape B: ``if(outer){ if(flag){ revert(); } }``. The outer-true branch
    can ESCAPE (the inner false arm falls through without reverting), so the
    outer IF does NOT always revert -> no outer gate. Only the inner flag-IF
    always reverts on exactly one arm -> exactly one gate. Guards against
    BFS over-attribution that would emit two gates (outer AND inner)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            bool public flag;
            function f() external {
                if (msg.sender != ownerVar) {
                    if (flag) { revert(); }
                }
                ownerVar = msg.sender;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert sum(1 for g in gates if g.kind in ("if_revert", "custom_revert")) == 1, _gate_kinds(gates)


def test_both_branches_revert_emits_no_if_gate(tmp_path):
    """``if(c){ revert A(); } else { revert B(); }`` — BOTH arms always revert
    (the function reverts unconditionally), which is not a conditional access
    fork, so no if-revert gate is fabricated (matches the real ENS both-arms
    case the always-reverts model correctly drops)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            error A();
            error B();
            function f(bool c) external pure {
                if (c) { revert A(); } else { revert B(); }
            }
        }
    """,
    )
    fn = _function(sl, "f")
    gates = RevertDetector(fn).run()
    assert [g for g in gates if g.kind in ("if_revert", "custom_revert")] == [], _gate_kinds(gates)


def test_branch_always_reverts_unbounded_cycle_escapes_not_guard():
    """White-box hardening for ``_branch_always_reverts``: a branch whose only
    exit is an unbounded cycle (no revert, no return — e.g. ``while(true){…}``)
    must report ESCAPE ``(False, None)``, never a fabricated always-reverts
    gate. Built on minimal fake CFG nodes so it pins the drain-with-no-revert
    branch independent of Slither's loop lowering."""
    from types import SimpleNamespace

    # Two nodes forming a cycle; neither reverts nor returns.
    a = SimpleNamespace(irs=[], irs_ssa=None, type=None, sons=[])
    b = SimpleNamespace(irs=[], irs_ssa=None, type=None, sons=[])
    a.sons = [b]
    b.sons = [a]
    detector = RevertDetector(SimpleNamespace(nodes=[]))
    assert detector._branch_always_reverts(a) == (False, None)

    # Positive control: a node that reverts always-reverts and returns its IR.
    class SolidityCall:  # type-name drives _ir_is_solidity_revert
        def __init__(self) -> None:
            self.function = SimpleNamespace(name="revert()")

    rev_ir = SolidityCall()
    r = SimpleNamespace(irs=[rev_ir], irs_ssa=None, type=None, sons=[])
    assert detector._branch_always_reverts(r) == (True, rev_ir)


# ---------------------------------------------------------------------------
# Calls to an ALWAYS-reverting callee as a branch sink. Solady EnumerableRoles
# writes its authorization as ``if (!isOwner()) _revertUnauthorized();`` where
# ``_revertUnauthorized`` is a helper that unconditionally reverts in assembly.
# Before the fix the branch walk only accepted a literal revert IR as a sink,
# so the guard branch "escaped" (the helper call looked like ordinary code),
# no gate was lifted, and RoleRegistry setRole/grantRole/revokeRole defaulted
# public. Treating an always-reverting CALLEE as a sink recovers the caller
# gate, which the earned-public rail then fails CLOSED to external_check_only.
# The conservative twin pins the load-bearing condition: a helper that reverts
# only *conditionally* (a require that can pass) must NOT manufacture a gate.
# ---------------------------------------------------------------------------


def test_call_to_always_reverting_helper_recovers_gate(tmp_path):
    """``if (!_isOwner()) _revertUnauthorized();`` with an assembly-``revert``
    helper and a ``caller()``-reading check → the guard is recovered as one
    if_revert gate and the function resolves external_check_only (fail-closed),
    not public. Pre-fix this yielded zero gates → conditional_universal."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function _isOwner() private view returns (bool result) {
                /// @solidity memory-safe-assembly
                assembly {
                    mstore(0x00, 0x8da5cb5b)
                    result := eq(caller(), mload(0x00))
                }
            }
            function _revertUnauthorized() private pure {
                /// @solidity memory-safe-assembly
                assembly { revert(0x00, 0x00) }
            }
            function admin() external {
                if (!_isOwner()) _revertUnauthorized();
            }
        }
    """,
    )
    fn = _function(sl, "admin")
    gates = RevertDetector(fn).run()
    if_gates = [g for g in gates if g.kind in ("if_revert", "custom_revert")]
    assert len(if_gates) == 1, f"expected the recovered guard, got: {_gate_kinds(gates)}"
    assert if_gates[0].polarity == "allowed_when_false"
    cap = _cap_for(sl, "admin()")
    assert cap.kind == "external_check_only", f"recovered caller gate must fail closed, got {cap.kind}"


def test_call_to_conditionally_reverting_helper_manufactures_no_gate(tmp_path):
    """Conservative twin (load-bearing): the same ``if (!check()) helper();``
    shape where ``helper`` reverts only *conditionally* (a require that can
    pass, then a normal return) must NOT be treated as an always-reverting sink
    — no if_revert/custom_revert gate is fabricated and the function stays
    public (conditional_universal), never external_check_only. Over-closing
    here is the failure mode that manufactured false positives in the inverse
    direction."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function _condFn() private view returns (bool) { return x > 0; }
            function _maybeRevert() private { require(x > 0, "no"); x = x; }
            function admin() external {
                if (!_condFn()) _maybeRevert();
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "admin")
    gates = RevertDetector(fn).run()
    if_gates = [g for g in gates if g.kind in ("if_revert", "custom_revert")]
    assert if_gates == [], f"conditionally-reverting helper must not fabricate a guard, got {_gate_kinds(gates)}"
    cap = _cap_for(sl, "admin()")
    assert cap.kind != "external_check_only", f"business-only require must not fail closed, got {cap.kind}"
    assert cap.kind == "conditional_universal", cap.kind


def test_solady_enumerable_roles_setrole_shape_gates_closed(tmp_path):
    """Revert-proof pinning the RoleRegistry shape verbatim: Solady
    EnumerableRoles' ``_enumerableRolesSenderIsContractOwner`` (assembly
    reading ``caller()`` and ``staticcall``-ing ``owner()``) guarding
    ``setRole`` through ``_authorizeSetRole``'s
    ``if (!isOwner()) _revertEnumerableRolesUnauthorized();``. The public
    entrypoint routes through two internal hops and an always-reverting
    assembly helper; the recovered gate must resolve external_check_only."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function _enumerableRolesSenderIsContractOwner() private view returns (bool result) {
                /// @solidity memory-safe-assembly
                assembly {
                    mstore(0x00, 0x8da5cb5b)
                    result := and(
                        and(eq(caller(), mload(0x00)), gt(returndatasize(), 0x1f)),
                        staticcall(gas(), address(), 0x1c, 0x04, 0x00, 0x20)
                    )
                }
            }
            function _revertEnumerableRolesUnauthorized() private pure {
                /// @solidity memory-safe-assembly
                assembly {
                    mstore(0x00, 0x99152cca)
                    revert(0x1c, 0x04)
                }
            }
            function _authorizeSetRole(address holder, uint256 role, bool active) internal virtual {
                if (!_enumerableRolesSenderIsContractOwner()) _revertEnumerableRolesUnauthorized();
            }
            function setRole(address holder, uint256 role, bool active) public virtual {
                _authorizeSetRole(holder, role, active);
            }
        }
    """,
    )
    fn = _function(sl, "setRole")
    gates = RevertDetector(fn).run()
    assert any(g.kind in ("if_revert", "custom_revert") for g in gates), _gate_kinds(gates)
    cap = _cap_for(sl, "setRole(address,uint256,bool)")
    assert cap.kind == "external_check_only", f"Solady owner-gated setRole must fail closed, got {cap.kind}"


# ---------------------------------------------------------------------------
# A modifier on an INTERNAL callee is a real gate of the entry function.
# EigenLayer StrategyManager routes both deposit entries through
# ``_depositIntoStrategy(...) internal onlyStrategiesWhitelistedForDeposit(strategy)``
# whose body is a mapping-allowlist require on parameter 0; the entry's result
# is assigned/returned, never branched on, so the cross-function recursion is
# the ONLY path to the gate. Commit a96b2ca3 restored that recursion; these
# arms pin the class so it cannot silently regress (the published verdict was a
# false ``unconstrained_proven`` — a positive proof of absence over a gate that
# exists).
# ---------------------------------------------------------------------------

_L38_SOURCE = """
    pragma solidity ^0.8.19;
    contract C {
        mapping(address => bool) public strategyWhitelist;
        uint256 public totalShares;
        modifier onlyWhitelisted(address strategy) {
            require(strategyWhitelist[strategy], "strategy not whitelisted");
            _;
        }
        function deposit(address strategy, uint256 amount) external returns (uint256 shares) {
            shares = _deposit(strategy, amount);
        }
        // Negative control (the sweepDust discipline): same topology, a real
        // tree (the amount guard), and NO gate on ``strategy``. The fix must
        // not manufacture a constraint here.
        function sweep(address strategy, uint256 amount) external returns (uint256 shares) {
            require(amount > 0, "zero amount");
            shares = _sweepInner(strategy, amount);
        }
        function _deposit(address strategy, uint256 amount) internal onlyWhitelisted(strategy) returns (uint256) {
            totalShares += amount;
            return amount;
        }
        function _sweepInner(address strategy, uint256 amount) internal returns (uint256) {
            totalShares += amount;
            return amount;
        }
    }
"""


def test_internal_callee_modifier_gate_is_lifted(tmp_path):
    """Detector arm: the whitelist require inside the internal callee's
    modifier is found from the entry function."""
    sl = _compile(tmp_path, _L38_SOURCE)
    gates = RevertDetector(_function(sl, "deposit")).run()
    requires = [g for g in gates if g.kind == "require" and "strategyWhitelist" in (g.expression_text or "")]
    assert requires, f"internal-callee-modifier gate must be lifted, got {_gate_kinds(gates)}"
    control_gates = RevertDetector(_function(sl, "sweep")).run()
    assert not any("strategyWhitelist" in (g.expression_text or "") for g in control_gates), (
        "the ungated sibling must not inherit the gate"
    )


def test_internal_callee_modifier_gate_reaches_param_constraints(tmp_path):
    """Claims arm: the published verdict for the gated entry's parameter 0 is
    ``constrained``/``mapping_allowlist`` (this exact row published
    ``{'state': 'unconstrained_proven'}`` on the two StrategyManager deposit
    entries in the local DB — the false adverse), while the ungated
    sibling KEEPS its honest ``unconstrained_proven``."""
    from services.static.claims.context import ClaimContext
    from services.static.claims.matchers import _facts

    sl = _compile(tmp_path, _L38_SOURCE)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = {fn.full_name: build_predicate_tree(fn) for fn in contract.functions if not fn.is_constructor}
    effects = {
        "contract_name": "C",
        "functions": {
            sig: {"sinks": [], "value_flows": [], "parameter_names": ["strategy", "amount"]}
            for sig in ("deposit(address,uint256)", "sweep(address,uint256)")
        },
    }
    ctx = ClaimContext(None, effects, {"trees": trees})
    gated = _facts.param_constraint(ctx, "deposit(address,uint256)", 0)
    assert gated["state"] == "constrained", f"expected constrained, got {gated}"
    assert gated.get("guard") == "mapping_allowlist", f"expected mapping_allowlist, got {gated}"
    control = _facts.param_constraint(ctx, "sweep(address,uint256)", 0)
    assert control == {"state": "unconstrained_proven"}, (
        f"the ungated sibling must keep its proven-unconstrained state, got {control}"
    )
