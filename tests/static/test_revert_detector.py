"""Asserts gates by count, kind and polarity; condition_value identity is Slither-version dependent."""

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
from tests.support.slither_compile import _compile, _function  # noqa: E402
from tests.support.solc import _solc_086  # noqa: E402

pytestmark = pytest.mark.compile


def _cap_for(sl: Slither, full_name: str, cname: str = "C"):
    contract = next(c for c in sl.contracts if c.name == cname)
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    return evaluate_tree(trees[full_name])


def _gate_kinds(gates: list[RevertGate]) -> list[str]:
    return [g.kind for g in gates]


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


def test_if_revert_inverts_polarity(tmp_path):
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


def test_inline_asm_conditional_revert_structurally_parsed(tmp_path):
    """Slither parses it as structured IF + revert."""
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
    """The opaque marker is reserved for textual reverts we couldn't extract."""
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


def test_try_catch_with_revert_in_catch_emits_opaque_gate(tmp_path):
    """Otherwise the function looks unguarded."""
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


# Keeping the call selector and target lets the resolver expand members; opaque left EtherFi's ``upgradeTo``
# unresolvable.


def test_try_catch_around_external_authority_call_is_not_opaque(tmp_path):
    """The OZ AccessManaged / EtherFi RoleRegistry upgrade pattern."""
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
    assert gates, "expected at least one revert gate"
    opaque_only = all(g.kind == "opaque" and g.unsupported_reason == "opaque_try_catch" for g in gates)
    assert not opaque_only, (
        "try/catch wrapping a single authority-check call collapsed to opaque(opaque_try_catch); "
        "expected kind='try_catch_revert' (or similar non-opaque kind) so the call selector + "
        "target are recoverable downstream"
    )
    assert any(g.kind == "try_catch_revert" for g in gates), (
        f"no gate with kind='try_catch_revert' found; got kinds={_gate_kinds(gates)}"
    )


# Slither lowers ``require(cond, MyError())`` to ``require(bool,error)``; dropping it defaulted the function to public.


def _compile_086(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f), solc=_solc_086())


def test_require_custom_error_is_lifted(tmp_path):
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


# A walked but unlifted require/assert fails closed instead of defaulting to public.


def test_unmodeled_require_fails_closed(tmp_path, monkeypatch):
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

    baseline = RevertDetector(fn).run()
    assert not any(g.unsupported_reason == "unmodeled_require_gate" for g in baseline)
    assert any(g.kind == "require" for g in baseline)

    monkeypatch.setattr(rd, "_ir_is_require", lambda ir: False)
    gates = RevertDetector(fn).run()
    assert any(g.kind == "opaque" and g.unsupported_reason == "unmodeled_require_gate" for g in gates), (
        "an unmodeled require slipped through with no gate — the function would "
        f"default to public; got {_gate_kinds(gates)}"
    )


def test_genuinely_ungated_function_stays_gateless(tmp_path):
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


def test_discarded_bool_guard_helper_gate_is_found(tmp_path):
    """The lvalue skip dropped it, so every EtherFiRedemptionManager admin function defaulted to public."""
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


# A returned result is never branched on, so recursion is the only path to the gate (G3 class F).


def test_returned_helper_result_still_recurses_for_the_gate(tmp_path):
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
    assert gated.kind == "finite_set", f"forwarder must resolve to the owner set, got {gated.kind}"
    assert ungated.kind == "conditional_universal", f"the ungated control must stay open, got {ungated.kind}"


def test_result_reaching_a_condition_transitively_is_not_double_walked(tmp_path):
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


# The expression-text memo is instance-scoped so ``id(expr)`` keys never outlive the parse.


# #115: Slither lowers a multi-statement guard to an EXPRESSION chain, and the one-hop son scan returned ``[]``
# (fail-open).


def test_multi_statement_emit_then_revert_is_recovered(tmp_path):
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
    """Every path out of the outer branch reverts; BFS-to-ENDIF dropped the outer guard."""
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
    """The outer branch can escape via the inner false arm."""
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
    """Matches the real ENS both-arms case."""
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
    """Fake CFG nodes pin the drain-with-no-revert branch independent of Slither's loop lowering."""
    from types import SimpleNamespace

    a = SimpleNamespace(irs=[], irs_ssa=None, type=None, sons=[])
    b = SimpleNamespace(irs=[], irs_ssa=None, type=None, sons=[])
    a.sons = [b]
    b.sons = [a]
    detector = RevertDetector(SimpleNamespace(nodes=[]))
    assert detector._branch_always_reverts(a) == (False, None)

    class SolidityCall:  # type-name drives _ir_is_solidity_revert
        def __init__(self) -> None:
            self.function = SimpleNamespace(name="revert()")

    rev_ir = SolidityCall()
    r = SimpleNamespace(irs=[rev_ir], irs_ssa=None, type=None, sons=[])
    assert detector._branch_always_reverts(r) == (True, rev_ir)


# Solady EnumerableRoles reverts in an assembly helper; accepting only literal revert IR left RoleRegistry
# setRole/grantRole/revokeRole public. A conditionally reverting helper must not manufacture a gate.


def test_call_to_always_reverting_helper_recovers_gate(tmp_path):
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
    """Over-closing produced false positives in the inverse direction."""
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


# EigenLayer StrategyManager's ``_depositIntoStrategy`` carries the whitelist modifier; recursion (a96b2ca3) is the only
# path to it, and losing it published a false ``unconstrained_proven``.

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
    sl = _compile(tmp_path, _L38_SOURCE)
    gates = RevertDetector(_function(sl, "deposit")).run()
    requires = [g for g in gates if g.kind == "require" and "strategyWhitelist" in (g.expression_text or "")]
    assert requires, f"internal-callee-modifier gate must be lifted, got {_gate_kinds(gates)}"
    control_gates = RevertDetector(_function(sl, "sweep")).run()
    assert not any("strategyWhitelist" in (g.expression_text or "") for g in control_gates), (
        "the ungated sibling must not inherit the gate"
    )


def test_internal_callee_modifier_gate_reaches_param_constraints(tmp_path):
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
