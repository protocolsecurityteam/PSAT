"""Asserts gates by count, kind and polarity; condition_value identity is Slither-version dependent."""

from __future__ import annotations

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


# Keeping the call selector and target lets the resolver expand members; opaque left EtherFi's ``upgradeTo``
# unresolvable.


# Slither lowers ``require(cond, MyError())`` to ``require(bool,error)``; dropping it defaulted the function to public.


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


# A returned result is never branched on, so recursion is the only path to the gate (G3 class F).


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


# The expression-text memo is instance-scoped so ``id(expr)`` keys never outlive the parse.


# #115: Slither lowers a multi-statement guard to an EXPRESSION chain, and the one-hop son scan returned ``[]``
# (fail-open).


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
