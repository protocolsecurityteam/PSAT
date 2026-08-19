"""P1 — typed resolution outcome: the read-failure reason is carried end-to-end.

The binary ``exact``/``lower_bound`` collapse discarded *why* an authority point
read came back empty — revert vs empty-return vs nothing-attempted all funneled
to one silent ``lower_bound`` sink. P1 attaches a machine-readable ``empty_reason``
to the labeled empty and threads it through the persisted ``capability_expr``,
WITHOUT changing the outcome (kind / quality / members / surface status stay put).

These cases use NON-pending operands on purpose: they isolate the labeling layer
(P1) from the empty-by-design promotion (P2, tested separately). On main the
serialized capability carries no ``empty_reason`` key, so every assertion here
fails — pinning that P1 is what adds it.

Pure/offline, ``test_authority_live_getter_resolution`` pattern; the global
``_stub_live_authority`` fixture is deliberately not used.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x" + "11" * 20

# Non-pending operands (so the read-failure reason — not empty_by_design — is what
# rides through). ``membershipManager`` / ``vault`` are bare address state vars;
# ``receivers[originEid]`` is a param-keyed mapping read, modeled as a member
# operand with no nullary getter (nothing is read).
REVERTING_VAR = {"source": "state_variable", "state_variable_name": "membershipManager"}
EMPTY_RETURN_VAR = {"source": "state_variable", "state_variable_name": "vault"}
UNREAD_MEMBER = {"source": "state_variable", "state_variable_name": "receivers", "member_path": ["originEid"]}


class _Outer:
    def __init__(self, rpc_url: str | None, contract_address: str | None, block: int | None = None) -> None:
        self.rpc_url = rpc_url
        self.contract_address = contract_address
        self.block = block


class _Adapter:
    def __init__(self, outer: _Outer | None) -> None:
        if outer is not None:
            self._outer_ctx = outer

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:  # noqa: ARG002
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx_with_rpc(rpc_url: str = "http://rpc.test") -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(_Outer(rpc_url, CONTRACT)))


def _stub_rpc(monkeypatch: pytest.MonkeyPatch, mode: str, *, recorder: list | None = None) -> None:
    """``mode``: ``revert`` (raise) or ``empty`` (bare ``0x`` — empty/no-code)."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if mode == "revert":
            raise RuntimeError("execution reverted")
        return "0x"

    monkeypatch.setattr("utils.rpc.rpc_request", fake)


def _expr_dict(cap: CapabilityExpr) -> dict[str, Any]:
    """The persisted ``capability_expr`` JSON the policy/surface layers read."""
    return capability_to_dict(cap)


def _status(cap_dict: dict[str, Any]) -> str | None:
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


def _assert_unchanged_empty(cap_dict: dict[str, Any]) -> None:
    """kind / quality / members / status are exactly the main-branch placeholder."""
    assert cap_dict["kind"] == "finite_set"
    assert cap_dict["membership_quality"] == "lower_bound"
    assert cap_dict["members"] == []
    assert _status(cap_dict) != "resolved_empty"


def test_revert_carries_unreadable_revert(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, "revert")
    cap_dict = _expr_dict(evaluate_tree(_eq_tree(REVERTING_VAR), _ctx_with_rpc()))

    assert cap_dict["empty_reason"] == "unreadable_revert"
    _assert_unchanged_empty(cap_dict)


def test_empty_return_carries_unreadable_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, "empty")
    cap_dict = _expr_dict(evaluate_tree(_eq_tree(EMPTY_RETURN_VAR), _ctx_with_rpc()))

    assert cap_dict["empty_reason"] == "unreadable_empty"
    _assert_unchanged_empty(cap_dict)


def test_nothing_attempted_carries_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    # A struct-member operand has no nullary getter — nothing is read.
    recorder: list = []
    _stub_rpc(monkeypatch, "revert", recorder=recorder)
    cap_dict = _expr_dict(evaluate_tree(_eq_tree(UNREAD_MEMBER), _ctx_with_rpc()))

    assert cap_dict["empty_reason"] == "not_read"
    assert recorder == []  # nothing attempted
    _assert_unchanged_empty(cap_dict)


def test_empty_reason_absent_on_populated_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Precision: a resolved (non-empty) authority carries NO empty_reason — the
    field is emit-when-non-default, so populated sets keep their wire shape."""
    addr = "0x" + "ab" * 20
    monkeypatch.setattr(
        "utils.rpc.rpc_request",
        lambda *a, **k: "0x" + addr[2:].rjust(64, "0"),
    )
    cap_dict = _expr_dict(evaluate_tree(_eq_tree(REVERTING_VAR), _ctx_with_rpc()))

    assert cap_dict["members"] == [addr]
    assert "empty_reason" not in cap_dict
