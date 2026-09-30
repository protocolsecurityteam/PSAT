"""P1: ``empty_reason`` (revert vs empty-return vs nothing-attempted) rides through to the persisted
``capability_expr`` without changing the outcome. Non-pending operands isolate this from the P2 empty-by-design
promotion; the global ``_stub_live_authority`` fixture is deliberately not used.
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

# ``receivers[originEid]`` has no nullary getter, so nothing is read.
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

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx_with_rpc(rpc_url: str = "http://rpc.test") -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(_Outer(rpc_url, CONTRACT)))


def _stub_rpc(monkeypatch: pytest.MonkeyPatch, mode: str, *, recorder: list | None = None) -> None:

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if mode == "revert":
            raise RuntimeError("execution reverted")
        return "0x"

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)


def _expr_dict(cap: CapabilityExpr) -> dict[str, Any]:
    return capability_to_dict(cap)


def _status(cap_dict: dict[str, Any]) -> str | None:
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


def _assert_unchanged_empty(cap_dict: dict[str, Any]) -> None:
    assert cap_dict["kind"] == "finite_set"
    assert cap_dict["membership_quality"] == "lower_bound"
    assert cap_dict["members"] == []
    assert _status(cap_dict) != "resolved_empty"


@pytest.mark.parametrize(
    "mode, var, expected_reason, attempted",
    [
        pytest.param("revert", REVERTING_VAR, "unreadable_revert", True, id="revert"),
        pytest.param("empty", EMPTY_RETURN_VAR, "unreadable_empty", True, id="empty-return"),
        pytest.param("revert", UNREAD_MEMBER, "not_read", False, id="nothing-attempted"),
    ],
)
def test_empty_reason_labels_why_the_set_is_empty(
    monkeypatch: pytest.MonkeyPatch, mode: str, var: Any, expected_reason: str, attempted: bool
) -> None:
    recorder: list = []
    _stub_rpc(monkeypatch, mode, recorder=recorder)
    cap_dict = _expr_dict(evaluate_tree(_eq_tree(var), _ctx_with_rpc()))

    assert cap_dict["empty_reason"] == expected_reason
    assert bool(recorder) is attempted
    _assert_unchanged_empty(cap_dict)


def test_empty_reason_absent_on_populated_set(monkeypatch: pytest.MonkeyPatch) -> None:
    addr = "0x" + "ab" * 20
    monkeypatch.setattr(
        "services.clients.rpc.rpc_request",
        lambda *a, **k: "0x" + addr[2:].rjust(64, "0"),
    )
    cap_dict = _expr_dict(evaluate_tree(_eq_tree(REVERTING_VAR), _ctx_with_rpc()))

    assert cap_dict["members"] == [addr]
    assert "empty_reason" not in cap_dict


# Claim-#3 net: real operand shapes behind the etherfi under-resolved functions (run 1279e07382b24d32).
#   A ``claimGovernance``: ``view_call _pendingGovernor()``, internal, reverts everywhere.
#   B ``acceptDefaultAdminTransfer``: ``_pendingDefaultAdmin.newAdmin``; OZ's getter inlines to the struct read.
# Both resolve to an empty caller set with no principal rows. The flip to ``resolved_empty`` is pinned in
# ``test_pending_transfer_ceiling``; non-pending getter-less authorities must not flip.

OWNER_SELECTOR = "0x8da5cb5b"  # owner()

A_PENDING_GOVERNOR = {
    "source": "view_call",
    "callee": "_pendingGovernor()",
    "callee_signature": "_pendingGovernor()",
    "callee_selector": "0x638adcc8",
}
B_PENDING_DEFAULT_ADMIN = {
    "source": "state_variable",
    "state_variable_name": "_pendingDefaultAdmin",
    "member_path": ["newAdmin"],
}
GUARD_OWNER = {"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR}
