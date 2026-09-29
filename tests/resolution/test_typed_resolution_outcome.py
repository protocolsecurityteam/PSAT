"""P1 — typed resolution outcome: the read-failure reason is carried end-to-end.

The binary ``exact``/``lower_bound`` collapse discarded *why* an authority read came back
empty (revert vs empty-return vs nothing-attempted). P1 attaches a machine-readable
``empty_reason`` to the labeled empty and threads it through the persisted ``capability_expr``
WITHOUT changing the outcome (kind / quality / members / surface status). On main the
serialized capability has no ``empty_reason`` key, so every assertion here fails.

P1 cases use NON-pending operands to isolate labeling from the empty-by-design promotion (P2,
tested separately). The second half is the claim-#3 characterization net (see its header).
Pure/offline; the global ``_stub_live_authority`` fixture is deliberately not used.
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

# Non-pending operands (so the read-failure reason, not empty_by_design, rides through).
# ``receivers[originEid]`` is a param-keyed mapping read modeled as a member operand with no
# nullary getter (nothing is read).
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
    """``mode``: ``revert`` (raise) or ``empty`` (bare ``0x`` — empty/no-code)."""

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
        # not_read means no RPC was attempted at all.
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
    """Precision: a populated authority carries NO empty_reason (emit-when-non-default keeps its wire shape)."""
    addr = "0x" + "ab" * 20
    monkeypatch.setattr(
        "services.clients.rpc.rpc_request",
        lambda *a, **k: "0x" + addr[2:].rjust(64, "0"),
    )
    cap_dict = _expr_dict(evaluate_tree(_eq_tree(REVERTING_VAR), _ctx_with_rpc()))

    assert cap_dict["members"] == [addr]
    assert "empty_reason" not in cap_dict


# ==========================================================================
# Claim-#3 characterization net.
#
# Pins the lowering of the operand shapes behind the etherfi (protocol_id=1, run
# ``1279e07382b24d32``) ``finite_set/lower_bound`` under-resolved functions. Operands are the
# REAL shapes from compiling on-chain source through the production static pipeline:
#   * A ``claimGovernance`` — ``view_call _pendingGovernor()`` (internal; reverts/empties everywhere).
#   * B ``acceptDefaultAdminTransfer`` — ``state_variable _pendingDefaultAdmin`` member
#     ``newAdmin`` (OZ's public getter is inlined to the struct read: nothing is read).
#
# Locks what holds on both main and the P1/P2 branch: A/B resolve to an EMPTY caller set with
# NO principal rows. The flip to ``resolved_empty`` is pinned by ``test_pending_transfer_ceiling``,
# so this net stays a stable scope witness: non-pending getter-less authorities must NOT flip.
# ==========================================================================

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
