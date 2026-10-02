"""P2: accept-side 2-step transfer gates are uncallable until a transfer is queued, so a ``pending``-prefixed
accessor lowers to ``empty_by_design``. Operand shapes are compiled from source; the global
``_stub_live_authority`` fixture is deliberately not used.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.policy.capability_surface import (
    _is_resolved_empty_capability,
    project_capability_surface,
)
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import (
    EvaluationContext,
    _is_pending_authority_accessor_operand,
    evaluate_tree,
)
from tests.support.authority_reads import _Adapter, _Outer, _status
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x" + "11" * 20
OWNER_SELECTOR = "0x8da5cb5b"  # owner()

A_PENDING_GOVERNOR = {
    "source": "view_call",
    "callee": "_pendingGovernor()",
    "callee_signature": "_pendingGovernor()",
    "callee_selector": "0x638adcc8",
}
# The shape if provenance hadn't inlined the getter to the struct read.


def _ctx_with_rpc(rpc_url: str = "http://rpc.test") -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(_Outer(rpc_url, CONTRACT)))


def _stub_rpc(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if mode == "revert":
            raise RuntimeError("execution reverted")
        if mode == "empty":
            return "0x"
        if mode == "tuple_zero":
            return "0x" + "00" * 64
        raise AssertionError(f"unexpected mode {mode}")

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)


def _assert_empty_by_design(cap: CapabilityExpr) -> None:
    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"
    assert cap.empty_reason == "empty_by_design"
    assert project_capability_surface(capability_to_dict(cap)).principal_rows == []
    assert _status(cap) == "resolved_empty"


@pytest.mark.parametrize("mode", ["revert", "empty"])
def test_pending_governor_accept_gate_is_resolved_empty(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    _stub_rpc(monkeypatch, mode)
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR), _ctx_with_rpc())
    _assert_empty_by_design(cap)


# Over-reach would re-open the open-on-ambiguity false-positive class.


# Built with lower_bound so only the empty_reason branch can classify it.


def test_resolved_empty_capability_false_for_populated_finite_set() -> None:
    populated = capability_to_dict(CapabilityExpr.finite_set(["0x" + "ab" * 20], quality="exact"))
    assert _is_resolved_empty_capability(populated) is False


# --------------------------------------------------------------------------
# Detector precision: only the pending half of view_call / state_variable operands
# matches; other sources and a missing signature fail closed.
# --------------------------------------------------------------------------


def test_detector_fails_closed_for_non_authority_operand_sources() -> None:
    assert _is_pending_authority_accessor_operand({"source": "constant", "constant_value": "0x0"}) is False
    assert _is_pending_authority_accessor_operand({"source": "parameter"}) is False


def test_detector_handles_missing_signature() -> None:
    assert _is_pending_authority_accessor_operand({"source": "view_call", "callee_signature": None}) is False
    assert _is_pending_authority_accessor_operand({"source": "view_call"}) is False
