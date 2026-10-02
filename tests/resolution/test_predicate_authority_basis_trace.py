"""Three getter choices rest on an identifier, not the ABI: slot keywords, the de-underscore convention and the
``pending`` prefix. These pin that provenance and the refusal of a locator naming two roles.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.resolution.capabilities import CapabilityExpr
from services.resolution.predicate_evaluator import (
    EvaluationContext,
    evaluate_tree,
)
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x" + "11" * 20
GOVERNOR = "0x" + "ab" * 20


class _Outer:
    def __init__(self) -> None:
        self.rpc_url = "http://rpc.test"
        self.contract_address = CONTRACT
        self.block = None


class _Adapter:
    def __init__(self) -> None:
        self._outer_ctx = _Outer()

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx() -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter())


def _basis_steps(cap: CapabilityExpr, step: str) -> list[dict[str, Any]]:
    return [entry for entry in cap.trace if entry.get("step") == step]


GOVERNOR_SELECTOR = "0x0c340a24"  # governor()


def test_pending_ceiling_records_that_it_was_never_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The trace distinguishes it from a zero-read-confirmed empty."""

    def revert(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("execution reverted")

    monkeypatch.setattr("services.clients.rpc.rpc_request", revert)
    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "_pendingGovernor()"}),
        _ctx(),
    )

    assert cap.empty_reason == "empty_by_design"
    ceiling = _basis_steps(cap, "pending_transfer_ceiling")
    assert len(ceiling) == 1
    assert ceiling[0]["basis"] == "accessor_name"
    assert ceiling[0]["role"] == "governor"
    assert ceiling[0]["read_outcome"] == "unreadable_revert"


def test_struct_member_pending_ceiling_records_no_read_attempt(monkeypatch: pytest.MonkeyPatch) -> None:

    def revert(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("execution reverted")

    monkeypatch.setattr("services.clients.rpc.rpc_request", revert)
    cap = evaluate_tree(
        _eq_tree(
            {
                "source": "state_variable",
                "state_variable_name": "_pendingDefaultAdmin",
                "member_path": ["newAdmin"],
            }
        ),
        _ctx(),
    )

    assert cap.empty_reason == "empty_by_design"
    ceiling = _basis_steps(cap, "pending_transfer_ceiling")
    assert ceiling[0]["read_outcome"] == "not_attempted"
    assert ceiling[0]["role"] == "defaultadmin"
