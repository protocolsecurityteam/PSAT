"""A published authority principal must carry the basis its getter was picked on.

Three of the getter choices in ``predicate_evaluator`` are decided by an
identifier rather than by the ABI — a slot constant's keyword
(``_GOVERNOR_SLOT`` -> ``governor()``), the ``_x()`` -> ``x()`` de-underscore
convention, and the ``pending`` prefix that lowers an accept gate to
``empty_by_design``. The read that follows is real, but the CHOICE is not
verified, so the resulting capability records which basis produced it. These
tests pin that provenance and the one place the choice is now refused outright:
a locator naming two different roles.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.resolution.capabilities import CapabilityExpr
from services.resolution.predicate_evaluator import (
    EvaluationContext,
    _canonical_authority_selector_for_slot,
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


def _only_governor_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    """``governor()`` returns an address; every other selector reverts — the
    real shape, where a slot constant's own ``_GOVERNOR_SLOT()`` has no code."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if params[0].get("data") != GOVERNOR_SELECTOR:
            raise RuntimeError("execution reverted")
        return "0x" + GOVERNOR[2:].rjust(64, "0")

    monkeypatch.setattr("utils.rpc.rpc_request", fake)


def test_slot_keyword_principal_declares_its_name_basis(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_GOVERNOR_SLOT`` has no getter of its own; ``governor()`` is chosen
    because the identifier contains "governor". The address read back is real,
    so it is published — but the trace says the selection came from the name."""
    _only_governor_reads(monkeypatch)
    cap = evaluate_tree(_eq_tree({"source": "state_variable", "state_variable_name": "_GOVERNOR_SLOT"}), _ctx())

    assert cap.members == [GOVERNOR]
    assert [e["basis"] for e in _basis_steps(cap, "authority_getter_basis")] == ["slot_name_keyword"]


def test_public_state_var_principal_declares_the_abi_basis(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: a plain ``governor`` state var resolves through the
    auto-getter the compiler generates for it, so the basis is the ABI rule —
    not a keyword guess. Same published address, different provenance."""
    _only_governor_reads(monkeypatch)
    cap = evaluate_tree(_eq_tree({"source": "state_variable", "state_variable_name": "governor"}), _ctx())

    assert cap.members == [GOVERNOR]
    assert [e["basis"] for e in _basis_steps(cap, "authority_getter_basis")] == ["abi_auto_getter"]


def test_locator_naming_two_roles_resolves_to_no_getter() -> None:
    """``AuthorityOwnableStorageLocation`` supports ``authority()`` and
    ``owner()`` equally well; whichever the scan reached first would be
    published as THE principal. With no basis to prefer one, refuse — the
    fail-silent direction."""
    assert _canonical_authority_selector_for_slot("AuthorityOwnableStorageLocation") is None
    # Single-role locators still resolve.
    assert _canonical_authority_selector_for_slot("_GOVERNOR_SLOT") is not None
    assert _canonical_authority_selector_for_slot("OwnableStorageLocation") is not None


def test_pending_ceiling_records_that_it_was_never_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The accept-side ceiling is reached only when nothing could be read. The
    verdict stays ``empty_by_design`` (its consumers are unchanged), but the
    trace now names the accessor prefix it rests on and the read outcome that
    preceded it, so it is distinguishable from a zero-read-confirmed empty."""

    def revert(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("execution reverted")

    monkeypatch.setattr("utils.rpc.rpc_request", revert)
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
    """The OZ ``_pendingDefaultAdmin.newAdmin`` shape has no getter at all, so
    no read is even attempted — the trace says so rather than implying the
    emptiness was observed."""

    def revert(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("execution reverted")

    monkeypatch.setattr("utils.rpc.rpc_request", revert)
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
