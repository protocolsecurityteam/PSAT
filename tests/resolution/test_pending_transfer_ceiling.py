"""P2 — accept-side 2-step transfer gates are ``resolved_empty`` (empty-by-design).

``claimGovernance`` (gate ``msg.sender == _pendingGovernor()``) and
``acceptDefaultAdminTransfer`` (gate ``msg.sender == pendingDefaultAdmin().newAdmin``)
are the accept halves of a 2-step authority handover: uncallable until a transfer
is queued. With no transfer pending the pending slot reads empty (or, for the OZ
struct member, has no getter to read at all), and the binary lowering filed that
as a silent ``finite_set/lower_bound`` gap. P2 recognizes the ``pending``-prefixed
accessor and lowers it to ``finite_set([], exact, empty_by_design)`` so the surface
reports ``resolved_empty`` ("provably nobody, until a transfer is pending") instead
of an under-resolution.

Operand shapes are the REAL ones (compiled from source):
  * A — ``view_call _pendingGovernor()`` (internal accessor; reverts/empties).
  * B — ``state_variable _pendingDefaultAdmin`` member ``newAdmin``: OZ's public
    ``pendingDefaultAdmin()`` is inlined by provenance to its storage struct read,
    so the operand is a struct member with no getter — nothing is read.

On main these stay ``lower_bound`` / not ``resolved_empty``, so every flip
assertion fails; reverting either P1 or P2 restores that.

Pure/offline, ``test_authority_live_getter_resolution`` pattern; the global
``_stub_live_authority`` fixture is deliberately not used.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.policy.capability_surface import (
    _is_resolved_empty_capability,
    capability_surface_status,
    project_capability_surface,
)
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import (
    EvaluationContext,
    _is_pending_authority_accessor_operand,
    evaluate_tree,
)
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x" + "11" * 20
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
# Defensive coverage of the detector's other half: a public ``pendingDefaultAdmin()``
# getter operand (the shape if provenance had NOT inlined it to the struct read).
B_PENDING_DEFAULT_ADMIN_GETTER = {
    "source": "view_call",
    "callee_signature": "pendingDefaultAdmin()",
    "callee_selector": "0xcefc1429",
}
GUARD_OWNER = {"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR}


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


def _stub_rpc(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """``mode``: ``revert`` (raise), ``empty`` (bare ``0x``), or ``tuple_zero``
    (two zero words — the ``(address, uint48)`` zero return of an unset
    ``pendingDefaultAdmin()``)."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if mode == "revert":
            raise RuntimeError("execution reverted")
        if mode == "empty":
            return "0x"
        if mode == "tuple_zero":
            return "0x" + "00" * 64
        raise AssertionError(f"unexpected mode {mode}")

    monkeypatch.setattr("utils.rpc.rpc_request", fake)


def _status(cap: CapabilityExpr) -> str | None:
    cap_dict = capability_to_dict(cap)
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


def _assert_empty_by_design(cap: CapabilityExpr) -> None:
    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"
    assert cap.empty_reason == "empty_by_design"
    assert project_capability_surface(capability_to_dict(cap)).principal_rows == []
    assert _status(cap) == "resolved_empty"


# --------------------------------------------------------------------------
# A — claimGovernance: _pendingGovernor() reverts (proxy) and empties (impl).
# Both read-failure shapes must promote to empty-by-design.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["revert", "empty"])
def test_pending_governor_accept_gate_is_resolved_empty(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    _stub_rpc(monkeypatch, mode)
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR), _ctx_with_rpc())
    _assert_empty_by_design(cap)


# --------------------------------------------------------------------------
# B — acceptDefaultAdminTransfer: the real struct-member operand (no getter to
# read) and, defensively, the public-getter shape returning two zero words.
# --------------------------------------------------------------------------


def test_pending_default_admin_member_is_resolved_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, "revert")  # never reached — struct member has no getter
    cap = evaluate_tree(_eq_tree(B_PENDING_DEFAULT_ADMIN), _ctx_with_rpc())
    _assert_empty_by_design(cap)


def test_pending_default_admin_getter_two_zero_words_is_resolved_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the gate had stayed a public ``pendingDefaultAdmin()`` view (no
    inlining), an unset ``(address,uint48)`` return is two zero words → still
    ``resolved_empty`` (here via the clean-zero read path)."""
    _stub_rpc(monkeypatch, "tuple_zero")
    cap = evaluate_tree(_eq_tree(B_PENDING_DEFAULT_ADMIN_GETTER), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert _status(cap) == "resolved_empty"


# --------------------------------------------------------------------------
# Precision guard — a NON-pending owner() that reverts is a real read failure,
# NOT "provably nobody". It must stay lower_bound, never resolved_empty;
# over-reach here re-opens the "open-on-ambiguity" false-positive class.
# --------------------------------------------------------------------------


def test_non_pending_owner_revert_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, "revert")
    cap = evaluate_tree(_eq_tree(GUARD_OWNER), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason != "empty_by_design"
    assert _status(cap) != "resolved_empty"


def test_pending_governor_with_active_transfer_resolves_to_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pending accessor that DOES read a live address (a transfer in flight)
    resolves to that principal — empty-by-design only kicks in on an empty read."""
    pending = "0x" + "cd" * 20
    monkeypatch.setattr("utils.rpc.rpc_request", lambda *a, **k: "0x" + pending[2:].rjust(64, "0"))
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR), _ctx_with_rpc())

    assert cap.members == [pending]
    assert cap.membership_quality == "exact"
    assert cap.empty_reason is None


# --------------------------------------------------------------------------
# Surface contract (pins the capability_surface.py change in isolation): an
# empty-by-design set is resolved_empty regardless of membership_quality. Built
# directly with lower_bound so ONLY the new empty_reason branch can classify it
# (the pre-existing exact-empty check would not) — revert-proof for that file.
# --------------------------------------------------------------------------


def test_empty_by_design_is_resolved_empty_regardless_of_quality() -> None:
    cap = CapabilityExpr.finite_set([], quality="lower_bound", empty_reason="empty_by_design")
    cap_dict = capability_to_dict(cap)

    assert _is_resolved_empty_capability(cap_dict) is True
    assert capability_surface_status(cap_dict, project_capability_surface(cap_dict)) == "resolved_empty"


def test_lower_bound_without_empty_by_design_is_not_resolved_empty() -> None:
    cap = CapabilityExpr.finite_set([], quality="lower_bound", empty_reason="unreadable_revert")
    cap_dict = capability_to_dict(cap)

    assert _is_resolved_empty_capability(cap_dict) is False
    assert capability_surface_status(cap_dict, project_capability_surface(cap_dict)) != "resolved_empty"


def test_resolved_empty_capability_false_for_populated_finite_set() -> None:
    """A populated finite_set is never 'provably nobody' — the members-present
    guard short-circuits (reached via AND/OR recursion over a populated child)."""
    populated = capability_to_dict(CapabilityExpr.finite_set(["0x" + "ab" * 20], quality="exact"))
    assert _is_resolved_empty_capability(populated) is False


# --------------------------------------------------------------------------
# Detector precision: only the pending half of view_call / state_variable
# operands matches; other sources and a missing signature fail closed.
# --------------------------------------------------------------------------


def test_detector_fails_closed_for_non_authority_operand_sources() -> None:
    assert _is_pending_authority_accessor_operand({"source": "constant", "constant_value": "0x0"}) is False
    assert _is_pending_authority_accessor_operand({"source": "parameter"}) is False


def test_detector_handles_missing_signature() -> None:
    assert _is_pending_authority_accessor_operand({"source": "view_call", "callee_signature": None}) is False
    assert _is_pending_authority_accessor_operand({"source": "view_call"}) is False


def test_detector_matches_pending_shapes_rejects_plain_authority() -> None:
    assert _is_pending_authority_accessor_operand({"source": "view_call", "callee_signature": "_pendingGovernor()"})
    assert _is_pending_authority_accessor_operand(
        {"source": "state_variable", "state_variable_name": "_pendingDefaultAdmin", "member_path": ["newAdmin"]}
    )
    # Plain (non-pending) authorities must NOT match — the precision boundary.
    assert not _is_pending_authority_accessor_operand({"source": "view_call", "callee_signature": "owner()"})
    assert not _is_pending_authority_accessor_operand({"source": "state_variable", "state_variable_name": "governor"})
