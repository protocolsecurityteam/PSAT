"""Characterization / lock-in for the claim-#3 under-resolution groups.

Pins the lowering of the operand shapes behind the etherfi (protocol_id=1, run
``1279e07382b24d32``) ``finite_set/lower_bound`` under-resolved functions, so the
P1/P2 fixes are measurable and the out-of-scope groups provably stay put. Every
operand here is the REAL shape, taken by compiling the on-chain source through
the production static pipeline (not guessed):

  * A ``claimGovernance``        — ``view_call _pendingGovernor()`` (internal,
    reverts/empties on every deployment).
  * B ``acceptDefaultAdminTransfer`` — ``state_variable _pendingDefaultAdmin``
    member ``newAdmin``. The provenance engine inlines OZ's public
    ``pendingDefaultAdmin()`` down to its storage struct read, so the operand is a
    struct member with NO getter to call — nothing is read at runtime.
  * D ``MembershipNFT.membershipManager`` — bare internal ``state_variable`` whose
    getter reverts (kept here only as an out-of-scope precision baseline; it needs
    P3's storage read, NOT touched by this slice).

What this net locks (true on both main and the P1/P2 branch, so it never goes
stale): the five A/B functions resolve to an EMPTY caller set with NO principal
rows — the under-resolution symptom. The status *flip* those empties undergo
(A/B → ``resolved_empty`` once the empty-by-design detector lands) is pinned by
``test_pending_transfer_ceiling`` so this file stays a stable scope witness:
non-pending getter-less authorities (the guard + D) must NOT flip.

Pure/offline, ``test_authority_live_getter_resolution`` pattern: literal predicate
trees, a stubbed ``utils.rpc.rpc_request``, a stub adapter exposing ``_outer_ctx``.
The global ``_stub_live_authority`` conftest fixture is deliberately NOT used — it
forces ``_live_resolve_authority`` to ``None`` and would defeat the point.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree

CONTRACT = "0x" + "11" * 20
OWNER_SELECTOR = "0x8da5cb5b"  # owner()

# Real operand shapes (compiled from source — see module docstring).
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
D_MEMBERSHIP_MANAGER = {"source": "state_variable", "state_variable_name": "membershipManager"}


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


def _eq_tree(other_operand: dict[str, Any]) -> PredicateTree:
    return cast(
        PredicateTree,
        {
            "op": "LEAF",
            "leaf": {
                "kind": "equality",
                "operator": "eq",
                "authority_role": "caller_authority",
                "operands": [{"source": "msg_sender"}, other_operand],
                "references_msg_sender": True,
                "parameter_indices": [],
                "expression": "msg.sender == X",
                "basis": [],
            },
        },
    )


def _stub_rpc(monkeypatch: pytest.MonkeyPatch, mode: str, *, recorder: list | None = None) -> None:
    """Stub ``utils.rpc.rpc_request``. ``mode``: ``revert`` (raise), ``empty`` (a
    bare ``0x``, the no-code/empty return), or an address to left-pad into a word."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if mode == "revert":
            raise RuntimeError("execution reverted")
        if mode == "empty":
            return "0x"
        return "0x" + mode[2:].rjust(64, "0")

    monkeypatch.setattr("utils.rpc.rpc_request", fake)


def _status(cap: CapabilityExpr) -> str | None:
    cap_dict = capability_to_dict(cap)
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


def _principal_rows(cap: CapabilityExpr) -> list[dict[str, Any]]:
    return project_capability_surface(capability_to_dict(cap)).principal_rows


# --------------------------------------------------------------------------
# A + B: empty caller set, no principal rows (the under-resolution symptom).
# Stable across main and the fix — the status flip is pinned in the P2 file.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["revert", "empty"])
def test_group_a_pending_governor_yields_empty_caller_set(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    _stub_rpc(monkeypatch, mode)
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert _principal_rows(cap) == []


def test_group_b_pending_default_admin_member_yields_empty_caller_set(monkeypatch: pytest.MonkeyPatch) -> None:
    # Struct member, no getter — recorder proves no read is attempted.
    recorder: list = []
    _stub_rpc(monkeypatch, "revert", recorder=recorder)
    cap = evaluate_tree(_eq_tree(B_PENDING_DEFAULT_ADMIN), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert _principal_rows(cap) == []
    assert recorder == []  # no getter exists to call


# --------------------------------------------------------------------------
# Precision baselines — these must STAY under-resolved (never resolved_empty),
# proving the P1/P2 changes don't over-reach onto non-pending authorities.
# --------------------------------------------------------------------------


def test_guard_non_pending_owner_revert_stays_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, "revert")
    cap = evaluate_tree(_eq_tree(GUARD_OWNER), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert _status(cap) != "resolved_empty"


def test_group_d_internal_var_revert_stays_unresolved_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """D (``membershipManager``) needs P3's storage-slot read — NOT this slice.
    A non-pending internal var whose getter reverts stays the lower_bound
    placeholder, never resolved_empty."""
    _stub_rpc(monkeypatch, "revert")
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert _status(cap) != "resolved_empty"
