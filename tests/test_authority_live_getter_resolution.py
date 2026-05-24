"""Regression: owner()/governor()-gated functions must resolve a principal.

Pins the etherfi recall gap where ``msg.sender == owner()`` /
``== governor()`` produced an empty ``finite_set(lower_bound)`` (hence zero
``FunctionPrincipal`` rows, hence no surfaced controller) because the equality
evaluator consulted only the persisted ``state_var_values`` feed and never read
the getter. EtherfiL1SyncPoolETH (onlyOwner) and LRTSquaredCore (onlyGovernor)
each lost their governor this way; CumulativeMerkleDrop is the separate
self-AccessControl case (see module docstring of ``predicate_evaluator``).

The fix (``predicate_evaluator._live_resolve_authority``) reads the getter live
when an RPC is reachable through the outer resolver context. These tests are
pure/offline: the predicate trees are literal dicts and the RPC is stubbed, so
they pin the behaviour without the analysis pipeline or MinIO artifacts.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from services.policy.capability_surface import project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree

CONTRACT = "0x" + "11" * 20
OWNER = "0x" + "ab" * 20
GOVERNOR = "0x" + "cd" * 20
OWNER_SELECTOR = "0x8da5cb5b"  # owner()


# --------------------------------------------------------------------------
# Stub resolver context: exposes ``_outer_ctx`` (carrying rpc_url + address)
# exactly the way the real registry-backed adapter does, so the equality
# resolver's live-getter path can reach an RPC. No outer ⇒ no RPC ⇒ the
# pre-fix empty-placeholder behaviour (the gap condition).
# --------------------------------------------------------------------------


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


def _ctx_no_rpc() -> EvaluationContext:
    # An adapter with no _outer_ctx — the pure-unit path, no RPC reachable.
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None))


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


def _stub_rpc(monkeypatch: pytest.MonkeyPatch, return_addr: str | None, *, recorder: list | None = None) -> None:
    """Patch utils.rpc.rpc_request to return ``return_addr`` left-padded to a
    32-byte word (the eth_call ABI shape for a single address return)."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if return_addr is None:
            raise RuntimeError("rpc unavailable")
        return "0x" + return_addr[2:].rjust(64, "0")

    monkeypatch.setattr("utils.rpc.rpc_request", fake)


# --------------------------------------------------------------------------
# The gap condition: no RPC reachable ⇒ empty placeholder ⇒ no principal.
# --------------------------------------------------------------------------


def test_owner_view_call_without_rpc_stays_empty_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})

    cap = evaluate_tree(tree, _ctx_no_rpc())

    # Reproduces the recall gap: gated, but no principal enumerated.
    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert recorder == []  # no outer ctx ⇒ no RPC attempt
    assert project_capability_surface(capability_to_dict(cap)).principal_rows == []


# --------------------------------------------------------------------------
# The fix: with an RPC reachable, owner()/governor() resolve to the principal.
# --------------------------------------------------------------------------


def test_owner_view_call_resolves_via_live_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, OWNER)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [OWNER]
    assert cap.membership_quality == "exact"
    assert cap.confidence == "enumerable"


def test_view_call_resolves_from_signature_when_selector_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, GOVERNOR)
    # No callee_selector — must be derived from the nullary signature.
    tree = _eq_tree({"source": "view_call", "callee_signature": "governor()"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [GOVERNOR]


def test_state_var_miss_resolves_via_live_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    """`msg.sender == governor` as a bare state variable whose value wasn't in
    the ControllerValue feed (LRTSquaredCore's governor was filed under the
    wrong key) — the getter is read live."""
    _stub_rpc(monkeypatch, GOVERNOR)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "governor"})

    # state_var_values intentionally empty (the miss).
    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [GOVERNOR]
    assert cap.membership_quality == "exact"


def test_renounced_getter_resolves_to_exact_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Getter returns the zero address (renounced/unset) — distinguishable
    'exact empty' rather than the 'unresolved' lower_bound placeholder."""
    _stub_rpc(monkeypatch, "0x" + "00" * 20)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"


# --------------------------------------------------------------------------
# Precision guards: don't regress existing behaviour or re-introduce noise.
# --------------------------------------------------------------------------


def test_state_var_present_wins_without_any_rpc_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """A value already in state_var_values resolves from the feed — the live
    getter must not fire (no behaviour change, no extra RPC)."""
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "owner"})

    ctx = EvaluationContext(
        contract_address=CONTRACT,
        adapter=_Adapter(_Outer("http://rpc.test", CONTRACT)),
        state_var_values={"owner": GOVERNOR},
    )
    cap = evaluate_tree(tree, ctx)

    assert cap.members == [GOVERNOR]
    assert recorder == []  # fast path: no live call


def test_struct_member_destination_is_not_live_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """`accountantState.payoutAddress` is a fund destination, not a caller.
    It has no nullary getter and must stay the placeholder — the FP-only
    attribution must not re-acquire fee-destination noise this way."""
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree(
        {
            "source": "state_variable",
            "state_variable_name": "accountantState",
            "member_path": ["payoutAddress"],
        }
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert recorder == []  # struct member ⇒ no getter attempted


def test_view_call_with_args_is_not_live_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """`msg.sender == roleAdmin(role)` takes an argument and can't be read
    with empty calldata — left as the placeholder, no RPC attempted."""
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree(
        {
            "source": "view_call",
            "callee_signature": "roleAdmin(bytes32)",
            "callee_selector": "0x12345678",
            "callee_args": [{"source": "constant", "constant_value": "0x" + "00" * 32}],
        }
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert recorder == []


# --------------------------------------------------------------------------
# End-to-end: the resolved capability surfaces as a FunctionPrincipal row,
# which is the signal services.governance.primary_controller keys on.
# --------------------------------------------------------------------------


def test_resolved_owner_surfaces_as_function_principal_row(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, OWNER)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})

    resolved = evaluate_tree(tree, _ctx_with_rpc())
    unresolved = evaluate_tree(tree, _ctx_no_rpc())

    resolved_rows = project_capability_surface(capability_to_dict(resolved)).principal_rows
    unresolved_rows = project_capability_surface(capability_to_dict(unresolved)).principal_rows

    # The bridge: a resolved owner becomes exactly one caller principal row…
    assert [r["address"] for r in resolved_rows] == [OWNER]
    assert all(r.get("principal_type") == "controller" for r in resolved_rows)
    # …whereas the unresolved placeholder emits none (the recall gap).
    assert unresolved_rows == []


def test_resolved_owner_becomes_primary_controller() -> None:
    """The downstream consumer: once the resolved owner is an FP caller on the
    contract, assign_primary_controllers surfaces it as the primary — the
    controller that was missing for SyncPool / LRTSquaredCore. With no FP
    caller (the pre-fix state) the same Safe wins nothing."""
    from services.governance.primary_controller import assign_primary_controllers

    principals = [{"address": OWNER, "type": "safe"}]

    post_fix = assign_primary_controllers(principals, {CONTRACT: {OWNER}})
    assert post_fix[OWNER.lower()] == [CONTRACT.lower()]

    pre_fix = assign_primary_controllers(principals, {CONTRACT: set()})
    assert pre_fix[OWNER.lower()] == []
