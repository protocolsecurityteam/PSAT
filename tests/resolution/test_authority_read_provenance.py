"""A2/A3: an exact-empty caller set used to be published with no step, selector, block or reason, and the accessor
basis lived only in the trace. Reads are pinned to block 25643300.
"""

from __future__ import annotations

from typing import Any

import pytest
from eth_utils.crypto import keccak

from services.policy.capability_surface import project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x62247d29b4b9becf4bb73e0c722cf6445cfc7ce9"
GOVERNOR = "0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5"
BURN = "0x" + "00" * 18 + "dead"
PINNED_BLOCK = 25643300

OWNER_SELECTOR = "0x8da5cb5b"  # owner()
GOVERNOR_SELECTOR = "0x0c340a24"  # governor()


class _Outer:
    def __init__(self, block: int | None) -> None:
        self.rpc_url = "http://rpc.test"
        self.contract_address = CONTRACT
        self.block = block
        self.meta: dict[str, Any] = {"live_read_memo": {}}


class _Adapter:
    def __init__(self, block: int | None) -> None:
        self._outer_ctx = _Outer(block)

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx(block: int | None = PINNED_BLOCK) -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(block))


def _word(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _stub_getter(monkeypatch: pytest.MonkeyPatch, *, returns: str, only: str | None = None) -> list[list[Any]]:
    calls: list[list[Any]] = []

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        calls.append([method, params])
        if only is not None and params[0].get("data") != only:
            raise RuntimeError("execution reverted")
        if returns == "revert":
            raise RuntimeError("execution reverted")
        return returns

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)
    return calls


def test_zero_read_publishes_the_whole_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_getter(monkeypatch, returns=_word("0x" + "00" * 20), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())

    assert capability_to_dict(cap) == {
        "kind": "finite_set",
        "members": [],
        "membership_quality": "exact",
        "confidence": "enumerable",
        "trace": [
            {
                "step": "live_getter_resolution",
                "selector": OWNER_SELECTOR,
                "contract": CONTRACT,
                "observed_at_block": PINNED_BLOCK,
            },
            {"step": "authority_getter_basis", "basis": "callee_selector", "selector": OWNER_SELECTOR},
        ],
        "empty_reason": "owner_read_zero",
    }


def test_latest_path_publishes_no_observation_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stamping a height on a ``"latest"`` read would bound an unbounded claim."""
    calls = _stub_getter(monkeypatch, returns=_word("0x" + "00" * 20), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx(block=None))

    assert calls[0][1][1] == "latest"
    assert cap.empty_reason == "owner_read_zero"
    assert "observed_at_block" not in cap.trace[0]


SLOT = "0x" + keccak(text="LRTSquare.pending.governor").hex()


def _stub_slot(monkeypatch: pytest.MonkeyPatch, word: str) -> list[list[Any]]:
    calls: list[list[Any]] = []

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        calls.append([method, params])
        if method == "eth_call":
            raise RuntimeError("execution reverted")
        return word

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)
    return calls


def test_zero_slot_publishes_the_read_not_a_classification(monkeypatch: pytest.MonkeyPatch) -> None:
    """``empty_by_design`` used to arrive from a default argument."""
    calls = _stub_slot(monkeypatch, "0x" + "00" * 32)
    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "_pendingGovernor()", "storage_slot": SLOT}),
        _ctx(),
    )

    assert cap.members == []
    assert cap.membership_quality == "exact"
    assert cap.empty_reason == "slot_read_zero"
    assert cap.trace == [
        {
            "step": "live_slot_resolution",
            "slot": SLOT,
            "contract": CONTRACT,
            "observed_at_block": PINNED_BLOCK,
        }
    ]
    assert ["eth_getStorageAt", [CONTRACT, SLOT, hex(PINNED_BLOCK)]] in calls


def test_burn_slot_is_not_an_exact_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_slot(monkeypatch, _word(BURN))
    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "_pendingGovernor()", "storage_slot": SLOT}),
        _ctx(),
    )

    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "owner_read_burn_address"
    assert cap.trace[0]["read_address"] == BURN


def test_slot_latest_path_publishes_no_observation_block(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_slot(monkeypatch, "0x" + "00" * 32)
    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "_pendingGovernor()", "storage_slot": SLOT}),
        _ctx(block=None),
    )
    assert cap.empty_reason == "slot_read_zero"
    assert "observed_at_block" not in cap.trace[0]


def _authority_details(cap: CapabilityExpr) -> dict[str, Any]:
    rows = project_capability_surface(capability_to_dict(cap)).principal_rows
    assert len(rows) == 1
    return rows[0]["details"]


def test_oz_v5_namespaced_accessor_gets_its_own_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """OZ-v5 accessors used to share the de-underscore label, hiding a standard-anchored match from a 3-name guess."""
    _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=OWNER_SELECTOR)
    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "_getAccessControlDefaultAdminRulesStorage()"}),
        _ctx(),
    )

    assert cap.members == [GOVERNOR]
    details = _authority_details(cap)
    assert details["authority_basis"] == "standard_namespaced_accessor"
    # An exact-name match is still a name match.
    assert details["accessor_slot_agreement"] == "not_determined"


def test_unknown_internal_accessor_resolves_to_no_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_frobnicate()"}), _ctx())

    assert cap.members == []
    assert project_capability_surface(capability_to_dict(cap)).principal_rows == []
