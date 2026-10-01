"""LRTSquared ``claimGovernance`` reads internal ``_pendingGovernor()``; the name-based guess lowered it to "nobody",
but the live slot is non-zero, so it's read instead. The global ``_stub_live_authority`` fixture is deliberately
not used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from services.policy.capability_surface import project_capability_surface
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree
from tests.support.authority_reads import _Adapter, _Outer, _status, _stub
from tests.support.eq_tree import eq_tree

CONTRACT = "0x" + "11" * 20
PENDING_GOVERNOR = "0x" + "cd" * 20
PENDING_GOVERNOR_SLOT = "0x0fe544e960ecab9b6f1eee0df869972d09c3c135c0d116422cce176351b52237"
INTERNAL_PENDING_GOVERNOR_SELECTOR = "0x638adcc8"  # _pendingGovernor()

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authority"

A_PENDING_GOVERNOR_SLOT: dict[str, Any] = {
    "source": "view_call",
    "callee_signature": "_pendingGovernor()",
    "callee_selector": INTERNAL_PENDING_GOVERNOR_SELECTOR,
    "storage_slot": PENDING_GOVERNOR_SLOT,
}
# Only getter-less, slot-less pending operands keep the name-based fallback.
A_PENDING_GOVERNOR_NO_SLOT: dict[str, Any] = {
    "source": "view_call",
    "callee_signature": "_pendingGovernor()",
    "callee_selector": INTERNAL_PENDING_GOVERNOR_SELECTOR,
}


def _ctx_with_rpc(rpc_url: str = "http://rpc.test", address: str = CONTRACT) -> EvaluationContext:
    return EvaluationContext(contract_address=address, adapter=_Adapter(_Outer(rpc_url, address)))


def _eq_tree(other_operand: dict[str, Any]) -> PredicateTree:
    return eq_tree(other_operand, "msg.sender == _pendingGovernor()")


def _word(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def test_nonzero_slot_resolves_to_pending_governor(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub(monkeypatch, slot=_word(PENDING_GOVERNOR), recorder=recorder)
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [PENDING_GOVERNOR]
    assert cap.membership_quality == "exact"
    assert cap.empty_reason is None
    assert _status(cap) != "resolved_empty"
    assert ("eth_getStorageAt", [CONTRACT.lower(), PENDING_GOVERNOR_SLOT, "latest"]) in recorder


def test_confirmed_zero_slot_is_resolved_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """The reason names the read that happened, not a classification."""
    _stub(monkeypatch, slot="0x" + "00" * 32)
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"
    assert cap.empty_reason == "slot_read_zero"
    assert _status(cap) == "resolved_empty"
    assert cap.trace[0]["step"] == "live_slot_resolution"
    assert cap.trace[0]["slot"] == PENDING_GOVERNOR_SLOT


def test_unreadable_slot_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, slot="revert")
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_revert"
    assert _status(cap) != "resolved_empty"


def test_no_rpc_with_slot_is_lower_bound_not_guess(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slot disables the name-based guess entirely."""
    cap = evaluate_tree(
        _eq_tree(A_PENDING_GOVERNOR_SLOT), EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None))
    )

    assert cap.membership_quality == "lower_bound"
    assert _status(cap) != "resolved_empty"


def test_slotless_pending_operand_keeps_empty_by_design_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, slot="revert")  # eth_call getter reverts; no slot on the operand
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_NO_SLOT), _ctx_with_rpc())

    assert cap.members == []
    assert cap.empty_reason == "empty_by_design"
    assert _status(cap) == "resolved_empty"


pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts  # noqa: E402
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile


def _claim_governance_tree() -> Any:
    solc = _solc_path_for((0, 8, 25))
    if solc is None:
        pytest.skip("no installed solc satisfies ^0.8.25 for Governable.sol")
    sl = Slither(str(FIXTURES_DIR / "Governable.sol"), solc=solc)
    contract = next(c for c in sl.contracts if c.name == "Governable")
    return build_predicate_artifacts(contract)["trees"]["claimGovernance()"]


class TestGovernableClaimGovernanceSlot:
    @pytest.mark.parametrize(
        ("slot", "expected_rows", "resolved_empty"),
        [
            pytest.param(_word(PENDING_GOVERNOR), [PENDING_GOVERNOR], False, id="live_pending_governor"),
            pytest.param("0x" + "00" * 32, [], True, id="confirmed_zero_slot"),
            pytest.param("revert", [], False, id="unreadable_slot"),
        ],
    )
    def test_slot_states_resolve_claim_governance(
        self, monkeypatch: pytest.MonkeyPatch, slot: str, expected_rows: list[str], resolved_empty: bool
    ) -> None:
        _stub(monkeypatch, slot=slot)
        cap = evaluate_tree(_claim_governance_tree(), _ctx_with_rpc())
        surface = project_capability_surface(capability_to_dict(cap))

        assert [r["address"] for r in surface.principal_rows] == expected_rows
        assert (_status(cap) == "resolved_empty") is resolved_empty
