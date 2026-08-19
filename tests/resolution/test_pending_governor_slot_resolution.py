"""Getter-less ``pending`` authority gates resolve by reading the live storage
slot — not by guessing ``resolved_empty`` from the accessor name.

Governable ``claimGovernance`` is gated by ``msg.sender == _pendingGovernor()``,
an INTERNAL accessor that ``sload``s ``keccak256("LRTSquare.pending.governor")``
and has NO public getter. The audited interim fix lowered any ``pending``-named
accessor whose getter reverts to ``finite_set([], exact, empty_by_design)`` —
i.e. "provably nobody" — *without reading the slot*. On the live LRTSquared proxy
that slot is **non-zero** (it equals ``governor()``: ``_changeGovernor`` never
clears the pending slot, so after a completed transfer it stays == governor and
the accept gate is satisfiable by the sitting governor), so ``claimGovernance``
is actually callable and the label was a false negative.

The fix: the static stage carries the keccak slot on the operand
(``storage_slot``), and resolution reads it with ``eth_getStorageAt``:
  * non-zero slot  → ``finite_set([pendingGovernor], exact)`` (the real caller),
  * confirmed-zero → ``resolved_empty`` (read-confirmed accept-side ceiling),
  * unreadable     → honest ``lower_bound`` (never a fabricated resolved_empty).

Layered like ``test_canonical_authority_getter_resolution.py``: literal-dict unit
tests pin the resolver and always run; the integration test compiles the verbatim
on-chain Governable source and proves the operand carries the slot end-to-end.
The global ``_stub_live_authority`` fixture is deliberately not used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree
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
# The pre-fix shape (no slot carried) — exercises the name-based fallback that
# only survives for getter-less, slot-less pending operands (OZ struct member).
A_PENDING_GOVERNOR_NO_SLOT: dict[str, Any] = {
    "source": "view_call",
    "callee_signature": "_pendingGovernor()",
    "callee_selector": INTERNAL_PENDING_GOVERNOR_SELECTOR,
}


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


def _ctx_with_rpc(rpc_url: str = "http://rpc.test", address: str = CONTRACT) -> EvaluationContext:
    return EvaluationContext(contract_address=address, adapter=_Adapter(_Outer(rpc_url, address)))


def _eq_tree(other_operand: dict[str, Any]) -> PredicateTree:
    return eq_tree(other_operand, "msg.sender == _pendingGovernor()")


def _stub(monkeypatch: pytest.MonkeyPatch, *, slot: str, getter: str = "revert", recorder: list | None = None) -> None:
    """``eth_call`` getters use ``getter`` ('revert' to raise; else returned
    verbatim — there is no public ``pendingGovernor()``); ``eth_getStorageAt``
    returns ``slot`` ('revert' to simulate an unreadable slot)."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if method == "eth_getStorageAt":
            if slot == "revert":
                raise RuntimeError("execution reverted")
            return slot
        if getter == "revert":
            raise RuntimeError("execution reverted")
        return getter

    monkeypatch.setattr("utils.rpc.rpc_request", fake)


def _word(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _status(cap: CapabilityExpr) -> str | None:
    cap_dict = capability_to_dict(cap)
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


# --------------------------------------------------------------------------
# Resolver unit tests (literal operand; always run).
# --------------------------------------------------------------------------


def test_nonzero_slot_resolves_to_pending_governor(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live (non-empty) pending slot IS the authorized caller — the
    LRTSquared reality the name-guess mislabeled as 'provably nobody'."""
    recorder: list = []
    _stub(monkeypatch, slot=_word(PENDING_GOVERNOR), recorder=recorder)
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [PENDING_GOVERNOR]
    assert cap.membership_quality == "exact"
    assert cap.empty_reason is None
    assert _status(cap) != "resolved_empty"
    # The getter is tried first (and reverts) before the slot is read.
    assert ("eth_getStorageAt", [CONTRACT.lower(), PENDING_GOVERNOR_SLOT, "latest"]) in recorder


def test_confirmed_zero_slot_is_resolved_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """A read-confirmed zero slot (no transfer pending — PriceProvider reality)
    is a genuine accept-side ceiling, and the verdict (``resolved_empty``) is
    unchanged.

    What it publishes as its REASON changed with A2: ``slot_read_zero``, which
    reports the read that happened, rather than ``empty_by_design``, which came
    from a default argument value and asserted a classification. The
    accept-side-ceiling claim rests on the accessor's ``pending`` prefix — an
    identifier — and now lives only where it discloses that basis
    (``_pending_ceiling_capability``)."""
    _stub(monkeypatch, slot="0x" + "00" * 32)
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"
    assert cap.empty_reason == "slot_read_zero"
    assert _status(cap) == "resolved_empty"
    # The read that produced it is on the row, so the empty is reconstructible.
    assert cap.trace[0]["step"] == "live_slot_resolution"
    assert cap.trace[0]["slot"] == PENDING_GOVERNOR_SLOT


def test_unreadable_slot_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """The anti-regression: when BOTH the getter and the slot are unreadable, the
    honest answer is ``lower_bound`` (unknown), never a fabricated resolved_empty.
    This is the exact failure the name-based guess introduced."""
    _stub(monkeypatch, slot="revert")
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_revert"
    assert _status(cap) != "resolved_empty"


def test_no_rpc_with_slot_is_lower_bound_not_guess(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slot-bearing operand with no reachable RPC stays an honest unknown — the
    presence of a slot disables the name-based empty-by-design guess entirely."""
    cap = evaluate_tree(
        _eq_tree(A_PENDING_GOVERNOR_SLOT), EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None))
    )

    assert cap.membership_quality == "lower_bound"
    assert _status(cap) != "resolved_empty"


def test_slotless_pending_operand_keeps_empty_by_design_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """The narrowed fallback: a getter-less, slot-less ``pending`` accessor (the
    OZ ``_pendingDefaultAdmin.newAdmin`` struct member) still lowers to
    empty-by-design — the slot read above guarantees this only fires when there is
    genuinely nothing to read."""
    _stub(monkeypatch, slot="revert")  # eth_call getter reverts; no slot on the operand
    cap = evaluate_tree(_eq_tree(A_PENDING_GOVERNOR_NO_SLOT), _ctx_with_rpc())

    assert cap.members == []
    assert cap.empty_reason == "empty_by_design"
    assert _status(cap) == "resolved_empty"


# --------------------------------------------------------------------------
# Integration: compile the verbatim on-chain Governable and prove the slot is
# carried + read end-to-end. Skips when no compatible solc is installed.
# --------------------------------------------------------------------------

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts  # noqa: E402
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile


def _claim_governance_tree() -> Any:
    # Returns the compiled tree as Any (a PredicateTree at runtime) — the
    # integration assertions subscript NotRequired keys, mirroring the untyped
    # access in test_canonical_authority_getter_resolution.py.
    solc = _solc_path_for((0, 8, 25))
    if solc is None:
        pytest.skip("no installed solc satisfies ^0.8.25 for Governable.sol")
    sl = Slither(str(FIXTURES_DIR / "Governable.sol"), solc=solc)
    contract = next(c for c in sl.contracts if c.name == "Governable")
    return build_predicate_artifacts(contract)["trees"]["claimGovernance()"]


class TestGovernableClaimGovernanceSlot:
    def test_operand_carries_keccak_slot(self) -> None:
        """The static stage recovers the keccak slot the accessor sload()s and
        attaches it to the (getter-less) view_call operand."""
        tree = _claim_governance_tree()
        leaf = next(
            child["leaf"] for child in tree["children"] if child["leaf"]["authority_role"] == "caller_authority"
        )
        view_op = next(o for o in leaf["operands"] if o.get("source") == "view_call")
        assert view_op["callee_signature"] == "_pendingGovernor()"
        assert view_op.get("storage_slot") == PENDING_GOVERNOR_SLOT

    def test_resolves_live_pending_governor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end: getter reverts, the carried slot is read, the live value is
        the principal — claimGovernance is NOT resolved_empty (the LRTSquared fix)."""
        _stub(monkeypatch, slot=_word(PENDING_GOVERNOR))
        cap = evaluate_tree(_claim_governance_tree(), _ctx_with_rpc())
        surface = project_capability_surface(capability_to_dict(cap))

        assert [r["address"] for r in surface.principal_rows] == [PENDING_GOVERNOR]
        assert _status(cap) != "resolved_empty"

    def test_confirmed_zero_slot_is_resolved_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub(monkeypatch, slot="0x" + "00" * 32)
        cap = evaluate_tree(_claim_governance_tree(), _ctx_with_rpc())

        assert project_capability_surface(capability_to_dict(cap)).principal_rows == []
        assert _status(cap) == "resolved_empty"

    def test_unreadable_slot_is_not_resolved_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub(monkeypatch, slot="revert")
        cap = evaluate_tree(_claim_governance_tree(), _ctx_with_rpc())

        assert _status(cap) != "resolved_empty"
