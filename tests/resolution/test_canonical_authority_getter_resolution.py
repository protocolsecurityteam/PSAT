"""Caller-equality gates read through a non-canonical accessor resolve via the canonical public getter.

#4: Governable ``onlyGovernor`` reads internal ``_governor()``; fall back to ``governor()``.
#6: Solady ``Ownable`` reads the ``_OWNER_SLOT`` constant; fall back to ``owner()`` and never mint a
``role_identifier:_OWNER_SLOT`` target. The fixture tests compile real on-chain source and skip without solc.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from services.resolution.capabilities import CapabilityExpr
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x" + "11" * 20
OWNER = "0x" + "ab" * 20
GOVERNOR = "0x" + "cd" * 20
BURN = "0x" + "00" * 18 + "dead"

OWNER_SELECTOR = "0x8da5cb5b"  # owner()
GOVERNOR_SELECTOR = "0x0c340a24"  # governor()
INTERNAL_GOVERNOR_SELECTOR = "0x95260843"  # _governor()
OWNER_SLOT_SELECTOR = "0x12f93717"  # _OWNER_SLOT()

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authority"


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


def _ctx_no_rpc() -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None))


def _stub_rpc_map(monkeypatch: pytest.MonkeyPatch, returns: dict[str, str | None], recorder: list) -> None:

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        selector = params[0]["data"]
        recorder.append(selector)
        value = returns.get(selector)
        if value is None:
            raise RuntimeError("execution reverted")
        return "0x" + value[2:].rjust(64, "0")

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)


def _called(recorder: list, selector: str) -> bool:
    return any(s == selector for s in recorder)


def test_governor_internal_accessor_resolves_via_public_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc_map(monkeypatch, {INTERNAL_GOVERNOR_SELECTOR: None, GOVERNOR_SELECTOR: GOVERNOR}, recorder)
    tree = _eq_tree(
        {"source": "view_call", "callee_signature": "_governor()", "callee_selector": INTERNAL_GOVERNOR_SELECTOR}
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [GOVERNOR]
    assert cap.membership_quality == "exact"
    assert _called(recorder, GOVERNOR_SELECTOR)
    assert not _called(recorder, INTERNAL_GOVERNOR_SELECTOR)


def test_governor_internal_accessor_without_public_getter_stays_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc_map(monkeypatch, {INTERNAL_GOVERNOR_SELECTOR: None, GOVERNOR_SELECTOR: None}, recorder)
    tree = _eq_tree(
        {"source": "view_call", "callee_signature": "_governor()", "callee_selector": INTERNAL_GOVERNOR_SELECTOR}
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert _called(recorder, GOVERNOR_SELECTOR)  # the canonical getter WAS attempted


def test_public_getter_view_call_not_double_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc_map(monkeypatch, {GOVERNOR_SELECTOR: GOVERNOR}, recorder)
    tree = _eq_tree({"source": "view_call", "callee_signature": "governor()", "callee_selector": GOVERNOR_SELECTOR})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == [GOVERNOR]
    assert recorder == [GOVERNOR_SELECTOR]  # exactly one call, the literal getter


# A wrong controller is worse than a missing one: only owner/governor/authority de-underscore, and only owner locators
# reroute to owner().
@pytest.mark.parametrize(
    ("returns", "operand", "forbidden_selector"),
    [
        pytest.param(
            {"0x3ec954ed": OWNER},  # keccak("recoveryWallet()")[:4]
            {"source": "view_call", "callee_signature": "_recoveryWallet()"},
            "0x3ec954ed",
            id="non-authority-internal-accessor-not-de-underscored",
        ),
        pytest.param(
            {OWNER_SELECTOR: OWNER},
            {"source": "state_variable", "state_variable_name": "BaseMessengerStorageLocation"},
            OWNER_SELECTOR,
            id="non-authority-storage-slot-stays-placeholder",
        ),
    ],
)
def test_non_authority_accessor_is_not_rerouted(
    monkeypatch: pytest.MonkeyPatch, returns: dict[str, str | None], operand: dict, forbidden_selector: str
) -> None:
    recorder: list = []
    _stub_rpc_map(monkeypatch, returns, recorder)
    tree = _eq_tree(operand)

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert not _called(recorder, forbidden_selector)


# OZ-v5 surfaces the slot constant (``OwnableStorageLocation``) too.
@pytest.mark.parametrize(
    ("returns", "slot_name"),
    [
        pytest.param({OWNER_SLOT_SELECTOR: None, OWNER_SELECTOR: OWNER}, "_OWNER_SLOT", id="owner-slot-constant"),
        pytest.param({OWNER_SELECTOR: OWNER}, "OwnableStorageLocation", id="oz-v5-ownable-storage-location"),
    ],
)
def test_owner_slot_constant_resolves_via_owner_getter(
    monkeypatch: pytest.MonkeyPatch, returns: dict[str, str | None], slot_name: str
) -> None:
    recorder: list = []
    _stub_rpc_map(monkeypatch, returns, recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": slot_name})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [OWNER]
    assert cap.membership_quality == "exact"
    assert _called(recorder, OWNER_SELECTOR)


slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)
from services.static.contract_analysis_pipeline.tracking import build_controller_tracking  # noqa: E402
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile


def _compile_fixture(rel_path: str, floor: tuple[int, int, int]):
    solc = _solc_path_for(floor)
    if solc is None:
        pytest.skip(f"no installed solc satisfies ^{'.'.join(str(x) for x in floor)} for {rel_path}")
    return Slither(str(FIXTURES_DIR / rel_path), solc=solc)


def _contract(sl, name: str):
    return next(c for c in sl.contracts if c.name == name)


class TestGovernableFixture:

    def test_transfer_governance_resolves_governor_via_canonical_getter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sl = _compile_fixture("Governable.sol", (0, 8, 25))
        contract = _contract(sl, "Governable")
        trees = build_predicate_artifacts(contract)["trees"]
        tree = trees["transferGovernance(address)"]

        leaf = tree["leaf"]
        view_op = next(o for o in leaf["operands"] if o.get("source") == "view_call")
        assert view_op["callee_signature"] == "_governor()"
        assert view_op["callee_selector"] == INTERNAL_GOVERNOR_SELECTOR

        recorder: list = []
        _stub_rpc_map(monkeypatch, {INTERNAL_GOVERNOR_SELECTOR: None, GOVERNOR_SELECTOR: GOVERNOR}, recorder)

        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert cap.members == [GOVERNOR], "onlyGovernor gate must resolve to the governor"
        assert cap.membership_quality == "exact"
        assert _called(recorder, GOVERNOR_SELECTOR), "must read the canonical governor()"


class TestTopUpSoladyFixture:

    # Since A2 the burned owner concludes only an empty ``lower_bound``, never "provably nobody".
    @pytest.mark.parametrize(
        ("owner", "members", "quality", "empty_reason"),
        [
            pytest.param(BURN, [], "lower_bound", "owner_read_burn_address", id="burned-owner"),
            pytest.param(OWNER, [OWNER], "exact", None, id="live-owner"),
        ],
    )
    def test_process_top_up_resolves_owner_not_slot(
        self, monkeypatch: pytest.MonkeyPatch, owner: str, members: list[str], quality: str, empty_reason: str | None
    ) -> None:
        sl = _compile_fixture("TopUpSolady.sol", (0, 8, 4))
        contract = _contract(sl, "TopUpSolady")
        trees = build_predicate_artifacts(contract)["trees"]
        tree = trees["processTopUp(address[])"]

        assert "'state_variable_name': '_OWNER_SLOT'" in json.dumps(tree).replace('"', "'")

        recorder: list = []
        _stub_rpc_map(monkeypatch, {OWNER_SLOT_SELECTOR: None, OWNER_SELECTOR: owner}, recorder)

        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert cap.kind == "finite_set"
        assert cap.members == members
        assert cap.membership_quality == quality
        assert cap.empty_reason == empty_reason
        assert _called(recorder, OWNER_SELECTOR), "must read owner(), not _OWNER_SLOT()"

    def test_controller_tracking_emits_no_dead_owner_slot_role(self) -> None:
        """D6-reject removed it at the source; the downstream suppression must still hold on its own."""
        sl = _compile_fixture("TopUpSolady.sol", (0, 8, 4))
        contract = _contract(sl, "TopUpSolady")
        project_dir = FIXTURES_DIR
        predicate_trees = build_predicate_artifacts(contract)
        effects = build_effects(contract)
        semantic = _build_semantic_control_summary(contract, project_dir, predicate_trees, effects)

        assert "_OWNER_SLOT" not in [r.get("role") for r in semantic.get("role_definitions", [])]

        targets = build_controller_tracking(contract, project_dir, predicate_trees, effects, semantic)
        controller_ids = {t["controller_id"] for t in targets}

        assert "role_identifier:_OWNER_SLOT" not in controller_ids
        assert not any(cid.startswith("role_identifier:") and "_SLOT" in cid for cid in controller_ids)
