"""Caller-equality gates read through a non-canonical accessor resolve via the canonical public getter.

#4: Governable ``onlyGovernor`` reads internal ``_governor()``; fall back to ``governor()``.
#6: Solady ``Ownable`` reads the ``_OWNER_SLOT`` constant; fall back to ``owner()`` and never mint a
``role_identifier:_OWNER_SLOT`` target. The fixture tests compile real on-chain source and skip without solc.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from tests.support.authority_reads import _Adapter, _Outer, _stub_rpc_map

CONTRACT = "0x" + "11" * 20
OWNER = "0x" + "ab" * 20
GOVERNOR = "0x" + "cd" * 20
BURN = "0x" + "00" * 18 + "dead"

OWNER_SELECTOR = "0x8da5cb5b"  # owner()
GOVERNOR_SELECTOR = "0x0c340a24"  # governor()
INTERNAL_GOVERNOR_SELECTOR = "0x95260843"  # _governor()
OWNER_SLOT_SELECTOR = "0x12f93717"  # _OWNER_SLOT()

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authority"


def _ctx_with_rpc(rpc_url: str = "http://rpc.test") -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(_Outer(rpc_url, CONTRACT)))


def _ctx_no_rpc() -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None))


def _called(recorder: list, selector: str) -> bool:
    return any(s == selector for s in recorder)


# A wrong controller is worse than a missing one: only owner/governor/authority de-underscore, and only owner locators
# reroute to owner().


# OZ-v5 surfaces the slot constant (``OwnableStorageLocation``) too.


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
