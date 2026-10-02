"""Getter-less internal address authorities resolve by reading their sequential storage slot.

ether.fi ``MembershipNFT`` gates on an internal ``membershipManager`` whose getter reverts. The static pass stamps
the slot and resolution reads it: nonzero is the principal, confirmed zero is ``slot_read_zero``, unreadable stays
``lower_bound``. The global ``_stub_live_authority`` fixture is deliberately not used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from services.policy.capability_surface import project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree
from tests.support.authority_reads import _Adapter, _Outer, _status, _stub
from tests.support.eq_tree import eq_tree

CONTRACT = "0x" + "11" * 20
MANAGER = "0x" + "ab" * 20
MEMBERSHIP_MANAGER_SLOT = "0x" + format(2, "064x")  # sequential layout slot in the fixture

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authority"

D_MEMBERSHIP_MANAGER_SLOT: dict[str, Any] = {
    "source": "state_variable",
    "state_variable_name": "membershipManager",
    "storage_slot": MEMBERSHIP_MANAGER_SLOT,
}
# The slot is what recovers the principal.
D_MEMBERSHIP_MANAGER_NO_SLOT: dict[str, Any] = {
    "source": "state_variable",
    "state_variable_name": "membershipManager",
}
# The low-20-byte decode is only valid for a bare scalar at offset 0.
D_STRUCT_MEMBER_WITH_SLOT: dict[str, Any] = {
    "source": "state_variable",
    "state_variable_name": "_pendingThing",
    "member_path": ["addr"],
    "storage_slot": MEMBERSHIP_MANAGER_SLOT,
}


def _ctx_with_rpc(rpc_url: str = "http://rpc.test", address: str = CONTRACT) -> EvaluationContext:
    return EvaluationContext(contract_address=address, adapter=_Adapter(_Outer(rpc_url, address)))


def _eq_tree(other_operand: dict[str, Any]) -> PredicateTree:
    return eq_tree(other_operand, "msg.sender == address(membershipManager)")


def _word(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _principals(cap: CapabilityExpr) -> list[str]:
    return [r["address"] for r in project_capability_surface(capability_to_dict(cap)).principal_rows]


def test_unreadable_slot_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, slot="revert")
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_revert"
    assert _status(cap) != "resolved_empty"


def test_empty_slot_return_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, slot="0x")
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER_SLOT), _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_empty"
    assert _status(cap) != "resolved_empty"


def test_no_rpc_with_slot_is_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = evaluate_tree(
        _eq_tree(D_MEMBERSHIP_MANAGER_SLOT),
        EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None)),
    )

    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "not_read"
    assert _status(cap) != "resolved_empty"


# --------------------------------------------------------------------------
# Integration: compile the MembershipNFT fixture and prove the static pass
# stamps the sequential slot and resolution reads it end-to-end.
# --------------------------------------------------------------------------

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.internal_authority_slot import (  # noqa: E402
    _slots_for_vars,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts  # noqa: E402
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile


def _membership_nft() -> Any:
    solc = _solc_path_for((0, 8, 13))
    if solc is None:
        pytest.skip("no installed solc satisfies ^0.8.13 for MembershipNFT.sol")
    sl = Slither(str(FIXTURES_DIR / "MembershipNFT.sol"), solc=solc)
    return next(c for c in sl.contracts if c.name == "MembershipNFT")


def _tree_for(contract: Any, signature: str) -> Any:
    return build_predicate_artifacts(contract)["trees"][signature]


class TestMembershipNFTStorageSlot:
    def test_static_pass_precision(self) -> None:
        """Public vars, private vars with a manual getter, mappings and non-address vars are excluded."""
        contract = _membership_nft()
        slots = _slots_for_vars(
            contract,
            {
                "membershipManager",  # internal, contract-typed, no getter → slot
                "_legacyController",  # private, plain address, no getter → slot
                "_owner",  # private BUT owner() exists → excluded (use the getter)
                "liquidityPool",  # public → excluded (auto-getter)
                "eapDepositProcessed",  # mapping → excluded
                "nextMintTokenId",  # public non-address → excluded
                "__gap0",  # internal non-address → excluded
            },
        )
        assert slots == {
            "membershipManager": MEMBERSHIP_MANAGER_SLOT,
            "_legacyController": "0x" + format(1, "064x"),
        }

    def test_resolves_live_membership_manager(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tree = _tree_for(_membership_nft(), "mint(address,uint256)")
        _stub(monkeypatch, slot=_word(MANAGER))
        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert _principals(cap) == [MANAGER]
        assert _status(cap) != "resolved_empty"
