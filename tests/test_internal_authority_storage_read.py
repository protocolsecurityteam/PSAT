"""Getter-less *internal* address authority vars resolve by reading the live
sequential storage slot (claim #3 group D).

ether.fi ``MembershipNFT`` gates ``mint`` / ``burn`` / ``incrementLock`` /
``processDepositFromEapUser`` on ``msg.sender == address(membershipManager)``,
where ``membershipManager`` is declared WITHOUT ``public`` — so its
``membershipManager()`` getter reverts on *every* deployment (there is no such
selector), and the persisted ``ControllerValue`` feed recorded only the revert.
Before P3 that funneled to ``finite_set([], lower_bound)`` — a silent
under-resolution, even though the manager is a real, recoverable controller.

The fix is two-part:
  * STATIC — a post-pass stamps the var's *sequential* storage slot onto the bare
    ``state_variable`` operand (``apply_internal_authority_slot_pass``), gated to
    getter-less address-typed scalars at offset 0;
  * RESOLUTION — the ``state_variable`` branch of ``_resolve_equality_principal``
    reads that slot with ``eth_getStorageAt`` against the runtime address:
    non-zero → ``finite_set([manager], exact)``; confirmed-zero → ``resolved_empty``
    (renounced/unset — NOT ``empty_by_design``, unlike the pending-governor gate);
    unreadable → honest ``lower_bound``.

Layered like ``test_pending_governor_slot_resolution.py``: literal-operand unit
tests pin the resolver and always run; the integration test compiles the
``MembershipNFT`` fixture and proves the slot is stamped + read end-to-end. The
global ``_stub_live_authority`` fixture is deliberately not used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree

CONTRACT = "0x" + "11" * 20
MANAGER = "0x" + "ab" * 20
MEMBERSHIP_MANAGER_SLOT = "0x" + format(2, "064x")  # sequential layout slot in the fixture
MEMBERSHIP_MANAGER_GETTER = "0xee305116"  # membershipManager() — reverts on-chain (no public getter)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "contracts" / "authority"

# Bare internal address var, slot carried by the static pass.
D_MEMBERSHIP_MANAGER_SLOT: dict[str, Any] = {
    "source": "state_variable",
    "state_variable_name": "membershipManager",
    "storage_slot": MEMBERSHIP_MANAGER_SLOT,
}
# The pre-P3 shape (no slot): proves the slot is what recovers the principal — a
# slot-less internal var whose getter reverts must stay under-resolved.
D_MEMBERSHIP_MANAGER_NO_SLOT: dict[str, Any] = {
    "source": "state_variable",
    "state_variable_name": "membershipManager",
}
# Defensive precision: a struct member that (impossibly) carries a slot must not be
# slot-read — the low-20-byte decode is only valid for a bare scalar at offset 0.
D_STRUCT_MEMBER_WITH_SLOT: dict[str, Any] = {
    "source": "state_variable",
    "state_variable_name": "_pendingThing",
    "member_path": ["addr"],
    "storage_slot": MEMBERSHIP_MANAGER_SLOT,
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

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:  # noqa: ARG002
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx_with_rpc(rpc_url: str = "http://rpc.test", address: str = CONTRACT) -> EvaluationContext:
    return EvaluationContext(contract_address=address, adapter=_Adapter(_Outer(rpc_url, address)))


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
                "expression": "msg.sender == address(membershipManager)",
                "basis": [],
            },
        },
    )


def _stub(monkeypatch: pytest.MonkeyPatch, *, slot: str, getter: str = "revert", recorder: list | None = None) -> None:
    """``eth_call`` getters use ``getter`` ('revert' to raise — there is no public
    ``membershipManager()``); ``eth_getStorageAt`` returns ``slot`` ('revert' to
    simulate an unreadable slot, '0x' for an empty/no-code return)."""

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


def _principals(cap: CapabilityExpr) -> list[str]:
    return [r["address"] for r in project_capability_surface(capability_to_dict(cap)).principal_rows]


# --------------------------------------------------------------------------
# Resolver unit tests (literal operand; always run).
# --------------------------------------------------------------------------


def test_nonzero_slot_resolves_to_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live slot value IS the authorized caller — the recovery P3 lands."""
    recorder: list = []
    _stub(monkeypatch, slot=_word(MANAGER), recorder=recorder)
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [MANAGER]
    assert cap.membership_quality == "exact"
    assert cap.empty_reason is None
    assert _principals(cap) == [MANAGER]
    assert _status(cap) != "resolved_empty"
    # The getter is tried first (and reverts) before the slot is read.
    assert recorder[0][0] == "eth_call"
    assert ("eth_getStorageAt", [CONTRACT.lower(), MEMBERSHIP_MANAGER_SLOT, "latest"]) in recorder


def test_confirmed_zero_slot_is_resolved_empty_not_by_design(monkeypatch: pytest.MonkeyPatch) -> None:
    """A read-confirmed zero is a renounced/unset authority — ``resolved_empty``
    with NO ``empty_reason`` (the pending-governor gate's ``empty_by_design`` is a
    DIFFERENT, accept-side semantic and must not be borrowed here)."""
    _stub(monkeypatch, slot="0x" + "00" * 32)
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"
    assert cap.empty_reason is None
    assert _status(cap) == "resolved_empty"


def test_unreadable_slot_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both the getter and the slot are unreadable → honest ``lower_bound``
    (unknown), never a fabricated ``resolved_empty``."""
    _stub(monkeypatch, slot="revert")
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER_SLOT), _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_revert"
    assert _status(cap) != "resolved_empty"


def test_empty_slot_return_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bare ``0x`` (empty / no-code) slot return is unreadable, not empty."""
    _stub(monkeypatch, slot="0x")
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER_SLOT), _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_empty"
    assert _status(cap) != "resolved_empty"


def test_no_rpc_with_slot_is_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slot-bearing operand with no reachable RPC is an honest unknown
    (``not_read``), never a guess."""
    cap = evaluate_tree(
        _eq_tree(D_MEMBERSHIP_MANAGER_SLOT),
        EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None)),
    )

    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "not_read"
    assert _status(cap) != "resolved_empty"


def test_slotless_internal_var_stays_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """The before/after witness: WITHOUT the carried slot the same operand stays
    the ``lower_bound`` placeholder (the getter reverts, nothing else to read) —
    so the slot is exactly what recovers the principal."""
    _stub(monkeypatch, slot=_word(MANAGER))  # slot WOULD resolve, but the operand carries none
    cap = evaluate_tree(_eq_tree(D_MEMBERSHIP_MANAGER_NO_SLOT), _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_revert"
    assert _status(cap) != "resolved_empty"


def test_struct_member_slot_is_never_storage_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Precision: a struct-member operand is never slot-read even if a slot is
    present — the low-20-byte decode is valid only for a bare scalar. No
    ``eth_getStorageAt`` is issued and the manager value is not adopted."""
    recorder: list = []
    _stub(monkeypatch, slot=_word(MANAGER), recorder=recorder)
    cap = evaluate_tree(_eq_tree(D_STRUCT_MEMBER_WITH_SLOT), _ctx_with_rpc())

    assert cap.members == []  # MANAGER was NOT adopted from the slot
    assert _status(cap) != "resolved_empty"
    assert all(method != "eth_getStorageAt" for method, _ in recorder)


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


def _solc_path_for(floor: tuple[int, int, int]) -> str | None:
    try:
        from solc_select import solc_select as ss
    except Exception:
        return None
    best: tuple[int, int, int] | None = None
    for version in ss.installed_versions():
        try:
            parsed = cast(tuple[int, int, int], tuple(int(x) for x in version.split(".")))
        except ValueError:
            continue
        if parsed[:2] == floor[:2] and parsed >= floor and (best is None or parsed > best):
            best = parsed
    if best is None:
        return None
    return str(ss.artifact_path(".".join(str(x) for x in best)))


def _membership_nft() -> Any:
    solc = _solc_path_for((0, 8, 13))
    if solc is None:
        pytest.skip("no installed solc satisfies ^0.8.13 for MembershipNFT.sol")
    sl = Slither(str(FIXTURES_DIR / "MembershipNFT.sol"), solc=solc)
    return next(c for c in sl.contracts if c.name == "MembershipNFT")


def _tree_for(contract: Any, signature: str) -> Any:
    return build_predicate_artifacts(contract)["trees"][signature]


def _caller_operand(tree: Any) -> dict[str, Any]:
    out: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            if leaf.get("kind") == "equality" and leaf.get("authority_role") == "caller_authority":
                out.extend(o for o in (leaf.get("operands") or []) if o.get("source") != "msg_sender")
            return
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    assert len(out) == 1, f"expected one caller operand, got {out}"
    return out[0]


class TestMembershipNFTStorageSlot:
    def test_static_pass_precision(self) -> None:
        """Only *getter-less* address scalars get a slot — both a contract/interface
        type (``membershipManager``) and a plain ``address`` (``_legacyController``).
        Excluded: public vars (auto-getter), private vars WITH a manual getter
        (``_owner``→``owner()``), mappings, and non-address vars."""
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

    def test_private_var_with_manual_getter_is_not_stamped(self) -> None:
        """The over-reach guard: an OZ-Ownable ``_owner`` is private (no auto-getter)
        but the contract exposes ``owner()``, so its ``onlyOwner`` gate must resolve
        through that getter — NEVER a layout-sensitive slot read. The operand on the
        ``_owner``-gated function must carry no ``storage_slot``."""
        op = _caller_operand(_tree_for(_membership_nft(), "adminAction()"))
        assert op["state_variable_name"] == "_owner"
        assert op.get("storage_slot") is None

    def test_operand_carries_sequential_slot(self) -> None:
        """The static stage stamps the var's sequential layout slot onto the
        getter-less ``state_variable`` operand of every gated function."""
        contract = _membership_nft()
        for sig in ("mint(address,uint256)", "burn(address,uint256,uint256)", "incrementLock(uint256,uint32)"):
            op = _caller_operand(_tree_for(contract, sig))
            assert op["source"] == "state_variable"
            assert op["state_variable_name"] == "membershipManager"
            assert op.get("storage_slot") == MEMBERSHIP_MANAGER_SLOT

    def test_public_sibling_var_has_no_slot(self) -> None:
        """A function gated by a PUBLIC address var resolves through its
        auto-getter — the pass must NOT stamp a slot on it."""
        op = _caller_operand(_tree_for(_membership_nft(), "rebase(uint256)"))
        assert op["state_variable_name"] == "liquidityPool"
        assert op.get("storage_slot") is None

    def test_resolves_live_membership_manager(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end: getter reverts, the stamped slot is read, the live value is
        the principal — ``mint`` is NOT under-resolved."""
        tree = _tree_for(_membership_nft(), "mint(address,uint256)")
        _stub(monkeypatch, slot=_word(MANAGER))
        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert _principals(cap) == [MANAGER]
        assert _status(cap) != "resolved_empty"

    def test_confirmed_zero_slot_resolved_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tree = _tree_for(_membership_nft(), "burn(address,uint256,uint256)")
        _stub(monkeypatch, slot="0x" + "00" * 32)
        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert _principals(cap) == []
        assert _status(cap) == "resolved_empty"
        assert cap.empty_reason is None

    def test_unreadable_slot_not_resolved_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tree = _tree_for(_membership_nft(), "incrementLock(uint256,uint32)")
        _stub(monkeypatch, slot="revert")
        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert cap.membership_quality == "lower_bound"
        assert _status(cap) != "resolved_empty"

    def test_public_sibling_resolves_via_getter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The ``liquidityPool``-gated function still resolves through its getter
        (no slot), proving the slot path is additive, not a replacement."""
        tree = _tree_for(_membership_nft(), "rebase(uint256)")
        _stub(monkeypatch, slot="revert", getter=_word(MANAGER))
        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert _principals(cap) == [MANAGER]
        assert _status(cap) != "resolved_empty"
