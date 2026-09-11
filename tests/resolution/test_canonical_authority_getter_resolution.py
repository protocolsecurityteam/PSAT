"""Regression: caller-equality authority gates that read the principal through a
NON-canonical accessor must resolve via the contract's canonical public getter.

Two etherfi (protocol_id=1) recall gaps, both the same root cause — the static
stage faithfully records *what the gate literally reads*, but that literal form
isn't a readable public getter:

  * #4 — Governable ``onlyGovernor`` lowers to ``msg.sender == _governor()``,
    where ``_governor()`` is INTERNAL (no external selector). The resolver's
    live-getter read of ``_governor()`` (0x95260843) reverts; it must fall back
    to the canonical public ``governor()`` (0x0c340a24).
    (LRTSquaredCore 0x1cb489ef…, LRTSquaredAdmin 0xd2b8c78a…)

  * #6 — Solady ``Ownable`` stores the owner in the bytes32 constant slot
    ``_OWNER_SLOT`` read via assembly. A gate ``_owner = owner(); require(_owner
    == msg.sender)`` lowers to a caller-equality operand naming the constant
    ``_OWNER_SLOT``. Reading ``_OWNER_SLOT()`` (0x12f93717) reverts; it must fall
    back to ``owner()`` (0x8da5cb5b). It must also NOT become a dead
    ``role_identifier:_OWNER_SLOT`` controller target.
    (TopUp 0x5bdd4b0d…, TopUpV2 0x80b1931d…, owner() == 0x…dEaD on both)

Generalizes the PR #104 OZ-v5 ``member_path==["_owner"]`` → ``owner()`` precedent.

Layered like the #104 tests (``test_authority_live_getter_resolution.py``):
literal-dict unit tests pin the resolver behaviour with a stubbed RPC and always
run; the ``Test...Fixture`` integration tests compile the REAL on-chain source
(tests/fixtures/contracts/authority/) through the production static pipeline and
resolve the real predicate trees, proving the fix against real contracts. They
skip only when no compatible solc is installed.
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


# --------------------------------------------------------------------------
# Stub resolver context (mirrors test_authority_live_getter_resolution.py):
# the adapter exposes ``_outer_ctx`` carrying rpc_url + address, the only path
# the equality resolver's live getter can reach. No outer ⇒ no RPC.
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

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx_with_rpc(rpc_url: str = "http://rpc.test") -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(_Outer(rpc_url, CONTRACT)))


def _ctx_no_rpc() -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None))


def _stub_rpc_map(monkeypatch: pytest.MonkeyPatch, returns: dict[str, str | None], recorder: list) -> None:
    """Stub ``services.clients.rpc.rpc_request`` from a selector→address map. A value of
    ``None`` (or a selector absent from the map) raises — i.e. the eth_call
    reverts, exactly like calling a function the contract doesn't expose."""

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


# ==========================================================================
# #4 — internal-accessor governor gate (view_call _governor()).
# ==========================================================================


def test_governor_internal_accessor_resolves_via_public_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    # _governor() is internal (no external selector); governor() resolves.
    _stub_rpc_map(monkeypatch, {INTERNAL_GOVERNOR_SELECTOR: None, GOVERNOR_SELECTOR: GOVERNOR}, recorder)
    tree = _eq_tree(
        {"source": "view_call", "callee_signature": "_governor()", "callee_selector": INTERNAL_GOVERNOR_SELECTOR}
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [GOVERNOR]
    assert cap.membership_quality == "exact"
    # The fix reads the canonical governor() directly; the dead internal
    # _governor() selector is never called (canonical-first, not revert-reliant).
    assert _called(recorder, GOVERNOR_SELECTOR)
    assert not _called(recorder, INTERNAL_GOVERNOR_SELECTOR)


def test_governor_internal_accessor_without_public_getter_stays_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed: if the contract exposes no public ``governor()`` either, the
    gate stays the 'guarded but unresolved' placeholder — no false principal."""
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
    """Precision: a normal ``msg.sender == governor()`` (already public, no
    underscore) resolves directly and the de-underscore fallback is never
    consulted — no behaviour change for the common case."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {GOVERNOR_SELECTOR: GOVERNOR}, recorder)
    tree = _eq_tree({"source": "view_call", "callee_signature": "governor()", "callee_selector": GOVERNOR_SELECTOR})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == [GOVERNOR]
    assert recorder == [GOVERNOR_SELECTOR]  # exactly one call, the literal getter


def test_non_authority_internal_accessor_is_not_de_underscored(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hardening: a non-authority internal accessor (``_recoveryWallet()``) must
    NOT be de-underscored to a public ``recoveryWallet()`` — resolving it would
    mint a wrong controller, worse than a missing one. Only owner/governor/
    authority (and pending variants) are de-underscored; everything else stays
    fail-closed, and the public getter is never called even though it would
    return an address here."""
    recovery_wallet_selector = "0x3ec954ed"  # keccak("recoveryWallet()")[:4]
    recorder: list = []
    _stub_rpc_map(monkeypatch, {recovery_wallet_selector: OWNER}, recorder)
    tree = _eq_tree({"source": "view_call", "callee_signature": "_recoveryWallet()"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert not _called(recorder, recovery_wallet_selector)  # never de-underscored


# ==========================================================================
# #6 — Solady owner-slot constant (state_variable _OWNER_SLOT).
# ==========================================================================


def test_owner_slot_constant_resolves_via_owner_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    # _OWNER_SLOT() reverts (slot locator, not a getter); owner() resolves.
    _stub_rpc_map(monkeypatch, {OWNER_SLOT_SELECTOR: None, OWNER_SELECTOR: OWNER}, recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_OWNER_SLOT"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [OWNER]
    assert cap.membership_quality == "exact"
    # Resolved via owner() (0x8da5cb5b), NOT _OWNER_SLOT().
    assert _called(recorder, OWNER_SELECTOR)


def test_owner_slot_burned_is_empty_but_not_a_proven_nobody(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real TopUp/TopUpV2 owner is 0x…dEaD. Reading owner() yields the burn
    sentinel: no principal is published (never a phantom 0x…dEaD controller),
    and the set is empty — but the emptiness is a ``lower_bound``, not the
    ``exact`` "provably nobody".

    AMENDED (A2/A6): this used to publish ``exact``, which asserts that no caller
    can pass the gate. That rests on 0x…dEaD being unspendable, which is a
    CONVENTION, not something any read establishes — unlike ``0x0``, which can
    never be ``msg.sender`` on mainnet and is what makes a zero read a real
    nobody. The honest statement is "no known caller", so the row publishes
    ``owner_read_burn_address`` with the address it read and does not earn the
    earned-negative credit."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {OWNER_SLOT_SELECTOR: None, OWNER_SELECTOR: BURN}, recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_OWNER_SLOT"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "owner_read_burn_address"
    assert _called(recorder, OWNER_SELECTOR)


def test_oz_v5_ownable_storage_location_slot_resolves_via_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """OZ-v5 namespaced Ownable also surfaces the slot constant as a bare
    state-var operand (``OwnableStorageLocation``); it maps to owner() too."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {OWNER_SELECTOR: OWNER}, recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "OwnableStorageLocation"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == [OWNER]
    assert cap.membership_quality == "exact"
    assert _called(recorder, OWNER_SELECTOR)


def test_non_authority_storage_slot_stays_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed precision: a slot constant that is NOT an owner/governor/
    authority locator (e.g. ``BaseMessengerStorageLocation``) must not be
    rerouted to owner() — it stays the placeholder."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {OWNER_SELECTOR: OWNER}, recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "BaseMessengerStorageLocation"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    # The literal ``BaseMessengerStorageLocation()`` getter is attempted (and
    # reverts) like any bare state-var, but owner() must NOT be falsely called.
    assert not _called(recorder, OWNER_SELECTOR)


def test_owner_slot_without_rpc_stays_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gap condition: no RPC reachable ⇒ the slot gate stays unresolved
    (pre-#104 behaviour), never a false negative masquerading as resolved."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {OWNER_SELECTOR: OWNER}, recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_OWNER_SLOT"})

    cap = evaluate_tree(tree, _ctx_no_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert recorder == []


# ==========================================================================
# Integration: compile the REAL on-chain source and resolve its real predicate
# trees through the production static pipeline. Skips if no compatible solc.
# ==========================================================================

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.static_analysis.effects import build_effects  # noqa: E402
from services.static.static_analysis.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.static_analysis.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)
from services.static.static_analysis.tracking import build_controller_tracking  # noqa: E402
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
    """#4 against the verbatim on-chain ether.fi Governable."""

    def test_transfer_governance_resolves_governor_via_canonical_getter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sl = _compile_fixture("Governable.sol", (0, 8, 25))
        contract = _contract(sl, "Governable")
        trees = build_predicate_artifacts(contract)["trees"]
        tree = trees["transferGovernance(address)"]

        # Sanity: the real gate lowered to a view_call on the INTERNAL accessor.
        leaf = tree["leaf"]
        view_op = next(o for o in leaf["operands"] if o.get("source") == "view_call")
        assert view_op["callee_signature"] == "_governor()"
        assert view_op["callee_selector"] == INTERNAL_GOVERNOR_SELECTOR

        recorder: list = []
        # On-chain governor() at the proxy is a Safe; _governor() has no external fn.
        _stub_rpc_map(monkeypatch, {INTERNAL_GOVERNOR_SELECTOR: None, GOVERNOR_SELECTOR: GOVERNOR}, recorder)

        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert cap.members == [GOVERNOR], "onlyGovernor gate must resolve to the governor"
        assert cap.membership_quality == "exact"
        assert _called(recorder, GOVERNOR_SELECTOR), "must read the canonical governor()"


class TestTopUpSoladyFixture:
    """#6 against the verbatim Solady Ownable + on-chain TopUp.processTopUp gate."""

    def test_process_top_up_resolves_owner_not_slot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sl = _compile_fixture("TopUpSolady.sol", (0, 8, 4))
        contract = _contract(sl, "TopUpSolady")
        trees = build_predicate_artifacts(contract)["trees"]
        tree = trees["processTopUp(address[])"]

        # Sanity: the real gate names the bytes32 slot constant as its operand.
        assert "'state_variable_name': '_OWNER_SLOT'" in json.dumps(tree).replace('"', "'")

        recorder: list = []
        # The real on-chain owner() of TopUp/TopUpV2 is 0x…dEaD.
        _stub_rpc_map(monkeypatch, {OWNER_SLOT_SELECTOR: None, OWNER_SELECTOR: BURN}, recorder)

        cap = evaluate_tree(tree, _ctx_with_rpc())

        # The fix under test is still what it was: read the real owner(), never
        # _OWNER_SLOT(), and never mint 0x…dEaD as a principal. What the burn
        # sentinel is allowed to CONCLUDE is narrower since A2 — see
        # ``test_owner_slot_burned_is_empty_but_not_a_proven_nobody``.
        assert cap.kind == "finite_set"
        assert cap.members == []
        assert cap.membership_quality == "lower_bound"
        assert cap.empty_reason == "owner_read_burn_address"
        assert _called(recorder, OWNER_SELECTOR), "must read owner(), not _OWNER_SLOT()"

    def test_process_top_up_resolves_live_owner(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Same gate with a live (non-renounced) owner resolves to that owner —
        the positive proof the principal is recovered."""
        sl = _compile_fixture("TopUpSolady.sol", (0, 8, 4))
        contract = _contract(sl, "TopUpSolady")
        tree = build_predicate_artifacts(contract)["trees"]["processTopUp(address[])"]

        recorder: list = []
        _stub_rpc_map(monkeypatch, {OWNER_SLOT_SELECTOR: None, OWNER_SELECTOR: OWNER}, recorder)

        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert cap.members == [OWNER]
        assert _called(recorder, OWNER_SELECTOR)

    def test_controller_tracking_emits_no_dead_owner_slot_role(self) -> None:
        """No dead ``role_identifier:_OWNER_SLOT`` controller target.

        The Pass-1 fix suppressed the target downstream while ``_OWNER_SLOT``
        still reached ``role_definitions`` as a bytes32-constant caller operand.
        D6-reject removed it at the source: a slot pointer is an equality leaf
        with no set descriptor, so it is no longer admitted as a role at all.
        Both halves are asserted — the downstream suppression must survive on its
        own, since it also covers slot constants reaching the tracking plane by
        any other route."""
        sl = _compile_fixture("TopUpSolady.sol", (0, 8, 4))
        contract = _contract(sl, "TopUpSolady")
        project_dir = FIXTURES_DIR
        predicate_trees = build_predicate_artifacts(contract)
        effects = build_effects(contract)
        semantic = _build_semantic_control_summary(contract, project_dir, predicate_trees, effects)

        # D6-reject: the slot constant is no longer minted as a role upstream …
        assert "_OWNER_SLOT" not in [r.get("role") for r in semantic.get("role_definitions", [])]

        targets = build_controller_tracking(contract, project_dir, predicate_trees, effects, semantic)
        controller_ids = {t["controller_id"] for t in targets}

        # … but no dead role_identifier:_OWNER_SLOT target is emitted.
        assert "role_identifier:_OWNER_SLOT" not in controller_ids
        assert not any(cid.startswith("role_identifier:") and "_SLOT" in cid for cid in controller_ids)
