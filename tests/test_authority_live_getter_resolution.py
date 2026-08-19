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

from typing import Any

import pytest

from services.policy.capability_surface import project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x" + "11" * 20
OWNER = "0x" + "ab" * 20
GOVERNOR = "0x" + "cd" * 20
OWNER_SELECTOR = "0x8da5cb5b"  # owner()
GOVERNOR_SELECTOR = "0x0c340a24"  # governor()


# --------------------------------------------------------------------------
# Stub resolver context: exposes ``_outer_ctx`` (carrying rpc_url + address)
# exactly the way the real registry-backed adapter does, so the equality
# resolver's live-getter path can reach an RPC. No outer ⇒ no RPC ⇒ the
# pre-fix empty-placeholder behaviour (the gap condition).
# --------------------------------------------------------------------------


class _Outer:
    def __init__(
        self,
        rpc_url: str | None,
        contract_address: str | None,
        block: int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.rpc_url = rpc_url
        self.contract_address = contract_address
        self.block = block
        self.meta = meta


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


def _sel(signature: str) -> str:
    from eth_utils.crypto import keccak

    return "0x" + keccak(text=signature).hex()[:8]


def _stub_rpc_by_selector(
    monkeypatch: pytest.MonkeyPatch, returns: dict[str, str], *, recorder: list | None = None
) -> None:
    """Selector-aware ``eth_call`` stub: returns the 32-byte word for
    ``returns[selector]`` and reverts on any other selector — so a test can prove
    *which* getter recovered the principal (e.g. ``owner()`` but never
    ``_owner()``)."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if method == "eth_call":
            data = params[0]["data"]
            if data in returns:
                return "0x" + returns[data][2:].rjust(64, "0")
        raise RuntimeError("execution reverted")

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
# Leading-underscore state-var operand: an OZ-v4 ``onlyOwner`` lowers to
# ``msg.sender == _owner`` (the trivial ``owner(){return _owner;}`` getter is
# inlined to its backing private var). ``_owner()`` has no selector, so on a
# snapshot miss the state_variable branch must de-underscore to ``owner()`` —
# the same fallback the view_call branch already does for ``_governor()``. Pins
# the gap where this branch tried only ``_owner()`` (revert) and dropped the
# principal. Selector-aware stub proves ``owner()`` — never ``_owner()`` — is
# what recovers it.
# --------------------------------------------------------------------------


def test_underscore_owner_state_var_resolves_via_canonical_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc_by_selector(monkeypatch, {OWNER_SELECTOR: OWNER}, recorder=recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_owner"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [OWNER]
    assert cap.membership_quality == "exact"
    # ``_owner()`` (the var's own dead selector) is tried and reverts; ``owner()``
    # (de-underscored) is what actually resolves the principal.
    selectors = [p[0]["data"] for m, p in recorder if m == "eth_call"]
    assert _sel("_owner()") in selectors
    assert OWNER_SELECTOR in selectors


def test_underscore_governor_state_var_resolves_via_canonical_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc_by_selector(monkeypatch, {GOVERNOR_SELECTOR: GOVERNOR})
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_governor"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [GOVERNOR]
    assert cap.membership_quality == "exact"


def test_underscore_owner_renounced_resolves_to_exact_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """A de-underscored ``owner()`` reading the zero address is a renounced/unset
    authority — ``exact`` empty, not the ``lower_bound`` unresolved placeholder."""
    _stub_rpc_by_selector(monkeypatch, {OWNER_SELECTOR: "0x" + "00" * 20})
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_owner"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "exact"


def test_arbitrary_underscore_state_var_is_not_de_underscored(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed over-reach guard: only {owner,governor,authority} de-underscore.
    A ``_secret`` whose own ``_secret()`` getter reverts must NOT be bound to
    whatever public ``secret()`` returns — a wrong controller is worse than a
    missing one. ``secret()`` is readable here yet must never be called."""
    recorder: list = []
    _stub_rpc_by_selector(monkeypatch, {_sel("secret()"): OWNER}, recorder=recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_secret"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    selectors = [p[0]["data"] for m, p in recorder if m == "eth_call"]
    assert _sel("secret()") not in selectors  # the de-underscored getter was never guessed


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


# --------------------------------------------------------------------------
# OZ v5 (ERC-7201) namespaced Ownable: the owner lives in a storage struct, so
# the gate is ``msg.sender == OwnableStorageLocation._owner`` — a struct-member
# operand. Its canonical accessor is the same ``owner()`` getter, so it must be
# read live. This is the EtherfiL1SyncPoolETH owner gap (owner = EtherFiTimelock)
# that the "treat the slot-pointer constant as a getter" heuristic missed.
# --------------------------------------------------------------------------


def test_oz_v5_namespaced_owner_resolves_via_owner_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree(
        {"source": "state_variable", "state_variable_name": "OwnableStorageLocation", "member_path": ["_owner"]}
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [OWNER]
    assert cap.membership_quality == "exact"
    # Resolved by calling owner() (0x8da5cb5b) — NOT OwnableStorageLocation().
    assert recorder, "expected a live getter call"
    assert recorder[-1][1][0]["data"] == OWNER_SELECTOR


def test_oz_v5_namespaced_owner_without_rpc_stays_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree(
        {"source": "state_variable", "state_variable_name": "OwnableStorageLocation", "member_path": ["_owner"]}
    )

    cap = evaluate_tree(tree, _ctx_no_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert recorder == []


# --------------------------------------------------------------------------
# Within-pass live-getter memo: owner()/governor() reads are deterministic at a
# fixed block, so N functions gating on the same getter need ONE read. The memo
# rides on the resolver's contract-scoped meta['live_read_memo']; only SUCCESSFUL
# reads are cached, so a failure is never poisoned across the pass. Resolution
# results are identical — only the RPC count drops.
# --------------------------------------------------------------------------


def _ctx_with_memo(memo: dict, rpc_url: str = "http://rpc.test") -> EvaluationContext:
    # meta is the contract-scoped carrier the resolver wires (meta['live_read_memo']).
    outer = _Outer(rpc_url, CONTRACT, meta={"live_read_memo": memo})
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(outer))


def test_live_getter_memo_dedups_repeat_reads_in_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})
    memo: dict = {}
    ctx = _ctx_with_memo(memo)

    cap1 = evaluate_tree(tree, ctx)
    cap2 = evaluate_tree(tree, ctx)

    assert cap1.members == cap2.members == [OWNER]
    assert cap1.membership_quality == cap2.membership_quality == "exact"
    assert len(recorder) == 1, "the second gated function must be served from the pass memo"


def test_live_getter_memo_does_not_cache_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reverting/transient read is never memoized, so each gated function still reads/retries
    independently — a blip on the first function can't drop principals for the rest of the pass."""
    recorder: list = []
    _stub_rpc(monkeypatch, None, recorder=recorder)  # rpc_request raises every time
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})
    memo: dict = {}
    ctx = _ctx_with_memo(memo)

    cap1 = evaluate_tree(tree, ctx)
    cap2 = evaluate_tree(tree, ctx)

    assert cap1.members == cap2.members == []
    assert len(recorder) == 2, "failed reads must not be cached — each function reads independently"


def test_live_getter_memo_zero_address_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """A renounced getter (zero address) is a deterministic SUCCESS, so it is memoized as the
    'exact empty' set and reused — identical to the un-memoized result, one fewer read."""
    recorder: list = []
    _stub_rpc(monkeypatch, "0x" + "00" * 20, recorder=recorder)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})
    memo: dict = {}
    ctx = _ctx_with_memo(memo)

    cap1 = evaluate_tree(tree, ctx)
    cap2 = evaluate_tree(tree, ctx)

    assert cap1.members == cap2.members == []
    assert cap1.membership_quality == cap2.membership_quality == "exact"
    assert len(recorder) == 1


def test_static_external_operand_memo_dedups(monkeypatch: pytest.MonkeyPatch) -> None:
    from services.resolution import predicate_evaluator as pe

    recorder: list = []

    def fake(_url: str, _method: str, params: list, **_: Any) -> str:
        recorder.append(params)
        return "0x" + "11" * 32

    monkeypatch.setattr("utils.rpc.rpc_request", fake)
    operand = {"source": "external_call", "callee_signature": "someGetter()", "callee_selector": "0x12345678"}
    memo: dict = {}

    r1 = pe._resolve_static_external_call_operand(
        operand, callee_contract_address="0x" + "22" * 20, rpc_url="http://rpc", block=None, memo=memo
    )
    r2 = pe._resolve_static_external_call_operand(
        operand, callee_contract_address="0x" + "22" * 20, rpc_url="http://rpc", block=None, memo=memo
    )

    assert r1 == r2 == {"source": "constant", "constant_value": "0x" + "11" * 32}
    assert len(recorder) == 1, "the second identical operand read is served from the pass memo"


def test_static_external_operand_failure_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    from services.resolution import predicate_evaluator as pe

    calls = {"n": 0}

    def flaky(_url: str, _method: str, _params: list, **_: Any) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return "0x" + "11" * 32

    monkeypatch.setattr("utils.rpc.rpc_request", flaky)
    operand = {"source": "external_call", "callee_signature": "someGetter()", "callee_selector": "0x12345678"}
    memo: dict = {}

    r1 = pe._resolve_static_external_call_operand(
        operand, callee_contract_address="0x" + "22" * 20, rpc_url="http://rpc", block=None, memo=memo
    )
    r2 = pe._resolve_static_external_call_operand(
        operand, callee_contract_address="0x" + "22" * 20, rpc_url="http://rpc", block=None, memo=memo
    )

    assert r1 is None, "first attempt failed"
    assert r2 == {"source": "constant", "constant_value": "0x" + "11" * 32}, "retry succeeded — failure not poisoned"
    assert calls["n"] == 2
