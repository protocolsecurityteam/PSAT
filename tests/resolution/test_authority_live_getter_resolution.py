"""The equality evaluator only consulted persisted ``state_var_values``, so ``msg.sender == owner()`` gates gave no
principal (EtherfiL1SyncPoolETH, LRTSquaredCore). ``_live_resolve_authority`` reads the getter.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.policy.capability_surface import project_capability_surface
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from tests.support.authority_reads import _Adapter
from tests.support.eq_tree import eq_tree as _eq_tree

CONTRACT = "0x" + "11" * 20
OWNER = "0x" + "ab" * 20
GOVERNOR = "0x" + "cd" * 20
AUTHORITY = "0x" + "ef" * 20
OWNER_SELECTOR = "0x8da5cb5b"  # owner()
GOVERNOR_SELECTOR = "0x0c340a24"  # governor()
AUTHORITY_SELECTOR = "0xbf7e214f"  # authority()


# No outer means no RPC.


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


def _ctx_with_rpc(rpc_url: str = "http://rpc.test") -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(_Outer(rpc_url, CONTRACT)))


def _ctx_no_rpc() -> EvaluationContext:
    return EvaluationContext(contract_address=CONTRACT, adapter=_Adapter(None))


def _stub_rpc(monkeypatch: pytest.MonkeyPatch, return_addr: str | None, *, recorder: list | None = None) -> None:

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if return_addr is None:
            raise RuntimeError("rpc unavailable")
        return "0x" + return_addr[2:].rjust(64, "0")

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)


def _sel(signature: str) -> str:
    from eth_utils.crypto import keccak

    return "0x" + keccak(text=signature).hex()[:8]


def _stub_rpc_by_selector(
    monkeypatch: pytest.MonkeyPatch, returns: dict[str, str], *, recorder: list | None = None
) -> None:
    """Proves which getter recovered the principal."""

    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if method == "eth_call":
            data = params[0]["data"]
            if data in returns:
                return "0x" + returns[data][2:].rjust(64, "0")
        raise RuntimeError("execution reverted")

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)


def test_owner_view_call_without_rpc_stays_empty_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: list = []
    _stub_rpc(monkeypatch, OWNER, recorder=recorder)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})

    cap = evaluate_tree(tree, _ctx_no_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert recorder == []  # no outer ctx ⇒ no RPC attempt
    assert project_capability_surface(capability_to_dict(cap)).principal_rows == []


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
    tree = _eq_tree({"source": "view_call", "callee_signature": "governor()"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [GOVERNOR]


def test_state_var_miss_resolves_via_live_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    """LRTSquaredCore's governor was filed under the wrong key."""
    _stub_rpc(monkeypatch, GOVERNOR)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "governor"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [GOVERNOR]
    assert cap.membership_quality == "exact"


def test_renounced_getter_resolves_to_exact_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, "0x" + "00" * 20)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"


# An OZ-v4 ``onlyOwner`` lowers to ``msg.sender == _owner``, which has no selector; the fallback must de-underscore to
# ``owner()``.


@pytest.mark.parametrize(
    ("basename", "selector", "resolved"),
    [
        ("owner", OWNER_SELECTOR, OWNER),
        ("governor", GOVERNOR_SELECTOR, GOVERNOR),
        ("authority", AUTHORITY_SELECTOR, AUTHORITY),
    ],
)
def test_underscore_authority_state_var_resolves_via_canonical_getter(
    monkeypatch: pytest.MonkeyPatch, basename: str, selector: str, resolved: str
) -> None:
    recorder: list = []
    _stub_rpc_by_selector(monkeypatch, {selector: resolved}, recorder=recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": f"_{basename}"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [resolved]
    assert cap.membership_quality == "exact"
    selectors = [p[0]["data"] for m, p in recorder if m == "eth_call"]
    assert _sel(f"_{basename}()") in selectors
    assert selector in selectors


def test_underscore_owner_renounced_resolves_to_exact_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc_by_selector(monkeypatch, {OWNER_SELECTOR: "0x" + "00" * 20})
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_owner"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "exact"


def test_arbitrary_underscore_state_var_is_not_de_underscored(monkeypatch: pytest.MonkeyPatch) -> None:
    """A wrong controller is worse than a missing one."""
    recorder: list = []
    _stub_rpc_by_selector(monkeypatch, {_sel("secret()"): OWNER}, recorder=recorder)
    tree = _eq_tree({"source": "state_variable", "state_variable_name": "_secret"})

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    selectors = [p[0]["data"] for m, p in recorder if m == "eth_call"]
    assert _sel("secret()") not in selectors  # the de-underscored getter was never guessed


def test_state_var_present_wins_without_any_rpc_call(monkeypatch: pytest.MonkeyPatch) -> None:
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
    """A fund destination, not a caller."""
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


# FunctionPrincipal rows are what primary_controller keys on.


def test_resolved_owner_surfaces_as_function_principal_row(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rpc(monkeypatch, OWNER)
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()", "callee_selector": OWNER_SELECTOR})

    resolved = evaluate_tree(tree, _ctx_with_rpc())
    unresolved = evaluate_tree(tree, _ctx_no_rpc())

    resolved_rows = project_capability_surface(capability_to_dict(resolved)).principal_rows
    unresolved_rows = project_capability_surface(capability_to_dict(unresolved)).principal_rows

    assert [r["address"] for r in resolved_rows] == [OWNER]
    assert all(r.get("principal_type") == "controller" for r in resolved_rows)
    assert unresolved_rows == []


# ERC-7201: the gate reads a struct member whose accessor is ``owner()`` (the EtherfiL1SyncPoolETH gap).


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


# Getter reads are deterministic at a fixed block, so one read serves the pass; only successes are cached.


def _ctx_with_memo(memo: dict, rpc_url: str = "http://rpc.test") -> EvaluationContext:
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

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)
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

    monkeypatch.setattr("services.clients.rpc.rpc_request", flaky)
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
