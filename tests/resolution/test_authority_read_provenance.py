"""A2/A3 — a published authority read carries the read that produced it.

An exact-EMPTY caller set (the strongest earned negative: "nobody can call this") was
published bare: no step, selector, block or reason. Four such rows exist and none can be
reconstructed (EACAggregatorProxy's ``pendingOwner()`` reverts on mainnet, so it can't
have come from the zero branch). Separately, the accessor BASIS was recorded only inside
``details->'trace'``. Reads are stubbed at ``services.clients.rpc.rpc_request`` and
pinned to block 25643300.
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
    """``only`` (a selector) answers with ``returns``; everything else reverts."""
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


# ---------------------------------------------------------------------------
# A2 — the live getter's zero branch
# ---------------------------------------------------------------------------


def test_zero_read_publishes_the_whole_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The byte-exact payload; the same verdict used to ship as ``{finite_set, [], exact, enumerable}`` alone."""
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
    """THE fail-closed arm for the block: with no pinned height the eth_call goes to
    ``"latest"``, and stamping a height would put a bounded-in-time claim on an
    unbounded read, so the key is absent."""
    calls = _stub_getter(monkeypatch, returns=_word("0x" + "00" * 20), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx(block=None))

    assert calls[0][1][1] == "latest"
    assert cap.empty_reason == "owner_read_zero"
    assert "observed_at_block" not in cap.trace[0]


def test_non_empty_read_carries_its_block_and_reads_at_the_pinned_hex_block(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())

    assert calls[0][1][1] == hex(PINNED_BLOCK)
    assert cap.members == [GOVERNOR]
    assert cap.trace[0]["observed_at_block"] == PINNED_BLOCK


def test_burn_address_is_not_an_exact_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """``0x0`` can never be ``msg.sender``, which makes a zero read a real "nobody".
    ``0x…dEaD`` is only BELIEVED keyless — a convention, not a proof — so it may not
    share the zero shape or be published as a member. The raw address is recorded."""
    _stub_getter(monkeypatch, returns=_word(BURN), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.confidence == "partial"
    assert cap.empty_reason == "owner_read_burn_address"
    assert cap.trace[0]["read_address"] == BURN


def test_revert_stays_an_honest_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """A revert is not an answer; it must never become a read-confirmed zero (the fail-open this unit prevents)."""
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_revert"


def test_pending_ceiling_shape_is_byte_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression guard on a real mainnet shape: EACAggregatorProxy's ``pendingOwner()``
    reverts, reaching the UNCHANGED accept-side ceiling, including ``empty_by_design`` and
    the ``basis: "accessor_name"`` disclosure that keeps it out of the earned-negative gate."""
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "pendingOwner()"}), _ctx())

    assert cap.empty_reason == "empty_by_design"
    assert cap.trace[0]["step"] == "pending_transfer_ceiling"
    assert cap.trace[0]["basis"] == "accessor_name"
    assert cap.trace[0]["read_outcome"] == "unreadable_revert"
    assert cap.empty_reason != "owner_read_zero"


def test_no_rpc_leaves_the_placeholder_not_read() -> None:
    class _NoRpc(_Adapter):
        def __init__(self) -> None:
            super().__init__(None)
            self._outer_ctx.rpc_url = None  # pyright: ignore[reportAttributeAccessIssue]

    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "owner()"}),
        EvaluationContext(contract_address=CONTRACT, adapter=_NoRpc()),
    )
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "not_read"


def test_memo_hit_is_byte_identical_to_the_fresh_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pass memo's contract is a byte-identical result; the block is threaded onto
    BOTH paths so a memo hit can't serve a payload that lost its observation block."""
    calls = _stub_getter(monkeypatch, returns=_word("0x" + "00" * 20), only=OWNER_SELECTOR)
    ctx = _ctx()
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()"})

    fresh = capability_to_dict(evaluate_tree(tree, ctx))
    wire_calls = len(calls)
    memoized = capability_to_dict(evaluate_tree(tree, ctx))

    assert memoized == fresh
    assert memoized["trace"][0]["observed_at_block"] == PINNED_BLOCK
    assert len(calls) == wire_calls, "the second evaluation must not re-hit the wire"


def test_memo_does_not_merge_zero_and_burn(monkeypatch: pytest.MonkeyPatch) -> None:
    """The memo used to store a collapsed ``""`` for both, making the answers indistinguishable in-process."""
    ctx = _ctx()
    tree = _eq_tree({"source": "view_call", "callee_signature": "owner()"})

    _stub_getter(monkeypatch, returns=_word(BURN), only=OWNER_SELECTOR)
    first = evaluate_tree(tree, ctx)
    second = evaluate_tree(tree, ctx)  # memo hit

    assert first.empty_reason == second.empty_reason == "owner_read_burn_address"
    assert second.membership_quality == "lower_bound"


# ---------------------------------------------------------------------------
# A2 — the slot reader
# ---------------------------------------------------------------------------

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
    """``empty_by_design`` used to arrive from a DEFAULT ARGUMENT — a label asserting an
    intentional accept-side ceiling, applied with no trace or block to check it. The read
    is now what is published."""
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


# ---------------------------------------------------------------------------
# A3 — the accessor basis, split and hoisted
# ---------------------------------------------------------------------------


def _authority_details(cap: CapabilityExpr) -> dict[str, Any]:
    rows = project_capability_surface(capability_to_dict(cap)).principal_rows
    assert len(rows) == 1
    return rows[0]["details"]


@pytest.mark.parametrize(
    "returned",
    [
        pytest.param(GOVERNOR, id="labelled_and_hoisted"),
        # Anti-name-inference control. A reverting internal ``_governor()`` AND an unrelated public ``governor()``
        # returning a DIFFERENT address still resolves to the public getter (that is the convention), but must
        # publish ``deunderscore_convention``: the row discloses a name match rather than claiming it was checked.
        # A genuine slot differential would invert this, but it is unrunnable on 2 of 3 runtime addresses and
        # non-identifying on the third, so ``accessor_slot_agreement`` stays ``not_determined``.
        pytest.param("0x" + "77" * 20, id="disclosed_not_validated"),
    ],
)
def test_deunderscore_convention(monkeypatch: pytest.MonkeyPatch, returned: str) -> None:
    """``onlyGovernor`` lowers to ``msg.sender == _governor()``; the accessor has no
    selector so it reverts and the resolver falls back to the de-underscored public
    getter. The row says so BESIDE its strength fields, not only inside the trace."""
    _stub_getter(monkeypatch, returns=_word(returned), only=GOVERNOR_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_governor()"}), _ctx())

    assert cap.members == [returned]
    assert {"step": "authority_getter_basis", "basis": "deunderscore_convention", "selector": GOVERNOR_SELECTOR} in (
        cap.trace
    )
    details = _authority_details(cap)
    assert details["authority_basis"] == "deunderscore_convention"
    assert details["accessor_slot_agreement"] == "not_determined"
    assert details["membership_quality"] == "exact"


def test_public_getter_is_abi_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: ``abi_auto_getter`` (renamed from ``auto_getter``) is the one arm the compiler forces."""
    _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=GOVERNOR_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "state_variable", "state_variable_name": "governor"}), _ctx())

    details = _authority_details(cap)
    assert details["authority_basis"] == "abi_auto_getter"
    # No accessor name was matched, so no slot-agreement residual to state.
    assert "accessor_slot_agreement" not in details


def test_oz_v5_namespaced_accessor_gets_its_own_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """The 6 CumulativeMerkleDrop rows. OZ-v5 keeps ownership in an ERC-7201 namespace, so
    an ``owner()`` gate inlines to a ``view_call`` of the private accessor. It shared the
    de-underscore convention's label, so a consumer couldn't tell a standard-anchored match
    from a 3-name guess."""
    _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=OWNER_SELECTOR)
    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "_getAccessControlDefaultAdminRulesStorage()"}),
        _ctx(),
    )

    assert cap.members == [GOVERNOR]
    details = _authority_details(cap)
    assert details["authority_basis"] == "standard_namespaced_accessor"
    # Same tier as the convention arm: an exact-name match against the standard's table is
    # still a name match, with the same residual open.
    assert details["accessor_slot_agreement"] == "not_determined"


def test_unknown_internal_accessor_resolves_to_no_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed: ``_frobnicate()`` isn't in the authority basenames, so no getter is
    substituted, no principal published, and the basis key is ABSENT (not ``"unknown"``, not null)."""
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_frobnicate()"}), _ctx())

    assert cap.members == []
    assert project_capability_surface(capability_to_dict(cap)).principal_rows == []


def test_a_lower_bound_read_never_stamps_a_basis(monkeypatch: pytest.MonkeyPatch) -> None:
    """A refactor must not stamp a basis onto an unresolved read: only on a short-circuit at ``exact``."""
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_governor()"}), _ctx())

    assert cap.membership_quality != "exact"
    assert [step for step in cap.trace if step.get("step") == "authority_getter_basis"] == []
