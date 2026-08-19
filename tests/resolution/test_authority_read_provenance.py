"""A2/A3 — a published authority read carries the read that produced it.

Two defects, one shape. An exact-EMPTY caller set is the strongest earned
negative the resolver publishes ("nobody can call this"), and it was published
bare: no step, no selector, no block, no reason. Four such rows exist on the
corpus and none can be reconstructed — one of them (EACAggregatorProxy) cannot
even have come from the zero branch, because its ``pendingOwner()`` reverts on
mainnet. Separately, the accessor BASIS a principal rests on was recorded only
inside ``details->'trace'``, beside strength fields that read as maximal.

Every read here is stubbed at the wire (``utils.rpc.rpc_request``) and pinned to
block 25643300 — the height every investigation read reproduces at.
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

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:  # noqa: ARG002
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

    monkeypatch.setattr("utils.rpc.rpc_request", fake)
    return calls


# ---------------------------------------------------------------------------
# A2 — the live getter's zero branch
# ---------------------------------------------------------------------------


def test_zero_read_publishes_the_whole_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The byte-exact payload. Before this, the same verdict shipped as
    ``{finite_set, [], exact, enumerable}`` with nothing else at all."""
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
    """THE fail-closed arm for the block. With no pinned height the eth_call
    goes to ``"latest"``; stamping a height there would put a bounded-in-time
    claim on an unbounded read, so the key is simply absent."""
    calls = _stub_getter(monkeypatch, returns=_word("0x" + "00" * 20), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx(block=None))

    assert calls[0][1][1] == "latest"
    assert cap.empty_reason == "owner_read_zero"
    assert "observed_at_block" not in cap.trace[0]


def test_pinned_read_uses_the_hex_block(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=OWNER_SELECTOR)
    evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())
    assert calls[0][1][1] == hex(PINNED_BLOCK)


def test_non_empty_read_also_carries_its_block(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())

    assert cap.members == [GOVERNOR]
    assert cap.trace[0]["observed_at_block"] == PINNED_BLOCK


def test_burn_address_is_not_an_exact_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """``0x0`` can never be ``msg.sender`` on mainnet, which is what makes a zero
    read a real "nobody". ``0x…dEaD`` is an ordinary address merely BELIEVED
    keyless — a convention, not a proof — so it may not share the zero shape and
    may not be published as a member either. The raw address is recorded so the
    characterization is checkable downstream."""
    _stub_getter(monkeypatch, returns=_word(BURN), only=OWNER_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.confidence == "partial"
    assert cap.empty_reason == "owner_read_burn_address"
    assert cap.trace[0]["read_address"] == BURN


def test_revert_stays_an_honest_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """A revert is not an answer. It must never become a read-confirmed zero —
    that is the exact fail-open this whole unit exists to prevent."""
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "owner()"}), _ctx())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert cap.empty_reason == "unreadable_revert"


def test_pending_ceiling_shape_is_byte_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression guard on a real mainnet shape: EACAggregatorProxy's
    ``pendingOwner()`` genuinely reverts. That reaches the accept-side ceiling,
    which is UNCHANGED by this unit — including its ``empty_by_design`` and the
    ``basis: "accessor_name"`` disclosure that keeps it out of the earned-negative
    gate."""
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
    """The pass memo dedups reads across functions gating on the same getter, and
    its contract is a byte-identical result. The block is threaded onto BOTH
    paths, so a memo hit cannot serve an otherwise-identical payload that has
    quietly lost its observation block."""
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
    """The memo used to store a collapsed ``""`` for both, making the two
    answers indistinguishable in-process as well as on the wire."""
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

    monkeypatch.setattr("utils.rpc.rpc_request", fake)
    return calls


def test_zero_slot_publishes_the_read_not_a_classification(monkeypatch: pytest.MonkeyPatch) -> None:
    """``empty_by_design`` used to arrive here from a DEFAULT ARGUMENT — a label
    asserting the gate is an intentional accept-side ceiling, applied to any
    caller that did not opt out, on a set with no trace and no block to check it
    against. It is now the read that is published."""
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


def test_deunderscore_convention_is_labelled_and_hoisted(monkeypatch: pytest.MonkeyPatch) -> None:
    """``onlyGovernor`` lowers to ``msg.sender == _governor()``; the internal
    accessor has no selector so reading it reverts, and the resolver falls back
    to the de-underscored public getter. Real address, name-chosen getter — and
    the row now says so BESIDE its strength fields, not only inside the trace."""
    _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=GOVERNOR_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_governor()"}), _ctx())

    assert cap.members == [GOVERNOR]
    assert {"step": "authority_getter_basis", "basis": "deunderscore_convention", "selector": GOVERNOR_SELECTOR} in (
        cap.trace
    )
    details = _authority_details(cap)
    assert details["authority_basis"] == "deunderscore_convention"
    assert details["accessor_slot_agreement"] == "not_determined"
    assert details["membership_quality"] == "exact"


def test_public_getter_is_abi_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control. ``auto_getter`` was renamed ``abi_auto_getter`` so the one
    arm the compiler forces cannot be confused with the name-matched ones."""
    _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=GOVERNOR_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "state_variable", "state_variable_name": "governor"}), _ctx())

    details = _authority_details(cap)
    assert details["authority_basis"] == "abi_auto_getter"
    # No accessor name was matched, so there is no slot-agreement residual to state.
    assert "accessor_slot_agreement" not in details


def test_oz_v5_namespaced_accessor_gets_its_own_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """The 6 CumulativeMerkleDrop rows. OZ-v5 keeps ownership in an ERC-7201
    namespace, so an ``owner()`` gate inlines to a ``view_call`` of the private
    accessor. It was published under the SAME label as the de-underscore
    convention, so a consumer reading the basis still could not tell a
    standard-anchored match from a 3-name guess."""
    _stub_getter(monkeypatch, returns=_word(GOVERNOR), only=OWNER_SELECTOR)
    cap = evaluate_tree(
        _eq_tree({"source": "view_call", "callee_signature": "_getAccessControlDefaultAdminRulesStorage()"}),
        _ctx(),
    )

    assert cap.members == [GOVERNOR]
    details = _authority_details(cap)
    assert details["authority_basis"] == "standard_namespaced_accessor"
    # Seated in the SAME tier as the convention arm: an exact-name match against
    # the standard's table is still a name match, and the same residual is open.
    assert details["accessor_slot_agreement"] == "not_determined"


def test_the_namespaced_arms_erc7201_slot_is_the_accesscontrol_one() -> None:
    """The anchor the arm is named for, recomputed rather than quoted. Lane A's
    spec pinned the *Initializable* namespace, a different slot entirely — this
    test is what would have caught that.

    Note what is NOT published: the resolver reads ``owner()``, never this slot,
    so publishing it as a witness of the resolution would be a computed constant
    dressed as evidence. It anchors the arm here and nowhere else."""

    def erc7201(namespace: str) -> str:
        inner = int.from_bytes(keccak(text=namespace), "big") - 1
        return "0x" + (int.from_bytes(keccak(inner.to_bytes(32, "big")), "big") & ~0xFF).to_bytes(32, "big").hex()

    assert (
        erc7201("openzeppelin.storage.AccessControlDefaultAdminRules")
        == "0xeef3dac4538c82c8ace4063ab0acd2d15cdb5883aa1dff7c2673abb3d8698400"
    )
    assert erc7201("openzeppelin.storage.Initializable") != erc7201(
        "openzeppelin.storage.AccessControlDefaultAdminRules"
    )


def test_unknown_internal_accessor_resolves_to_no_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed: ``_frobnicate()`` is not in the authority basenames, so no
    getter is substituted, no principal is published, and the basis key is
    ABSENT — not ``"unknown"``, not null."""
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_frobnicate()"}), _ctx())

    assert cap.members == []
    assert project_capability_surface(capability_to_dict(cap)).principal_rows == []


def test_a_lower_bound_read_never_stamps_a_basis(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pinned so a later refactor cannot stamp a basis onto an unresolved read:
    the basis is stamped only on a short-circuit at ``exact``."""
    _stub_getter(monkeypatch, returns="revert")
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_governor()"}), _ctx())

    assert cap.membership_quality != "exact"
    assert [step for step in cap.trace if step.get("step") == "authority_getter_basis"] == []


def test_the_convention_is_disclosed_not_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anti-name-inference control. A contract carrying a reverting internal
    ``_governor()`` AND an unrelated public ``governor()`` that returns a
    DIFFERENT address still resolves to the public getter's value — because that
    is what the convention does — but it must publish
    ``deunderscore_convention``, i.e. the row discloses that the binding is a
    name match rather than claiming it was checked.

    This is the test a genuine slot differential would have to invert: it would
    have to prove ``_governor()`` and ``governor()`` read the same storage, and
    refuse the principal when they do not. On this corpus that differential is
    unrunnable on 2 of 3 runtime addresses and non-identifying on the third, so
    ``accessor_slot_agreement`` stays ``not_determined``."""
    unrelated = "0x" + "77" * 20
    _stub_getter(monkeypatch, returns=_word(unrelated), only=GOVERNOR_SELECTOR)
    cap = evaluate_tree(_eq_tree({"source": "view_call", "callee_signature": "_governor()"}), _ctx())

    assert cap.members == [unrelated]
    details = _authority_details(cap)
    assert details["authority_basis"] == "deunderscore_convention"
    assert details["accessor_slot_agreement"] == "not_determined"
