"""Regression: OZ-v5 ERC-7201 namespaced ownership / AccessControlDefaultAdminRules.

Two layers share one OZ-v5 recognition table:
  * Layer 1 (controller recall): the owner lives in a namespaced struct, so the only operand
    is the suppressed ``*StorageLocation`` constant. ``build_controller_tracking`` emits a
    CANONICAL owner controller (read via ``owner()``, never the dead slot constant) for the
    two known slots (``OwnableStorageLocation`` -> EtherfiL1SyncPoolETH cid 615;
    ``AccessControlDefaultAdminRulesStorageLocation`` -> CumulativeMerkleDrop cid 462).
  * Layer 2 (function authority): CumulativeMerkleDrop overrides ``owner()`` to
    ``defaultAdmin()``, which Slither inlines to a ``view_call`` of the private accessor
    ``_getAccessControlDefaultAdminRulesStorage()`` (no external selector). The resolver
    recognizes it by EXACT name and reads the public ``owner()`` instead.
The L1BaseSyncPool namespace (``_getL1BaseSyncPoolStorage``) and the parametric
AccessControl root (``_getAccessControlStorage``) are NOT owner authorities: fail-closed.

Layered like ``test_canonical_authority_getter_resolution.py``: literal-dict unit tests always
run; integration tests compile a REAL OZ-v5 fixture and skip only without a compatible solc.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from services.resolution.capabilities import CapabilityExpr
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree
from services.static.contract_analysis_pipeline.tracking import (
    _emit_oz_v5_owner_target,
    _oz_v5_ownership_getter_for_accessor,
    _oz_v5_ownership_getter_for_slot_constant,
)
from tests.support.eq_tree import eq_tree

CONTRACT = "0x" + "11" * 20
SAFE = "0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52"  # CumulativeMerkleDrop owner()/defaultAdmin()
TIMELOCK = "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761"  # EtherfiL1SyncPoolETH owner()

OWNER_SELECTOR = "0x8da5cb5b"  # owner()
# _getAccessControlDefaultAdminRulesStorage() — the dead private accessor selector.
DEAD_ACCESSOR_SELECTOR = "0xce49c281"

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authority"


# --------------------------------------------------------------------------
# Stub resolver context (mirrors test_canonical_authority_getter_resolution.py).
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


def _eq_tree(other_operand: dict[str, Any]) -> PredicateTree:
    return eq_tree(other_operand, "owner() != _msgSender()")


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


# ==========================================================================
# Recognition table — exact-name scoping (unit, always runs).
# ==========================================================================

OWNERSHIP_SLOT_CONSTANTS = ["OwnableStorageLocation", "AccessControlDefaultAdminRulesStorageLocation"]
OWNERSHIP_ACCESSORS = ["_getOwnableStorage", "_getAccessControlDefaultAdminRulesStorage"]
# Real namespaced identifiers from the etherfi run that are NOT owner authorities.
NON_OWNERSHIP_SLOT_CONSTANTS = [
    "ReentrancyGuardStorageLocation",
    "PausableStorageLocation",
    "EIP712StorageLocation",
    "BaseMessengerStorageLocation",
    "L1BaseSyncPoolStorageLocation",
    "_OWNER_SLOT",
]
NON_OWNERSHIP_ACCESSORS = [
    "_getL1BaseSyncPoolStorage",
    "_getAccessControlStorage",  # parametric role-admin, NOT the owner root
    "_getOAppCoreStorage",
    "_getERC20Storage",
]


_RECOGNIZERS = {
    "slot_constant": _oz_v5_ownership_getter_for_slot_constant,
    "accessor": _oz_v5_ownership_getter_for_accessor,
}


@pytest.mark.parametrize(
    "kind,name,expected",
    [pytest.param("slot_constant", n, "owner", id=f"slot_constant-owner-{n}") for n in OWNERSHIP_SLOT_CONSTANTS]
    + [pytest.param("slot_constant", n, None, id=f"slot_constant-not_mapped-{n}") for n in NON_OWNERSHIP_SLOT_CONSTANTS]
    + [pytest.param("accessor", n, "owner", id=f"accessor-owner-{n}") for n in OWNERSHIP_ACCESSORS]
    + [pytest.param("accessor", n, None, id=f"accessor-not_mapped-{n}") for n in NON_OWNERSHIP_ACCESSORS],
)
def test_recognition_table(kind: str, name: str, expected: str | None) -> None:
    assert _RECOGNIZERS[kind](name) == expected


# ==========================================================================
# Layer 2 — view_call namespaced-accessor resolution (unit, always runs).
# ==========================================================================


def test_oz_v5_accessor_view_call_resolves_via_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """CumulativeMerkleDrop's ``owner()`` override inlines to a view_call of the private
    accessor; its own selector reverts, so the resolver reads the public ``owner()``."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {DEAD_ACCESSOR_SELECTOR: None, OWNER_SELECTOR: SAFE}, recorder)
    tree = _eq_tree(
        {
            "source": "view_call",
            "callee": "_getAccessControlDefaultAdminRulesStorage()",
            "callee_signature": "_getAccessControlDefaultAdminRulesStorage()",
            "callee_selector": DEAD_ACCESSOR_SELECTOR,
        }
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.kind == "finite_set"
    assert cap.members == [SAFE]
    assert cap.membership_quality == "exact"
    assert _called(recorder, OWNER_SELECTOR), "must read the canonical owner()"


def test_oz_v5_accessor_view_call_renounced_resolves_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """A zero owner() (renounced/unset) resolves to exact-empty, not a lower_bound."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {DEAD_ACCESSOR_SELECTOR: None, OWNER_SELECTOR: "0x" + "00" * 20}, recorder)
    tree = _eq_tree(
        {
            "source": "view_call",
            "callee_signature": "_getAccessControlDefaultAdminRulesStorage()",
            "callee_selector": DEAD_ACCESSOR_SELECTOR,
        }
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "exact"
    assert _called(recorder, OWNER_SELECTOR)


def test_non_ownership_accessor_view_call_stays_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed: the L1BaseSyncPool accessor is NOT an owner authority and must NOT be
    rerouted to owner() even though owner() would return an address."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {OWNER_SELECTOR: TIMELOCK}, recorder)
    tree = _eq_tree(
        {
            "source": "view_call",
            "callee_signature": "_getL1BaseSyncPoolStorage()",
            "callee_selector": "0xdeadbeef",
        }
    )

    cap = evaluate_tree(tree, _ctx_with_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert not _called(recorder, OWNER_SELECTOR), "non-owner accessor must not read owner()"


def test_oz_v5_accessor_without_rpc_stays_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    """No reachable RPC => the gate stays unresolved, never a false negative."""
    recorder: list = []
    _stub_rpc_map(monkeypatch, {OWNER_SELECTOR: SAFE}, recorder)
    tree = _eq_tree(
        {
            "source": "view_call",
            "callee_signature": "_getAccessControlDefaultAdminRulesStorage()",
            "callee_selector": DEAD_ACCESSOR_SELECTOR,
        }
    )

    cap = evaluate_tree(tree, _ctx_no_rpc())

    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert recorder == []


# ==========================================================================
# Layer 1 — owner-target emission helper (unit, always runs).
# ==========================================================================


class _StubContract:
    """Minimal Slither stand-in: no functions/state vars, so the emitter takes the no-event
    ``state_only`` branch."""

    functions: list = []
    state_variables_ordered: list = []
    events: list = []


def test_emit_owner_target_state_only_when_no_ownership_events() -> None:
    targets: list = []
    seen: set = set()
    _emit_oz_v5_owner_target(
        targets, seen, "owner", "OwnableStorageLocation", _StubContract(), FIXTURES_DIR, {}, {"functions": {}}
    )
    assert len(targets) == 1
    owner = targets[0]
    assert owner["controller_id"] == "state_variable:owner"
    assert owner["read_spec"]["target"] == "owner"
    assert owner["tracking_mode"] == "state_only"
    assert owner["associated_events"] == []


def test_emit_owner_target_dedupes_on_seen_id() -> None:
    targets: list = []
    seen: set = set()
    args = (targets, seen, "owner", "OwnableStorageLocation", _StubContract(), FIXTURES_DIR, {}, {"functions": {}})
    _emit_oz_v5_owner_target(*args)
    _emit_oz_v5_owner_target(*args)
    assert len(targets) == 1, "a second emission for the same getter is suppressed"


# ==========================================================================
# Integration: compile the OZ-v5 fixture through the production static pipeline.
# ==========================================================================

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.tracking import build_controller_tracking  # noqa: E402
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile

FIXTURE = "OzV5NamespacedOwnable.sol"
FLOOR = (0, 8, 25)


@pytest.fixture(scope="module")
def _slither():
    solc = _solc_path_for(FLOOR)
    if solc is None:
        pytest.skip(f"no installed solc satisfies ^{'.'.join(str(x) for x in FLOOR)}")
    return Slither(str(FIXTURES_DIR / FIXTURE), solc=solc)


def _contract(sl, name: str):
    return next(c for c in sl.contracts if c.name == name)


def _build_targets(
    sl, name: str, role_definitions: list[dict[str, str]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    contract = _contract(sl, name)
    trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic = cast(Any, {"role_definitions": role_definitions})
    targets = build_controller_tracking(contract, FIXTURES_DIR, trees, effects, semantic)
    return cast("list[dict[str, Any]]", targets), trees


_ACCESS_CONTROL_ROLES = [
    {"role": "AccessControlDefaultAdminRulesStorageLocation"},
    {"role": "DEFAULT_ADMIN_ROLE"},
]

# (fixture contract, role_definitions): OZ-v5 Ownable (EtherfiL1SyncPoolETH cid 615 form) and
# AccessControlDefaultAdminRules (CumulativeMerkleDrop cid 462 form).
_LAYER1_FORMS = [
    pytest.param("OzV5Ownable", [{"role": "OwnableStorageLocation"}], id="ownable"),
    pytest.param("OzV5AccessControlDefaultAdmin", _ACCESS_CONTROL_ROLES, id="access_control_default_admin"),
]


@pytest.mark.parametrize("contract_name,roles", _LAYER1_FORMS)
def test_layer1_emits_single_owner_controller_read_via_owner(_slither, contract_name, roles) -> None:
    targets, _trees = _build_targets(_slither, contract_name, roles)
    owners = [t for t in targets if t["controller_id"] == "state_variable:owner"]
    assert len(owners) == 1, "exactly one canonical owner controller"
    owner = owners[0]
    assert owner["read_spec"]["target"] == "owner"
    assert owner["read_spec"]["type_kind"] == "address"


@pytest.mark.parametrize("contract_name,roles", _LAYER1_FORMS)
def test_layer1_no_dead_slot_controller_emitted(_slither, contract_name, roles) -> None:
    targets, _trees = _build_targets(_slither, contract_name, roles)
    ids = {t["controller_id"] for t in targets}
    assert not any("StorageLocation" in cid for cid in ids), "no dead slot-constant getter row"
    assert not any(cid.startswith("role_identifier:") and "Storage" in cid for cid in ids)


class TestLayer1OwnableForm:
    """OZ-v5 OwnableUpgradeable (EtherfiL1SyncPoolETH cid 615 form): the slot
    constant reaches role_definitions; the owner controller reads owner()."""

    def test_owner_controller_carries_ownership_event_and_writers(self, _slither) -> None:
        targets, _trees = _build_targets(_slither, "OzV5Ownable", [{"role": "OwnableStorageLocation"}])
        owner = next(t for t in targets if t["controller_id"] == "state_variable:owner")
        events = {e["signature"] for e in owner.get("associated_events", [])}
        assert events == {"OwnershipTransferred(address,address)"}, "clean ownership-only event set"
        writers = {w.get("function") for w in owner.get("writer_functions", [])}
        # Only the canonical ownership mutators, NOT incidental namespace setters.
        assert writers == {"transferOwnership(address)", "renounceOwnership()"}


class TestLayer1AccessControlForm:
    """OZ-v5 AccessControlDefaultAdminRules (CumulativeMerkleDrop cid 462 form):
    the slot constant reaches role_definitions on-chain."""

    ROLES = _ACCESS_CONTROL_ROLES

    def test_gate_operand_is_namespaced_accessor_view_call(self, _slither) -> None:
        _targets, trees = _build_targets(_slither, "OzV5AccessControlDefaultAdmin", self.ROLES)
        leaf = trees["trees"]["setPeer(address)"]["leaf"]
        other = next(o for o in leaf["operands"] if o.get("source") != "msg_sender")
        assert other["source"] == "view_call"
        assert other["callee_signature"] == "_getAccessControlDefaultAdminRulesStorage()"


class TestLayer2AccessControlResolution:
    """End-to-end: the compiled CMD-form ``setPeer`` gate resolves to the live
    owner() through the namespaced accessor recognition."""

    def test_set_peer_resolves_to_owner(self, _slither, monkeypatch: pytest.MonkeyPatch) -> None:
        contract = _contract(_slither, "OzV5AccessControlDefaultAdmin")
        tree = build_predicate_artifacts(contract)["trees"]["setPeer(address)"]

        leaf = tree["leaf"]
        view_op = next(o for o in leaf["operands"] if o.get("source") == "view_call")
        assert view_op["callee_signature"] == "_getAccessControlDefaultAdminRulesStorage()"

        recorder: list = []
        # The dead accessor selector reverts; owner() returns the Safe.
        accessor_selector = view_op["callee_selector"]
        _stub_rpc_map(monkeypatch, {accessor_selector: None, OWNER_SELECTOR: SAFE}, recorder)

        cap = evaluate_tree(tree, _ctx_with_rpc())

        assert cap.members == [SAFE], "owner-gated setPeer must resolve to owner()"
        assert cap.membership_quality == "exact"
        assert _called(recorder, OWNER_SELECTOR)
