"""Parameter-keyed authority mappings resolve by enumerating their value set from setter events.

ether.fi's receivers gate on ``msg.sender == receivers[originEid]``, which collapsed to a bare ``view_call`` and
resolved to nothing. Static stamps ``mapping_name`` and the ``ReceiverSet`` writer spec; resolution folds the
values into a lower-bound set, or ``external_check_only`` when nothing folds, never a phantom empty.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution import mapping_enumerator as ME
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree
from tests.support.eq_tree import eq_tree

CONTRACT = "0x" + "11" * 20
R1 = "0x" + "a1" * 20
R2 = "0x" + "b2" * 20

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authority"

# Key in topic1, value in data word 0.
RECEIVERS_WRITER_SPEC: dict[str, Any] = {
    "mapping_name": "receivers",
    "event_signature": "ReceiverSet(uint32,address)",
    "event_name": "ReceiverSet",
    "key_position": 0,
    "indexed_positions": [0],
    "direction": "set",
    "writer_function": "_setReceiver(uint32,address)",
    "value_position": 1,
}

PARAM_KEYED_OPERAND: dict[str, Any] = {
    "source": "view_call",
    "callee": "_getL1BaseSyncPoolStorage()",
    "callee_signature": "_getL1BaseSyncPoolStorage()",
    "callee_selector": "0x98ea52ff",
    "mapping_name": "receivers",
    "mapping_writer_specs": [RECEIVERS_WRITER_SPEC],
}
PARAM_KEYED_OPERAND_NO_SPEC: dict[str, Any] = {
    "source": "view_call",
    "callee_signature": "_getL1BaseSyncPoolStorage()",
    "callee_selector": "0x98ea52ff",
    "mapping_name": "receivers",
}
# The pre-P4 shape.
BARE_VIEW_CALL_OPERAND: dict[str, Any] = {
    "source": "view_call",
    "callee_signature": "_getL1BaseSyncPoolStorage()",
    "callee_selector": "0x98ea52ff",
}


def _uint_topic(value: int) -> str:
    return "0x" + f"{value:064x}"


def _addr_data(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _receiver_set_log(eid: int, receiver: str, block: int = 10) -> SimpleNamespace:
    return SimpleNamespace(
        topics=["0x" + ME._event_topic0("ReceiverSet(uint32,address)")[2:], _uint_topic(eid)],
        data=_addr_data(receiver),
        block_number=block,
        log_index=0,
        transaction_hash="0x" + "f" * 64,
    )


def _fake_client(*logs: SimpleNamespace) -> Any:
    state = {"done": False}

    class _Client:
        async def get(self, _query: Any) -> Any:
            if state["done"]:
                return SimpleNamespace(data=[], next_block=None)
            state["done"] = True
            return SimpleNamespace(data=list(logs), next_block=None)

    return _Client()


class _FakeFieldEnumMeta(type):
    _members = ("address", "topic0", "data", "block_number")

    def __iter__(cls) -> Any:
        for name in cls._members:
            yield cls(name)


class _FakeFieldEnum(metaclass=_FakeFieldEnumMeta):
    def __init__(self, name: str) -> None:
        self.value = name


class _FakeHypersyncModule:
    Query = SimpleNamespace
    LogSelection = SimpleNamespace
    FieldSelection = SimpleNamespace
    LogField = _FakeFieldEnum


class _Outer:
    def __init__(self, meta: dict[str, Any], contract_address: str | None = CONTRACT) -> None:
        self.rpc_url = "http://rpc.test"
        self.contract_address = contract_address
        self.block = None
        self.session = None
        self.chain_id = 1
        self.meta = meta


class _Adapter:
    def __init__(self, outer: _Outer) -> None:
        self._outer_ctx = outer

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx(meta: dict[str, Any] | None = None, contract_address: str | None = CONTRACT) -> EvaluationContext:
    return EvaluationContext(
        contract_address=contract_address or CONTRACT,
        adapter=_Adapter(_Outer(meta or {}, contract_address)),
    )


def _seeded_meta(*logs: SimpleNamespace) -> dict[str, Any]:
    return {"hypersync_client": _fake_client(*logs), "hypersync_module": _FakeHypersyncModule()}


def _eq_tree(other_operand: dict[str, Any]) -> PredicateTree:
    return eq_tree(other_operand, "msg.sender == receivers[originEid]")


def _status(cap: CapabilityExpr) -> str | None:
    cap_dict = capability_to_dict(cap)
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


def _principals(cap: CapabilityExpr) -> list[str]:
    return [r["address"] for r in project_capability_surface(capability_to_dict(cap)).principal_rows]


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "0")
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)

    # The unstamped witness drives the getter path, which would dial the blocked rpc_url.
    def _revert(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("execution reverted")

    monkeypatch.setattr("services.clients.rpc.rpc_request", _revert)

    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "resolve_scan_floor_with_basis", lambda *_a, **_k: (0, "creation_block_lookup"))

    ME.clear_enumeration_cache()
    yield
    ME.clear_enumeration_cache()


def test_receivers_resolve_to_value_set() -> None:
    """Event replay is a lower bound on the live set."""
    meta = _seeded_meta(_receiver_set_log(30183, R1), _receiver_set_log(30260, R2))
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert cap.kind == "finite_set"
    assert cap.members == sorted([R1, R2])  # resolver returns deduped + sorted
    assert cap.membership_quality == "lower_bound"
    assert sorted(_principals(cap)) == sorted([R1, R2])
    assert _status(cap) != "resolved_empty"


def test_param_keyed_scan_floors_from_block_at_creation_block(monkeypatch) -> None:
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(
        floor_mod, "resolve_scan_floor_with_basis", lambda *_a, **_k: (12_345_678 - 1, "creation_block_lookup")
    )

    captured: dict[str, Any] = {}
    orig = ME.enumerate_mapping_values_sync

    def spy(contract_address, writer_specs, **kwargs):
        captured["from_block"] = kwargs.get("from_block")
        return orig(contract_address, writer_specs, **kwargs)

    monkeypatch.setattr(ME, "enumerate_mapping_values_sync", spy)

    meta = _seeded_meta(_receiver_set_log(30183, R1))
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert captured.get("from_block") == 12_345_678 - 1
    step = next(s for s in cap.trace if s.get("step") == "param_keyed_mapping_enumeration")
    assert (step["scan_from_block"], step["floor_basis"]) == (12_345_678 - 1, "creation_block_lookup")
    assert "scan_to_block" in step


def test_latest_value_per_key_is_folded() -> None:
    meta = _seeded_meta(
        _receiver_set_log(30183, R1, block=10),
        _receiver_set_log(30183, R2, block=20),
    )
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert cap.members == [R2]


def test_no_events_is_external_check_not_phantom_empty() -> None:
    """The receivers were set on the proxy, not this implementation."""
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(_seeded_meta()))

    assert cap.kind == "external_check_only"
    assert _principals(cap) == []
    assert _status(cap) != "resolved_empty"


@pytest.mark.parametrize(
    ("operand", "meta"),
    [
        pytest.param(PARAM_KEYED_OPERAND, {}, id="no_event_source"),
        pytest.param(
            PARAM_KEYED_OPERAND_NO_SPEC,
            _seeded_meta(_receiver_set_log(30183, R1)),
            id="no_writer_spec",
        ),
    ],
)
def test_unenumerable_mapping_is_external_check(operand, meta) -> None:
    cap = evaluate_tree(_eq_tree(operand), _ctx(meta))

    assert cap.kind == "external_check_only"
    assert _principals(cap) == []


def test_zero_receiver_values_are_dropped() -> None:
    meta = _seeded_meta(_receiver_set_log(30183, "0x" + "00" * 20), _receiver_set_log(30260, R1))
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert cap.members == [R1]


def test_unstamped_operand_stays_lower_bound() -> None:
    """Fails on the pre-P4 evaluator."""
    cap = evaluate_tree(_eq_tree(BARE_VIEW_CALL_OPERAND), _ctx(_seeded_meta(_receiver_set_log(30183, R1))))

    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "lower_bound"
    assert _status(cap) != "resolved_empty"


# --------------------------------------------------------------------------
# Integration: compile the L1SyncPoolReceiver fixture and prove the static stage
# stamps the mapping identity + writer specs and resolution enumerates end-to-end.
# --------------------------------------------------------------------------

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts  # noqa: E402
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile


def _receiver_contract() -> Any:
    solc = _solc_path_for((0, 8, 24))
    if solc is None:
        pytest.skip("no installed solc satisfies ^0.8.24 for L1SyncPoolReceiver.sol")
    sl = Slither(str(FIXTURES_DIR / "L1SyncPoolReceiver.sol"), solc=solc)
    return next(c for c in sl.contracts if c.name == "L1SyncPoolReceiver")


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


_ON_MESSAGE = "onMessageReceived(uint32,bytes32,address,uint256,uint256)"


class TestL1SyncPoolReceiver:
    def test_static_stamps_mapping_identity_and_writer_spec(self) -> None:
        op = _caller_operand(_tree_for(_receiver_contract(), _ON_MESSAGE))
        assert op.get("mapping_name") == "receivers"
        specs = op.get("mapping_writer_specs")
        assert isinstance(specs, list) and len(specs) == 1
        spec = specs[0]
        assert spec["event_signature"] == "ReceiverSet(uint32,address)"
        assert spec["key_position"] == 0
        assert spec["value_position"] == 1
        assert spec["indexed_positions"] == [0]
        assert spec["direction"] == "set"

    def test_constant_keyed_mapping_is_not_stamped(self) -> None:
        """A constant key isn't parameter-keyed; stamping it would enumerate the whole mapping."""
        op = _caller_operand(_tree_for(_receiver_contract(), "defaultReceiverGate()"))
        assert op.get("mapping_name") is None
        assert op.get("mapping_writer_specs") is None

    def test_resolves_receivers_end_to_end(self) -> None:
        tree = _tree_for(_receiver_contract(), _ON_MESSAGE)
        meta = _seeded_meta(_receiver_set_log(30183, R1), _receiver_set_log(30260, R2))
        cap = evaluate_tree(tree, _ctx(meta))

        assert cap.kind == "finite_set"
        assert cap.members == sorted([R1, R2])  # resolver returns deduped + sorted
        assert cap.membership_quality == "lower_bound"
        assert sorted(_principals(cap)) == sorted([R1, R2])
        assert _status(cap) != "resolved_empty"
