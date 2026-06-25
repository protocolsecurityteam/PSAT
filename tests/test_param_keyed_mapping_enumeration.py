"""Parameter-keyed authority mappings resolve by enumerating their VALUE set from
setter events (claim #3 group C).

ether.fi's L1/SyncPool receivers gate ``onMessageReceived`` on
``msg.sender == receivers[originEid]`` — a ``mapping(uint32 => address)`` keyed by a
function PARAMETER, inside ERC-7201 namespaced storage. There is no single getter to
read: the authorized caller is whichever receiver the (caller-chosen) ``originEid``
maps to. The static stage otherwise collapses ``$.receivers[originEid]`` to the bare
``_getL1BaseSyncPoolStorage()`` ``view_call`` operand, so before P4 the gate funneled
to ``finite_set([], lower_bound)`` — a silent under-resolution.

The fix is two-part:
  * STATIC — the builder stamps ``mapping_name`` onto the non-caller operand of a
    ``msg.sender == mapping[param]`` equality (``_stamp_param_keyed_authority_mapping``),
    and the contract-wide ``apply_mapping_event_hint_pass`` attaches the
    value-enumeration ``mapping_writer_specs`` (the ``ReceiverSet`` setter event);
  * RESOLUTION — ``_resolve_equality_principal`` routes such an operand to
    ``_resolve_param_keyed_authority_mapping``, which folds the mapping's value set
    from those setter events on the runtime address. Receivers found → ``finite_set``
    of them (``lower_bound`` — event replay is a lower bound on the live set); no event
    source / no setter spec / empty fold → ``external_check_only`` (an explicit query
    interface, never a phantom empty).

Layered like ``test_internal_authority_storage_read.py``: literal-operand unit tests
pin the resolver and always run; the integration test compiles the
``L1SyncPoolReceiver`` fixture and proves the operand is stamped + enumerated
end-to-end. The hypersync event source is stubbed via an injected fake client (the
wire), not by replacing the enumerator.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution import mapping_enumerator as ME
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree

CONTRACT = "0x" + "11" * 20
R1 = "0x" + "a1" * 20
R2 = "0x" + "b2" * 20

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "contracts" / "authority"

# The value-enumeration writer spec the static post-pass attaches for ``receivers``
# (ReceiverSet(uint32 indexed originEid, address receiver) — key indexed in topic1,
# value in data word 0). Verbatim shape of ``discover_mapping_writer_events`` output.
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

# The param-keyed mapping operand, as the static stage emits it (the bare storage
# accessor view_call + the stamped mapping identity).
PARAM_KEYED_OPERAND: dict[str, Any] = {
    "source": "view_call",
    "callee": "_getL1BaseSyncPoolStorage()",
    "callee_signature": "_getL1BaseSyncPoolStorage()",
    "callee_selector": "0x98ea52ff",
    "mapping_name": "receivers",
    "mapping_writer_specs": [RECEIVERS_WRITER_SPEC],
}
# Same operand minus the writer spec — a mapping with no discoverable setter event.
PARAM_KEYED_OPERAND_NO_SPEC: dict[str, Any] = {
    "source": "view_call",
    "callee_signature": "_getL1BaseSyncPoolStorage()",
    "callee_selector": "0x98ea52ff",
    "mapping_name": "receivers",
}
# The pre-P4 shape (no mapping identity): the before/after witness — without the
# stamp the same gate funnels to the silent lower_bound placeholder.
BARE_VIEW_CALL_OPERAND: dict[str, Any] = {
    "source": "view_call",
    "callee_signature": "_getL1BaseSyncPoolStorage()",
    "callee_selector": "0x98ea52ff",
}


# --------------------------------------------------------------------------
# Fake hypersync event source (the wire stub). Mirrors test_mapping_enumerator.
# --------------------------------------------------------------------------


def _uint_topic(value: int) -> str:
    return "0x" + f"{value:064x}"


def _addr_data(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _receiver_set_log(eid: int, receiver: str, block: int = 10) -> SimpleNamespace:
    """ReceiverSet(uint32 indexed originEid, address receiver) — eid in topic1, the
    receiver value in data word 0 (the value the fold must extract)."""
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


# --------------------------------------------------------------------------
# Context plumbing.
# --------------------------------------------------------------------------


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

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:  # noqa: ARG002
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _ctx(meta: dict[str, Any] | None = None, contract_address: str | None = CONTRACT) -> EvaluationContext:
    return EvaluationContext(
        contract_address=contract_address or CONTRACT,
        adapter=_Adapter(_Outer(meta or {}, contract_address)),
    )


def _seeded_meta(*logs: SimpleNamespace) -> dict[str, Any]:
    return {"hypersync_client": _fake_client(*logs), "hypersync_module": _FakeHypersyncModule()}


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
                "expression": "msg.sender == receivers[originEid]",
                "basis": [],
            },
        },
    )


def _status(cap: CapabilityExpr) -> str | None:
    cap_dict = capability_to_dict(cap)
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


def _principals(cap: CapabilityExpr) -> list[str]:
    return [r["address"] for r in project_capability_surface(capability_to_dict(cap)).principal_rows]


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "0")
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)

    # Stub the getter wire: the unstamped-operand witness drives the view_call getter
    # path, which would otherwise dial the (blocked) rpc_url. A revert is the honest
    # outcome there (``_getL1BaseSyncPoolStorage()`` is internal) and keeps the suite
    # offline. The enumeration path uses the injected hypersync client, not this.
    def _revert(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("execution reverted")

    monkeypatch.setattr("utils.rpc.rpc_request", _revert)

    # The live param-keyed value scan now floors from_block at the contract's
    # creation block; keep that lookup off the (blocked) Etherscan wire offline.
    import services.resolution.creation_block_floor as floor_mod

    floor_mod._FLOOR_CACHE.clear()
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: None)

    ME.clear_enumeration_cache()
    yield
    ME.clear_enumeration_cache()


# --------------------------------------------------------------------------
# Resolver unit tests (literal operand; always run).
# --------------------------------------------------------------------------


def test_receivers_resolve_to_value_set() -> None:
    """The folded receiver VALUES are the authorized callers — the recovery P4 lands.
    ``lower_bound`` because event replay is a lower bound on the live set."""
    meta = _seeded_meta(_receiver_set_log(30183, R1), _receiver_set_log(30260, R2))
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert cap.kind == "finite_set"
    assert cap.members == sorted([R1, R2])  # resolver returns deduped + sorted
    assert cap.membership_quality == "lower_bound"
    assert sorted(_principals(cap)) == sorted([R1, R2])
    assert _status(cap) != "resolved_empty"


def test_param_keyed_scan_floors_from_block_at_creation_block(monkeypatch) -> None:
    """The live param-keyed value scan starts at the contract's creation block
    (deploy→head), not genesis: identical receiver set, no pre-deployment scan."""
    import services.resolution.creation_block_floor as floor_mod

    floor_mod._FLOOR_CACHE.clear()
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 12_345_678)

    captured: dict[str, Any] = {}
    orig = ME.enumerate_mapping_values_sync

    def spy(contract_address, writer_specs, **kwargs):
        captured["from_block"] = kwargs.get("from_block")
        return orig(contract_address, writer_specs, **kwargs)

    # The resolver imports the enumerator locally from ``mapping_enumerator``, so
    # patching it on that module is sufficient.
    monkeypatch.setattr(ME, "enumerate_mapping_values_sync", spy)

    meta = _seeded_meta(_receiver_set_log(30183, R1))
    evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert captured.get("from_block") == 12_345_678 - 1


def test_latest_value_per_key_is_folded() -> None:
    """Two assignments to the same eid fold to the latest receiver only — the value
    set is current, not historical."""
    meta = _seeded_meta(
        _receiver_set_log(30183, R1, block=10),
        _receiver_set_log(30183, R2, block=20),
    )
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert cap.members == [R2]


def test_no_events_is_external_check_not_phantom_empty() -> None:
    """An event source was reached but folded no receivers (the standalone-impl case
    whose receivers were set on the proxy): an explicit query interface, never a
    fabricated ``finite_set([])`` / ``resolved_empty``."""
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(_seeded_meta()))

    assert cap.kind == "external_check_only"
    assert _principals(cap) == []
    assert _status(cap) != "resolved_empty"


def test_no_event_source_is_external_check() -> None:
    """No hypersync token and no injected client → can't enumerate → external check,
    not a silent empty."""
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx({}))

    assert cap.kind == "external_check_only"
    assert _principals(cap) == []


def test_no_writer_spec_is_external_check() -> None:
    """A param-keyed mapping with no discoverable setter event can't be enumerated →
    external check (even with a live event source)."""
    cap = evaluate_tree(
        _eq_tree(PARAM_KEYED_OPERAND_NO_SPEC),
        _ctx(_seeded_meta(_receiver_set_log(30183, R1))),
    )

    assert cap.kind == "external_check_only"
    assert _principals(cap) == []


def test_zero_receiver_values_are_dropped() -> None:
    """A receiver set to the zero address is not an authorized caller — it must not
    appear in the principal set."""
    meta = _seeded_meta(_receiver_set_log(30183, "0x" + "00" * 20), _receiver_set_log(30260, R1))
    cap = evaluate_tree(_eq_tree(PARAM_KEYED_OPERAND), _ctx(meta))

    assert cap.members == [R1]


def test_unstamped_operand_stays_lower_bound() -> None:
    """The before/after witness: WITHOUT the stamped ``mapping_name`` the same gate
    funnels to the silent ``lower_bound`` placeholder (the view_call getter reverts,
    nothing else to read) — so the stamp + enumeration is exactly what recovers the
    principals. Fails on the pre-P4 evaluator."""
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
        """The static stage stamps ``mapping_name`` + the value-enumeration writer
        spec (from the contract's ``ReceiverSet`` setter) onto the param-keyed
        operand of ``onMessageReceived``."""
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
        """Precision: a caller gate reading the mapping by a CONSTANT key
        (``receivers[0]``) is not parameter-keyed — there is no caller-chosen key, so
        no value set to enumerate. The static pass must NOT stamp it (else resolution
        would wrongly enumerate the whole mapping for a fixed-key gate)."""
        op = _caller_operand(_tree_for(_receiver_contract(), "defaultReceiverGate()"))
        assert op.get("mapping_name") is None
        assert op.get("mapping_writer_specs") is None

    def test_getter_is_not_stamped(self) -> None:
        """``getReceiver(uint32)`` reads the same mapping but is not a caller gate, so
        no param-keyed marker is attached to anything in its (absent) guard tree."""
        art = build_predicate_artifacts(_receiver_contract())
        # getReceiver has no revert path → no tree (publicly callable).
        assert "getReceiver(uint32)" not in art["trees"]

    def test_resolves_receivers_end_to_end(self) -> None:
        """End-to-end: the stamped operand routes to value enumeration; the seeded
        ReceiverSet events fold to the receiver set — ``onMessageReceived`` is NOT
        under-resolved."""
        tree = _tree_for(_receiver_contract(), _ON_MESSAGE)
        meta = _seeded_meta(_receiver_set_log(30183, R1), _receiver_set_log(30260, R2))
        cap = evaluate_tree(tree, _ctx(meta))

        assert cap.kind == "finite_set"
        assert cap.members == sorted([R1, R2])  # resolver returns deduped + sorted
        assert cap.membership_quality == "lower_bound"
        assert sorted(_principals(cap)) == sorted([R1, R2])
        assert _status(cap) != "resolved_empty"

    def test_empty_receivers_external_check_end_to_end(self) -> None:
        """End-to-end: with no ReceiverSet events on the analyzed (impl) address the
        gate becomes an explicit external check, not a silent ``lower_bound`` — out
        of the under-resolution bucket."""
        tree = _tree_for(_receiver_contract(), _ON_MESSAGE)
        cap = evaluate_tree(tree, _ctx(_seeded_meta()))

        assert cap.kind == "external_check_only"
        assert _principals(cap) == []
        assert _status(cap) != "resolved_empty"
