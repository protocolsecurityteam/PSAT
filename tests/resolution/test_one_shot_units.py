"""Pure-function unit coverage for the one-shot static + resolver helpers.

No Slither, no wire — exercises the guard/classify/decode primitives and the
proxy-standard fallbacks (implementation() getter, EIP-2535 diamond) directly,
so the branch logic is pinned independently of the real-compile fixtures.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from eth_utils.crypto import keccak

from services.resolution.one_shot_probe import (
    _classify_value,
    _guard_allows,
    _parse_guard_constant,
    _read_latch_value,
    collect_one_shot_latches,
    detect_proxy_standard,
)
from services.static.contract_analysis_pipeline.one_shot import (
    _is_monotonic_ascent_latch,
    _parse_constant,
    _scalar_candidate,
    _write_falsifies_guard,
)
from services.static.contract_analysis_pipeline.predicate_types import LeafPredicate

_ZERO = "0x" + "0" * 64
PROXY = "0x" + "11" * 20
IMPL = "0x" + "22" * 20


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


# ---------------------------------------------------------------------------
# Static guard primitives (one_shot.py)
# ---------------------------------------------------------------------------


def test_write_falsifies_guard_every_operator():
    assert _write_falsifies_guard("falsy", None, 1) is True
    assert _write_falsifies_guard("falsy", None, 0) is False
    assert _write_falsifies_guard("truthy", None, 0) is True
    assert _write_falsifies_guard("truthy", None, 1) is False
    assert _write_falsifies_guard("eq", 1, 2) is True  # written != guard → guard broken
    assert _write_falsifies_guard("eq", 1, 1) is False
    assert _write_falsifies_guard("ne", 1, 1) is True
    assert _write_falsifies_guard("lt", 100, 100) is True  # v<100 broken by writing 100
    assert _write_falsifies_guard("lte", 100, 101) is True
    assert _write_falsifies_guard("gt", 0, 0) is True
    assert _write_falsifies_guard("gte", 1, 0) is True
    assert _write_falsifies_guard("eq", None, 5) is False  # no constant → can't decide


def test_monotonic_ascent_latch_excludes_rearmable_and_descending():
    # consuming: ALLOW while flag falsy, write moves it up
    assert _is_monotonic_ascent_latch("falsy", None, {1}) is True
    assert _is_monotonic_ascent_latch("falsy", None, {0}) is False  # writing 0 doesn't consume
    # versioned: eq 0 guard, write to >0
    assert _is_monotonic_ascent_latch("eq", 0, {1, 2}) is True
    assert _is_monotonic_ascent_latch("eq", 1, {2}) is True
    # inverted / descending forms are NOT latches (re-armable)
    assert _is_monotonic_ascent_latch("truthy", None, {0}) is False
    assert _is_monotonic_ascent_latch("ne", 0, {1}) is False
    assert _is_monotonic_ascent_latch("eq", None, {1}) is False


class _StubType:
    def __init__(self, name: str, size: int):
        self._name = name
        self.storage_size = (size, True)

    def __str__(self) -> str:
        return self._name


class _StubCompilationUnit:
    def __init__(self, slot: int):
        self._slot = slot

    def storage_layout_of(self, _contract, _state_var):
        return (self._slot, 0)


def _latch_contract(name: str, type_name: str = "bool", slot: int = 3):
    var = SimpleNamespace(name=name, type=_StubType(type_name, 1), is_constant=False, is_immutable=False)
    return SimpleNamespace(state_variables_ordered=[var], compilation_unit=_StubCompilationUnit(slot))


def _eq_leaf(operands: list[dict[str, Any]]) -> LeafPredicate:
    return cast(LeafPredicate, {"operator": "eq", "operands": operands})


def test_scalar_candidate_partitions_operands_by_position():
    """The non-state-variable operands are the complement of the state-variable
    POSITIONS. This pins that semantics; it is not evidence of a fixed defect —
    it holds for the dict-equality form too, which was correct exactly because
    the state-variable test is a pure function of the operand dict. Widening
    that test is what would separate the two forms."""
    sv = {"source": "state_variable", "state_variable_name": "initialized"}
    const = {"source": "constant", "constant_value": "0"}
    contract = _latch_contract("initialized")
    writes = {"initialized": {"non_constant": False, "values": {1}}}

    candidate = _scalar_candidate(contract, _eq_leaf([dict(sv), dict(const)]), writes)
    assert candidate is not None
    assert candidate["variable"] == "initialized"
    assert candidate["slot"] == "0x" + "0" * 63 + "3"

    # Two equal state-variable operands occupy two positions: two latch reads,
    # not one read counted once.
    twins = _eq_leaf([dict(sv), dict(sv), dict(const)])
    assert _scalar_candidate(contract, twins, writes) is None

    # A structural twin carrying one extra field is judged on its own: it is
    # not a state-variable operand and not a constant, so the candidate is
    # refused.
    asymmetric = _eq_leaf([dict(sv), {**sv, "member_path": ["flag"]}, dict(const)])
    assert _scalar_candidate(contract, asymmetric, writes) is None


def test_parse_constant_forms():
    assert _parse_constant(True) == 1
    assert _parse_constant(5) == 5
    assert _parse_constant("0x10") == 16
    assert _parse_constant("true") == 1
    assert _parse_constant("false") == 0
    assert _parse_constant("not-a-number") is None
    assert _parse_constant(None) is None


# ---------------------------------------------------------------------------
# Resolver decode primitives (one_shot_probe.py)
# ---------------------------------------------------------------------------


def test_guard_allows_every_operator():
    assert _guard_allows("falsy", None, 0) is True
    assert _guard_allows("falsy", None, 1) is False
    assert _guard_allows("truthy", None, 1) is True
    assert _guard_allows("eq", 3, 3) is True
    assert _guard_allows("ne", 3, 4) is True
    assert _guard_allows("lt", 5, 4) is True
    assert _guard_allows("lte", 5, 5) is True
    assert _guard_allows("gt", 5, 6) is True
    assert _guard_allows("gte", 5, 5) is True
    assert _guard_allows("eq", None, 1) is None  # no constant → undecidable


def test_parse_guard_constant_forms():
    assert _parse_guard_constant(True) == 1
    assert _parse_guard_constant(7) == 7
    assert _parse_guard_constant("0xff") == 255
    assert _parse_guard_constant("bad") is None
    assert _parse_guard_constant(None) is None


def test_classify_value_standard_storage_layout():
    """The classification AND the oracle that produced it — a consumed verdict
    reached through the sentinel, the version compare and the bare non-zero
    compare are three different claims and must not collapse to one label."""
    v4 = {"standard": "storage_layout", "size_bytes": 1, "expected_version": 1}
    assert _classify_value(v4, 1) == ("consumed", "version_ge")
    assert _classify_value(v4, 0) == ("armed", "version_ge")
    assert _classify_value(v4, 0xFF) == ("consumed", "sentinel")  # _disableInitializers
    v5 = {"standard": "oz_v5_namespaced", "size_bytes": 8, "expected_version": 1}
    assert _classify_value(v5, 0xFFFFFFFFFFFFFFFF) == ("consumed", "sentinel")  # uint64
    assert _classify_value(v5, 2) == ("consumed", "version_ge")
    no_expected = {"standard": "storage_layout", "size_bytes": 1}
    assert _classify_value(no_expected, 3) == ("consumed", "value_gt_zero")
    assert _classify_value(no_expected, 0) == ("armed", "value_gt_zero")


def test_classify_value_structural_guard():
    latch = {"standard": "structural_scalar_latch", "guard": {"operator": "falsy", "constant": None}}
    assert _classify_value(latch, 0) == ("armed", "guard")  # guard allows → not yet consumed
    assert _classify_value(latch, 1) == ("consumed", "guard")
    unknown = {"standard": "unstructured_slot_latch", "guard": {"operator": "weird", "constant": None}}
    # Nothing decided: no basis, so nothing may be published as the oracle.
    assert _classify_value(unknown, 5) == ("unknown", None)


def test_read_latch_value_byte_offset_extraction():
    class _Rpc:
        def __call__(self, *a, **k):
            # a packed word: byte 20 = 0x01 (FiatToken initialized after an address)
            return _word(0x01 << (8 * 20))

    latch = {"slot": _ZERO, "byte_offset": 20, "size_bytes": 1}
    value, read = _read_latch_value(_Rpc(), "x", PROXY, latch, "latest", {})
    assert value == 1
    assert read == {"kind": "storage", "slot": _ZERO, "value": hex(0x01 << (8 * 20))}


def test_detect_proxy_standard_implementation_getter_fallback():
    impl_sel = "0x" + keccak(text="implementation()").hex()[:8]

    class _Rpc:
        def __call__(self, rpc_url, method, params, retries=1):
            if method == "eth_getStorageAt":
                return _ZERO  # no slot-based proxy markers
            if method == "eth_call" and params[0]["data"] == impl_sel:
                return _word(int(IMPL, 16))  # implementation() returns an address
            return "0x"

    transcript: dict = {}
    assert detect_proxy_standard(_Rpc(), "x", PROXY, "latest", transcript) == "implementation_getter"


def test_detect_proxy_standard_diamond_fallback():
    facet_sel = "0x" + keccak(text="facetAddresses()").hex()[:8]

    class _Rpc:
        def __call__(self, rpc_url, method, params, retries=1):
            if method == "eth_getStorageAt":
                return _ZERO
            if method == "eth_call" and params[0]["data"] == facet_sel:
                return "0x" + "00" * 32 + "01" * 32 + "22" * 32  # non-empty dynamic array
            return "0x"

    assert detect_proxy_standard(_Rpc(), "x", PROXY, "latest", {}) == "eip2535_diamond"


def test_detect_proxy_standard_none_for_bare_contract():
    class _Rpc:
        def __call__(self, *a, **k):
            return _ZERO if a[1] == "eth_getStorageAt" else "0x"

    assert detect_proxy_standard(_Rpc(), "x", IMPL, "latest", {}) is None


def test_collect_one_shot_latches_root_candidate():
    tree = {
        "op": "AND",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "business",
                    "operands": [],
                    "references_msg_sender": False,
                    "expression": "",
                    "basis": [],
                },
            }
        ],
        "one_shot_candidate_latch": {"standard": "unstructured_slot_latch", "slot": "0x" + "ab" * 32},
    }
    latches = collect_one_shot_latches(tree)
    assert latches["candidate"] and latches["candidate"][0]["standard"] == "unstructured_slot_latch"
    assert not latches["standard"]
