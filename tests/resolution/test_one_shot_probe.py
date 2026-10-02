"""A ``live`` verdict is earned only from a confirmed proxy with an armed latch; a bare implementation with an empty
latch is ``indeterminate``, never ``live``.
"""

from __future__ import annotations

from eth_utils.crypto import keccak

from services.resolution.one_shot_probe import (
    EIP1967_IMPL_SLOT,
    annotate_capability_one_shot,
    resolve_one_shot_state,
)
from tests.support.rpc_stubs import FakeRpc, _word

PROXY = "0x" + "11" * 20
IMPL = "0x" + "22" * 20
_ZERO = "0x" + "0" * 64


def _v4_latch(slot="0x" + "0" * 64, expected=1):
    return {
        "kind": "storage",
        "variable": "_initialized",
        "slot": slot,
        "byte_offset": 0,
        "size_bytes": 1,
        "value_type": "uint8",
        "expected_version": expected,
        "standard": "storage_layout",
    }


ERC7201_SLOT = "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"


def _v5_version_latch(expected=1):
    return {
        "kind": "storage",
        "variable": "INITIALIZABLE_STORAGE",
        "slot": ERC7201_SLOT,
        "byte_offset": 0,
        "size_bytes": 8,
        "value_type": "uint64",
        "expected_version": expected,
        "standard": "oz_v5_namespaced",
    }


def _v5_transient_latch(expected=1):
    return {
        "kind": "storage",
        "variable": "INITIALIZABLE_STORAGE",
        "slot": ERC7201_SLOT,
        "byte_offset": 8,
        "size_bytes": 1,
        "value_type": "bool",
        "expected_version": expected,
        "standard": "oz_v5_namespaced",
    }


def test_erc7201_slot_matches_canonical_derivation():
    inner = int.from_bytes(keccak(text="openzeppelin.storage.Initializable"), "big") - 1
    derived = int.from_bytes(keccak(inner.to_bytes(32, "big")), "big") & ~0xFF
    assert "0x" + format(derived, "064x") == "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"


def test_consumed_on_proxy_with_set_latch():
    rpc = FakeRpc(
        storage={
            (PROXY, EIP1967_IMPL_SLOT.lower()): _word(int(IMPL, 16)),
            (PROXY, _ZERO): _word(1),
        }
    )
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[_v4_latch()], rpc=rpc)
    assert result.state == "consumed"
    assert result.target_kind == "proxy:eip1967"


def test_live_on_proxy_with_unset_latch():
    rpc = FakeRpc(
        storage={
            (PROXY, EIP1967_IMPL_SLOT.lower()): _word(int(IMPL, 16)),
            (PROXY, _ZERO): _word(0),
        }
    )
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[_v4_latch()], rpc=rpc)
    assert result.state == "live"
    assert result.target_kind == "proxy:eip1967"


def test_bare_template_with_empty_latch_is_indeterminate_not_live():
    rpc = FakeRpc(storage={(IMPL, _ZERO): _word(0)})  # everything else zero → no proxy
    result = resolve_one_shot_state(rpc_url="x", address=IMPL, latches=[_v4_latch()], rpc=rpc)
    assert result.state == "indeterminate"
    assert result.target_kind == "unverified"


def test_disable_initializers_sentinel_is_consumed_even_unconfirmed():
    rpc = FakeRpc(storage={(IMPL, _ZERO): _word(0xFF)})
    result = resolve_one_shot_state(rpc_url="x", address=IMPL, latches=[_v4_latch()], rpc=rpc)
    assert result.state == "consumed"


def test_db_linked_proxy_skips_detection_and_reads_live():
    rpc = FakeRpc(storage={(PROXY, _ZERO): _word(0)})
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[_v4_latch()], db_proxy_linked=True, rpc=rpc)
    assert result.state == "live"
    assert result.target_kind == "db_linked_proxy"
    assert not any(slot == EIP1967_IMPL_SLOT.lower() for _, _, slot in rpc.log if _ == "storage")


def test_initialized_v5_proxy_with_transient_latch_first_is_consumed():
    """The version member at byte 0 decides, even with a transient-flag latch collected first."""
    rpc = FakeRpc(storage={(PROXY, ERC7201_SLOT): _word(2)})
    result = resolve_one_shot_state(
        rpc_url="x",
        address=PROXY,
        latches=[_v5_transient_latch(), _v5_version_latch()],
        db_proxy_linked=True,
        rpc=rpc,
    )
    assert result.state == "consumed"
    assert result.value == 2
    assert result.target_kind == "db_linked_proxy"


def test_transient_flag_only_latch_is_indeterminate_never_live():
    rpc = FakeRpc(storage={(PROXY, ERC7201_SLOT): _word(2)})
    result = resolve_one_shot_state(
        rpc_url="x", address=PROXY, latches=[_v5_transient_latch()], db_proxy_linked=True, rpc=rpc
    )
    assert result.state == "indeterminate"
    assert result.transcript.get("reason") == "no_decisive_latch"


def test_uninitialized_v5_proxy_still_reads_live():
    rpc = FakeRpc()  # every storage read returns the zero word
    result = resolve_one_shot_state(
        rpc_url="x",
        address=PROXY,
        latches=[_v5_transient_latch(), _v5_version_latch()],
        db_proxy_linked=True,
        rpc=rpc,
    )
    assert result.state == "live"
    assert result.value == 0


def test_v4_transient_initializing_variable_is_dropped():
    latch = {
        "kind": "storage",
        "variable": "_initializing",
        "slot": "0x" + "0" * 64,
        "byte_offset": 1,
        "size_bytes": 1,
        "value_type": "bool",
        "expected_version": None,
        "standard": "storage_layout",
    }
    rpc = FakeRpc(storage={(PROXY, "0x" + "0" * 64): _word(1)})
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[latch], db_proxy_linked=True, rpc=rpc)
    assert result.state == "indeterminate"
    assert result.transcript.get("reason") == "no_decisive_latch"


def test_version_tagged_latch_is_read_before_untagged_legacy():
    """Tagged latches are read before untagged legacy payloads regardless of collection order."""
    tagged = dict(_v5_version_latch(), role="version")
    rpc = FakeRpc(storage={(PROXY, ERC7201_SLOT): _word(2)})  # slot 0 reads zero
    result = resolve_one_shot_state(
        rpc_url="x",
        address=PROXY,
        latches=[_v4_latch(), tagged],
        db_proxy_linked=True,
        rpc=rpc,
    )
    assert result.state == "consumed"
    assert result.value == 2


def test_undecisive_slot_only_latch_does_not_mask_a_decisive_one():
    slot_only = {
        "kind": "storage",
        "variable": "INITIALIZABLE_STORAGE",
        "slot": ERC7201_SLOT,
        "byte_offset": None,
        "size_bytes": None,
        "value_type": None,
        "expected_version": 1,
        "standard": "namespaced_slot_constant",
    }
    guard_latch = {
        "kind": "storage",
        "variable": "initialized",
        "slot": "0x" + "ab" * 32,
        "byte_offset": 0,
        "size_bytes": 1,
        "value_type": "bool",
        "standard": "structural_scalar_latch",
        "guard": {"operator": "falsy", "constant": None},
    }
    rpc = FakeRpc(storage={(PROXY, ERC7201_SLOT): _word(2), (PROXY, "0x" + "ab" * 32): _word(1)})
    result = resolve_one_shot_state(
        rpc_url="x", address=PROXY, latches=[slot_only, guard_latch], db_proxy_linked=True, rpc=rpc
    )
    assert result.state == "consumed"  # guard falsy(1) → disallows → consumed
    assert result.value == 1


def test_zeppelinos_proxy_confirms_when_eip1967_empty():
    from utils.evm import OZ_LEGACY_IMPL_SLOT as ZEPPELINOS_IMPL_SLOT

    rpc = FakeRpc(
        storage={
            (PROXY, ZEPPELINOS_IMPL_SLOT.lower()): _word(int(IMPL, 16)),
            (PROXY, _ZERO): _word(0),
        }
    )
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[_v4_latch()], rpc=rpc)
    assert result.state == "live"
    assert result.target_kind == "proxy:zeppelinos"


def test_getter_latch_prefers_eth_call():
    version_selector = "0x" + keccak(text="getContractVersion()").hex()[:8]
    latch = {
        "kind": "storage",
        "variable": "getContractVersion",
        "slot": "0x" + "ab" * 32,
        "standard": "unstructured_slot_latch",
        "guard": {"operator": "eq", "constant": "0"},
        "getter_selector": version_selector,
    }
    rpc = FakeRpc(
        storage={(PROXY, EIP1967_IMPL_SLOT.lower()): _word(int(IMPL, 16))},
        calls={(PROXY, version_selector): _word(3)},  # version 3 → consumed
    )
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[latch], rpc=rpc)
    assert result.state == "consumed"


def test_annotate_capability_lands_latch_state_on_condition():
    from services.resolution.one_shot_probe import LatchReadResult

    cap_dict = {
        "kind": "conditional_universal",
        "conditions": [{"kind": "one_shot", "description": "init latch"}],
    }
    annotate_capability_one_shot(
        cap_dict,
        LatchReadResult("consumed", 1, "proxy:eip1967"),
        confirmed_candidate=False,
    )
    cond = cap_dict["conditions"][0]
    assert cond["latch_state"] == "consumed"
    assert cond["latch_target"] == "proxy:eip1967"


def test_annotate_confirmed_candidate_appends_one_shot_condition():
    from services.resolution.one_shot_probe import LatchReadResult

    cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "business", "description": "x"}]}
    annotate_capability_one_shot(
        cap_dict,
        LatchReadResult("live", 0, "proxy:eip1967"),
        confirmed_candidate=True,
    )
    kinds = [c["kind"] for c in cap_dict["conditions"]]
    assert "one_shot" in kinds
    one_shot = next(c for c in cap_dict["conditions"] if c["kind"] == "one_shot")
    assert one_shot["latch_state"] == "live"


def test_indeterminate_candidate_does_not_append_condition():
    """Only consumed/live promote a candidate."""
    from services.resolution.one_shot_probe import LatchReadResult

    cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "business", "description": "x"}]}
    annotate_capability_one_shot(
        cap_dict,
        LatchReadResult("indeterminate", 0, "unverified"),
        confirmed_candidate=True,
    )
    assert all(c["kind"] != "one_shot" for c in cap_dict["conditions"])


# The offline ``_stub_live_authority`` fixture no-ops the latch read wholesale, so it's monkeypatched here.


def _one_shot_tree(standard: bool = True) -> dict:
    leaf = {
        "kind": "equality",
        "operator": "truthy",
        "authority_role": "one_shot" if standard else "business",
        "operands": [{"source": "state_variable", "state_variable_name": "_initialized"}],
        "references_msg_sender": False,
        "expression": "init latch",
        "basis": [],
        "one_shot_latch": _v4_latch(),
    }
    if not standard:
        leaf["one_shot_candidate"] = True
    return {"op": "LEAF", "leaf": leaf}


def test_maybe_one_shot_probe_annotates_standard(monkeypatch):
    from services.resolution import capability_resolver as cr
    from services.resolution.one_shot_probe import LatchReadResult

    monkeypatch.setattr(cr, "_resolve_probe_block", lambda *a, **k: 123)
    monkeypatch.setattr(cr, "resolve_one_shot_state", lambda **kw: LatchReadResult("consumed", 1, "proxy:eip1967"))
    cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "one_shot", "description": "init"}]}
    cr.clear_one_shot_cache()
    cr._maybe_one_shot_probe(
        cap_dict,
        tree=_one_shot_tree(standard=True),
        runtime_addr=PROXY,
        rpc_url="x",
        chain_id=1,
        block=None,
        block_cell=[cr._UNRESOLVED_BLOCK],
        db_proxy_linked=True,
        pass_cache={},
    )
    cond = next(c for c in cap_dict["conditions"] if c["kind"] == "one_shot")
    assert cond["latch_state"] == "consumed" and cond["latch_target"] == "proxy:eip1967"


def test_maybe_one_shot_probe_uses_pass_cache(monkeypatch):
    from services.resolution import capability_resolver as cr
    from services.resolution.one_shot_probe import LatchReadResult

    calls = {"n": 0}

    def _count(**kw):
        calls["n"] += 1
        return LatchReadResult("consumed", 1, "db_linked_proxy")

    monkeypatch.setattr(cr, "_resolve_probe_block", lambda *a, **k: 123)
    monkeypatch.setattr(cr, "resolve_one_shot_state", _count)
    cr.clear_one_shot_cache()
    pass_cache: dict = {}
    block_cell = [cr._UNRESOLVED_BLOCK]
    for _ in range(3):
        cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "one_shot"}]}
        cr._maybe_one_shot_probe(
            cap_dict,
            tree=_one_shot_tree(),
            runtime_addr=PROXY,
            rpc_url="x",
            chain_id=1,
            block=None,
            block_cell=block_cell,
            db_proxy_linked=True,
            pass_cache=pass_cache,
        )
    assert calls["n"] == 1  # one wire read serves all three identical rows
