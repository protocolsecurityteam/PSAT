"""Unit tests for the on-chain one-shot consumed/live resolver.

Stubs only the RPC wire (a fake ``rpc`` callable returning canned
``eth_getStorageAt`` / ``eth_call`` responses), driving the real
``resolve_one_shot_state`` decode + proxy-confirmation logic. The #1
invariant under test: a ``live`` verdict is earned ONLY from a confirmed
proxy with an armed latch — a bare implementation/template with an empty
latch returns ``indeterminate``, never ``live`` (the false-open this branch
exists to kill).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_utils.crypto import keccak  # noqa: E402

from services.resolution.one_shot_probe import (  # noqa: E402
    EIP1967_IMPL_SLOT,
    annotate_capability_one_shot,
    resolve_one_shot_state,
)
from tests.support.rpc_stubs import FakeRpc, _word  # noqa: E402

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
    """The mis-stamp shape persisted artifacts can carry: a latch on the
    transient ``_initializing`` member (byte 8 of the namespaced word)."""
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
    """The hardcoded OZ v5 namespaced slot equals the ERC-7201 derivation, so
    the resolver reads the right word on a real v5 proxy."""
    inner = int.from_bytes(keccak(text="openzeppelin.storage.Initializable"), "big") - 1
    derived = int.from_bytes(keccak(inner.to_bytes(32, "big")), "big") & ~0xFF
    assert "0x" + format(derived, "064x") == "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"


def test_consumed_on_proxy_with_set_latch():
    """EIP-1967 proxy, latch = 1 (>= expected): consumed."""
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
    """EIP-1967 proxy, latch = 0 (< expected) on a CONFIRMED proxy: live."""
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
    """THE regression guard: an unconfirmed address (empty EIP-1967, no proxy
    marker) with latch = 0 reads exactly like a live proxy would, so it must
    return indeterminate — never live."""
    rpc = FakeRpc(storage={(IMPL, _ZERO): _word(0)})  # everything else zero → no proxy
    result = resolve_one_shot_state(rpc_url="x", address=IMPL, latches=[_v4_latch()], rpc=rpc)
    assert result.state == "indeterminate"
    assert result.target_kind == "unverified"


def test_disable_initializers_sentinel_is_consumed_even_unconfirmed():
    """A locked implementation (``_initialized = 255``) is consumed regardless
    of proxy confirmation — the sentinel is unambiguous."""
    rpc = FakeRpc(storage={(IMPL, _ZERO): _word(0xFF)})
    result = resolve_one_shot_state(rpc_url="x", address=IMPL, latches=[_v4_latch()], rpc=rpc)
    assert result.state == "consumed"


def test_db_linked_proxy_skips_detection_and_reads_live():
    """When the pipeline already linked a proxy→impl job, the address IS a
    proxy; an unset latch reads live without an on-chain proxy probe."""
    rpc = FakeRpc(storage={(PROXY, _ZERO): _word(0)})
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[_v4_latch()], db_proxy_linked=True, rpc=rpc)
    assert result.state == "live"
    assert result.target_kind == "db_linked_proxy"
    # No EIP-1967 probe should have run.
    assert not any(slot == EIP1967_IMPL_SLOT.lower() for _, _, slot in rpc.log if _ == "storage")


def test_initialized_v5_proxy_with_transient_latch_first_is_consumed():
    """THE OZ-v5 regression guard: on an initialized v5 proxy the namespaced
    word holds version >= 1 at byte 0 while the at-rest transient flag reads
    0 at byte 8. Even when a (historically persisted) transient-flag latch is
    collected FIRST, the verdict must come from the version member — consumed,
    never live."""
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
    """A tree whose only latch payload targets the transient flag must abstain
    even on a confirmed proxy: the flag reads 0 on consumed and live
    deployments alike, so no verdict can be earned from it."""
    rpc = FakeRpc(storage={(PROXY, ERC7201_SLOT): _word(2)})
    result = resolve_one_shot_state(
        rpc_url="x", address=PROXY, latches=[_v5_transient_latch()], db_proxy_linked=True, rpc=rpc
    )
    assert result.state == "indeterminate"
    assert result.transcript.get("reason") == "no_decisive_latch"


def test_uninitialized_v5_proxy_still_reads_live():
    """The transient filter must not weaken the real-live path: a confirmed v5
    proxy whose namespaced word is fully zero (version 0) is genuinely live."""
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
    """The packed v4 layout's ``_initializing`` bool (reachable through an
    ``onlyInitializing``-only chain) is equally undecidable at rest — a latch
    naming it must never decide consumed/live."""
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
    """The static pass tags its latches ``role="version"``; the resolver must
    read those before untagged legacy payloads, so a re-analyzed artifact's
    authoritative anchor always wins regardless of collection order. Here the
    legacy slot-0 word reads 0 (would be live) while the tagged v5 anchor
    reads version 2 — the verdict must be the anchor's."""
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
    """A slot-only payload (no byte range, no guard — the namespaced-constant
    fallback shape) can never decide, so it must not be read first and mask a
    decisive latch behind an ``unknown`` classification."""
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
    """USDC/cbETH family: EIP-1967 impl slot empty, legacy zeppelinos slot set."""
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
    """A getter-backed latch (Lido ``getContractVersion()``) reads the version
    via eth_call; nonzero version on a confirmed proxy = consumed."""
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


def test_no_latch_location_is_indeterminate():
    rpc = FakeRpc()
    result = resolve_one_shot_state(rpc_url="x", address=PROXY, latches=[], rpc=rpc)
    assert result.state == "indeterminate"
    assert result.transcript.get("reason") == "no_latch_location"


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
    """An unconfirmed structural candidate must NOT manufacture a one_shot
    badge — only consumed/live promote it."""
    from services.resolution.one_shot_probe import LatchReadResult

    cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "business", "description": "x"}]}
    annotate_capability_one_shot(
        cap_dict,
        LatchReadResult("indeterminate", 0, "unverified"),
        confirmed_candidate=True,
    )
    assert all(c["kind"] != "one_shot" for c in cap_dict["conditions"])


# ---------------------------------------------------------------------------
# Resolver wiring (`_maybe_one_shot_probe`) — exercised here with the latch
# read monkeypatched, so the cache/annotation glue is covered without a wire
# (the offline `_stub_live_authority` fixture no-ops this function wholesale).
# ---------------------------------------------------------------------------


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


def test_maybe_one_shot_probe_skips_non_one_shot(monkeypatch):
    from services.resolution import capability_resolver as cr

    called = {"n": 0}

    def _boom(**kw):
        called["n"] += 1
        raise AssertionError("must not probe a non-one-shot row")

    monkeypatch.setattr(cr, "resolve_one_shot_state", _boom)
    cap_dict = {"kind": "finite_set", "members": []}
    plain_tree = {
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
    cr._maybe_one_shot_probe(
        cap_dict,
        tree=plain_tree,
        runtime_addr=PROXY,
        rpc_url="x",
        chain_id=1,
        block=None,
        block_cell=[cr._UNRESOLVED_BLOCK],
        db_proxy_linked=False,
        pass_cache={},
    )
    assert called["n"] == 0


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
