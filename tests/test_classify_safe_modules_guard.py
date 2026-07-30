"""C1: the Safe module/guard protection probe on the resolution classifier.

Two storage words plus ``VERSION()``, fired after an address classifies as a
Safe. The register previously published "modules empty on all 9 Safes, so k/n is
exact"; there are 19 Safe principals and one of them
(``0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca``) has an enabled module, so k/n is
an upper bound on its protection.

Every pinned word below was re-read at block 25643300 through ``utils.rpc``
(eRPC) while writing these tests; both scenarios are real Safes from the
``function_principals.resolved_type='safe'`` set.

The load-bearing negative: the head word can prove the module list EMPTY (head ==
sentinel) but can never enumerate it. A non-sentinel head is published as
``module_set: not_determined`` + ``protection_is_upper_bound: true``, NOT as a
one-element list — a two-module Safe would otherwise be published as having one.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

import pytest
from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution import tracking  # noqa: E402
from services.resolution.tracking import (  # noqa: E402
    _classify_uncached,
    _classify_uncached_batched,
    _resolve_pinned_block,
)


def _protection(details: dict) -> dict:
    """The nested protection witness, typed for the checker."""
    return cast(dict, details["safe_protection"])


PROBE_BLOCK = 25643300

# Real addresses, pinned at PROBE_BLOCK.
MODULE_FREE_SAFE = "0x427989bb12f4a390d11e7647d467dea02b9d2ee3"  # VERSION() 1.4.1
MODULE_BEARING_SAFE = "0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca"  # VERSION() 1.1.1

SENTINEL_WORD = "0x" + "0" * 63 + "1"
ZERO_WORD = "0x" + "0" * 64
# The real word read at modules[SENTINEL] on MODULE_BEARING_SAFE.
MODULE_BEARING_HEAD_WORD = "0x0000000000000000000000002e1b5a40edc922bce489668b11749b8eabd67f6b"
ENABLED_MODULE = "0x2e1b5a40edc922bce489668b11749b8eabd67f6b"

OWNER = "0x" + "11" * 20


def test_slot_preimages_recomputed():
    """The two probed slots equal the keccak of the preimages the deployed Safe
    singletons carry; recomputed here rather than copied from the module."""
    modules_head = "0x" + keccak((1).to_bytes(32, "big") + (1).to_bytes(32, "big")).hex()
    guard = "0x" + keccak(text="guard_manager.guard.address").hex()
    module_guard = "0x" + keccak(text="module_manager.module_guard.address").hex()

    assert modules_head == "0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f"
    assert guard == "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
    assert module_guard == "0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947"

    assert tracking._SAFE_MODULES_HEAD_SLOT == modules_head
    assert tracking._SAFE_GUARD_SLOT == guard
    # module_manager.module_guard.address exists only from Safe 1.5.0 and reads
    # zero on all 19 corpus Safes, which is "feature absent", not "no guard".
    # Nothing is published about it, so it is not probed.
    assert module_guard not in (tracking._SAFE_MODULES_HEAD_SLOT, tracking._SAFE_GUARD_SLOT)


def _abi_encode_address_array(addrs: list[str]) -> str:
    body = format(32, "064x") + format(len(addrs), "064x")
    for a in addrs:
        body += a.lower().replace("0x", "").rjust(64, "0")
    return "0x" + body


def _abi_encode_uint256(n: int) -> str:
    return "0x" + format(n, "064x")


def _abi_encode_string(s: str) -> str:
    raw = s.encode("utf-8")
    pad = (32 - (len(raw) % 32)) % 32
    return "0x" + format(32, "064x") + format(len(raw), "064x") + raw.hex() + ("00" * pad)


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    tracking.clear_classify_cache()
    yield
    tracking.clear_classify_cache()


def _wire(
    monkeypatch,
    *,
    version: str | None,
    head_word: str | None,
    guard_word: str | None,
    threshold: int = 4,
    storage_raises: bool = False,
    pinned_block: int | None = PROBE_BLOCK,
):
    """Stub the classifier's wire. Both the batched and sequential paths route
    through ``_eth_call_raw`` / ``_rpc_batch_request_with_status`` /
    ``_get_storage_at``, so one wiring drives both."""
    calls: list[tuple[str, str]] = []

    responses = {
        "getOwners()": _abi_encode_address_array([OWNER]),
        "getThreshold()": _abi_encode_uint256(threshold),
    }
    if version is not None:
        responses["VERSION()"] = _abi_encode_string(version)

    def _fake_eth_call_raw(_rpc_url, addr, signature, block, chain_id=None):
        calls.append((signature, block))
        return responses.get(signature, "0x")

    def _fake_batch(_rpc_url, batch_calls, chain_id=None):
        return [(responses.get(sig, "0x"), False) for sig, _abi in tracking._CLASSIFY_PROBE_SIGS]

    words = {
        tracking._SAFE_MODULES_HEAD_SLOT: head_word,
        tracking._SAFE_GUARD_SLOT: guard_word,
    }

    def _fake_get_storage_at(_rpc_url, addr, slot, block, chain_id=None):
        calls.append((slot, block))
        if storage_raises:
            raise RuntimeError("eth_getStorageAt failed")
        word = words.get(slot, ZERO_WORD)
        if word is None:
            raise RuntimeError("eth_getStorageAt failed")
        return word

    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_k: "0x60")
    monkeypatch.setattr(tracking, "_eth_call_raw", _fake_eth_call_raw)
    monkeypatch.setattr(tracking, "_rpc_batch_request_with_status", _fake_batch)
    monkeypatch.setattr(tracking, "_get_storage_at", _fake_get_storage_at)
    monkeypatch.setattr(tracking, "_resolve_pinned_block", lambda *_a, **_k: pinned_block)
    return calls


def _both_paths(monkeypatch, address, **kwargs):
    _wire(monkeypatch, **kwargs)
    seq = _classify_uncached("https://rpc", address, "latest")
    tracking.clear_classify_cache()
    _wire(monkeypatch, **kwargs)
    batch = _classify_uncached_batched("https://rpc", address, "latest")
    assert seq == batch, "batched and sequential classify must agree byte-for-byte"
    return seq


def test_module_free_safe_141_publishes_proven_empty(monkeypatch):
    """Head == sentinel is the ONLY thing that earns ``module_set: []``, and it
    carries its basis and the block it was true at."""
    kind, details, _cacheable = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.4.1",
        head_word=SENTINEL_WORD,
        guard_word=ZERO_WORD,
    )
    assert kind == "safe"
    assert details == {
        "address": MODULE_FREE_SAFE,
        "owners": [OWNER],
        "threshold": 4,
        "safe_protection": {
            "probe_block": PROBE_BLOCK,
            "safe_version": "1.4.1",
            "modules_head": SENTINEL_WORD,
            "module_set": [],
            "module_set_basis": "storage_linked_list_terminated",
            "protection_is_upper_bound": "not_determined",
            "guard": "proven_zero",
        },
    }


def test_module_bearing_safe_111_publishes_upper_bound_not_a_list(monkeypatch):
    """The real 1.1.1 Safe. ``module_set`` stays not_determined — the head word
    proves a module EXISTS, never how many — and the guard slot's zero is
    ``feature_absent`` because 1.1.1 has no guard, not ``proven_zero``."""
    kind, details, _cacheable = _both_paths(
        monkeypatch,
        MODULE_BEARING_SAFE,
        version="1.1.1",
        head_word=MODULE_BEARING_HEAD_WORD,
        guard_word=ZERO_WORD,
    )
    assert kind == "safe"
    assert details == {
        "address": MODULE_BEARING_SAFE,
        "owners": [OWNER],
        "threshold": 4,
        "safe_protection": {
            "probe_block": PROBE_BLOCK,
            "safe_version": "1.1.1",
            "modules_head": MODULE_BEARING_HEAD_WORD,
            "modules_head_address": ENABLED_MODULE,
            "module_set": "not_determined",
            "module_set_basis": "not_determined",
            "protection_is_upper_bound": True,
            "guard": "feature_absent",
        },
    }
    # The refuted over-claim, pinned: no enumerated list anywhere in the payload.
    assert _protection(details)["module_set"] != [ENABLED_MODULE]
    assert "modules" not in _protection(details)


def test_guard_set_on_141_is_proven_address(monkeypatch):
    guard_addr = "0x" + "ab" * 20
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.4.1",
        head_word=SENTINEL_WORD,
        guard_word="0x" + "0" * 24 + "ab" * 20,
    )
    protection = _protection(details)
    assert protection["guard"] == "proven_address"
    assert protection["guard_address"] == guard_addr


def test_guard_zero_on_130_is_proven_zero(monkeypatch):
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.3.0",
        head_word=SENTINEL_WORD,
        guard_word=ZERO_WORD,
    )
    assert _protection(details)["guard"] == "proven_zero"


# --- fail-closed arms ------------------------------------------------------


def test_unknown_version_leaves_guard_not_determined(monkeypatch):
    """A version whose deployed source was never read cannot tell a zero word's
    "no guard set" from "no guard feature". Includes the 1.3.0 variant suffix."""
    for version in ("1.3.0+L2", "1.5.0", "9.9.9"):
        tracking.clear_classify_cache()
        _, details, _ = _both_paths(
            monkeypatch,
            MODULE_FREE_SAFE,
            version=version,
            head_word=SENTINEL_WORD,
            guard_word=ZERO_WORD,
        )
        protection = _protection(details)
        assert protection["safe_version"] == version
        assert protection["guard"] == "not_determined"
        # The module determination is version-independent and still lands.
        assert protection["module_set"] == []


def test_absent_version_leaves_guard_not_determined(monkeypatch):
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version=None,
        head_word=SENTINEL_WORD,
        guard_word=ZERO_WORD,
    )
    protection = _protection(details)
    assert protection["safe_version"] == "not_determined"
    assert protection["guard"] == "not_determined"


def test_nonzero_guard_word_on_a_guardless_version_is_not_determined(monkeypatch):
    """1.1.1 has no guard feature, so a nonzero word at that slot is
    unexplained — neither ``feature_absent`` nor ``proven_address``."""
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_BEARING_SAFE,
        version="1.1.1",
        head_word=SENTINEL_WORD,
        guard_word="0x" + "0" * 24 + "ab" * 20,
    )
    protection = _protection(details)
    assert protection["guard"] == "not_determined"
    assert "guard_address" not in protection


def test_storage_read_failure_yields_not_determined_never_empty(monkeypatch):
    """A failed read is the exact shape the fail-open series closed: it must not
    read as "no modules" or "no guard"."""
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.4.1",
        head_word=None,
        guard_word=None,
        storage_raises=True,
    )
    assert _protection(details) == {
        "probe_block": PROBE_BLOCK,
        "safe_version": "1.4.1",
        "modules_head": "not_determined",
        "module_set": "not_determined",
        "module_set_basis": "not_determined",
        "protection_is_upper_bound": "not_determined",
        "guard": "not_determined",
    }


def test_zero_head_word_is_not_an_empty_module_set(monkeypatch):
    """An unwritten ``modules[SENTINEL]`` entry (Safe never set up) is not a
    terminated list. Absence of the sentinel is not proof of emptiness."""
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.4.1",
        head_word=ZERO_WORD,
        guard_word=ZERO_WORD,
    )
    protection = _protection(details)
    assert protection["module_set"] == "not_determined"
    assert protection["module_set_basis"] == "not_determined"
    assert protection["protection_is_upper_bound"] == "not_determined"


def test_head_word_that_is_not_an_address_is_not_determined(monkeypatch):
    """Top 12 bytes set ⇒ the word is not a left-padded address ⇒ nothing about
    the list is established."""
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.4.1",
        head_word="0x" + "ff" * 32,
        guard_word=ZERO_WORD,
    )
    protection = _protection(details)
    assert protection["modules_head"] == "0x" + "ff" * 32
    assert protection["module_set"] == "not_determined"
    assert protection["protection_is_upper_bound"] == "not_determined"


def test_unresolvable_block_suppresses_the_probe_entirely(monkeypatch):
    """No pinned height ⇒ a now-fact with no block ⇒ nothing published, and no
    storage read is even issued."""
    calls = _wire(
        monkeypatch,
        version="1.4.1",
        head_word=SENTINEL_WORD,
        guard_word=ZERO_WORD,
        pinned_block=None,
    )
    _kind, details, _ = _classify_uncached_batched("https://rpc", MODULE_FREE_SAFE, "latest")
    assert _protection(details) == {
        "probe_block": "not_determined",
        "safe_version": "not_determined",
        "modules_head": "not_determined",
        "module_set": "not_determined",
        "module_set_basis": "not_determined",
        "protection_is_upper_bound": "not_determined",
        "guard": "not_determined",
    }
    assert tracking._SAFE_MODULES_HEAD_SLOT not in [c[0] for c in calls]
    assert "VERSION()" not in [c[0] for c in calls]


def test_probe_reads_are_pinned_to_the_resolved_height(monkeypatch):
    """Not ``latest``: every protection read carries the same explicit height
    that is published as ``probe_block``."""
    calls = _wire(monkeypatch, version="1.4.1", head_word=SENTINEL_WORD, guard_word=ZERO_WORD)
    _classify_uncached_batched("https://rpc", MODULE_FREE_SAFE, "latest")
    protection_reads = [
        c for c in calls if c[0] in (tracking._SAFE_MODULES_HEAD_SLOT, tracking._SAFE_GUARD_SLOT, "VERSION()")
    ]
    assert len(protection_reads) == 3
    assert {block for _target, block in protection_reads} == {hex(PROBE_BLOCK)}


def test_non_safe_addresses_carry_no_protection_keys(monkeypatch):
    """The classifier must not attach Safe fields to a timelock or a plain
    contract."""

    def _fake_eth_call_raw(_rpc_url, _addr, signature, _block, chain_id=None):
        if signature == "getMinDelay()":
            return _abi_encode_uint256(172800)
        return "0x"

    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_k: "0x60")
    monkeypatch.setattr(tracking, "_eth_call_raw", _fake_eth_call_raw)
    monkeypatch.setattr(
        tracking,
        "_rpc_batch_request_with_status",
        lambda _u, _c, chain_id=None: [
            (_abi_encode_uint256(172800) if sig == "getMinDelay()" else "0x", False)
            for sig, _abi in tracking._CLASSIFY_PROBE_SIGS
        ],
    )
    monkeypatch.setattr(tracking, "_get_storage_at", lambda *_a, **_k: ZERO_WORD)
    monkeypatch.setattr(tracking, "_resolve_pinned_block", lambda *_a, **_k: PROBE_BLOCK)

    kind, details, _ = _classify_uncached_batched("https://rpc", "0x" + "cd" * 20, "latest")
    assert kind == "timelock"
    assert "safe_protection" not in details


# --- block resolution ------------------------------------------------------


def test_resolve_pinned_block_uses_an_explicit_quantity_tag(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("must not read head when the tag is already a height")

    monkeypatch.setattr(tracking, "_current_block_number", _boom)
    assert _resolve_pinned_block("https://rpc", hex(PROBE_BLOCK)) == PROBE_BLOCK


def test_resolve_pinned_block_resolves_a_moving_alias(monkeypatch):
    monkeypatch.setattr(tracking, "_current_block_number", lambda *_a, **_k: PROBE_BLOCK)
    assert _resolve_pinned_block("https://rpc", "latest") == PROBE_BLOCK
    assert _resolve_pinned_block("https://rpc", "finalized") == PROBE_BLOCK


def test_resolve_pinned_block_returns_none_on_head_read_failure(monkeypatch):
    def _boom(*_a, **_k):
        raise RuntimeError("head read failed")

    monkeypatch.setattr(tracking, "_current_block_number", _boom)
    assert _resolve_pinned_block("https://rpc", "latest") is None


def test_resolve_pinned_block_rejects_an_unrecognised_tag(monkeypatch):
    monkeypatch.setattr(tracking, "_current_block_number", lambda *_a, **_k: PROBE_BLOCK)
    assert _resolve_pinned_block("https://rpc", "0xnothex") is None
    assert _resolve_pinned_block("https://rpc", "") is None
