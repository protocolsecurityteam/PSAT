"""C1: the Safe module/guard probe.

One of 19 corpus Safes has an enabled module, contrary to an earlier "modules empty" claim. The head word can prove the
list empty but never enumerate it, so a non-sentinel head is ``not_determined`` and an upper bound.
"""

from __future__ import annotations

from typing import cast

import pytest

from services.resolution import tracking
from services.resolution.tracking import (
    _classify_uncached,
    _classify_uncached_batched,
    _resolve_pinned_block,
)
from tests.support.isolation import _isolated_classify_cache  # noqa: F401  (fixture, registered by import)


def _protection(details: dict) -> dict:
    return cast(dict, details["safe_protection"])


PROBE_BLOCK = 25643300

MODULE_FREE_SAFE = "0x427989bb12f4a390d11e7647d467dea02b9d2ee3"  # VERSION() 1.4.1
MODULE_BEARING_SAFE = "0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca"  # VERSION() 1.1.1

SENTINEL_WORD = "0x" + "0" * 63 + "1"
ZERO_WORD = "0x" + "0" * 64
MODULE_BEARING_HEAD_WORD = "0x0000000000000000000000002e1b5a40edc922bce489668b11749b8eabd67f6b"
ENABLED_MODULE = "0x2e1b5a40edc922bce489668b11749b8eabd67f6b"

OWNER = "0x" + "11" * 20


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
    """Both classify paths route through the same three helpers."""
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
    """Head == sentinel is the only thing that earns ``module_set: []``."""
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
    """The head word proves a module exists, never how many; 1.1.1 has no guard feature."""
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


def test_unknown_version_leaves_guard_not_determined(monkeypatch):
    """A version whose source was never read can't tell "no guard" from "no guard feature"."""
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
    """An unwritten entry is not a terminated list."""
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
    calls = _wire(monkeypatch, version="1.4.1", head_word=SENTINEL_WORD, guard_word=ZERO_WORD)
    _classify_uncached_batched("https://rpc", MODULE_FREE_SAFE, "latest")
    protection_reads = [
        c for c in calls if c[0] in (tracking._SAFE_MODULES_HEAD_SLOT, tracking._SAFE_GUARD_SLOT, "VERSION()")
    ]
    assert len(protection_reads) == 3
    assert {block for _target, block in protection_reads} == {hex(PROBE_BLOCK)}


def test_non_safe_addresses_carry_no_protection_keys(monkeypatch):

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


def test_resolve_pinned_block_uses_an_explicit_quantity_tag(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("must not read head when the tag is already a height")

    monkeypatch.setattr(tracking, "_current_block_number", _boom)
    assert _resolve_pinned_block("https://rpc", hex(PROBE_BLOCK)) == PROBE_BLOCK


# A non-32-byte answer is not an observation of storage. A left-pad-then-check decoder would turn ``"0x"`` into "no
# guard" and ``"0x1"`` into the modules sentinel.

_ALL_NOT_DETERMINED = {
    "modules_head": "not_determined",
    "module_set": "not_determined",
    "module_set_basis": "not_determined",
    "protection_is_upper_bound": "not_determined",
    "guard": "not_determined",
}


def _malformed(monkeypatch, word: str) -> dict:
    tracking.clear_classify_cache()
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.4.1",
        head_word=word,
        guard_word=word,
    )
    return _protection(details)


def test_empty_storage_return_is_not_a_zero_word(monkeypatch):
    protection = _malformed(monkeypatch, "0x")
    assert protection["guard"] == "not_determined"
    assert protection["guard"] != "proven_zero"
    assert "guard_address" not in protection
    for key, value in _ALL_NOT_DETERMINED.items():
        assert protection[key] == value


def test_one_nibble_return_does_not_pad_into_the_modules_sentinel(monkeypatch):
    protection = _malformed(monkeypatch, "0x1")
    assert protection["module_set"] == "not_determined"
    assert protection["module_set"] != []
    assert protection["module_set_basis"] != "storage_linked_list_terminated"
    for key, value in _ALL_NOT_DETERMINED.items():
        assert protection[key] == value


@pytest.mark.parametrize(
    "word",
    [
        # ``bytes.fromhex`` ignores whitespace.
        pytest.param("0x" + " " * 64, id="whitespace_body"),
        # The shape a bare length check lets through.
        pytest.param("0x" + "0" * 62 + "1" + "\n", id="short_body_trailing_newline"),
        pytest.param("0x" + "0" * 61 + "1" + "  ", id="short_body_trailing_spaces"),
        # ``int()`` accepts separators, which is why this decoder avoids it.
        pytest.param("0x" + "1_" + "0" * 62, id="underscore_body"),
    ],
)
def test_malformed_word_body_is_rejected(monkeypatch, word):
    protection = _malformed(monkeypatch, word)
    for key, value in _ALL_NOT_DETERMINED.items():
        assert protection[key] == value


def test_uppercase_hex_digits_still_decode(monkeypatch):
    guard_addr = "0x" + "ab" * 20
    _, details, _ = _both_paths(
        monkeypatch,
        MODULE_FREE_SAFE,
        version="1.4.1",
        head_word=SENTINEL_WORD,
        guard_word="0x" + "0" * 24 + "AB" * 20,
    )
    protection = _protection(details)
    assert protection["guard"] == "proven_address"
    assert protection["guard_address"] == guard_addr
