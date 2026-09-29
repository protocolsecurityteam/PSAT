"""Regression tests for the bytecode-keccak classifier shortcut in
``services.resolution.tracking``.

The shortcut skips the 6-probe sequence when the contract's bytecode keccak matches a
known canonical impl. Byte-exact, so no false positives, and every Safe singleton proxy
shares one code hash. ``_KNOWN_BYTECODE_IMPLS`` is empty by default; production seeds it.
"""

from __future__ import annotations

import pytest

from services.resolution import tracking
from services.resolution.tracking import _classify_uncached, _classify_uncached_batched


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    tracking.clear_classify_cache()
    yield
    tracking.clear_classify_cache()


def _stub_get_code(monkeypatch, code: str = "0x60806040"):
    """Stub _get_code at the tracking layer (not services.clients.rpc)."""
    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_kw: code)


def _stub_keccak(monkeypatch, keccak_hex: str):
    """Stub services.clients.rpc.get_code_with_keccak so the shortcut can read the keccak."""
    monkeypatch.setattr(
        "services.clients.rpc.get_code_with_keccak", lambda _rpc, _addr, chain_id=None: ("0x60", keccak_hex)
    )


def test_sequential_classifier_shortcut_fires_on_registry_hit(monkeypatch):
    """A registry hit returns kind + merged details without calling the probe sequence."""
    _stub_get_code(monkeypatch)
    _stub_keccak(monkeypatch, "0x" + "ab" * 32)

    fake_registry = {"0x" + "ab" * 32: ("safe", {"owners": ["0xowner"], "threshold": 1})}
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", fake_registry)

    def _no_probes(*_a, **_kw):
        raise AssertionError("probe sequence must not run when shortcut fires")

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", _no_probes)

    addr = "0x" + "11" * 20
    kind, details, had_error = _classify_uncached("https://rpc", addr, "latest")
    assert kind == "safe"
    assert details["address"] == addr
    assert details["owners"] == ["0xowner"]
    assert details["threshold"] == 1
    assert had_error is False


def test_batched_classifier_shortcut_fires_on_registry_hit(monkeypatch):
    """Same shortcut on the batched path, independent of the env flag."""
    _stub_get_code(monkeypatch)
    _stub_keccak(monkeypatch, "0x" + "cd" * 32)

    fake_registry = {"0x" + "cd" * 32: ("timelock", {"delay": 600})}
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", fake_registry)

    def _no_batch(*_a, **_kw):
        raise AssertionError("batch probe must not run when shortcut fires")

    monkeypatch.setattr(tracking, "_batch_probe", _no_batch)

    addr = "0x" + "22" * 20
    kind, details, had_error = _classify_uncached_batched("https://rpc", addr, "latest")
    assert kind == "timelock"
    assert details["delay"] == 600
    assert details["address"] == addr
    assert had_error is False


def test_empty_registry_skips_shortcut(monkeypatch):
    """The shortcut is gated by ``if _KNOWN_BYTECODE_IMPLS:``; an empty registry must not
    even call get_code_with_keccak."""
    _stub_get_code(monkeypatch)

    keccak_calls = []

    def _track_keccak(_rpc, _addr):
        keccak_calls.append(_addr)
        return ("0x60", "0x" + "ee" * 32)

    monkeypatch.setattr("services.clients.rpc.get_code_with_keccak", _track_keccak)
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", {})

    # Every probe returns None so the classifier reaches the generic fallthrough.
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *_a, **_kw: None)
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_kw: {})

    _classify_uncached("https://rpc", "0x" + "33" * 20, "latest")
    assert keccak_calls == [], "empty registry must not call get_code_with_keccak"


def test_registry_miss_falls_through_to_probes(monkeypatch):
    """Registry has entries but THIS contract's keccak isn't in it →
    fall through to the normal probe sequence."""
    _stub_get_code(monkeypatch)
    _stub_keccak(monkeypatch, "0x" + "ff" * 32)  # not in registry

    fake_registry = {"0x" + "00" * 32: ("safe", {})}  # different keccak
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", fake_registry)
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *_a, **_kw: None)
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_kw: {})

    kind, _details, _had_error = _classify_uncached("https://rpc", "0x" + "44" * 20, "latest")
    assert kind == "contract"


def test_keccak_fetch_failure_falls_through(monkeypatch):
    """A transient get_code_with_keccak failure falls through to the probe sequence."""
    _stub_get_code(monkeypatch)

    def _boom(_rpc, _addr):
        raise RuntimeError("RPC down")

    monkeypatch.setattr("services.clients.rpc.get_code_with_keccak", _boom)
    fake_registry = {"0x" + "ff" * 32: ("safe", {})}
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", fake_registry)
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *_a, **_kw: None)
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_kw: {})

    kind, _details, _had_error = _classify_uncached("https://rpc", "0x" + "55" * 20, "latest")
    assert kind == "contract", "keccak fetch failure must not crash; must fall through"


def test_partial_details_merged_with_address(monkeypatch):
    """The registry stores partial details; the classifier adds the address. The merge must
    not drop fields."""
    _stub_get_code(monkeypatch)
    _stub_keccak(monkeypatch, "0x" + "77" * 32)
    fake_registry = {
        "0x" + "77" * 32: (
            "proxy_admin",
            {"upgrade_interface_version": "5.0.0", "owner": "0xdeadbeef"},
        )
    }
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", fake_registry)
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *_a, **_kw: None)

    addr = "0x" + "88" * 20
    _kind, details, _had_error = _classify_uncached("https://rpc", addr, "latest")
    assert details["address"] == addr
    assert details["upgrade_interface_version"] == "5.0.0"
    assert details["owner"] == "0xdeadbeef"
