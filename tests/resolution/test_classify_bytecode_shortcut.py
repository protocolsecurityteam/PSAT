"""The shortcut skips the probes when the bytecode keccak matches a known impl; byte-exact, so no false positives.

The registry is empty by default.
"""

from __future__ import annotations

from services.resolution import tracking
from services.resolution.tracking import _classify_uncached, _classify_uncached_batched
from tests.support.isolation import _isolated_classify_cache  # noqa: F401  (fixture, registered by import)


def _stub_get_code(monkeypatch, code: str = "0x60806040"):
    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_kw: code)


def _stub_keccak(monkeypatch, keccak_hex: str):
    monkeypatch.setattr(
        "services.clients.rpc.get_code_with_keccak", lambda _rpc, _addr, chain_id=None: ("0x60", keccak_hex)
    )


def test_sequential_classifier_shortcut_fires_on_registry_hit(monkeypatch):
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


def test_registry_miss_falls_through_to_probes(monkeypatch):
    _stub_get_code(monkeypatch)
    _stub_keccak(monkeypatch, "0x" + "ff" * 32)  # not in registry

    fake_registry = {"0x" + "00" * 32: ("safe", {})}  # different keccak
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", fake_registry)
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *_a, **_kw: None)
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_kw: {})

    kind, _details, _had_error = _classify_uncached("https://rpc", "0x" + "44" * 20, "latest")
    assert kind == "contract"
