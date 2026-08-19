"""Regression tests for the bytecode-keccak classifier shortcut in
``services.resolution.tracking``.

Phase B Step 3. The shortcut skips the 6-probe sequence (Safe / Timelock
/ ProxyAdmin / generic) when the contract's bytecode keccak matches a
known canonical impl. The registry ``_KNOWN_BYTECODE_IMPLS`` is empty
by default; production seeds it with manually-fetched mainnet keccaks
for impls like Gnosis Safe singletons + OZ TimelockController + OZ
ProxyAdmin.

Why bytecode keccak is the right key:
- It's a byte-exact match — false positives are impossible
- Two different addresses with the same impl bytecode share the same
  classification (every Safe singleton across DeFi uses the same code
  at different proxy addresses)
- We already have the keccak cheaply via utils.rpc.get_code_with_keccak
  (commit 00b1034)

Tests:
1. Empty registry → no shortcut, falls through to probe sequence.
2. Registry hit → kind + details returned without issuing any probes.
3. Registry miss (different keccak) → falls through to probe sequence.
4. get_code_with_keccak failure → falls through gracefully (no crash).
5. Both classifier paths (sequential + batched) honour the shortcut.
6. Returned details include both registry partial AND the address.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution import tracking
from services.resolution.tracking import _classify_uncached, _classify_uncached_batched


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    tracking.clear_classify_cache()
    yield
    tracking.clear_classify_cache()


def _stub_get_code(monkeypatch, code: str = "0x60806040"):
    """Stub _get_code at the tracking layer (not utils.rpc)."""
    monkeypatch.setattr(tracking, "_get_code", lambda *_a, **_kw: code)


def _stub_keccak(monkeypatch, keccak_hex: str):
    """Stub utils.rpc.get_code_with_keccak so the shortcut can read the keccak."""
    monkeypatch.setattr("utils.rpc.get_code_with_keccak", lambda _rpc, _addr, chain_id=None: ("0x60", keccak_hex))


def test_sequential_classifier_shortcut_fires_on_registry_hit(monkeypatch):
    """When the bytecode keccak matches a registry entry, classify
    returns the registered kind + merged details without ever calling
    the probe sequence (would have raised AssertionError)."""
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
    """Same shortcut applies to the batched classifier path so the env
    flag setting doesn't change registry-shortcut behavior."""
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
    """The shortcut block is gated by `if _KNOWN_BYTECODE_IMPLS:` —
    an empty registry must not even call get_code_with_keccak. This
    keeps the no-op default truly free."""
    _stub_get_code(monkeypatch)

    keccak_calls = []

    def _track_keccak(_rpc, _addr):
        keccak_calls.append(_addr)
        return ("0x60", "0x" + "ee" * 32)

    monkeypatch.setattr("utils.rpc.get_code_with_keccak", _track_keccak)
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", {})

    # Make every probe return None so the classifier reaches the
    # generic 'contract' fallthrough cleanly.
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
    # Falls through, all probes return None → 'contract'.
    assert kind == "contract"


def test_keccak_fetch_failure_falls_through(monkeypatch):
    """If get_code_with_keccak raises (transient RPC), we shouldn't
    crash — fall through to the probe sequence and let it handle the
    error path the same way it always has."""
    _stub_get_code(monkeypatch)

    def _boom(_rpc, _addr):
        raise RuntimeError("RPC down")

    monkeypatch.setattr("utils.rpc.get_code_with_keccak", _boom)
    fake_registry = {"0x" + "ff" * 32: ("safe", {})}
    monkeypatch.setattr(tracking, "_KNOWN_BYTECODE_IMPLS", fake_registry)
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *_a, **_kw: None)
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *_a, **_kw: {})

    kind, _details, _had_error = _classify_uncached("https://rpc", "0x" + "55" * 20, "latest")
    assert kind == "contract", "keccak fetch failure must not crash; must fall through"


def test_partial_details_merged_with_address(monkeypatch):
    """The registry stores partial details (kind-specific fields) but
    the address is added by the classifier. Verify the merge doesn't
    drop any fields."""
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
