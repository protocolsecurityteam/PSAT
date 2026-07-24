"""A4 wire helper: read a plain contract's controlling address via canonical
owner getters (SCORING plan §4). Stubs the eth_call layer, never the transport."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution import tracking
from services.resolution.tracking import _PROBE_ERROR, read_contract_controller

OWNER = "0x" + "a" * 40
CONTRACT = "0x" + "1" * 40
ZERO = "0x" + "0" * 40


def _stub(monkeypatch, answers):
    """Map signature -> decoded return for _try_eth_call_decoded."""

    def _fake(rpc_url, address, signature, abi_type, block_tag="latest", *, chain_id=None):
        return answers.get(signature, None)

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", _fake)


def test_reads_owner_getter(monkeypatch):
    _stub(monkeypatch, {"owner()": OWNER})
    assert read_contract_controller("http://rpc", CONTRACT) == OWNER


def test_falls_through_to_authority(monkeypatch):
    _stub(monkeypatch, {"authority()": OWNER})
    assert read_contract_controller("http://rpc", CONTRACT) == OWNER


def test_zero_owner_is_none(monkeypatch):
    _stub(monkeypatch, {"owner()": ZERO})
    assert read_contract_controller("http://rpc", CONTRACT) is None


def test_no_getter_present_is_none(monkeypatch):
    _stub(monkeypatch, {})
    assert read_contract_controller("http://rpc", CONTRACT) is None


def test_probe_error_skips_to_next_getter(monkeypatch):
    def _fake(rpc_url, address, signature, abi_type, block_tag="latest", *, chain_id=None):
        if signature == "owner()":
            return _PROBE_ERROR
        if signature == "admin()":
            return OWNER
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", _fake)
    assert read_contract_controller("http://rpc", CONTRACT) == OWNER
