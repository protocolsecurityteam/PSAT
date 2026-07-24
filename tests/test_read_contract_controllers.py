"""A4 wire helper: read a plain contract's controlling addresses via canonical
control getters (SCORING plan §4). Probes owner()/authority()/admin() every call
and returns the DISTINCT nonzero set so the walk can fail closed on parallel
control planes. Stubs the eth_call layer, never the transport."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution import tracking
from services.resolution.tracking import _PROBE_ERROR, read_contract_controllers

OWNER = "0x" + "a" * 40
AUTHORITY = "0x" + "b" * 40
CONTRACT = "0x" + "1" * 40
ZERO = "0x" + "0" * 40


def _stub(monkeypatch, answers):
    """Map signature -> decoded return for _try_eth_call_decoded."""

    def _fake(rpc_url, address, signature, abi_type, block_tag="latest", *, chain_id=None):
        return answers.get(signature, None)

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", _fake)


def test_reads_owner_getter(monkeypatch):
    _stub(monkeypatch, {"owner()": OWNER})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]


def test_reads_authority_when_owner_absent(monkeypatch):
    _stub(monkeypatch, {"authority()": AUTHORITY})
    assert read_contract_controllers("http://rpc", CONTRACT) == [AUTHORITY]


def test_both_owner_and_authority_distinct_returns_both_in_order(monkeypatch):
    # Parallel control planes (Solmate/Solady Auth): both are witnessed, in
    # owner/authority precedence order.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": AUTHORITY})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER, AUTHORITY]


def test_same_address_from_two_getters_deduped(monkeypatch):
    # owner() == authority() (case-insensitively) is ONE controller, not two.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": OWNER.upper()})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]


def test_zero_answers_skipped(monkeypatch):
    _stub(monkeypatch, {"owner()": ZERO, "authority()": AUTHORITY})
    assert read_contract_controllers("http://rpc", CONTRACT) == [AUTHORITY]


def test_no_getter_present_is_empty(monkeypatch):
    _stub(monkeypatch, {})
    assert read_contract_controllers("http://rpc", CONTRACT) == []


def test_probe_error_skipped_per_getter(monkeypatch):
    # owner() errors transiently -> skipped, not a hard failure; admin() still read.
    def _fake(rpc_url, address, signature, abi_type, block_tag="latest", *, chain_id=None):
        if signature == "owner()":
            return _PROBE_ERROR
        if signature == "admin()":
            return OWNER
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]
