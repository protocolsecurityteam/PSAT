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


def test_clean_zero_is_not_an_error_proceeds_single_plane(monkeypatch):
    # authority() cleanly returns zero -> genuinely not a plane; owner() stands.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": ZERO})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]


def test_no_getter_present_is_empty(monkeypatch):
    _stub(monkeypatch, {})
    assert read_contract_controllers("http://rpc", CONTRACT) == []


def test_any_getter_error_makes_set_incomplete_returns_none(monkeypatch):
    # owner() answers but authority() ERRORS transiently -> the plane set is not
    # dispositively complete (a real second plane could hide behind the error), so
    # return None (retryable) rather than a possibly-false single plane.
    def _fake(rpc_url, address, signature, abi_type, block_tag="latest", *, chain_id=None):
        if signature == "owner()":
            return OWNER
        if signature == "authority()":
            return _PROBE_ERROR
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) is None


def test_all_getters_error_returns_none(monkeypatch):
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *a, **k: _PROBE_ERROR)
    assert read_contract_controllers("http://rpc", CONTRACT) is None
