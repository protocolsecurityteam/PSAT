"""A4 wiring: the policy-worker contract-controller step resolver (SCORING §4)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers.policy_worker import _make_terminal_controller_resolver

CONTRACT = "0x" + "1" * 40
OWNER = "0x" + "a" * 40


def test_none_rpc_url_yields_no_resolver():
    assert _make_terminal_controller_resolver(None) is None


def test_resolver_reads_owner_and_classifies(monkeypatch):
    monkeypatch.setattr("workers.policy_worker.read_contract_controller", lambda rpc, addr, **_kw: OWNER)
    monkeypatch.setattr(
        "workers.policy_worker.classify_resolved_address_with_status",
        lambda rpc, addr, **_kw: ("safe", {"address": addr, "threshold": 2}, True),
    )
    resolver = _make_terminal_controller_resolver("http://rpc", chain_id=1)
    assert resolver is not None
    step = resolver(CONTRACT)
    assert step == {"address": OWNER, "resolved_type": "safe", "details": {"address": OWNER, "threshold": 2}}


def test_resolver_returns_none_when_no_owner(monkeypatch):
    monkeypatch.setattr("workers.policy_worker.read_contract_controller", lambda rpc, addr, **_kw: None)
    resolver = _make_terminal_controller_resolver("http://rpc")
    assert resolver is not None
    assert resolver(CONTRACT) is None
