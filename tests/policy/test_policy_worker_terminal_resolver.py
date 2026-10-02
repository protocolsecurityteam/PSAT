from __future__ import annotations

from workers.policy_worker import _make_terminal_controller_resolver

CONTRACT = "0x" + "1" * 40
OWNER = "0x" + "a" * 40
AUTHORITY = "0x" + "b" * 40


def test_resolver_returns_empty_when_canonical_getters_are_silent(monkeypatch):
    """``[]`` is probe-set silence, not proof of absence, and must reach the walk as ``controllers_not_determined``."""
    monkeypatch.setattr("workers.policy_worker.read_contract_controllers", lambda rpc, addr, **_kw: [])
    resolver = _make_terminal_controller_resolver("http://rpc")
    assert resolver is not None
    assert resolver(CONTRACT) == []
