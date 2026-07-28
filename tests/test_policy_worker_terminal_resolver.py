"""A4 wiring: the policy-worker contract-controller step resolver (SCORING §4)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers.policy_worker import _make_terminal_controller_resolver

CONTRACT = "0x" + "1" * 40
OWNER = "0x" + "a" * 40
AUTHORITY = "0x" + "b" * 40


def test_none_rpc_url_yields_no_resolver():
    assert _make_terminal_controller_resolver(None) is None


def test_resolver_reads_controllers_and_classifies_each(monkeypatch):
    monkeypatch.setattr("workers.policy_worker.read_contract_controllers", lambda rpc, addr, **_kw: [OWNER])
    monkeypatch.setattr(
        "workers.policy_worker.classify_resolved_address_with_status",
        lambda rpc, addr, **_kw: ("safe", {"address": addr, "threshold": 2}, True),
    )
    resolver = _make_terminal_controller_resolver("http://rpc", chain_id=1)
    assert resolver is not None
    steps = resolver(CONTRACT)
    assert steps == [{"address": OWNER, "resolved_type": "safe", "details": {"address": OWNER, "threshold": 2}}]


def test_resolver_returns_all_controller_planes(monkeypatch):
    # Parallel planes flow through as distinct steps for the walk to disambiguate.
    monkeypatch.setattr("workers.policy_worker.read_contract_controllers", lambda rpc, addr, **_kw: [OWNER, AUTHORITY])
    monkeypatch.setattr(
        "workers.policy_worker.classify_resolved_address_with_status",
        lambda rpc, addr, **_kw: ("eoa", {"address": addr}, True),
    )
    resolver = _make_terminal_controller_resolver("http://rpc")
    assert resolver is not None
    steps = resolver(CONTRACT)
    assert steps is not None
    assert [s["address"] for s in steps] == [OWNER, AUTHORITY]


def test_resolver_returns_empty_when_probed_clean_with_no_controller(monkeypatch):
    """INVERTED (was ``test_resolver_returns_none_when_no_controller``, which
    pinned the W2-B item 12 collapse): ``[]`` from
    ``read_contract_controllers`` means every canonical getter answered cleanly
    and named no controller — a PROVEN absence (a renounced / ownerless
    contract). Mapping it onto ``None`` here published "we could not look" over
    "there is no owner", which is why ``terminal_principal.status`` was
    ``unknown_unfetched`` on 180/180 armed rows. It now propagates as ``[]`` so
    the walk reports ``no_controller``."""
    monkeypatch.setattr("workers.policy_worker.read_contract_controllers", lambda rpc, addr, **_kw: [])
    resolver = _make_terminal_controller_resolver("http://rpc")
    assert resolver is not None
    assert resolver(CONTRACT) == []


def test_resolver_returns_none_on_probe_incomplete(monkeypatch):
    # read_contract_controllers returns None (a getter errored) -> the resolver
    # yields None so the walk reads unknown_unfetched, not a partial plane set.
    monkeypatch.setattr("workers.policy_worker.read_contract_controllers", lambda rpc, addr, **_kw: None)
    resolver = _make_terminal_controller_resolver("http://rpc")
    assert resolver is not None
    assert resolver(CONTRACT) is None
