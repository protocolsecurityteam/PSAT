"""The policy-worker contract-controller step resolver used by the authority walk."""

from __future__ import annotations

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


def test_resolver_returns_empty_when_canonical_getters_are_silent(monkeypatch):
    """``[]`` from ``read_contract_controllers`` means every canonical getter
    answered cleanly and named nothing — probe-set SILENCE, distinct from a
    probe error (``None``) but NOT proof of absence: the finite getter set
    cannot prove no controller exists (unpauser()/kernel()/*_admin()/
    ERC-1967-admin contracts return the same []). The resolver propagates it
    as ``[]`` so the walk reports ``controllers_not_determined`` with its
    basis, never a proven absence and never "we could not look"."""
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
