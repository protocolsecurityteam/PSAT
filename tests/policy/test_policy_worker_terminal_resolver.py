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


def test_pinned_terminal_reads_are_shared_and_return_detached_details(monkeypatch):
    reads = []
    monkeypatch.setattr(
        "workers.policy_worker.read_contract_controllers",
        lambda rpc, addr, **kw: reads.append((rpc, addr, kw)) or [OWNER],
    )
    monkeypatch.setattr(
        "workers.policy_worker.classify_resolved_address_with_status",
        lambda *a, **kw: ("safe", {"owners": [AUTHORITY]}, True),
    )
    resolver = _make_terminal_controller_resolver("http://rpc", chain_id=1, block_tag="0x10")
    assert resolver is not None
    first = resolver(CONTRACT)
    assert first is not None
    details = first[0]["details"]
    assert isinstance(details, dict) and isinstance(details["owners"], list)
    details["owners"].clear()
    second = resolver(CONTRACT)
    assert second is not None and second[0]["details"] == {"owners": [AUTHORITY]}
    assert len(reads) == 1 and reads[0][2] == {"chain_id": 1, "block_tag": "0x10"}
    other = _make_terminal_controller_resolver("http://rpc", chain_id=1, block_tag="0x11")
    assert other is not None
    other(CONTRACT)
    assert len(reads) == 2


def test_incomplete_or_failed_terminal_reads_retry(monkeypatch):
    reads = []
    answers = iter([None, [OWNER], [OWNER]])
    monkeypatch.setattr(
        "workers.policy_worker.read_contract_controllers", lambda *a, **kw: reads.append(1) or next(answers)
    )
    classifications = iter([("unknown", {}, False), ("eoa", {}, True)])
    monkeypatch.setattr(
        "workers.policy_worker.classify_resolved_address_with_status", lambda *a, **kw: next(classifications)
    )
    resolver = _make_terminal_controller_resolver("http://rpc", chain_id=1, block_tag="0x10")
    assert resolver is not None
    assert resolver(CONTRACT) is None
    for expected in ["unknown", "eoa", "eoa"]:
        observed = resolver(CONTRACT)
        assert observed is not None and observed[0]["resolved_type"] == expected
    assert len(reads) == 3


def test_converging_parallel_walks_coalesce_one_pinned_read(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    entered, release = Event(), Event()
    reads = []

    def read(*a, **kw):
        reads.append(1)
        entered.set()
        assert release.wait(5)
        return []

    monkeypatch.setattr("workers.policy_worker.read_contract_controllers", read)
    resolver = _make_terminal_controller_resolver("http://rpc", chain_id=1, block_tag="0x10")
    assert resolver is not None
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(resolver, CONTRACT)
        assert entered.wait(5)
        second = pool.submit(resolver, CONTRACT)
        release.set()
        assert first.result(5) == second.result(5) == []
    assert len(reads) == 1


def test_latest_controller_reads_are_not_memoized(monkeypatch):
    reads = []
    monkeypatch.setattr("workers.policy_worker.read_contract_controllers", lambda *a, **kw: reads.append(kw) or [])
    resolver = _make_terminal_controller_resolver("http://rpc", chain_id=1)
    assert resolver is not None
    assert resolver(CONTRACT) == resolver(CONTRACT) == []
    assert reads == [{"chain_id": 1}, {"chain_id": 1}]
