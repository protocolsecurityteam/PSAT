"""Memory and exactness regressions for disposition's page visitor and spool."""

from __future__ import annotations

import json
import os
import random
import resource
import subprocess
import sys
from pathlib import Path

import pytest
import requests

from services.monitoring import delivery_shape as ds
from services.monitoring.delivery_spool import DeliverySpool, DeliverySpoolError
from services.resolution.repos import event_logs_rpc as rpc

HOLDER = "0x" + "11" * 20
TOKEN = "0x" + "22" * 20
TOPICS = [[ds.TRANSFER_TOPIC0], None, [ds._pad32(HOLDER)]]


def raw_log(n: int) -> dict:
    return {
        "address": TOKEN,
        "topics": [ds.TRANSFER_TOPIC0, ds._pad32(TOKEN), ds._pad32(HOLDER)],
        "data": "0x" + f"{n:064x}",
        "transactionHash": "0x" + f"{n + 1:064x}",
        "blockHash": "0x" + f"{n + 100000:064x}",
        "logIndex": "0x0",
        "blockNumber": hex(n),
        "transactionIndex": "0x0",
    }


def visit(fetcher, consume, end=9):
    fetcher.visit_logs(event_address=[TOKEN], topics=TOPICS, from_block=0, to_block=end, consume=consume)


def fetcher_for(wire, *, cap=4, floor=1, window=100):
    fetcher = rpc.RpcEventLogFetcher(
        "http://stub.invalid", result_cap=cap, min_bisect_span=floor, max_block_range=window
    )
    fetcher._request_logs = wire
    return fetcher


def test_stream_matches_legacy_request_tree_and_output():
    def run(stream):
        calls = []

        def wire(params):
            lo, hi = (int(params[0][key], 16) for key in ("fromBlock", "toBlock"))
            calls.append((lo, hi))
            return [raw_log(i) for i in range(lo, min(hi + 1, lo + 4))]

        f = fetcher_for(wire, window=7)
        if stream:
            logs = []
            visit(f, logs.append, end=15)
        else:
            logs = f.fetch_logs(event_address=[TOKEN], topics=TOPICS, from_block=0, to_block=15)
        return calls, logs

    assert run(True) == run(False)


def test_capped_parent_and_accepted_pages_are_released_before_next_request():
    live = []

    class Page(list):
        def __init__(self, values):
            super().__init__(values)
            live.append(True)

        def __del__(self):
            live.pop()

    def wire(params):
        assert live == []
        lo, hi = (int(params[0][key], 16) for key in ("fromBlock", "toBlock"))
        return Page(raw_log(i) for i in range(lo, min(hi + 1, lo + 4)))

    blocks = []
    visit(fetcher_for(wire), lambda log: blocks.append(log.block_number))
    assert blocks == list(range(10)) and live == []


@pytest.mark.parametrize("bad", [None, {}, [None], [raw_log(0), {}]])
def test_malformed_page_never_reaches_callback(bad):
    consumed = []
    with pytest.raises(RuntimeError):
        visit(fetcher_for(lambda params: bad), consumed.append)
    assert consumed == []


@pytest.mark.parametrize(
    "patch",
    [
        {"blockNumber": "0xff"},
        {"removed": True},
        {"transactionHash": "0x12"},
        {"address": HOLDER},
        {"topics": [ds.TRANSFER_TOPIC0]},
        {"topics": [ds.TRANSFER_TOPIC0, "0xnot-hex", ds._pad32(HOLDER)]},
        {"data": "0x" + "z" * 64},
    ],
)
def test_invalid_member_refuses_whole_page(patch):
    bad = raw_log(1) | patch
    consumed = []
    with pytest.raises(RuntimeError):
        visit(fetcher_for(lambda params: [raw_log(0), bad]), consumed.append)
    assert consumed == []


@pytest.mark.parametrize("kind", ["cap", "reject", "timeout"])
def test_failure_at_floor_after_accepted_child_propagates(kind, monkeypatch):
    monkeypatch.setattr(rpc.time, "sleep", lambda _: None)
    calls = []

    def wire(params):
        lo, hi = (int(params[0][key], 16) for key in ("fromBlock", "toBlock"))
        calls.append((lo, hi))
        if lo == hi == 0:
            return [raw_log(0)]
        if kind == "cap":
            return [raw_log(lo)] * 4
        raise (rpc.RpcClientTimeout if kind == "timeout" else RuntimeError)("synthetic refusal")

    consumed = []
    with pytest.raises(RuntimeError):
        visit(fetcher_for(wire), consumed.append, end=1)
    assert len(consumed) == 1
    assert calls.count((1, 1)) == (2 if kind == "timeout" else 1)


def test_callback_failure_does_not_bisect_or_retry():
    calls = []

    def wire(params):
        calls.append(params)
        return [raw_log(0)]

    def fail(log):
        raise RuntimeError("consumer failed")

    with pytest.raises(RuntimeError, match="consumer failed"):
        visit(fetcher_for(wire), fail)
    assert len(calls) == 1


@pytest.mark.parametrize("budget", [1, 2])
def test_fetcher_timeout_retry_is_counted_and_budgeted(budget, monkeypatch):
    cost = ds.DispositionCost()
    calls = []

    def wire(*args, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise rpc.RpcClientTimeout("timeout")
        return []

    monkeypatch.setattr(rpc, "rpc_request", wire)
    monkeypatch.setattr(rpc.time, "sleep", lambda _: None)
    f = ds._DispositionFetcher(
        "http://stub.invalid", chain_id=1, cost=cost, budget=budget, max_block_range=100, min_bisect_span=1
    )
    if budget == 1:
        with pytest.raises(ds.DispositionBudgetExceeded):
            visit(f, lambda log: None)
    else:
        visit(f, lambda log: None)
    assert len(calls) == cost.get_logs == budget
    assert all(c["timeout"] == ds.DISPOSITION_SCAN_TIMEOUT_SECONDS for c in calls)


@pytest.mark.parametrize("budget", [1, 2, 3, 4])
def test_transport_and_fetcher_retries_share_getlogs_budget(budget, monkeypatch):
    from services.clients import rpc as client

    cost = ds.DispositionCost()
    calls = []

    class Transport:
        def post(self, *args, **kwargs):
            calls.append(kwargs)
            raise requests.Timeout("synthetic timeout")

    monkeypatch.setattr(client, "_assert_url_chain_id", lambda *a: None)
    monkeypatch.setattr(client, "_get_session", Transport)
    monkeypatch.setattr(client.time, "sleep", lambda _: None)
    f = ds._DispositionFetcher(
        "http://stub.invalid", chain_id=1, cost=cost, budget=budget, max_block_range=100, min_bisect_span=1
    )
    with pytest.raises(RuntimeError):
        visit(f, lambda log: None, end=0)
    assert cost.get_logs == len(calls) == budget


def test_exact_spool_deduplicates_outside_sample_and_filters_cursor(tmp_path, monkeypatch):
    monkeypatch.setenv("PSAT_DISPOSITION_SPOOL_DIR", str(tmp_path))
    with DeliverySpool() as spool:
        indices = list(range(100))
        random.Random(7).shuffle(indices)
        for pair in range(3):
            for n in indices + [99, 98, 97, 1]:
                log = rpc._decode_log(raw_log(n))
                assert log is not None
                spool.add(pair, log, meterable=True)
        for pair in range(3):
            count, sample = spool.summary(pair, cursor=80 + pair, keep=8)
            assert count == 19 - pair
            assert [r["block"] for r in sample] == list(range(81 + pair, 89 + pair))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "change", [{"data": "0x" + "f" * 64}, {"blockNumber": "0x2"}, {"transactionHash": "0x" + "ff" * 32}]
)
def test_conflicting_identity_or_position_discards_group(change):
    with DeliverySpool() as spool:
        first, second = (rpc._decode_log(r) for r in [raw_log(1), raw_log(1) | change])
        assert first is not None and second is not None
        spool.add(0, first, meterable=True)
        with pytest.raises(DeliverySpoolError):
            spool.add(0, second, meterable=True)


def test_spool_quota_failure_and_cleanup(tmp_path, monkeypatch):
    monkeypatch.setenv("PSAT_DISPOSITION_SPOOL_DIR", str(tmp_path))
    monkeypatch.setattr(DeliverySpool, "MAX_BYTES", 32768)
    with pytest.raises(DeliverySpoolError):
        with DeliverySpool() as spool:
            for n in range(2000):
                log = rpc._decode_log(raw_log(n))
                assert log is not None
                spool.add(0, log, meterable=True)
    assert list(tmp_path.iterdir()) == []


def test_spool_cleanup_on_cancellation(tmp_path, monkeypatch):
    monkeypatch.setenv("PSAT_DISPOSITION_SPOOL_DIR", str(tmp_path))
    with pytest.raises(KeyboardInterrupt):
        with DeliverySpool():
            if os.name == "posix":
                assert list(tmp_path.iterdir()) == []  # also safe on SIGKILL
            raise KeyboardInterrupt()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(not Path("/dev/shm").is_dir(), reason="requires Linux tmpfs")
def test_spool_refuses_memory_backed_filesystem(monkeypatch):
    monkeypatch.setenv("PSAT_DISPOSITION_SPOOL_DIR", "/dev/shm")
    with pytest.raises(DeliverySpoolError, match="memory-backed"):
        with DeliverySpool():
            pytest.fail("tmpfs would recreate the memory problem")


def memory_run(n: int) -> dict:
    """Exercise the actual production discovery, not a second implementation."""
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    baseline = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    calls = 0

    def wire(params):
        nonlocal calls
        calls += 1
        lo, hi = (int(params[0][key], 16) for key in ("fromBlock", "toBlock"))
        return [raw_log(i) for i in range(lo, min(hi + 1, lo + 40000))]

    f = fetcher_for(wire, cap=40000, window=n)
    measured = {(HOLDER, TOKEN): ds._Measured(0, n - 1)}
    ds._discover(
        f,
        [ds._Pair(HOLDER, TOKEN, 0, False)],
        chain_id=1,
        from_block=0,
        to_block=n - 1,
        measured=measured,
        priority={},
        cost=ds.DispositionCost(),
    )
    entry = measured[(HOLDER, TOKEN)]
    assert entry.delivery_count == n
    assert [r["block"] for r in entry.deliveries] == list(range(8))
    return {
        "n": n,
        "baseline_mib": baseline,
        "peak_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
        "calls": calls,
    }


@pytest.mark.skipif(sys.platform != "linux", reason="RSS units and address-space bound are Linux-specific")
def test_history_growth_does_not_grow_discovery_heap(tmp_path):
    results = []
    for n in (80000, 240000):
        env = os.environ | {
            "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            "PSAT_DISPOSITION_SPOOL_DIR": str(tmp_path),
        }
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), str(n)],
            env=env,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        results.append(json.loads(completed.stdout))
    assert all(r["peak_mib"] - r["baseline_mib"] < 110 for r in results)
    assert results[1]["peak_mib"] - results[0]["peak_mib"] < 32
    assert list(tmp_path.iterdir()) == []


if __name__ == "__main__":
    print(json.dumps(memory_run(int(sys.argv[1]))))
