"""Unit tests for utils/concurrency primitives.

Covers ordering, exception capture, heartbeat invocation, RpcExecutor
singleton semantics, and parallel_rpc_calls chunk routing. Every parallel
fan-out elsewhere in the codebase relies on these guarantees, so this file
is the safety net for the helper itself.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future

import pytest

from utils import concurrency
from utils.concurrency import (
    RpcExecutor,
    parallel_map,
    parallel_rpc_calls,
    submit_rpc,
    unwrap_results,
)


@pytest.fixture(autouse=True)
def _reset_executor():
    RpcExecutor.reset_for_tests()
    yield
    RpcExecutor.reset_for_tests()


# ---------------------------------------------------------------------------
# parallel_map
# ---------------------------------------------------------------------------


def test_parallel_map_preserves_input_order():
    """Output order must match input order regardless of completion order."""
    barrier = threading.Barrier(4)

    def slow_then_value(x):
        barrier.wait(timeout=5)
        return x * 2

    results = parallel_map(slow_then_value, [1, 2, 3, 4], max_workers=4)
    assert [item for item, _ in results] == [1, 2, 3, 4]
    assert [r for _, r in results] == [2, 4, 6, 8]


def test_parallel_map_returns_exceptions_instead_of_raising():
    """Per-item failures land in the result tuple; the helper itself never raises."""

    def maybe_fail(x):
        if x == 2:
            raise ValueError("boom")
        return x

    results = parallel_map(maybe_fail, [1, 2, 3], max_workers=3)
    assert results[0][1] == 1
    assert isinstance(results[1][1], ValueError)
    assert str(results[1][1]) == "boom"
    assert results[2][1] == 3


def test_parallel_map_calls_heartbeat_once_per_completion():
    """Heartbeat fires exactly once per completed task."""
    counter = {"n": 0}

    def increment_heartbeat():
        counter["n"] += 1

    parallel_map(lambda x: x, [1, 2, 3, 4, 5], max_workers=4, heartbeat=increment_heartbeat)
    assert counter["n"] == 5


def test_parallel_map_heartbeat_exception_is_swallowed():
    """A raising heartbeat must not break the fan-out for transient errors."""

    def bad_heartbeat():
        raise RuntimeError("hb broke")

    results = parallel_map(lambda x: x * 2, [1, 2, 3], max_workers=2, heartbeat=bad_heartbeat)
    assert [r for _, r in results] == [2, 4, 6]


def test_parallel_map_propagates_lease_lost_from_heartbeat_parallel_path():
    """LeaseLost is a directive — the lease has rolled to a sibling worker
    and continuing this fan-out would be wasted work on a job we no longer
    own. The parallel-path heartbeat handler must propagate LeaseLost so
    ``BaseWorker._execute_job`` can bail.

    Why this matters: psat-pr-73 hit duplicate-build symptoms because
    ``parallel_map`` previously caught LeaseLost as a generic Exception
    and continued, so the abandoned worker kept running forge builds on
    a job a sibling had already claimed (signal #4, 2026-05-08 08:17-21).
    """
    from db.queue import LeaseLost

    def lease_lost_heartbeat():
        raise LeaseLost("sibling owns the row now")

    with pytest.raises(LeaseLost):
        parallel_map(lambda x: x * 2, [1, 2, 3], max_workers=2, heartbeat=lease_lost_heartbeat)


def test_parallel_map_propagates_lease_lost_from_heartbeat_single_worker_path():
    """Same invariant for the ``max_workers=1`` heartbeat path."""
    from db.queue import LeaseLost

    def lease_lost_heartbeat():
        raise LeaseLost("sibling owns the row now")

    with pytest.raises(LeaseLost):
        parallel_map(lambda x: x, [1, 2, 3], max_workers=1, heartbeat=lease_lost_heartbeat)


def test_parallel_map_heartbeats_single_item_while_waiting(monkeypatch):
    monkeypatch.setenv("PSAT_PARALLEL_HEARTBEAT_INTERVAL_S", "0.01")
    release = threading.Event()
    counter = {"n": 0}

    def wait_for_release(x):
        assert release.wait(timeout=2)
        return x

    def heartbeat():
        counter["n"] += 1
        release.set()

    results = parallel_map(wait_for_release, [1], max_workers=8, heartbeat=heartbeat)

    assert results == [(1, 1)]
    assert counter["n"] >= 1


def test_parallel_map_heartbeats_while_waiting(monkeypatch):
    monkeypatch.setenv("PSAT_PARALLEL_HEARTBEAT_INTERVAL_S", "0.01")
    release = threading.Event()
    counter = {"n": 0}

    def wait_for_release(x):
        assert release.wait(timeout=2)
        return x

    def heartbeat():
        counter["n"] += 1
        release.set()

    results = parallel_map(wait_for_release, [1, 2], max_workers=2, heartbeat=heartbeat)

    assert [r for _, r in results] == [1, 2]
    assert counter["n"] >= 1


def test_parallel_map_heartbeats_while_submission_is_backpressured(monkeypatch):
    monkeypatch.setenv("PSAT_PARALLEL_HEARTBEAT_INTERVAL_S", "0.01")
    release = threading.Event()
    counter = {"n": 0}

    def wait_for_release(x):
        if x in (1, 2):
            assert release.wait(timeout=2)
        return x

    def heartbeat():
        counter["n"] += 1
        release.set()

    results = parallel_map(wait_for_release, [1, 2, 3], max_workers=2, heartbeat=heartbeat)

    assert [r for _, r in results] == [1, 2, 3]
    assert counter["n"] >= 1


def test_parallel_map_empty_input_returns_empty():
    assert parallel_map(lambda x: x, [], max_workers=4) == []


def test_parallel_map_workers_one_runs_sequentially_in_thread(monkeypatch):
    """``max_workers=1`` is parity mode: callers use it to assert sequential equivalence in tests."""
    seen_threads = []

    def record_thread(x):
        seen_threads.append(threading.current_thread().ident)
        return x

    parallel_map(record_thread, [1, 2, 3, 4], max_workers=1)
    assert len(set(seen_threads)) == 1
    assert seen_threads[0] == threading.current_thread().ident


def test_parallel_map_respects_psat_rpc_fanout_env(monkeypatch):
    """When max_workers is None, ``PSAT_RPC_FANOUT`` is the ceiling."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", "1")
    seen_threads = []

    def record_thread(x):
        seen_threads.append(threading.current_thread().ident)
        return x

    parallel_map(record_thread, [1, 2, 3])
    assert len(set(seen_threads)) == 1


def test_unwrap_results_raises_first_exception():
    results = [(1, "a"), (2, ValueError("oops")), (3, "c")]
    with pytest.raises(ValueError, match="oops"):
        unwrap_results(results)


def test_unwrap_results_returns_values_when_no_errors():
    results = [(1, "a"), (2, "b"), (3, "c")]
    assert unwrap_results(results) == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# RpcExecutor singleton
# ---------------------------------------------------------------------------


def test_rpc_executor_returns_same_instance_across_calls():
    a = RpcExecutor.get()
    b = RpcExecutor.get()
    assert a is b


def test_rpc_executor_submit_returns_future_resolving_to_result():
    fut = submit_rpc(lambda x: x + 1, 41)
    assert isinstance(fut, Future)
    assert fut.result(timeout=5) == 42


def test_rpc_executor_reset_drops_singleton():
    a = RpcExecutor.get()
    RpcExecutor.reset_for_tests()
    b = RpcExecutor.get()
    assert a is not b


# ---------------------------------------------------------------------------
# parallel_rpc_calls chunking
# ---------------------------------------------------------------------------


def test_parallel_rpc_calls_empty_returns_empty():
    assert parallel_rpc_calls("https://example.invalid", []) == []


def test_parallel_rpc_calls_under_max_batch_delegates(monkeypatch):
    """When N <= MAX_BATCH_SIZE the helper delegates without chunking."""
    captured = []

    def fake_batch(rpc_url, calls):
        captured.append((rpc_url, list(calls)))
        return [(idx, False) for idx, _ in enumerate(calls)]

    monkeypatch.setattr(concurrency, "rpc_batch_request_with_status", fake_batch)
    calls = [("eth_chainId", []) for _ in range(10)]
    out = parallel_rpc_calls("https://rpc.example", calls)
    assert len(captured) == 1
    assert captured[0][0] == "https://rpc.example"
    assert len(captured[0][1]) == 10
    assert out == [(idx, False) for idx in range(10)]


def test_parallel_rpc_calls_chunks_when_above_max_batch(monkeypatch):
    """N > MAX_BATCH_SIZE is split into ceil(N / MAX_BATCH_SIZE) chunks dispatched in parallel."""
    captured_chunks: list[int] = []

    def fake_batch(rpc_url, calls):
        captured_chunks.append(len(calls))
        return [(f"chunk_{idx}", False) for idx in range(len(calls))]

    monkeypatch.setattr(concurrency, "rpc_batch_request_with_status", fake_batch)
    monkeypatch.setattr(concurrency, "MAX_BATCH_SIZE", 100)
    calls = [("eth_chainId", []) for _ in range(250)]
    out = parallel_rpc_calls("https://rpc.example", calls)

    assert len(captured_chunks) == 3
    assert sorted(captured_chunks) == [50, 100, 100]
    assert len(out) == 250
    assert all(item[0] is not None for item in out)


def test_parallel_rpc_calls_preserves_order_across_chunks(monkeypatch):
    """A 2-chunk batch must still return results indexed by original call position."""

    def fake_batch(rpc_url, calls):
        # tag each result with its method+arg position so we can verify order
        return [(("done", method, params), False) for method, params in calls]

    monkeypatch.setattr(concurrency, "rpc_batch_request_with_status", fake_batch)
    monkeypatch.setattr(concurrency, "MAX_BATCH_SIZE", 5)

    calls = [("eth_chainId", [i]) for i in range(12)]
    out = parallel_rpc_calls("https://rpc.example", calls)
    assert len(out) == 12
    for i, (result, had_error) in enumerate(out):
        assert had_error is False
        assert result[2] == [i]


def test_parallel_rpc_calls_chunk_failure_leaves_default_errored(monkeypatch):
    """A chunk that raises wholesale leaves its slots flagged ``had_error=True``."""

    def fake_batch(rpc_url, calls):
        if calls and calls[0][1] == [0]:
            raise RuntimeError("chunk 0 down")
        return [(idx, False) for idx, _ in enumerate(calls)]

    monkeypatch.setattr(concurrency, "rpc_batch_request_with_status", fake_batch)
    monkeypatch.setattr(concurrency, "MAX_BATCH_SIZE", 5)

    calls = [("eth_chainId", [i]) for i in range(10)]
    out = parallel_rpc_calls("https://rpc.example", calls)
    assert all(out[i] == (None, True) for i in range(5))
    assert all(out[i][1] is False for i in range(5, 10))
