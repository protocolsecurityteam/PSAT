"""Unit tests for services/concurrency primitives (parallel_map, RpcExecutor). Every parallel
fan-out in the codebase relies on these."""

from __future__ import annotations

import threading
from concurrent.futures import Future

import pytest

from services.concurrency import (
    RpcExecutor,
    parallel_map,
    submit_rpc,
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
    barrier = threading.Barrier(4)

    def slow_then_value(x):
        barrier.wait(timeout=5)
        return x * 2

    results = parallel_map(slow_then_value, [1, 2, 3, 4], max_workers=4)
    assert [item for item, _ in results] == [1, 2, 3, 4]
    assert [r for _, r in results] == [2, 4, 6, 8]


def test_parallel_map_returns_exceptions_instead_of_raising():

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
    counter = {"n": 0}

    def increment_heartbeat():
        counter["n"] += 1

    parallel_map(lambda x: x, [1, 2, 3, 4, 5], max_workers=4, heartbeat=increment_heartbeat)
    assert counter["n"] == 5


def test_parallel_map_heartbeat_exception_is_swallowed():

    def bad_heartbeat():
        raise RuntimeError("hb broke")

    results = parallel_map(lambda x: x * 2, [1, 2, 3], max_workers=2, heartbeat=bad_heartbeat)
    assert [r for _, r in results] == [2, 4, 6]


def test_parallel_map_propagates_lease_lost_from_heartbeat_parallel_path():
    """LeaseLost must propagate so ``BaseWorker._execute_job`` can bail.

    psat-pr-73 hit duplicate builds because ``parallel_map`` caught it as a generic
    Exception, so the abandoned worker kept running forge builds on a job a sibling
    had claimed (signal #4, 2026-05-08 08:17-21).
    """
    from db.queue import LeaseLost

    def lease_lost_heartbeat():
        raise LeaseLost("sibling owns the row now")

    with pytest.raises(LeaseLost):
        parallel_map(lambda x: x * 2, [1, 2, 3], max_workers=2, heartbeat=lease_lost_heartbeat)


def test_parallel_map_propagates_lease_lost_from_heartbeat_single_worker_path():
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
    seen_threads = []

    def record_thread(x):
        seen_threads.append(threading.current_thread().ident)
        return x

    parallel_map(record_thread, [1, 2, 3, 4], max_workers=1)
    assert len(set(seen_threads)) == 1
    assert seen_threads[0] == threading.current_thread().ident


def test_parallel_map_respects_psat_rpc_fanout_env(monkeypatch):
    monkeypatch.setenv("PSAT_RPC_FANOUT", "1")
    seen_threads = []

    def record_thread(x):
        seen_threads.append(threading.current_thread().ident)
        return x

    parallel_map(record_thread, [1, 2, 3])
    assert len(set(seen_threads)) == 1


# ---------------------------------------------------------------------------
# RpcExecutor singleton
# ---------------------------------------------------------------------------


def test_rpc_executor_submit_returns_future_resolving_to_result():
    fut = submit_rpc(lambda x: x + 1, 41)
    assert isinstance(fut, Future)
    assert fut.result(timeout=5) == 42
