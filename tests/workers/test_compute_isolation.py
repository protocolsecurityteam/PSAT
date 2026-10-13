"""A budgeted child returns its result, or ends in a typed outcome: a budget overrun, the child's own error, a crash."""

from __future__ import annotations

import os
import signal
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

from db.queue import LeaseLost
from services.compute_isolation import (
    ChildProcessFailed,
    ChildProcessKilled,
    ComputeBudget,
    RemoteTraceback,
    ResourceExhausted,
    compute_cancel_var,
    policy_budget,
    run_isolated,
    shutdown_children,
    static_budget,
)
from tests.support import compute_children as children
from utils.logging import bind_trace_context, degraded_errors_var, stage_metrics_var
from workers.retry_policy import classify

ROOMY = ComputeBudget(memory_bytes=1024 * 1024 * 1024, cpu_seconds=30)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.setenv("PSAT_COMPUTE_ISOLATION", "1")


@pytest.fixture(scope="module", autouse=True)
def _fork_server():
    yield
    shutdown_children()


def _gone(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
    except OSError:
        return True
    return state == "Z"


def test_the_result_comes_back_with_the_childs_degraded_records_and_metrics():
    degraded: list = []
    metrics: dict = {}
    degraded_errors_var.set(degraded)
    stage_metrics_var.set(metrics)
    with bind_trace_context(job_id="job-7", stage="policy"):
        result = run_isolated(children.report, 5, budget=ROOMY, label="unit")
    assert result["value"] == 5
    assert result["pid"] != os.getpid()
    assert [(e.phase, e.job_id, e.stage) for e in degraded] == [("child_phase", "job-7", "policy")]
    assert metrics["child_metric"] == 5
    assert metrics["isolated_unit_peak_rss_bytes"] > 0
    assert metrics["isolated_unit_subprocess_cpu_s"] == 0


def test_the_cpu_of_what_the_child_spawned_is_reported():
    metrics: dict = {}
    stage_metrics_var.set(metrics)
    run_isolated(children.spawn_and_wait, budget=ROOMY, label="unit")
    assert metrics["isolated_unit_subprocess_cpu_s"] > 0.1


def test_a_child_stays_warm_for_the_next_job_and_an_overrun_replaces_it():
    first = run_isolated(children.report, 1, budget=ROOMY, label="unit")["pid"]
    assert run_isolated(children.report, 2, budget=ROOMY, label="unit")["pid"] == first
    with pytest.raises(ResourceExhausted):
        run_isolated(children.burn_cpu, 30, budget=ComputeBudget(ROOMY.memory_bytes, 0.5), label="unit")
    replacement = run_isolated(children.report, 3, budget=ROOMY, label="unit")["pid"]
    assert replacement != first
    assert _gone(first)


def test_the_cpu_budget_counts_only_the_current_job():
    budget = ComputeBudget(ROOMY.memory_bytes, 0.8)
    for _ in range(3):
        assert run_isolated(children.burn_cpu, 0.4, budget=budget, label="unit") > 0


def test_a_child_that_kept_a_large_heap_is_retired(monkeypatch):
    monkeypatch.setenv("PSAT_COMPUTE_RETIRE_RSS_MB", "200")
    pid = run_isolated(children.allocate_and_keep, 300, budget=ROOMY, label="unit")
    assert _gone(pid)


def test_an_idle_child_past_its_idle_time_is_retired(monkeypatch):
    pid = run_isolated(children.report, 1, budget=ROOMY, label="unit")["pid"]
    monkeypatch.setenv("PSAT_COMPUTE_IDLE_S", "0.01")
    time.sleep(0.05)
    assert run_isolated(children.report, 2, budget=ROOMY, label="unit")["pid"] != pid
    assert _gone(pid)


def test_shutdown_leaves_no_child_behind():
    pid = run_isolated(children.report, 1, budget=ROOMY, label="unit")["pid"]
    shutdown_children()
    assert _gone(pid)


def test_a_system_exit_in_the_child_is_a_failure_not_the_workers_exit():
    with pytest.raises(ChildProcessFailed, match="SystemExit"):
        run_isolated(children.exit_now, budget=ROOMY, label="unit")


def test_a_result_that_does_not_pickle_is_a_failure():
    with pytest.raises(ChildProcessFailed, match="does not pickle"):
        run_isolated(children.unpicklable, budget=ROOMY, label="unit")


def test_the_childs_own_error_is_raised_as_itself():
    with pytest.raises(ValueError, match="bad input") as caught:
        run_isolated(children.fail, "bad input", budget=ROOMY, label="unit")
    assert isinstance(caught.value.__cause__, RemoteTraceback)
    assert "compute_children.py" in str(caught.value.__cause__)
    assert classify(caught.value) == "terminal"


def test_a_cpu_overrun_kills_the_child_and_is_resource_exhausted():
    started = time.monotonic()
    with pytest.raises(ResourceExhausted) as caught:
        run_isolated(children.burn_cpu, 30, budget=ComputeBudget(ROOMY.memory_bytes, 0.5), label="unit")
    assert caught.value.resource == "cpu"
    assert caught.value.limit == 0.5 and caught.value.used > 0.5
    assert time.monotonic() - started < 10
    assert classify(caught.value) == "resource_exhausted"


def test_a_memory_overrun_kills_the_child_and_is_resource_exhausted():
    with pytest.raises(ResourceExhausted) as caught:
        run_isolated(children.allocate, 600, budget=ComputeBudget(300 * 1024 * 1024, 30), label="unit")
    assert caught.value.resource == "memory"
    assert caught.value.used > 300 * 1024 * 1024


def test_a_refused_allocation_in_the_child_is_a_memory_overrun():
    with pytest.raises(ResourceExhausted) as caught:
        run_isolated(children.raise_memory_error, budget=ROOMY, label="unit")
    assert caught.value.resource == "memory"


def test_a_crash_is_a_failure_not_a_budget_outcome():
    with pytest.raises(ChildProcessFailed) as caught:
        run_isolated(children.crash, budget=ROOMY, label="unit")
    assert not isinstance(caught.value, ResourceExhausted)
    assert "-11" in str(caught.value)
    assert classify(caught.value) == "terminal"


def test_a_kill_from_outside_is_retried(tmp_path):
    pid_file = tmp_path / "pid"

    def killer():
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if pid_file.exists() and pid_file.read_text():
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
                return
            time.sleep(0.05)

    thread = threading.Thread(target=killer)
    thread.start()
    with pytest.raises(ChildProcessKilled) as caught:
        run_isolated(children.write_pid_and_sleep, str(pid_file), budget=ROOMY, label="unit")
    thread.join()
    assert classify(caught.value) == "transient"


def test_a_lost_lease_stops_the_child(tmp_path):
    pid_file = tmp_path / "pid"
    cancel = threading.Event()
    token = compute_cancel_var.set(cancel)

    def lose_lease():
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not (pid_file.exists() and pid_file.read_text()):
            time.sleep(0.05)
        cancel.set()

    thread = threading.Thread(target=lose_lease)
    thread.start()
    try:
        with pytest.raises(LeaseLost):
            run_isolated(children.write_pid_and_sleep, str(pid_file), budget=ROOMY, label="unit")
    finally:
        compute_cancel_var.reset(token)
        thread.join()
    assert _gone(int(pid_file.read_text()))


def test_an_overrun_also_kills_what_the_child_spawned(tmp_path):
    pid_file = tmp_path / "grandchild"
    with pytest.raises(ResourceExhausted):
        run_isolated(
            children.spawn_grandchild_and_sleep,
            str(pid_file),
            budget=ComputeBudget(ROOMY.memory_bytes, 0.5),
            label="unit",
        )
    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not _gone(grandchild):
        time.sleep(0.05)
    assert _gone(grandchild)


def test_siblings_run_concurrently_and_one_overrun_leaves_the_other_alone():
    outcomes: dict[str, object] = {}

    def run(name, fn, *args, budget):
        try:
            outcomes[name] = run_isolated(fn, *args, budget=budget, label=name)
        except Exception as exc:
            outcomes[name] = exc

    threads = [
        threading.Thread(
            target=run, args=("heavy", children.burn_cpu, 30), kwargs={"budget": ComputeBudget(ROOMY.memory_bytes, 0.5)}
        ),
        threading.Thread(target=run, args=("light", children.sleep_then_echo, 1.0, "ok"), kwargs={"budget": ROOMY}),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert isinstance(outcomes["heavy"], ResourceExhausted)
    assert outcomes["light"] == "ok"


def test_disabled_isolation_runs_inline(monkeypatch):
    monkeypatch.setenv("PSAT_COMPUTE_ISOLATION", "0")
    assert run_isolated(children.report, 1, budget=ROOMY, label="unit")["pid"] == os.getpid()


def test_budgets_read_the_environment(monkeypatch):
    monkeypatch.setenv("PSAT_POLICY_COMPUTE_MEMORY_MB", "100")
    monkeypatch.setenv("PSAT_POLICY_COMPUTE_CPU_S", "7")
    monkeypatch.setenv("PSAT_STATIC_COMPUTE_CPU_S", "nonsense")
    assert policy_budget() == ComputeBudget(100 * 1024 * 1024, 7)
    assert static_budget().cpu_seconds == 600


def test_the_worker_signals_its_jobs_compute_when_the_lease_is_lost(monkeypatch):
    import uuid
    from unittest.mock import MagicMock

    from tests.support.worker_stubs import _make_job, _TestWorker

    monkeypatch.setenv("PSAT_JOB_HEARTBEAT_INTERVAL_S", "0.05")
    monkeypatch.setattr("workers.base.signal.signal", lambda *_a: None)
    monkeypatch.setattr("workers.base.advance_job", lambda *_a, **_k: None)
    monkeypatch.setattr("workers.base.store_artifact", lambda *_a, **_k: None)
    seen: dict[str, object] = {}

    class _Worker(_TestWorker):
        def _heartbeat(self, session, job):
            raise LeaseLost("moved")

        def process(self, session, job):
            cancel = compute_cancel_var.get()
            assert cancel is not None
            seen["set"] = cancel.wait(5)

    _Worker()._execute_job(MagicMock(), cast(Any, _make_job(lease_id=uuid.uuid4())))
    assert seen["set"] is True
    assert compute_cancel_var.get() is None


def test_a_worker_that_exits_leaves_no_child_and_does_not_wait_on_one(tmp_path):
    import subprocess
    import sys

    script = tmp_path / "worker.py"
    script.write_text(
        "import os\n"
        "from services.compute_isolation import ComputeBudget, run_isolated\n"
        "from tests.support import compute_children\n"
        "if __name__ == '__main__':\n"
        "    budget = ComputeBudget(1 << 30, 30)\n"
        "    print(run_isolated(compute_children.report, 1, budget=budget, label='exit')['pid'], flush=True)\n"
    )
    repo = Path(__file__).resolve().parents[2]
    done = subprocess.run(
        [sys.executable, str(script)],
        cwd=repo,
        env={**os.environ, "PSAT_COMPUTE_ISOLATION": "1", "PYTHONPATH": str(repo)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    child = int(done.stdout.strip().splitlines()[-1])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not _gone(child):
        time.sleep(0.05)
    assert _gone(child)


def test_children_start_from_a_preloaded_warmed_fork_server():
    shutdown_children()
    state = run_isolated(children.fork_server_state, budget=ROOMY, label="unit")
    assert state["missing_preloads"] == []
    assert state["mappers_configured"] is True
    assert state["frozen"] > 0


def test_warming_configures_mappers_caches_the_storage_client_and_freezes():
    import gc

    from db.storage import get_storage_client
    from services.compute_isolation import warm_fork_server

    get_storage_client.cache_clear()
    try:
        warm_fork_server()
        assert gc.get_freeze_count() > 0
        assert get_storage_client.cache_info().currsize == 1
    finally:
        gc.unfreeze()
        get_storage_client.cache_clear()
