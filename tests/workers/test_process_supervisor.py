"""A dead worker is restarted alone after a backoff; only a restart loop stops the machine; SIGTERM drains."""

from __future__ import annotations

import resource
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from workers.process_supervisor import Supervisor, WorkerSpec, main


def _spec(name: str, code: str, cap_mb: int = 0) -> WorkerSpec:
    return WorkerSpec(name=name, argv=(sys.executable, "-c", code), address_space_bytes=cap_mb * 1024 * 1024 or None)


SLEEPER = "import signal, sys, time\nsignal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\ntime.sleep(60)"


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _wait_dead(process: subprocess.Popen | None) -> None:
    assert process is not None
    process.wait(timeout=10)


def test_spec_parses_name_cap_and_module_arguments():
    spec = WorkerSpec.parse("monitor|512|workers.protocol_monitor --reconcile", python="/py")
    assert spec == WorkerSpec(
        name="monitor",
        argv=("/py", "-m", "workers.protocol_monitor", "--reconcile"),
        address_space_bytes=512 * 1024 * 1024,
    )
    assert WorkerSpec.parse("x|0|workers.x", python="/py").address_space_bytes is None
    with pytest.raises(ValueError):
        WorkerSpec.parse("x|0|", python="/py")


def test_only_the_dead_worker_restarts_after_its_backoff():
    clock = _Clock()
    beats: list[tuple[str, dict]] = []
    sup = Supervisor(
        [_spec("steady", SLEEPER), _spec("flaky", SLEEPER)],
        backoff_base_s=5,
        heartbeat=lambda status, detail: beats.append((status, detail)),
        clock=clock,
    )
    sup.start()
    try:
        steady, flaky = sup.workers
        assert steady.process is not None
        steady_pid = steady.process.pid
        assert flaky.process is not None
        flaky.process.kill()
        _wait_dead(flaky.process)

        assert sup.poll()
        assert flaky.process is None and flaky.restart_at == clock.now + 5
        assert beats[-1][0] == "restarting" and beats[-1][1]["worker"] == "flaky"

        clock.now += 4
        assert sup.poll()
        assert flaky.process is None

        clock.now += 1
        assert sup.poll()
        assert flaky.process is not None and flaky.process.poll() is None
        assert flaky.restarts == 1
        assert steady.process is not None and steady.process.pid == steady_pid and steady.process.poll() is None
        assert beats[-1][1]["workers"]["flaky"]["restarts"] == 1
    finally:
        sup.stop(grace_s=5)


def test_backoff_doubles_with_recent_deaths_up_to_its_cap():
    clock = _Clock()
    sup = Supervisor([_spec("flaky", "raise SystemExit(3)")], backoff_base_s=5, backoff_cap_s=12, clock=clock)
    sup.start()
    backoffs = []
    try:
        for _ in range(4):
            _wait_dead(sup.workers[0].process)
            assert sup.poll()
            restart_at = sup.workers[0].restart_at
            assert restart_at is not None
            backoffs.append(restart_at - clock.now)
            clock.now = restart_at
            assert sup.poll()
    finally:
        sup.stop(grace_s=5)
    assert backoffs == [5, 10, 12, 12]


def test_a_restart_loop_escalates_and_deaths_outside_the_window_do_not_count():
    clock = _Clock()
    beats: list[str] = []
    sup = Supervisor(
        [_spec("steady", SLEEPER), _spec("flaky", "raise SystemExit(3)")],
        max_restarts=3,
        window_s=60,
        backoff_base_s=1,
        heartbeat=lambda status, _detail: beats.append(status),
        clock=clock,
    )
    sup.start()
    steady = sup.workers[0].process
    try:
        flaky = sup.workers[1]
        _wait_dead(flaky.process)
        assert sup.poll()
        # Long enough apart that the first death has left the window.
        clock.now += 61
        assert sup.poll()
        for _ in range(2):
            _wait_dead(flaky.process)
            assert sup.poll()
            assert flaky.restart_at is not None
            clock.now = flaky.restart_at
            assert sup.poll()
        _wait_dead(flaky.process)
        assert not sup.poll()
        assert sup.escalated_by == "flaky"
        assert beats[-1] == "escalating"
    finally:
        sup.stop(grace_s=5)
    assert steady is not None and steady.poll() is not None


def test_run_drains_on_stop_without_restarting(tmp_path: Path):
    marker = tmp_path / "drained"
    code = (
        "import signal, sys, time\n"
        f"signal.signal(signal.SIGTERM, lambda *_: (open({str(marker)!r}, 'w').write('1'), sys.exit(0)))\n"
        "time.sleep(60)"
    )
    beats: list[str] = []
    sup = Supervisor([_spec("worker", code)], heartbeat=lambda status, _detail: beats.append(status))
    stop = threading.Event()
    result: list[int] = []
    runner = threading.Thread(target=lambda: result.append(sup.run(stop, poll_s=0.05)))
    runner.start()
    deadline = time.monotonic() + 10
    while sup.workers[0].process is None and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.5)
    stop.set()
    runner.join(timeout=10)
    assert result == [0]
    assert marker.read_text() == "1"
    assert beats[-2:] == ["draining", "stopped"]
    assert sup.workers[0].restarts == 0


def test_run_escalates_with_exit_code_one():
    sup = Supervisor([_spec("flaky", "raise SystemExit(3)")], max_restarts=2, backoff_base_s=0.01)
    assert sup.run(threading.Event(), poll_s=0.05) == 1
    assert sup.escalated_by == "flaky"


def test_stop_kills_a_worker_that_ignores_sigterm_past_the_grace():
    code = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)"
    sup = Supervisor([_spec("stubborn", code)])
    sup.start()
    process = sup.workers[0].process
    assert process is not None
    time.sleep(0.5)
    started = time.monotonic()
    sup.stop(grace_s=0.5)
    assert time.monotonic() - started < 5
    assert process.returncode == -signal.SIGKILL


def test_each_worker_starts_under_its_address_space_cap(tmp_path: Path):
    out = tmp_path / "limit"
    code = f"import resource\nopen({str(out)!r}, 'w').write(str(resource.getrlimit(resource.RLIMIT_AS)[0]))"
    sup = Supervisor([_spec("capped", code, cap_mb=2048)])
    sup.start()
    try:
        _wait_dead(sup.workers[0].process)
    finally:
        sup.stop(grace_s=5)
    assert int(out.read_text()) == 2048 * 1024 * 1024
    assert resource.getrlimit(resource.RLIMIT_AS)[0] != 2048 * 1024 * 1024


def test_main_forwards_sigterm_and_exits_zero(tmp_path: Path):
    marker = tmp_path / "drained"
    worker = (
        "import signal, sys, time\n"
        f"signal.signal(signal.SIGTERM, lambda *_: (open({str(marker)!r}, 'w').write('1'), sys.exit(0)))\n"
        "time.sleep(60)"
    )
    module = tmp_path / "standin_worker.py"
    module.write_text(worker)
    env = {
        **__import__("os").environ,
        "PYTHONPATH": f"{tmp_path}:{Path(__file__).resolve().parents[2]}",
        "DATABASE_URL": "postgresql://invalid:invalid@127.0.0.1:1/none",
    }
    supervisor = subprocess.Popen(
        [sys.executable, "-m", "workers.process_supervisor", "standin|1024|standin_worker"],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not _children(supervisor.pid):
        time.sleep(0.1)
    assert _children(supervisor.pid)
    supervisor.send_signal(signal.SIGTERM)
    assert supervisor.wait(timeout=30) == 0
    assert marker.read_text() == "1"


def _children(pid: int) -> list[str]:
    try:
        return Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
    except OSError:
        return []


def test_main_parses_specs_into_a_supervisor(monkeypatch):
    captured: dict = {}

    def fake_run(self, stop, poll_s=1.0):
        captured["specs"] = [w.spec for w in self.workers]
        captured["max_restarts"] = self.max_restarts
        return 0

    monkeypatch.setattr(Supervisor, "run", fake_run)
    monkeypatch.setenv("PSAT_SUPERVISOR_MAX_RESTARTS", "7")
    monkeypatch.setattr(signal, "signal", lambda *_a: None)
    assert main(["a|0|workers.a", "b|64|workers.b --flag"]) == 0
    assert [s.name for s in captured["specs"]] == ["a", "b"]
    assert captured["specs"][1].argv[-2:] == ("workers.b", "--flag")
    assert captured["max_restarts"] == 7
