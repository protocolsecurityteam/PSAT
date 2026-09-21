"""Real local processes: drain waits, unexpected exits fail, ownership is exclusive."""

import sys
import threading
import time

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from services.process_singleton import ProcessSingleton
from tests.conftest import DATABASE_URL, requires_postgres
from workers import machine_runtime

pytestmark = requires_postgres


def wait_for(predicate, timeout=8):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition did not become true")


@pytest.fixture
def runtime(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_LIFECYCLE_DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_MODE", "observe")
    monkeypatch.setenv("PSAT_INDEXER_GROUP", "workers")
    monkeypatch.setattr(machine_runtime, "SessionLocal", sessionmaker(db_session.bind))
    return db_session


def test_drain_waits_for_child_work_and_releases_singleton_only_after_exit(runtime, monkeypatch, tmp_path):
    script = tmp_path / "child.py"
    script.write_text("""import signal, sys, time, pathlib, subprocess
p=pathlib.Path(sys.argv[1])
signal.signal(signal.SIGTERM, lambda *_: (p / 'term').touch())
child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.3)'])
(p/'started').touch()
while not (p/'release').exists(): time.sleep(.01)
child.wait()
(p/'finished').touch()
""")
    monkeypatch.setattr(machine_runtime, "commands", lambda _: [[sys.executable, str(script), str(tmp_path)]])
    stop = threading.Event()
    results = []
    thread = threading.Thread(target=lambda: results.append(machine_runtime.run("workers", stop)))
    thread.start()
    second = ProcessSingleton("workers", DATABASE_URL)
    try:
        wait_for(lambda: (tmp_path / "started").exists())
        runtime.execute(text("UPDATE worker_lifecycle SET phase='draining'"))
        runtime.commit()
        wait_for(lambda: (tmp_path / "term").exists())
        assert thread.is_alive()
        assert not second.acquire()
        assert not (tmp_path / "finished").exists()
        (tmp_path / "release").touch()
        thread.join(5)
        assert results == [0]
        assert (tmp_path / "finished").exists()
        assert second.acquire()
        assert runtime.execute(text("SELECT phase FROM worker_lifecycle")).scalar_one() == "stopped"
    finally:
        (tmp_path / "release").touch()
        stop.set()
        thread.join(5)
        second.close()


@pytest.mark.parametrize("exit_code", [0, 7])
def test_unexpected_clean_or_failed_child_exit_is_failure(runtime, monkeypatch, exit_code):
    monkeypatch.setattr(
        machine_runtime, "commands", lambda _: [[sys.executable, "-c", f"raise SystemExit({exit_code})"]]
    )
    assert machine_runtime.run("workers", threading.Event()) == 1


def test_controller_credential_not_passed_to_analysis(runtime, monkeypatch, tmp_path):
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_TOKEN", "must-not-reach-child")
    output = tmp_path / "token-present"
    command = [
        sys.executable,
        "-c",
        "import os,sys,pathlib; pathlib.Path(sys.argv[1]).write_text(str('PSAT_WORKER_LIFECYCLE_TOKEN' in os.environ))",
        str(output),
    ]
    monkeypatch.setattr(machine_runtime, "commands", lambda _: [command])
    assert machine_runtime.run("workers", threading.Event()) == 1
    assert output.read_text() == "False"


def test_singleton_loss_kills_child_before_launcher_returns(runtime, monkeypatch, tmp_path):
    pidfile = tmp_path / "pid"
    command = [
        sys.executable,
        "-c",
        "import os,sys,time,pathlib; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)",
        str(pidfile),
    ]
    monkeypatch.setattr(machine_runtime, "commands", lambda _: [command])
    original = ProcessSingleton.check

    def lose(owner):
        if pidfile.exists():
            raise RuntimeError("simulated connection loss")
        original(owner)

    monkeypatch.setattr(ProcessSingleton, "check", lose)
    assert machine_runtime.run("workers", threading.Event()) == 1
    import os

    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


def test_indexer_and_monitor_commands_preserve_process_isolation(monkeypatch):
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_MODE", "enforce")
    monkeypatch.setenv("PSAT_INDEXER_GROUP", "monitor")
    commands = machine_runtime.commands("monitor")
    assert [sys.executable, "-m", "workers.protocol_monitor"] in commands
    assert [sys.executable, "-m", "workers.machine_runtime", "indexer"] in commands
    assert [sys.executable, "-m", "workers.lifecycle_controller"] in commands


def test_controller_crash_does_not_interrupt_monitoring(runtime, monkeypatch, tmp_path):
    script = tmp_path / "monitor.py"
    script.write_text("""import signal, time, sys, pathlib
stop=False
def shutdown(*_):
    global stop
    stop=True
signal.signal(signal.SIGTERM, shutdown)
p=pathlib.Path(sys.argv[1])
while not stop:
    p.write_text(str(time.monotonic()))
    time.sleep(.02)
""")
    heartbeat = tmp_path / "heartbeat"
    monkeypatch.setattr(
        machine_runtime,
        "commands",
        lambda _: [
            [sys.executable, str(script), str(heartbeat)],
            [sys.executable, "-c", "raise SystemExit(1)"],
        ],
    )
    stop = threading.Event()
    results = []
    thread = threading.Thread(target=lambda: results.append(machine_runtime.run("monitor", stop)))
    thread.start()
    try:
        wait_for(heartbeat.exists)
        first = heartbeat.read_text()
        time.sleep(1.2)
        assert thread.is_alive()
        assert heartbeat.read_text() != first
    finally:
        stop.set()
        thread.join(8)
    # A failed sibling may make the deployment exit nonzero, but its failure
    # must not have interrupted the healthy monitor before the stop request.
    assert not thread.is_alive()
