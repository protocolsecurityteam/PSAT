"""The preparer can restart independently and both processes drain on shutdown."""

import signal
import subprocess
from unittest.mock import Mock

import pytest

from workers import web_runtime as runtime


def child(pid, code=None):
    return Mock(pid=pid, returncode=code, poll=Mock(return_value=code))


def test_builder_crash_restarts_without_restarting_api(monkeypatch):
    api, failed, replacement = child(1), child(2, 1), child(3)
    launch = Mock(side_effect=[api, failed, replacement])
    monkeypatch.setattr(runtime, "launch", launch)
    monkeypatch.setattr(runtime, "enabled", lambda: True)
    clock = iter([0, 1, 1, 2, 3, 4])
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(clock))
    shutdown = Mock()
    monkeypatch.setattr(runtime, "shutdown", shutdown)
    stop = Mock(wait=Mock(side_effect=[False, False, True]))
    assert runtime.run(stop) == 0
    assert launch.call_args_list == [(), ((True,),), ((True,),)]
    shutdown.assert_called_once_with([api, replacement])


def test_api_failure_exits_nonzero_and_stops_builder(monkeypatch):
    api, builder = child(1, 0), child(2)
    monkeypatch.setattr(runtime, "launch", Mock(side_effect=[api, builder]))
    monkeypatch.setattr(runtime, "enabled", lambda: True)
    shutdown = Mock()
    monkeypatch.setattr(runtime, "shutdown", shutdown)
    assert runtime.run(Mock(wait=Mock(return_value=False))) == 1
    shutdown.assert_called_once_with([api, builder])


def test_disabled_preparation_only_launches_api(monkeypatch):
    launch = Mock(return_value=child(1))
    monkeypatch.setattr(runtime, "launch", launch)
    monkeypatch.setattr(runtime, "enabled", lambda: False)
    monkeypatch.setattr(runtime, "shutdown", Mock())
    assert runtime.run(Mock(wait=Mock(return_value=True))) == 0
    launch.assert_called_once_with()


def test_shutdown_grace_then_kill_releases_stuck_builder(monkeypatch):
    api, builder = child(1), child(2)
    builder.wait.side_effect = [subprocess.TimeoutExpired("builder", 25), 0]
    kill = Mock()
    monkeypatch.setattr(runtime.os, "killpg", kill)
    runtime.shutdown([api, builder])
    assert kill.call_args_list == [((1, signal.SIGTERM),), ((2, signal.SIGTERM),), ((2, signal.SIGKILL),)]
    assert builder.wait.call_count == 2


def test_launch_has_separate_interpreter_and_bounded_pool(monkeypatch):
    monkeypatch.setenv("PSAT_WORKER_LIFECYCLE_TOKEN", "must-not-inherit")
    monkeypatch.setenv("PSAT_WORKER_BOOT_ID", "must-not-inherit")
    popen = Mock()
    monkeypatch.setattr(runtime.subprocess, "Popen", popen)
    runtime.launch(True)
    args, kwargs = popen.call_args
    assert args[0][-2:] == ["-m", "workers.company_pages"]
    assert kwargs["start_new_session"] is True
    assert kwargs["env"]["PSAT_DB_POOL_SIZE"] == "2"
    assert "PSAT_WORKER_LIFECYCLE_TOKEN" not in kwargs["env"]
    assert "PSAT_WORKER_BOOT_ID" not in kwargs["env"]


def test_builder_launch_failure_still_stops_api(monkeypatch):
    api = child(1)
    monkeypatch.setattr(runtime, "launch", Mock(side_effect=[api, OSError("cannot spawn")]))
    monkeypatch.setattr(runtime, "enabled", lambda: True)
    shutdown = Mock()
    monkeypatch.setattr(runtime, "shutdown", shutdown)
    with pytest.raises(OSError):
        runtime.run(Mock())
    shutdown.assert_called_once_with([api])


def test_dedicated_builder_can_replace_colocated_builder(monkeypatch):
    monkeypatch.setenv("PSAT_PREPARED_COMPANY_PAGES", "1")
    assert runtime.enabled()
    monkeypatch.setenv("PSAT_COMPANY_BUILDER_ON_WEB", "0")
    assert not runtime.enabled()
