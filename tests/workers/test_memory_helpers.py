"""RSS values are host-dependent, so these pin behaviour, not numbers."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from utils.memory import (
    _vmrss_bytes,
    cache_pressure_message,
    cgroup_anon_file_bytes,
    cgroup_memory_max_bytes,
    count_sibling_python_procs,
    descendant_rss_samples,
    mb,
    reset_cache_pressure_state,
)


def test_descendant_sampler_sees_worker_owned_subprocess():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
    try:
        for _ in range(20):
            samples = descendant_rss_samples(os.getpid())
            if any(pid == child.pid and rss > 0 for pid, _ppid, _name, _start, rss in samples):
                break
            time.sleep(0.01)
        else:
            assert os.name != "posix", "live child was not sampled"
    finally:
        child.terminate()
        child.wait(timeout=3)


def test_vmrss_bytes_parses_fixture_and_tolerates_missing(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tanvil\nVmPeak:\t  200000 kB\nVmRSS:\t   13648 kB\n")
    assert _vmrss_bytes(status) == 13648 * 1024
    (tmp_path / "no_rss").write_text("Name:\tanvil\n")
    assert _vmrss_bytes(tmp_path / "no_rss") == 0
    assert _vmrss_bytes(tmp_path / "does_not_exist") == 0


def test_cgroup_helpers_dont_crash_on_dev_host():
    # None or 0 on a dev host without cgroup v2; ints on Fly.
    cgroup_memory_max_bytes()  # no exception
    anon, file = cgroup_anon_file_bytes()
    assert anon is None or anon >= 0
    assert file is None or file >= 0
    assert isinstance(count_sibling_python_procs(), int)


def test_mb_format():
    assert mb(0) == "0"
    assert mb(1024 * 1024) == "1"
    assert mb(2 * 1024 * 1024 * 1024) == "2048"
    assert mb(None) == "?"


def test_cache_pressure_fires_once_per_threshold():
    reset_cache_pressure_state("test_cache")

    assert cache_pressure_message("test_cache", 40, 100) is None

    msg = cache_pressure_message("test_cache", 50, 100)
    assert msg is not None and "test_cache" in msg and "50/100" in msg

    assert cache_pressure_message("test_cache", 55, 100) is None

    msg = cache_pressure_message("test_cache", 76, 100)
    assert msg is not None and "76/100" in msg

    msg = cache_pressure_message("test_cache", 95, 100)
    assert msg is not None and "95/100" in msg

    assert cache_pressure_message("test_cache", 99, 100) is None


@pytest.mark.parametrize(
    ("reset_arg", "y_level", "y_fires_again"),
    [
        pytest.param("x", 60, False, id="per_name"),
        pytest.param(None, 50, True, id="all"),
    ],
)
def test_reset_cache_pressure_state(reset_arg, y_level, y_fires_again):
    reset_cache_pressure_state("x")
    reset_cache_pressure_state("y")
    cache_pressure_message("x", 50, 100)
    cache_pressure_message("y", 50, 100)

    reset_cache_pressure_state(reset_arg)
    assert cache_pressure_message("x", 50, 100) is not None
    assert (cache_pressure_message("y", y_level, 100) is not None) is y_fires_again
