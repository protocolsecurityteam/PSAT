"""Tests for utils/memory.py — the introspection helpers wired into BaseWorker.

These deliberately don't assert exact RSS values (host-dependent); they just
pin behaviour: helpers don't crash on dev hosts (no cgroup v2), the cache-
pressure message fires once per threshold and resets cleanly.
"""

from __future__ import annotations

import os

from utils.memory import (
    _vmrss_bytes,
    cache_pressure_message,
    cgroup_memory_max_bytes,
    count_sibling_python_procs,
    current_rss_bytes,
    mb,
    reset_cache_pressure_state,
    rss_bytes_for_pid,
)


def test_current_rss_bytes_returns_positive_or_zero():
    rss = current_rss_bytes()
    # Linux returns a real value; non-Linux returns 0. Neither should raise.
    assert isinstance(rss, int)
    assert rss >= 0


def test_rss_bytes_for_pid_live_and_dead():
    # This process is alive → a real value on Linux, 0 on non-Linux; a pid that
    # cannot exist → 0 without raising.
    assert rss_bytes_for_pid(os.getpid()) >= 0
    assert rss_bytes_for_pid(-1) == 0
    # A pid well past any plausible live process: gone → /proc/<pid>/status absent.
    assert rss_bytes_for_pid(2**31 - 1) == 0


def test_vmrss_bytes_parses_fixture_and_tolerates_missing(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tanvil\nVmPeak:\t  200000 kB\nVmRSS:\t   13648 kB\n")
    assert _vmrss_bytes(status) == 13648 * 1024
    # No VmRSS line → 0; unreadable path → 0 (never raises).
    (tmp_path / "no_rss").write_text("Name:\tanvil\n")
    assert _vmrss_bytes(tmp_path / "no_rss") == 0
    assert _vmrss_bytes(tmp_path / "does_not_exist") == 0


def test_cgroup_helpers_dont_crash_on_dev_host():
    # On a dev host without cgroup v2 these all return None or 0.
    # On a Fly machine they return ints. Both are fine.
    cgroup_memory_max_bytes()  # no exception
    assert isinstance(count_sibling_python_procs(), int)


def test_mb_format():
    assert mb(0) == "0"
    assert mb(1024 * 1024) == "1"
    assert mb(2 * 1024 * 1024 * 1024) == "2048"
    assert mb(None) == "?"


def test_cache_pressure_fires_once_per_threshold():
    reset_cache_pressure_state("test_cache")

    # 40% — under the lowest threshold, no message.
    assert cache_pressure_message("test_cache", 40, 100) is None

    # 50% — first crossing.
    msg = cache_pressure_message("test_cache", 50, 100)
    assert msg is not None and "test_cache" in msg and "50/100" in msg

    # Repeat 50% — already logged, no message.
    assert cache_pressure_message("test_cache", 55, 100) is None

    # 76% — next threshold (75%).
    msg = cache_pressure_message("test_cache", 76, 100)
    assert msg is not None and "76/100" in msg

    # 95% — top threshold.
    msg = cache_pressure_message("test_cache", 95, 100)
    assert msg is not None and "95/100" in msg

    # Already at 95%, growing further is silent.
    assert cache_pressure_message("test_cache", 99, 100) is None


def test_cache_pressure_skips_to_top_threshold():
    """Going from 0 to ≥95% in one jump should fire once and stay there."""
    reset_cache_pressure_state("jumpy")

    msg = cache_pressure_message("jumpy", 96, 100)
    assert msg is not None and "96/100" in msg
    # No going back to lower thresholds.
    assert cache_pressure_message("jumpy", 50, 100) is None


def test_reset_cache_pressure_state_per_name():
    reset_cache_pressure_state("a")
    reset_cache_pressure_state("b")
    cache_pressure_message("a", 50, 100)
    cache_pressure_message("b", 50, 100)

    reset_cache_pressure_state("a")
    # Only 'a' was reset — 'b' still suppressed.
    assert cache_pressure_message("a", 50, 100) is not None
    assert cache_pressure_message("b", 60, 100) is None


def test_reset_cache_pressure_state_all():
    reset_cache_pressure_state("x")
    reset_cache_pressure_state("y")
    cache_pressure_message("x", 50, 100)
    cache_pressure_message("y", 50, 100)

    reset_cache_pressure_state(None)
    # Both should fire again.
    assert cache_pressure_message("x", 50, 100) is not None
    assert cache_pressure_message("y", 50, 100) is not None


def test_cache_pressure_handles_zero_max():
    # max_size=0 used to be a divide-by-zero — must return None safely.
    assert cache_pressure_message("zero_cache", 0, 0) is None
    assert cache_pressure_message("zero_cache", 5, 0) is None
