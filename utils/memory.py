"""Lightweight memory introspection helpers (Linux /proc + cgroup v2, no extra deps).

Used by workers/base.py to log per-process and per-job RSS so we can attribute
OOM kills back to specific worker × job pairs without pulling in psutil.

All functions return ``None`` (or an empty/zero default) on non-Linux hosts
or when the relevant proc/cgroup file is unreadable, so callers can use them
unconditionally.
"""

from __future__ import annotations

import os
from pathlib import Path

_PROC_STATUS = Path("/proc/self/status")
_PROC_MEMINFO = Path("/proc/meminfo")

# cgroup v2 paths (modern hosts)
_CGROUP_V2_MAX = Path("/sys/fs/cgroup/memory.max")
_CGROUP_V2_CURRENT = Path("/sys/fs/cgroup/memory.current")
_CGROUP_V2_PEAK = Path("/sys/fs/cgroup/memory.peak")

# cgroup v1 paths (Fly machines as of 2026, plus older Linux containers)
_CGROUP_V1_MAX = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
_CGROUP_V1_CURRENT = Path("/sys/fs/cgroup/memory/memory.usage_in_bytes")
_CGROUP_V1_PEAK = Path("/sys/fs/cgroup/memory/memory.max_usage_in_bytes")

# v1 unset-sentinel: kernel reports a near-2^63 value when no limit is set
# at this level (the actual cap lives on a parent cgroup). Treat anything
# above this as "no limit visible here, look at /proc/meminfo instead".
_CGROUP_V1_UNSET_SENTINEL = 1 << 60


def _vmrss_bytes(status_path: Path) -> int:
    """VmRSS from a ``/proc/<pid>/status`` file in bytes; 0 if the file is
    unreadable (process gone, non-Linux) or has no VmRSS line."""
    try:
        for line in status_path.read_text().splitlines():
            if line.startswith("VmRSS:"):
                # "VmRSS:    13648 kB"
                return int(line.split()[1]) * 1024
    except Exception:
        return 0
    return 0


def current_rss_bytes() -> int:
    """RSS of this process in bytes; 0 if /proc/self/status is unreadable."""
    return _vmrss_bytes(_PROC_STATUS)


def rss_bytes_for_pid(pid: int) -> int:
    """RSS of process *pid* in bytes; 0 if the process is gone, /proc is
    unreadable, or the host is non-Linux. Never raises."""
    return _vmrss_bytes(Path(f"/proc/{pid}/status"))


def _read_cgroup_int(path: Path) -> int | None:
    try:
        text = path.read_text().strip()
    except Exception:
        return None
    if text == "max":
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _meminfo_kb(field: str) -> int | None:
    """Parse a kB value from /proc/meminfo. None if unreadable / field absent."""
    try:
        for line in _PROC_MEMINFO.read_text().splitlines():
            if line.startswith(f"{field}:"):
                return int(line.split()[1])  # kB
    except Exception:
        return None
    return None


def cgroup_memory_max_bytes() -> int | None:
    """Container memory limit. Tries cgroup v2 → cgroup v1 → /proc/meminfo
    MemTotal (which reflects the cgroup cap on most container runtimes).
    Returns None only on hosts where none of these are readable."""
    v2 = _read_cgroup_int(_CGROUP_V2_MAX)
    if v2 is not None:
        return v2
    v1 = _read_cgroup_int(_CGROUP_V1_MAX)
    if v1 is not None and v1 < _CGROUP_V1_UNSET_SENTINEL:
        return v1
    mem_total_kb = _meminfo_kb("MemTotal")
    if mem_total_kb is not None:
        return mem_total_kb * 1024
    return None


def cgroup_memory_current_bytes() -> int | None:
    """Aggregate RSS across all processes in the cgroup. Tries cgroup v2 →
    cgroup v1 → MemTotal-MemAvailable from /proc/meminfo."""
    v2 = _read_cgroup_int(_CGROUP_V2_CURRENT)
    if v2 is not None:
        return v2
    v1 = _read_cgroup_int(_CGROUP_V1_CURRENT)
    if v1 is not None:
        return v1
    total_kb = _meminfo_kb("MemTotal")
    avail_kb = _meminfo_kb("MemAvailable")
    if total_kb is not None and avail_kb is not None:
        return (total_kb - avail_kb) * 1024
    return None


def cgroup_memory_peak_bytes() -> int | None:
    """High-water mark of cgroup memory since boot. cgroup v2 → cgroup v1.
    /proc/meminfo doesn't track this, so falls through to None."""
    v2 = _read_cgroup_int(_CGROUP_V2_PEAK)
    if v2 is not None:
        return v2
    return _read_cgroup_int(_CGROUP_V1_PEAK)


def count_sibling_python_procs() -> int:
    """Number of python processes visible in /proc — approximation of the
    fleet shape inside this VM. Returns 0 on non-Linux / restricted /proc."""
    n = 0
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                comm = Path(f"/proc/{entry}/comm").read_text().strip()
            except Exception:
                continue
            if comm.startswith("python"):
                n += 1
    except Exception:
        return 0
    return n


def mb(bytes_value: int | None) -> str:
    """Format bytes as MB (no decimals); '?' for None."""
    if bytes_value is None:
        return "?"
    return f"{bytes_value / (1024 * 1024):.0f}"


# ---------------------------------------------------------------------------
# Cache-pressure threshold tracking
# ---------------------------------------------------------------------------

# {cache_name: highest_threshold_pct_logged}; reset via reset_cache_pressure_state.
_CACHE_PRESSURE_STATE: dict[str, int] = {}


def cache_pressure_message(name: str, current: int, max_size: int) -> str | None:
    """Return a one-line pressure message when *current* crosses 50/75/95% of
    *max_size* for the first time; None otherwise. Per-name state, in-memory.

    Caller should ``logger.info("[CACHE_PRESSURE] %s", msg)`` when non-None.
    """
    if max_size <= 0:
        return None
    pct = (current / max_size) * 100
    last = _CACHE_PRESSURE_STATE.get(name, 0)
    for threshold in (95, 75, 50):
        if pct >= threshold > last:
            _CACHE_PRESSURE_STATE[name] = threshold
            return f"cache={name} size={current}/{max_size} ({pct:.0f}%)"
    return None


def reset_cache_pressure_state(name: str | None = None) -> None:
    """Forget the last threshold for *name* (or clear all if None). Call from
    cache ``clear_*`` helpers so post-test/manual resets don't suppress the
    next genuine pressure event."""
    if name is None:
        _CACHE_PRESSURE_STATE.clear()
    else:
        _CACHE_PRESSURE_STATE.pop(name, None)
