"""Lightweight memory introspection helpers (Linux /proc + cgroups, no extra deps).

Used by the logging bootstrap and worker lifecycle to sample process RSS and
record the process peak observed while each job ran, without pulling in psutil.

All functions return ``None`` (or an empty/zero default) on non-Linux hosts
or when the relevant proc/cgroup file is unreadable, so callers can use them
unconditionally.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
import uuid
from pathlib import Path

_PROC_STATUS = Path("/proc/self/status")
_PROC_MEMINFO = Path("/proc/meminfo")

# cgroup v2 paths (modern hosts)
_CGROUP_V2_MAX = Path("/sys/fs/cgroup/memory.max")
_CGROUP_V2_CURRENT = Path("/sys/fs/cgroup/memory.current")

# cgroup v1 paths (Fly machines as of 2026, plus older Linux containers)
_CGROUP_V1_MAX = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
_CGROUP_V1_CURRENT = Path("/sys/fs/cgroup/memory/memory.usage_in_bytes")

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
    """Cgroup memory charge, including file cache; not a sum of process RSS."""
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


def cgroup_anon_file_bytes() -> tuple[int | None, int | None]:
    """Anonymous and file-backed portions of the cgroup charge, when visible."""
    for path, anon_key, file_key in (
        (Path("/sys/fs/cgroup/memory.stat"), "anon", "file"),
        (Path("/sys/fs/cgroup/memory/memory.stat"), "total_rss", "total_cache"),
    ):
        try:
            values = dict(line.split() for line in path.read_text().splitlines() if len(line.split()) == 2)
            if anon_key in values and file_key in values:
                return int(values[anon_key]), int(values[file_key])
        except (OSError, ValueError):
            continue
    return None, None


def descendant_rss_samples(parent_pid: int) -> list[tuple[int, int, str, str, int]]:
    """Visible descendants as (pid, ppid, name, start-ticks, RSS)."""
    children: dict[int, list[tuple[int, str, str]]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            name, tail = stat.rsplit(") ", 1)
            fields = tail.split()
            ppid = int(fields[1])
            start_ticks = fields[19]
            children.setdefault(ppid, []).append((pid, name.split("(", 1)[1], start_ticks))
        except (OSError, ValueError, IndexError):
            continue
    found: list[tuple[int, int, str, str, int]] = []
    pending = [parent_pid]
    while pending:
        owner = pending.pop()
        for pid, name, start_ticks in children.get(owner, ()):
            pending.append(pid)
            rss = rss_bytes_for_pid(pid)
            if rss:
                found.append((pid, owner, name, start_ticks, rss))
    return found


class JobRssSpan:
    """Sampled process RSS while a job runs, shared by concurrent jobs."""

    def __init__(self, sampler: "ProcessMemorySampler | None") -> None:
        self._sampler = sampler
        self.start_bytes = current_rss_bytes()
        self.peak_bytes = self.start_bytes
        self._finished: dict[str, int] | None = None
        if sampler is not None:
            with sampler._lock:
                sampler._jobs.add(self)

    def finish(self) -> dict[str, int]:
        lock = self._sampler._lock if self._sampler is not None else threading.Lock()
        with lock:
            if self._finished is None:
                end = current_rss_bytes()
                self.peak_bytes = max(self.peak_bytes, end)
                if self._sampler is not None:
                    self._sampler._jobs.discard(self)
                self._finished = {
                    "process_rss_start_bytes": self.start_bytes,
                    "process_rss_peak_sampled_bytes": self.peak_bytes,
                    "process_rss_end_bytes": end,
                }
            return dict(self._finished)


class ProcessMemorySampler:
    """One passive sampler per Python process; no DB writes or supervisor."""

    def __init__(self, interval_s: float) -> None:
        self.pid = os.getpid()
        self.generation = uuid.uuid4().hex[:12]
        self._interval_s = interval_s
        self._lock = threading.Lock()
        self._jobs: set[JobRssSpan] = set()
        self._thread = threading.Thread(target=self._run, name="memory-sampler", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        logger = logging.getLogger(__name__)
        while True:
            # Forked children get their own sampler on configure_logging().
            if os.getpid() != self.pid:
                return
            rss = current_rss_bytes()
            with self._lock:
                for job in self._jobs:
                    job.peak_bytes = max(job.peak_bytes, rss)
            anon, file = cgroup_anon_file_bytes()
            logger.info(
                "process memory sample",
                extra={
                    "phase": "process_memory",
                    "pid": self.pid,
                    "process_generation": self.generation,
                    "process_name": Path(sys.argv[0]).name,
                    "machine_id": os.getenv("FLY_MACHINE_ID"),
                    "process_group": os.getenv("FLY_PROCESS_GROUP"),
                    "process_rss_bytes": rss,
                    "cgroup_used_bytes": cgroup_memory_current_bytes(),
                    "cgroup_limit_bytes": cgroup_memory_max_bytes(),
                    "cgroup_anon_bytes": anon,
                    "cgroup_file_bytes": file,
                },
            )
            # Worker-owned forge/Slither/Chromium children are outside Python's
            # own RSS. The machine-runtime parent skips this traversal because
            # its Python children sample themselves and their own descendants.
            if Path(sys.argv[0]).stem != "machine_runtime":
                for pid, ppid, name, start_ticks, child_rss in descendant_rss_samples(self.pid):
                    logger.info(
                        "process memory sample",
                        extra={
                            "phase": "process_memory",
                            "pid": pid,
                            "parent_pid": ppid,
                            "process_generation": start_ticks,
                            "process_name": name,
                            "machine_id": os.getenv("FLY_MACHINE_ID"),
                            "process_group": os.getenv("FLY_PROCESS_GROUP"),
                            "process_rss_bytes": child_rss,
                        },
                    )
            time.sleep(self._interval_s)


_sampler: ProcessMemorySampler | None = None
_sampler_lock = threading.Lock()


def start_memory_sampler() -> ProcessMemorySampler | None:
    """Start idempotently when the deployment enables cadence sampling."""
    global _sampler
    raw = os.getenv("PSAT_MEMORY_SAMPLE_INTERVAL_S", "")
    try:
        interval = float(raw)
    except ValueError:
        return None
    if interval <= 0:
        return None
    with _sampler_lock:
        if _sampler is None or _sampler.pid != os.getpid():
            _sampler = ProcessMemorySampler(interval)
        return _sampler


def start_job_rss_span() -> JobRssSpan:
    return JobRssSpan(start_memory_sampler())


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
