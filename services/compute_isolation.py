"""Heavy per-job compute in a child process with a memory and CPU-time budget.

The child is forked from a single-threaded fork server that never opened a DB connection, HTTP pool or thread, so it
inherits none of the worker's. The worker watches the child from outside: one that grows past its memory budget or
burns past its CPU budget is killed, with its descendants, and surfaces as :class:`ResourceExhausted`; no partial result
is ever returned. The child writes nothing to the database; it returns its result to the worker, which writes.
"""

from __future__ import annotations

import contextvars
import ctypes
import importlib
import logging
import multiprocessing
import os
import pickle
import resource
import signal
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from multiprocessing.context import BaseContext
from pathlib import Path
from typing import Any, TypeVar

from utils.logging import (
    address_var,
    chain_var,
    degraded_errors_var,
    job_id_var,
    record_stage_metric,
    stage_metrics_var,
    stage_var,
    trace_id_var,
    worker_id_var,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

RESOURCE_EXHAUSTED = "resource_exhausted"

# Imported once by the fork server so a job's child starts without paying for them.
_PRELOAD = (
    "db.models",
    "db.queue",
    "services.static.contract_analysis_pipeline.core",
    "services.resolution.capability_resolver",
    "services.policy.effective_permissions",
    "workers.policy_worker",
)

_POLL_S = 0.1
# A MemoryError in the child exits with this code: unwinding a near-full heap to report it could fail again.
_EXIT_MEMORY = 86
_PR_SET_PDEATHSIG = 1

# Set by the worker per job; a lost lease kills the job's child at once instead of letting it finish unused work.
compute_cancel_var: contextvars.ContextVar[threading.Event | None] = contextvars.ContextVar(
    "psat_compute_cancel", default=None
)


@dataclass(frozen=True)
class ComputeBudget:
    memory_bytes: int
    cpu_seconds: float


def _env_number(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def policy_budget() -> ComputeBudget:
    return ComputeBudget(
        memory_bytes=int(_env_number("PSAT_POLICY_COMPUTE_MEMORY_MB", 3072) * 1024 * 1024),
        cpu_seconds=_env_number("PSAT_POLICY_COMPUTE_CPU_S", 600),
    )


def static_budget() -> ComputeBudget:
    return ComputeBudget(
        memory_bytes=int(_env_number("PSAT_STATIC_COMPUTE_MEMORY_MB", 3072) * 1024 * 1024),
        cpu_seconds=_env_number("PSAT_STATIC_COMPUTE_CPU_S", 600),
    )


def isolation_enabled() -> bool:
    return os.getenv("PSAT_COMPUTE_ISOLATION", "1") != "0"


class ResourceExhausted(Exception):
    """The child ran past its memory or CPU budget. Deterministic for the same input: never retried."""

    def __init__(self, label: str, resource: str, used: float, limit: float):
        self.label = label
        self.resource = resource
        self.used = used
        self.limit = limit
        if resource == "cpu":
            amount = f"{used:.2f}s used, limit {limit:.2f}s"
        else:
            amount = f"{used:.0f} bytes used, limit {limit:.0f}"
        super().__init__(f"{label} exceeded its {resource} budget ({amount})")

    def __reduce__(self):
        return (type(self), (self.label, self.resource, self.used, self.limit))

    def detail(self) -> dict[str, Any]:
        return {"label": self.label, "resource": self.resource, "used": self.used, "limit": self.limit}


class ChildProcessFailed(RuntimeError):
    """The child died without a result and not by its budget: a crash, never published as a budget outcome."""


class ChildProcessKilled(ChildProcessFailed):
    """Something outside the worker killed the child (the kernel's OOM killer, an operator)."""


class RemoteTraceback(Exception):
    def __init__(self, text: str):
        self.text = text
        super().__init__(text)

    def __str__(self) -> str:
        return self.text


_context_lock = threading.Lock()
_context: BaseContext | None = None
_start_lock = threading.Lock()


def _get_context() -> BaseContext:
    global _context
    with _context_lock:
        if _context is None:
            ctx = multiprocessing.get_context("forkserver")
            ctx.set_forkserver_preload(list(_PRELOAD))
            _context = ctx
        return _context


def shutdown_fork_server() -> None:
    """Stop this process's fork server, so the next child starts from one that reads the current environment."""
    from multiprocessing import forkserver

    stop = getattr(forkserver._forkserver, "_stop", None)
    if stop is not None:
        stop()


def _reference(fn: Callable[..., Any]) -> tuple[str, str]:
    module = fn.__module__
    if module == "__main__":
        spec = getattr(sys.modules["__main__"], "__spec__", None)
        if spec is None or not spec.name:
            raise ValueError(f"{fn.__qualname__} lives in a script the child cannot import")
        module = spec.name
    return module, fn.__qualname__


def _resolve(reference: tuple[str, str]) -> Callable[..., Any]:
    target: Any = importlib.import_module(reference[0])
    for part in reference[1].split("."):
        target = getattr(target, part)
    return target


_CONTEXT_VARS = {
    "trace_id": trace_id_var,
    "job_id": job_id_var,
    "stage": stage_var,
    "worker_id": worker_id_var,
    "address": address_var,
    "chain": chain_var,
}


def _child_setup(parent_pid: int) -> None:
    # Its own process group, so a kill reaches the compilers it spawns; and dead with the fork server.
    os.setpgid(0, 0)
    try:
        ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    except (AttributeError, OSError):
        pass
    if os.getppid() != parent_pid:
        os._exit(1)
    # The worker drains in-flight jobs on SIGTERM and decides this child's fate itself.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    from db.models.session import engine

    engine.dispose(close=False)
    # The worker's sampler already reports descendants; a second one here would double-count.
    os.environ["PSAT_MEMORY_SAMPLE_INTERVAL_S"] = "0"
    from utils.logging import configure_logging

    configure_logging()


def _child_main(
    reference: tuple[str, str],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    result_path: str,
    log_context: dict[str, str | None],
    parent_pid: int,
) -> None:
    _child_setup(parent_pid)
    from utils.logging import bind_trace_context

    degraded: list[Any] = []
    metrics: dict[str, Any] = {}
    degraded_errors_var.set(degraded)
    stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(**log_context):
            value = _resolve(reference)(*args, **kwargs)
        envelope: tuple[Any, ...] = ("ok", value)
    except MemoryError:
        os._exit(_EXIT_MEMORY)
    except BaseException as exc:  # noqa: BLE001 — every failure goes back to the worker
        envelope = ("err", exc, traceback.format_exc())
    usage = resource.getrusage(resource.RUSAGE_SELF)
    spawned = resource.getrusage(resource.RUSAGE_CHILDREN)
    payload = (
        envelope,
        degraded,
        metrics,
        (usage.ru_utime + usage.ru_stime, usage.ru_maxrss * 1024, spawned.ru_utime + spawned.ru_stime),
    )
    tmp = result_path + ".tmp"
    try:
        with open(tmp, "wb") as fh:
            pickle.dump(payload, fh, protocol=pickle.HIGHEST_PROTOCOL)
    except MemoryError:
        os._exit(_EXIT_MEMORY)
    except Exception:
        if envelope[0] != "err":
            raise
        # An exception that doesn't pickle still reaches the worker, as text.
        fallback = ChildProcessFailed(f"{type(envelope[1]).__name__}: {envelope[1]}")
        with open(tmp, "wb") as fh:
            pickle.dump((("err", fallback, envelope[2]), *payload[1:]), fh, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, result_path)


_CLOCK_TICKS = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def _sample(pid: int) -> tuple[float, int] | None:
    """``(cpu seconds, resident bytes)`` of *pid*, or ``None`` once it is gone."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        statm = Path(f"/proc/{pid}/statm").read_text()
    except OSError:
        return None
    fields = stat.rsplit(") ", 1)[1].split()
    cpu = (int(fields[11]) + int(fields[12])) / _CLOCK_TICKS
    rss = int(statm.split()[1]) * _PAGE_SIZE
    return cpu, rss


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        os.kill(pid, signal.SIGKILL)


def run_isolated(
    fn: Callable[..., T],
    /,
    *args: Any,
    budget: ComputeBudget,
    label: str,
    **kwargs: Any,
) -> T:
    """``fn(*args, **kwargs)`` in a budgeted child; inline when ``PSAT_COMPUTE_ISOLATION=0``.

    Raises :class:`ResourceExhausted` on an overrun, the child's own exception when it raised, ``LeaseLost`` when the
    job's lease was lost meanwhile, and :class:`ChildProcessFailed` when it died otherwise. The child's degraded records
    and stage metrics join the caller's.
    """
    if not isolation_enabled():
        return fn(*args, **kwargs)
    from db.queue import LeaseLost

    reference = _reference(fn)
    ctx = _get_context()
    cancel = compute_cancel_var.get()
    log_context = {name: var.get() for name, var in _CONTEXT_VARS.items()}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="psat_compute_") as tmp:
        result_path = os.path.join(tmp, "result.pickle")
        with _start_lock:
            from multiprocessing import forkserver

            forkserver.ensure_running()
            # The child checks it is still the fork server's before it runs anything.
            process = ctx.Process(  # pyright: ignore[reportAttributeAccessIssue]
                target=_child_main,
                args=(reference, args, kwargs, result_path, log_context, _fork_server_pid()),
                name=f"psat-compute-{label}",
            )
            process.start()
        pid = process.pid
        assert pid is not None
        overrun: ResourceExhausted | None = None
        lease_lost = False
        cpu_used, peak_rss = 0.0, 0
        try:
            while True:
                process.join(_POLL_S)
                if process.exitcode is not None:
                    break
                sample = _sample(pid)
                if sample is not None:
                    cpu_used = sample[0]
                    peak_rss = max(peak_rss, sample[1])
                    if sample[1] > budget.memory_bytes:
                        overrun = ResourceExhausted(label, "memory", sample[1], budget.memory_bytes)
                    elif sample[0] > budget.cpu_seconds:
                        overrun = ResourceExhausted(label, "cpu", sample[0], budget.cpu_seconds)
                if cancel is not None and cancel.is_set():
                    lease_lost = True
                if overrun is not None or lease_lost:
                    _kill_group(pid)
                    process.join()
                    break
        except BaseException:
            _kill_group(pid)
            process.join()
            raise
        finally:
            exitcode = process.exitcode
            process.close()
        wall = time.monotonic() - started
        if overrun is not None:
            logger.warning(
                "isolated compute %s exceeded its %s budget",
                label,
                overrun.resource,
                extra={
                    "phase": "isolated_compute",
                    "outcome": RESOURCE_EXHAUSTED,
                    "compute_label": label,
                    "resource": overrun.resource,
                    "used": overrun.used,
                    "limit": overrun.limit,
                    "duration_ms": int(wall * 1000),
                },
            )
            raise overrun
        if lease_lost:
            raise LeaseLost(f"lease lost while {label} ran; its child was stopped")
        if exitcode == _EXIT_MEMORY:
            # The address-space cap the child inherited refused an allocation before the resident budget was reached.
            raise ResourceExhausted(label, "memory", peak_rss, _address_space_limit() or budget.memory_bytes)
        if exitcode != 0 or not os.path.exists(result_path):
            message = f"{label} child exited with {exitcode} and no result"
            if exitcode == -signal.SIGKILL:
                raise ChildProcessKilled(message)
            raise ChildProcessFailed(message)
        with open(result_path, "rb") as fh:
            envelope, degraded, metrics, (cpu_used, child_peak_rss, spawned_cpu) = pickle.load(fh)
            peak_rss = max(peak_rss, child_peak_rss)
    accumulator = degraded_errors_var.get()
    if accumulator is not None:
        accumulator.extend(degraded)
    for key, value in metrics.items():
        record_stage_metric(key, value)
    record_stage_metric(f"isolated_{label}_cpu_s", round(cpu_used, 3))
    record_stage_metric(f"isolated_{label}_peak_rss_bytes", peak_rss)
    record_stage_metric(f"isolated_{label}_subprocess_cpu_s", round(spawned_cpu, 3))
    if envelope[0] == "err":
        raise envelope[1] from RemoteTraceback(envelope[2])
    return envelope[1]


def _address_space_limit() -> int | None:
    soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    return None if soft == resource.RLIM_INFINITY else soft


def _fork_server_pid() -> int:
    from multiprocessing import forkserver

    pid = getattr(forkserver._forkserver, "_forkserver_pid", None)
    if not isinstance(pid, int):
        raise ChildProcessFailed("fork server did not start")
    return pid
