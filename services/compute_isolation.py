"""Heavy per-job compute in a child process with a memory and CPU-time budget.

Children are forked from a single-threaded fork server that never opened a DB connection, HTTP pool or thread, so
they inherit none of the worker's. Each child serves one job at a time and stays warm for the worker's next job, as
the worker process itself used to: its connections, clients and caches are its own. The worker watches the child from
outside while a job runs: one that grows past the memory budget or spends past the job's CPU budget is killed with its
descendants and replaced, and the job surfaces :class:`ResourceExhausted`; no partial result is ever returned. The child
writes nothing to the database; it returns its result to the worker, which writes.
"""

from __future__ import annotations

import atexit
import contextvars
import ctypes
import gc
import importlib
import logging
import multiprocessing
import os
import resource
import signal
import sys
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
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

# Imported once by the fork server (from the worker's working directory, the repository root) so a new child starts
# without paying for them; the last one finishes the setup each child would otherwise repeat.
_PRELOAD = (
    "db.models",
    "db.queue",
    "services.static.contract_analysis_pipeline.core",
    "services.resolution.capability_resolver",
    "services.policy.effective_permissions",
    "workers.policy_worker",
    "services.compute_warmup",
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


def warm_fork_server() -> None:
    """The first-use setup every child would otherwise repeat on its first job, done once in the fork server.

    Nothing here opens a connection: mapper configuration is in memory and the storage client connects lazily.
    """
    from sqlalchemy.orm import configure_mappers

    import db.models  # noqa: F401 — every mapper must be registered before configuring
    from db.storage import get_storage_client

    configure_mappers()
    get_storage_client()
    # Everything so far lives as long as the server: the children's collections then skip it, and its pages stay shared.
    gc.freeze()


def _child_setup(server_pid: int) -> None:
    # Its own process group, so a kill reaches the compilers it spawns; and dead with the fork server.
    os.setpgid(0, 0)
    try:
        ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    except (AttributeError, OSError):
        pass
    if os.getppid() != server_pid:
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


def _reset_peak_rss() -> bool:
    try:
        Path("/proc/self/clear_refs").write_text("5")
    except OSError:
        return False
    return True


def _peak_rss() -> int:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def _cpu(who: int) -> float:
    usage = resource.getrusage(who)
    return usage.ru_utime + usage.ru_stime


def _child_loop(conn: Connection, server_pid: int) -> None:
    _child_setup(server_pid)
    from utils.logging import bind_trace_context

    while True:
        try:
            reference, args, kwargs, log_context = conn.recv()
        except EOFError:
            return
        degraded: list[Any] = []
        metrics: dict[str, Any] = {}
        degraded_token = degraded_errors_var.set(degraded)
        metrics_token = stage_metrics_var.set(metrics)
        peak_known = _reset_peak_rss()
        cpu0, spawned0 = _cpu(resource.RUSAGE_SELF), _cpu(resource.RUSAGE_CHILDREN)
        try:
            with bind_trace_context(**log_context):
                envelope: tuple[Any, ...] = ("ok", _resolve(reference)(*args, **kwargs))
        except MemoryError:
            os._exit(_EXIT_MEMORY)
        except Exception as exc:
            envelope = ("err", exc, traceback.format_exc())
        except BaseException as exc:  # noqa: BLE001 — never re-raise a SystemExit inside the worker
            envelope = ("err", ChildProcessFailed(f"{type(exc).__name__}: {exc}"), traceback.format_exc())
        finally:
            degraded_errors_var.reset(degraded_token)
            stage_metrics_var.reset(metrics_token)
        usage = (
            _cpu(resource.RUSAGE_SELF) - cpu0,
            _peak_rss() if peak_known else 0,
            _cpu(resource.RUSAGE_CHILDREN) - spawned0,
        )
        try:
            conn.send((envelope, degraded, metrics, usage))
        except MemoryError:
            os._exit(_EXIT_MEMORY)
        except Exception as exc:
            # A result or exception that doesn't pickle still reaches the worker, as a failure.
            text = envelope[2] if envelope[0] == "err" else ""
            message = f"{reference[1]} returned a result that does not pickle: {type(exc).__name__}: {exc}"
            if envelope[0] == "err":
                message = f"{type(envelope[1]).__name__}: {envelope[1]}"
            conn.send((("err", ChildProcessFailed(message), text), degraded, metrics, usage))


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


@dataclass
class _Child:
    process: Any
    conn: Connection
    idle_since: float = field(default_factory=time.monotonic)

    @property
    def pid(self) -> int:
        return self.process.pid

    def discard(self) -> None:
        _kill_group(self.pid)
        self.process.join()
        self.conn.close()
        self.process.close()


class _Pool:
    """Idle warm children of this worker process; one per job running at once, never shared between jobs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._idle: list[_Child] = []
        self._live: set[int] = set()
        self._context: BaseContext | None = None
        self._exit_hook = False

    def _ctx(self) -> BaseContext:
        if self._context is None:
            ctx = multiprocessing.get_context("forkserver")
            ctx.set_forkserver_preload(list(_PRELOAD))
            self._context = ctx
        return self._context

    def acquire(self) -> _Child:
        stale: list[_Child] = []
        chosen: _Child | None = None
        now = time.monotonic()
        with self._lock:
            while self._idle:
                child = self._idle.pop()
                if not child.process.is_alive() or now - child.idle_since > _env_number("PSAT_COMPUTE_IDLE_S", 300):
                    stale.append(child)
                    continue
                chosen = child
                break
            for child in stale:
                self._live.discard(child.pid)
                child.discard()
            if chosen is not None:
                return chosen
            from multiprocessing import forkserver

            ctx = self._ctx()
            forkserver.ensure_running()
            server_pid = getattr(forkserver._forkserver, "_forkserver_pid", None)
            if not isinstance(server_pid, int):
                raise ChildProcessFailed("fork server did not start")
            parent_end, child_end = ctx.Pipe()
            process = ctx.Process(  # pyright: ignore[reportAttributeAccessIssue]
                target=_child_loop, args=(child_end, server_pid), name="psat-compute", daemon=False
            )
            process.start()
            child_end.close()
            if not self._exit_hook:
                # Before multiprocessing's own exit hook, which would wait forever on a child idling for its next job.
                atexit.register(self.shutdown)
                self._exit_hook = True
            self._live.add(process.pid)
            return _Child(process, parent_end)

    def release(self, child: _Child) -> None:
        sample = _sample(child.pid)
        retire_bytes = _env_number("PSAT_COMPUTE_RETIRE_RSS_MB", 512) * 1024 * 1024
        if sample is None or sample[1] > retire_bytes:
            # A child that kept a large heap would carry it into every later job.
            self.forget(child)
            return
        child.idle_since = time.monotonic()
        with self._lock:
            # Enough warm children for the jobs a worker runs at once; a burst's extras would only hold memory.
            if len(self._idle) < int(_env_number("PSAT_COMPUTE_MAX_IDLE", 2)):
                self._idle.append(child)
                return
        self.forget(child)

    def forget(self, child: _Child) -> None:
        with self._lock:
            self._live.discard(child.pid)
        child.discard()

    def shutdown(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
            live, self._live = self._live, set()
        for child in idle:
            child.discard()
        for pid in live:
            _kill_group(pid)
        from multiprocessing import forkserver

        stop = getattr(forkserver._forkserver, "_stop", None)
        if stop is not None:
            stop()
        self._context = None


_pool = _Pool()


def shutdown_children() -> None:
    """Retire every idle child and stop the fork server, so the next child starts from the current environment."""
    _pool.shutdown()


def _dispatch(request: tuple[Any, ...]) -> tuple[_Child, tuple[float, int] | None]:
    """Hand *request* to a warm child, replacing one that died while idle; its usage sampled just before."""
    child = _pool.acquire()
    baseline = _sample(child.pid)
    try:
        child.conn.send(request)
        return child, baseline
    except (BrokenPipeError, ConnectionResetError):
        _pool.forget(child)
    except BaseException:
        _pool.forget(child)
        raise
    child = _pool.acquire()
    baseline = _sample(child.pid)
    try:
        child.conn.send(request)
    except BaseException:
        _pool.forget(child)
        raise
    return child, baseline


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
    cancel = compute_cancel_var.get()
    log_context = {name: var.get() for name, var in _CONTEXT_VARS.items()}
    started = time.monotonic()
    child, baseline = _dispatch((reference, args, kwargs, log_context))
    pid = child.pid
    cpu0 = baseline[0] if baseline is not None else 0.0
    peak_rss = baseline[1] if baseline is not None else 0
    overrun: ResourceExhausted | None = None
    lease_lost = False
    reply: Any = None
    try:
        while True:
            if child.conn.poll(_POLL_S):
                try:
                    reply = child.conn.recv()
                except (EOFError, ConnectionResetError):
                    reply = None
                break
            if not child.process.is_alive():
                break
            sample = _sample(pid)
            if sample is not None:
                peak_rss = max(peak_rss, sample[1])
                if sample[1] > budget.memory_bytes:
                    overrun = ResourceExhausted(label, "memory", sample[1], budget.memory_bytes)
                elif sample[0] - cpu0 > budget.cpu_seconds:
                    overrun = ResourceExhausted(label, "cpu", sample[0] - cpu0, budget.cpu_seconds)
            if cancel is not None and cancel.is_set():
                lease_lost = True
            if overrun is not None or lease_lost:
                break
    except BaseException:
        _pool.forget(child)
        raise
    if reply is None:
        if overrun is None and not lease_lost:
            child.process.join(5)
        exitcode = child.process.exitcode
        _pool.forget(child)
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
                    "duration_ms": int((time.monotonic() - started) * 1000),
                },
            )
            raise overrun
        if lease_lost:
            raise LeaseLost(f"lease lost while {label} ran; its child was stopped")
        if exitcode == _EXIT_MEMORY:
            # The address-space cap the child inherited refused an allocation before the resident budget was reached.
            raise ResourceExhausted(label, "memory", peak_rss, _address_space_limit() or budget.memory_bytes)
        message = f"{label} child exited with {exitcode} and no result"
        if exitcode == -signal.SIGKILL:
            raise ChildProcessKilled(message)
        raise ChildProcessFailed(message)
    _pool.release(child)
    envelope, degraded, metrics, (cpu_used, child_peak_rss, spawned_cpu) = reply
    accumulator = degraded_errors_var.get()
    if accumulator is not None:
        accumulator.extend(degraded)
    for key, value in metrics.items():
        record_stage_metric(key, value)
    record_stage_metric(f"isolated_{label}_cpu_s", round(cpu_used, 3))
    record_stage_metric(f"isolated_{label}_peak_rss_bytes", child_peak_rss or peak_rss)
    record_stage_metric(f"isolated_{label}_subprocess_cpu_s", round(spawned_cpu, 3))
    if envelope[0] == "err":
        raise envelope[1] from RemoteTraceback(envelope[2])
    return envelope[1]


def _address_space_limit() -> int | None:
    soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    return None if soft == resource.RLIM_INFINITY else soft
