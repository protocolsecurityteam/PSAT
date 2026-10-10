"""Structured JSON logging + ``trace_id`` propagation via contextvars.

Level contract:

    ``ERROR``    Job-failing: the exception propagates out of ``process()``. Never from an ``except`` that
                 returns or continues; demote to WARNING.
    ``WARNING``  Degraded but continuing. Inside a swallowed ``except`` in pipeline code it MUST pair with
                 :func:`record_degraded` (enforced by ``tests/meta/test_log_level_contract.py``).
    ``INFO``     Lifecycle, one per real event.
    ``DEBUG``    Per-RPC / per-iteration noise.

``logger.exception`` is ERROR with a traceback: only in re-raising handlers. In a swallowed handler use
``logger.warning(..., extra={"exc_type": ...})``. Exemption: ``workers/base.py``'s keep-alive paths keep
``logger.exception`` deliberately; new stage code doesn't inherit that.

Contextvars don't cross threads: wrap pool submissions in ``copy_context().run`` (``parallel_map`` does).
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import resource
import subprocess
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterator

from utils.secrets import sanitize_obj, sanitize_string

if TYPE_CHECKING:
    from schemas.stage_errors import StageError

trace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_trace_id", default=None)
job_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_job_id", default=None)
stage_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_stage", default=None)
worker_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_worker_id", default=None)
address_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_address", default=None)
chain_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_chain", default=None)

# Per-job degraded-failure list, bound fresh by ``BaseWorker`` per job; ``None`` outside a job makes calls no-ops.
degraded_errors_var: contextvars.ContextVar[list["StageError"] | None] = contextvars.ContextVar(
    "psat_degraded_errors", default=None
)

# Per-job stage metrics folded into ``stage_timing_<stage>``; ``None`` outside a job makes calls no-ops.
stage_metrics_var: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "psat_stage_metrics", default=None
)

# Deny-list for the ``extra`` catch-all below.
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        # uvicorn's ANSI-coloured duplicate of ``message``.
        "color_message",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)


def _scrub_field(value: Any) -> Any:
    """Credentialed URLs can hide in string or nested ``extra`` values; non-string scalars pass through."""
    if isinstance(value, str):
        return sanitize_string(value)
    if isinstance(value, (dict, list)):
        return sanitize_obj(value)
    return value


class JsonFormatter(logging.Formatter):
    """Single-line JSON per record.

    Unset context fields are omitted rather than ``null`` to avoid indexing empty cardinality.
    """

    _CONTEXT_FIELDS: tuple[tuple[str, contextvars.ContextVar[str | None]], ...] = (
        ("trace_id", trace_id_var),
        ("job_id", job_id_var),
        ("stage", stage_var),
        ("worker_id", worker_id_var),
        ("address", address_var),
        ("chain", chain_var),
    )

    def format(self, record: logging.LogRecord) -> str:
        # ``formatTime`` goes through ``time.strftime``, which doesn't expand ``%f``.
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds")
        if ts.endswith("+00:00"):
            ts = ts[: -len("+00:00")] + "Z"
        # Last hop before the sink, so secret scrubbing is enforced here for every record.
        payload: dict[str, Any] = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize_string(record.getMessage()),
        }
        for key, var in self._CONTEXT_FIELDS:
            value = var.get()
            if value is not None:
                payload[key] = value
        for attr, value in record.__dict__.items():
            if attr in _RESERVED_RECORD_ATTRS or attr.startswith("_"):
                continue
            if attr in payload:
                continue
            payload[attr] = _scrub_field(value)
        if record.exc_info:
            payload["exc_info"] = sanitize_string(self.formatException(record.exc_info))
        if record.stack_info:
            payload["stack_info"] = sanitize_string(self.formatStack(record.stack_info))
        return json.dumps(payload, default=str)


class CryticCompileEchoDemoter(logging.Filter):
    """Demote crytic-compile's subprocess stdout/stderr echoes off ERROR.

    It logs a failed build's output at ERROR beside its exit-code line (the real failure witness), ~30 false ERRORs per
    run. Echoes are identified structurally (no format args, no ``exc_info``). Multi-line stdout (``"\\nstdout: "``
    prefix) drops to DEBUG; anything else may hold compiler diagnostics and drops only to WARNING. If upstream changes,
    the records keep their level.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno < logging.ERROR:
            return True
        if record.module != "subprocess" or record.funcName != "run":
            return True
        if record.args or record.exc_info:
            return True
        message = record.msg if isinstance(record.msg, str) else ""
        demoted = logging.DEBUG if "\nstdout: " in message else logging.WARNING
        record.levelno = demoted
        record.levelname = logging.getLevelName(demoted)
        # Filters run after the emitting logger's level check, so apply the gate the demoted level would have hit.
        return demoted >= logging.getLogger().getEffectiveLevel()


_CONFIGURED_FLAG = "_psat_json_logging_configured"


def _install_third_party_log_hygiene() -> None:
    crytic = logging.getLogger("CryticCompile")
    if not any(isinstance(existing, CryticCompileEchoDemoter) for existing in crytic.filters):
        crytic.addFilter(CryticCompileEchoDemoter())
    # So warnings become JSON records and pass the secret scrubber. Import-time warnings are already written.
    logging.captureWarnings(True)


def configure_logging(level: int | str | None = None) -> None:
    """Install :class:`JsonFormatter` on the root logger once per process.

    Later calls short-circuit so pytest's ``caplog`` handlers survive.
    """
    root = logging.getLogger()
    if getattr(root, _CONFIGURED_FLAG, False):
        from utils.memory import start_memory_sampler

        start_memory_sampler()
        return
    if level is None:
        level = os.getenv("PSAT_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    _install_third_party_log_hygiene()
    setattr(root, _CONFIGURED_FLAG, True)
    from utils.memory import start_memory_sampler

    start_memory_sampler()


@contextmanager
def bind_trace_context(
    *,
    trace_id: str | None = None,
    job_id: str | None = None,
    stage: str | None = None,
    worker_id: str | None = None,
    address: str | None = None,
    chain: str | None = None,
) -> Iterator[None]:
    """Bind logging context for a ``with`` block; ``None`` skips a field. Resets on exit so binds nest."""
    tokens: list[tuple[contextvars.ContextVar[str | None], contextvars.Token[str | None]]] = []
    bindings: tuple[tuple[contextvars.ContextVar[str | None], str | None], ...] = (
        (trace_id_var, trace_id),
        (job_id_var, job_id),
        (stage_var, stage),
        (worker_id_var, worker_id),
        (address_var, address),
        (chain_var, chain),
    )
    for var, value in bindings:
        if value is not None:
            tokens.append((var, var.set(value)))
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


def record_degraded(
    *,
    phase: str | None,
    exc: BaseException,
    context: dict[str, Any] | None = None,
    include_traceback: bool = False,
) -> None:
    """Record a degraded-but-continuing failure on the current job's ``stage_errors``. No-op outside a job context."""
    accumulator = degraded_errors_var.get()
    if accumulator is None:
        return
    # Lazy to avoid a startup cycle through pydantic during pytest plugin discovery.
    from schemas.stage_errors import StageError
    from utils.secrets import sanitize_obj, sanitize_string

    job_id = job_id_var.get() or "0"
    tb = traceback.format_exception(type(exc), exc, exc.__traceback__) if include_traceback else None
    error = StageError(
        stage=stage_var.get() or "?",
        severity="degraded",
        exc_type=f"{type(exc).__module__}.{type(exc).__name__}",
        message=sanitize_string(str(exc)),
        traceback=sanitize_string("".join(tb)) if tb else None,
        phase=phase,
        trace_id=trace_id_var.get(),
        job_id=str(job_id),
        worker_id=worker_id_var.get() or "?",
        failed_at=datetime.now(timezone.utc),
        context=sanitize_obj(context) if context is not None else None,
    )
    accumulator.append(error)


@contextmanager
def observe_degraded() -> Iterator[list["StageError"]]:
    """Yield a list that, on exit, holds the degraded errors recorded inside the block.

    In a job context they still reach the job's ``stage_errors``; outside one they are collected only here.
    """
    accumulator = degraded_errors_var.get()
    token = None
    if accumulator is None:
        accumulator = []
        token = degraded_errors_var.set(accumulator)
    start = len(accumulator)
    observed: list[StageError] = []
    try:
        yield observed
    finally:
        observed.extend(accumulator[start:])
        if token is not None:
            degraded_errors_var.reset(token)


def record_stage_metric(key: str, value: Any) -> None:
    """Record one progress metric into the stage's ``stage_timing`` artifact; later writes overwrite.

    No-op outside a job context.
    """
    metrics = stage_metrics_var.get()
    if metrics is None:
        return
    metrics[key] = value


# Jobs executing in this process. ``process_cpu_s`` and ``children_cpu_s`` cover every one of them, so a phase record
# attributes those two to its own job only when ``job_concurrency`` is 1.
_jobs_in_flight = 0
_jobs_in_flight_lock = threading.Lock()


@contextmanager
def job_in_flight() -> Iterator[None]:
    global _jobs_in_flight
    with _jobs_in_flight_lock:
        _jobs_in_flight += 1
    try:
        yield
    finally:
        with _jobs_in_flight_lock:
            _jobs_in_flight -= 1


def _children_cpu_s() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


@contextmanager
def log_timed_phase(
    logger: logging.Logger,
    phase: str,
    *,
    durations_ms: dict[str, int] | None = None,
    record_metric: bool = True,
    log_failure: bool = False,
    **fields: Any,
) -> Iterator[dict[str, Any]]:
    """Time a sub-step and emit one ``phase complete`` INFO with ``duration_ms`` + ``phase``.

    Yields a dict whose keys merge into the line's ``extra``. The duration is recorded into ``durations_ms`` and
    ``phase_ms_<phase>`` even if the block raises; the INFO line is emitted only on clean exit unless the caller asks
    otherwise.

    The line also carries CPU: ``cpu_s`` is the calling thread's own, so work the phase fans out to other threads is in
    ``process_cpu_s`` only; ``children_cpu_s`` is subprocesses reaped during the phase.
    """
    start = time.monotonic()
    thread_cpu_start = time.thread_time()
    process_cpu_start = time.process_time()
    children_cpu_start = _children_cpu_s()
    concurrency_start = _jobs_in_flight
    extra: dict[str, Any] = dict(fields)
    success = False
    try:
        yield extra
        success = True
    finally:
        ms = int((time.monotonic() - start) * 1000)
        if durations_ms is not None:
            durations_ms[phase] = ms
        if record_metric:
            record_stage_metric(f"phase_ms_{phase}", ms)
        cpu = {
            "cpu_s": round(time.thread_time() - thread_cpu_start, 4),
            "process_cpu_s": round(time.process_time() - process_cpu_start, 4),
            "children_cpu_s": round(_children_cpu_s() - children_cpu_start, 4),
            "job_concurrency": max(concurrency_start, _jobs_in_flight),
        }
        if success:
            logger.info(
                "phase complete: %s (%dms)",
                phase,
                ms,
                extra={"duration_ms": ms, "phase": phase, **cpu, **extra},
            )
        elif log_failure:
            logger.info(
                "phase ended with error: %s (%dms)",
                phase,
                ms,
                extra={"duration_ms": ms, "phase": phase, "outcome": "failed", **cpu, **extra},
            )


def stream_subprocess(
    cmd: "list[str] | str",
    *,
    logger: logging.Logger,
    source: str,
    level: int = logging.DEBUG,
    **popen_kwargs: Any,
) -> int:
    """Run *cmd*, logging each combined stdout+stderr line at *level* with ``extra={"source": source}``; WARNING on
    non-zero exit. Returns the exit code. stderr is merged so one reader drains both without deadlock.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        **popen_kwargs,
    )
    if proc.stdout is not None:
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if line:
                logger.log(level, "%s", line, extra={"source": source})
    returncode = proc.wait()
    if returncode != 0:
        logger.warning(
            "subprocess exited non-zero",
            extra={"source": source, "returncode": returncode},
        )
    return returncode


def uvicorn_log_config(level: int | str | None = None) -> dict[str, Any]:
    """``dictConfig`` routing uvicorn loggers through :class:`JsonFormatter`.

    ``api.serve()`` launches uvicorn programmatically because the CLI only takes a config file, and passes
    ``access_log=False`` since the request middleware already logs that line.
    """
    if level is None:
        level = os.getenv("PSAT_LOG_LEVEL", "INFO").upper()
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {"()": f"{__name__}.JsonFormatter"},
        },
        "handlers": {
            "json": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
                "formatter": "json",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["json"], "level": level, "propagate": False},
            "uvicorn.error": {"handlers": ["json"], "level": level, "propagate": False},
            "uvicorn.access": {"handlers": ["json"], "level": level, "propagate": False},
        },
    }


__all__ = [
    "CryticCompileEchoDemoter",
    "JsonFormatter",
    "bind_trace_context",
    "configure_logging",
    "degraded_errors_var",
    "observe_degraded",
    "log_timed_phase",
    "record_degraded",
    "record_stage_metric",
    "stream_subprocess",
    "uvicorn_log_config",
    "stage_metrics_var",
    "trace_id_var",
    "job_id_var",
    "stage_var",
    "worker_id_var",
    "address_var",
    "chain_var",
]
