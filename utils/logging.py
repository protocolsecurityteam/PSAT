"""Structured JSON logging + ``trace_id`` propagation.

Every API request and worker job advances under a 16-char hex ``trace_id``.
Binding it onto a :mod:`contextvars` ``ContextVar`` lets every ``logger.X``
call inside that request/job ride the same id without having to thread it
through function signatures.

Level contract:

    ``ERROR``    Job-failing. The exception will propagate out of
                 ``process()``; ``BaseWorker._execute_job`` catches it,
                 logs the failure with full traceback, and writes a
                 ``severity="error"`` ``StageError`` into the per-job
                 accumulator before calling ``fail_job``. Don't emit
                 ``logger.error`` from inside an ``except`` block that
                 returns or continues — it's not actually job-failing,
                 so demote to WARNING.
    ``WARNING``  Degraded but continuing. The job advances with a partial
                 outcome (a single source failed in a fan-out, optional
                 data was missing, a fallback path was taken). Every
                 WARNING site inside a swallowed ``except`` block in a
                 pipeline worker MUST also call :func:`record_degraded`
                 in the same handler so the swallow shows up in the
                 ``stage_errors`` artifact (queryable via
                 ``GET /api/jobs/{id}/errors``). Enforced by
                 ``tests/test_log_level_contract.py`` against the
                 pipeline workers it lists (``PIPELINE_WORKERS`` — six
                 today, and it grows as BaseWorker subclasses land);
                 intentional exemptions live in that test's allow-list.
    ``INFO``     Lifecycle: process boot, job claim, stage advance, job
                 completion, child-job spawn. One per real event, not
                 per loop iteration.
    ``DEBUG``    Per-RPC / per-iteration noise: individual ``eth_getCode``
                 / Etherscan batch tracebacks, per-future thread-pool
                 timings, per-page PDF parse failures, etc.

Notes on ``logger.exception``: it's just ``logger.error`` with
``exc_info=True``. Reserve it for genuine job-failing handlers that
re-raise — using it inside a swallowed ``except`` mis-levels the site
AND attaches a full traceback to a non-failure log line. The right
substitute is ``logger.warning("...", extra={"exc_type": type(exc).__name__})``
which keeps the exception type as a structured JSON field without
pretending the job failed.

One standing exemption: ``workers/base.py``'s ``logger.exception`` calls
inside swallowed handlers stay as they are. They are the framework's own
keep-alive paths (lease release, timing writes, the dispatcher's
catch-all, the main loop) — a worker that must not die while something
underneath it is broken. There is no job whose outcome they degrade, and
the traceback is the only description of the framework fault, so it is
kept deliberately. ``base.py`` is therefore not in the level-contract
test's ``PIPELINE_WORKERS`` list; new *stage* code does not inherit this
exemption.

Threading note: ``contextvars`` are per-thread by default. When fanning
out via :class:`concurrent.futures.ThreadPoolExecutor`, wrap every
submission with :func:`contextvars.copy_context().run` so the worker
threads see the parent job's ``trace_id`` instead of an empty context.
:mod:`utils.concurrency.parallel_map` already does this for callers, so
prefer it over a bare ``executor.submit`` whenever possible.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import subprocess
import sys
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

# Per-job accumulator for degraded-but-continuing failures. ``BaseWorker``
# binds a fresh list at the start of every ``_execute_job`` and drains it
# when the job completes. ``record_degraded`` (below) appends to this list.
# Default is ``None`` so calls outside a worker's job context become no-ops.
# Threading-wise this is intentional: the dispatcher in ``BaseWorker`` does a
# ``copy_context().run(...)`` per job, so each pool thread sees its own list.
degraded_errors_var: contextvars.ContextVar[list["StageError"] | None] = contextvars.ContextVar(
    "psat_degraded_errors", default=None
)

# Per-job accumulator for stage progress metrics (counts, key intermediate
# results). ``BaseWorker`` binds a fresh dict at the start of every
# ``_execute_job`` and folds it into that stage's ``stage_timing_<stage>``
# artifact when the stage finishes — so the monitoring UI can show what a
# stage actually did (deps discovered, principals resolved, coverage rows
# written) without scraping logs or querying the DB. ``record_stage_metric``
# (below) writes into it. Same threading story as the degraded accumulator:
# the dispatcher does a ``copy_context().run(...)`` per job, so each pool
# thread sees its own dict. Default ``None`` so calls outside a worker's job
# context are no-ops.
stage_metrics_var: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "psat_stage_metrics", default=None
)

# Standard ``LogRecord`` attributes we shouldn't echo into the JSON body —
# the formatter already promotes the ones it cares about (level, logger,
# message), and the rest are noise (pathname, lineno, processName, …).
# Anything passed via ``extra={...}`` lands on the record as a new attr and
# is surfaced; this set is the deny-list for the catch-all loop below.
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        # uvicorn passes its own ANSI-coloured copy of the message through
        # ``extra``. It is not a fact — it is the same string with escape codes
        # — so it would otherwise duplicate ``message`` on every uvicorn line.
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
    """Scrub secrets from a structured ``extra={...}`` log field.

    A value can carry a credentialed URL (RPC endpoint, provider key) as a
    bare string or nested inside a dict/list. Strings go through
    :func:`sanitize_string` and containers through :func:`sanitize_obj`;
    non-string scalars (counts, flags, block numbers) can't carry a URL
    secret and pass through untouched.
    """
    if isinstance(value, str):
        return sanitize_string(value)
    if isinstance(value, (dict, list)):
        return sanitize_obj(value)
    return value


class JsonFormatter(logging.Formatter):
    """Render each ``LogRecord`` as a single-line JSON object.

    Pulls ``trace_id`` / ``job_id`` / ``stage`` / ``worker_id`` /
    ``address`` / ``chain`` from the matching :mod:`contextvars` and any
    user-supplied ``extra={...}`` keys (e.g. ``duration_ms``) directly
    off the record. Unset context fields are omitted rather than
    serialized as ``null`` so log shippers don't index empty cardinality.
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
        # ``logging.Formatter.formatTime`` routes through ``time.strftime``
        # which doesn't expand ``%f`` to microseconds — build the ISO
        # timestamp by hand off the record's ``created`` epoch instead.
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds")
        if ts.endswith("+00:00"):
            ts = ts[: -len("+00:00")] + "Z"
        # The formatter is the last hop before the log sink, so it is where
        # secret-scrubbing is enforced for every record regardless of call
        # site: the message, each ``extra={}`` field, and the rendered
        # ``exc_info``/``stack_info`` are routed through ``utils.secrets``.
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
    """Demote crytic-compile's verbatim subprocess-output echoes off ERROR.

    ``crytic_compile.utils.subprocess.run`` logs a failed build's captured
    stdout AND stderr at ERROR, next to its own ``"'forge' returned non-zero
    exit code %d"`` line. That exit-code line is the failure witness; the two
    echoes are the tool's own text, and a failed ``forge build`` still prints
    its ordinary progress chatter there (``Compiling 45 files with Solc 0.7.0``
    / ``Solc 0.7.0 finished in 37ms``) — ~30 ERROR records per pipeline run
    that assert nothing failed, on top of the 60 that do.

    The echoes are identified structurally, never by content: within that one
    helper they are the only records carrying neither format args nor
    ``exc_info``. What the payload *is* then decides how far it drops, and only
    on proof: multi-line stdout carries the library's own ``"\\nstdout: "``
    continuation prefix, so it is provably progress chatter and goes to DEBUG.
    Every other echo may carry the compiler's diagnostics, so it drops only as
    far as WARNING — visible, queryable, out of ERROR-rate triage. Nothing is
    dropped on a content guess. If upstream moves these call sites the guards
    stop matching and the records keep their original level.
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
        # A logger-attached filter runs *after* the emitting logger's own level
        # check, and handlers only compare against their own level — so without
        # this a demoted record would still be emitted. Apply the gate the
        # library would have hit had it logged at the demoted level.
        return demoted >= logging.getLogger().getEffectiveLevel()


_CONFIGURED_FLAG = "_psat_json_logging_configured"


def _install_third_party_log_hygiene() -> None:
    """Tame the third-party loggers that would otherwise mis-level our stream."""
    crytic = logging.getLogger("CryticCompile")
    if not any(isinstance(existing, CryticCompileEchoDemoter) for existing in crytic.filters):
        crytic.addFilter(CryticCompileEchoDemoter())
    # Route the ``warnings`` module through logging (``py.warnings``) so a
    # DeprecationWarning / RequestsDependencyWarning becomes one JSON record
    # instead of a two-line raw stderr write that bypasses the formatter (and
    # the secret scrubber). Only covers warnings raised after this call — an
    # import-time warning has already been written by then.
    logging.captureWarnings(True)


def configure_logging(level: int | str | None = None) -> None:
    """Install :class:`JsonFormatter` on the root logger once per process.

    On first call this clears any pre-existing handlers (e.g. from
    ``logging.basicConfig`` in a worker ``main()``) and installs a JSON
    stream handler on stderr. Subsequent calls in the same process
    short-circuit so test harnesses (notably pytest's ``caplog``) can
    add their own handlers without our re-init wiping them mid-test.

    Reads the level from ``PSAT_LOG_LEVEL`` (default INFO) when *level*
    is omitted.

    Also installs the process-wide third-party stream hygiene (see
    :func:`_install_third_party_log_hygiene`): the
    :class:`CryticCompileEchoDemoter` filter, and ``logging.captureWarnings``
    so the ``warnings`` module emits through logging instead of raw stderr.
    """
    root = logging.getLogger()
    if getattr(root, _CONFIGURED_FLAG, False):
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
    """Bind logging context for the duration of a ``with`` block.

    Every keyword maps to its matching ``ContextVar``. ``None`` skips the
    bind so callers can pass through partials (e.g. the API ingress only
    knows ``trace_id``; the worker fills in ``job_id``/``stage``/...).
    Tokens are reset on exit so nested binds nest cleanly.
    """
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
    """Record a degraded-but-continuing failure on the current job.

    Reads ``trace_id`` / ``job_id`` / ``stage`` / ``worker_id`` from the
    ambient ``ContextVar``s set by :func:`bind_trace_context`, so callers
    don't have to thread them through. Appends a ``StageError`` (severity
    ``"degraded"``) onto the per-job accumulator that ``BaseWorker`` will
    drain into a ``stage_errors`` artifact on job completion.

    A no-op when called outside a worker's job context (no accumulator
    bound) — services and helpers can safely call this from contexts that
    aren't always under a worker, and tests don't have to install the
    accumulator just to import a service module.
    """
    accumulator = degraded_errors_var.get()
    if accumulator is None:
        return
    # Imported lazily to avoid a startup cycle: the schema module already
    # touches pydantic which transitively pulls in things we don't want
    # ``utils.logging`` to require at import time (notably during pytest's
    # very-early plugin discovery).
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


def record_stage_metric(key: str, value: Any) -> None:
    """Record a single progress metric for the current pipeline stage.

    Folds ``key -> value`` into the per-job metrics dict that ``BaseWorker``
    drains into the ``stage_timing_<stage>`` artifact on stage completion,
    surfacing it to the monitoring UI. ``value`` should be a small
    JSON-serialisable scalar (a count, flag, block number, or type name);
    later writes for the same key overwrite earlier ones, so a worker can
    update a running total as it goes.

    A no-op when called outside a worker's job context (no accumulator
    bound) — helpers and services can call it unconditionally, and tests
    don't have to install the accumulator just to import a module.
    """
    metrics = stage_metrics_var.get()
    if metrics is None:
        return
    metrics[key] = value


@contextmanager
def log_timed_phase(
    logger: logging.Logger,
    phase: str,
    *,
    durations_ms: dict[str, int] | None = None,
    record_metric: bool = True,
    **fields: Any,
) -> Iterator[dict[str, Any]]:
    """Time a pipeline sub-step and, on success, emit one ``phase complete``
    INFO line carrying ``duration_ms`` + ``phase`` — the house per-phase
    convention (see ``workers/resolution_worker.py``'s inline
    ``"resolution phase complete: …"`` lines and ``contract_analysis_pipeline.
    core._phase``). Use it to make a worker's ``process()`` self-describe where
    its time went, so a slow run is attributable to a named sub-step rather than
    a single opaque ``[JOB] elapsed_s`` number.

    Yields a mutable dict so the caller can attach result-derived structured
    fields discovered *inside* the block (counts, ids); they are merged into the
    emitted line's ``extra``::

        durations: dict[str, int] = {}
        with log_timed_phase(logger, "semantic_capabilities", durations_ms=durations) as ph:
            out = resolve(...)
            ph["function_count"] = len(out)

    Behaviour:

    * The duration is always recorded into ``durations_ms`` (when provided) and
      folded into the stage_timing artifact as ``phase_ms_<phase>`` (when
      ``record_metric`` is set; a no-op outside a worker job context) — *even if
      the block raises*, so an aggregate emitted by an outer handler still sees
      the partial cost.
    * The INFO line is emitted only on a clean exit. A raising block is left to
      the worker's failure handler to log/record, so this never double-logs a
      failure nor mislabels one as "complete" (which also keeps it clear of the
      ``logger.warning``-in-except level contract).
    """
    start = time.monotonic()
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
        if success:
            logger.info(
                "phase complete: %s (%dms)",
                phase,
                ms,
                extra={"duration_ms": ms, "phase": phase, **extra},
            )


def stream_subprocess(
    cmd: "list[str] | str",
    *,
    logger: logging.Logger,
    source: str,
    level: int = logging.DEBUG,
    **popen_kwargs: Any,
) -> int:
    """Run *cmd* and stream its combined stdout+stderr line-by-line into *logger*.

    Every output line is logged at *level* (DEBUG by default) carrying
    ``extra={"source": source}`` so subprocess chatter rides the bound
    trace context and stays queryable by the producing tool (``forge``,
    ``slither``, ``hypersync``, ``git``, …) instead of leaking as raw
    inherited plaintext on the parent's fds. On a non-zero exit one
    WARNING is emitted (same ``source`` plus ``returncode``); the exit
    code is returned so the caller decides whether that's fatal.

    Dependency-light: only stdlib ``subprocess`` + ``logging``. ``stderr``
    is merged into ``stdout`` so interleaving is preserved and a single
    reader drains both without a deadlock. Extra ``popen_kwargs`` (``cwd``,
    ``env``, …) pass straight through; ``stdout``/``stderr``/``text`` are
    fixed by this helper and must not be overridden.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        **popen_kwargs,
    )
    # ``stdout`` is always a pipe here (we set it above); the guard keeps
    # the type-checker happy and is cheap insurance against a future edit.
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
    """Return a ``logging.config.dictConfig`` routing uvicorn through :class:`JsonFormatter`.

    Pass the result as uvicorn's ``log_config`` (``uvicorn.run(...,
    log_config=uvicorn_log_config())``) so the ``uvicorn``, ``uvicorn.error``
    and ``uvicorn.access`` loggers emit the same single-line JSON — and pick
    up the same six contextvars — as the rest of the system, instead of
    uvicorn's default plaintext access/error lines that bypass the formatter.

    ``disable_existing_loggers`` is ``False`` so applying this never silences
    the application's own loggers. Level defaults to ``PSAT_LOG_LEVEL`` (then
    INFO) to match :func:`configure_logging`. ``api.serve()`` is the wiring:
    the uvicorn CLI can only take a log config as a *file*, so the server is
    launched programmatically. ``uvicorn.access`` is still declared here (a
    caller that wants the access line gets it as JSON), but ``serve()`` passes
    ``access_log=False`` — the ``api`` request middleware already emits the
    same line with ``trace_id`` and ``duration_ms``.
    """
    if level is None:
        level = os.getenv("PSAT_LOG_LEVEL", "INFO").upper()
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            # The ``()`` key tells dictConfig to call this factory, so the
            # access+error records render through our JsonFormatter.
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
