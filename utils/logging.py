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
                 ``tests/test_log_level_contract.py`` against the four
                 main pipeline workers; intentional exemptions live in
                 that test's allow-list.
    ``INFO``     Lifecycle: process boot, job claim, stage advance, job
                 completion, child-job spawn. One per real event, not
                 per loop iteration.
    ``DEBUG``    Per-RPC / per-iteration noise: individual ``eth_getCode``
                 / source-provider batch tracebacks, per-future thread-pool
                 timings, per-page PDF parse failures, etc.

Notes on ``logger.exception``: it's just ``logger.error`` with
``exc_info=True``. Reserve it for genuine job-failing handlers that
re-raise — using it inside a swallowed ``except`` mis-levels the site
AND attaches a full traceback to a non-failure log line. The right
substitute is ``logger.warning("...", extra={"exc_type": type(exc).__name__})``
which keeps the exception type as a structured JSON field without
pretending the job failed.

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
import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from schemas.stage_errors import StageError

trace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_trace_id", default=None)
job_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_job_id", default=None)
stage_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_stage", default=None)
worker_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_worker_id", default=None)
address_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_address", default=None)
chain_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("psat_chain_id", default=None)

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


class JsonFormatter(logging.Formatter):
    """Render each ``LogRecord`` as a single-line JSON object.

    Pulls ``trace_id`` / ``job_id`` / ``stage`` / ``worker_id`` /
    ``address`` / ``chain_id`` from the matching :mod:`contextvars` and any
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
        ("chain_id", chain_id_var),
    )

    def format(self, record: logging.LogRecord) -> str:
        # ``logging.Formatter.formatTime`` routes through ``time.strftime``
        # which doesn't expand ``%f`` to microseconds — build the ISO
        # timestamp by hand off the record's ``created`` epoch instead.
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds")
        if ts.endswith("+00:00"):
            ts = ts[: -len("+00:00")] + "Z"
        payload: dict[str, Any] = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
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
            payload[attr] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=str)


_CONFIGURED_FLAG = "_psat_json_logging_configured"


def configure_logging(level: int | str | None = None) -> None:
    """Install :class:`JsonFormatter` on the root logger once per process.

    On first call this clears any pre-existing handlers (e.g. from
    ``logging.basicConfig`` in a worker ``main()``) and installs a JSON
    stream handler on stderr. Subsequent calls in the same process
    short-circuit so test harnesses (notably pytest's ``caplog``) can
    add their own handlers without our re-init wiping them mid-test.

    Reads the level from ``PSAT_LOG_LEVEL`` (default INFO) when *level*
    is omitted.
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
    setattr(root, _CONFIGURED_FLAG, True)


@contextmanager
def bind_trace_context(
    *,
    trace_id: str | None = None,
    job_id: str | None = None,
    stage: str | None = None,
    worker_id: str | None = None,
    address: str | None = None,
    chain_id: int | str | None = None,
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
        (chain_id_var, str(chain_id) if chain_id is not None else None),
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
    from schemas.stage_errors import StageError, StageErrorSeverity
    from utils.secrets import sanitize_obj, sanitize_string

    job_id = job_id_var.get() or "0"
    tb = traceback.format_exception(type(exc), exc, exc.__traceback__) if include_traceback else None
    error = StageError(
        stage=stage_var.get() or "?",
        severity=StageErrorSeverity.DEGRADED,
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


__all__ = [
    "JsonFormatter",
    "bind_trace_context",
    "configure_logging",
    "degraded_errors_var",
    "log_timed_phase",
    "record_degraded",
    "record_stage_metric",
    "stage_metrics_var",
    "trace_id_var",
    "job_id_var",
    "stage_var",
    "worker_id_var",
    "address_var",
    "chain_id_var",
]
