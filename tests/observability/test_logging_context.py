"""``bind_trace_context`` must survive ``ThreadPoolExecutor.submit`` under ``copy_context().run``, and concurrent
contexts must never cross-contaminate.
"""

from __future__ import annotations

import io
import logging

from services.concurrency import RpcExecutor, parallel_map
from utils.logging import (
    JsonFormatter,
    bind_trace_context,
    trace_id_var,
)


def _capture(level: int = logging.INFO) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger(f"test.{id(stream)}")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger, stream


def test_parallel_map_propagates_trace_id():
    RpcExecutor.reset_for_tests()

    def read_trace(item: int) -> tuple[int, str | None]:
        return item, trace_id_var.get()

    try:
        with bind_trace_context(trace_id="parent-job"):
            results = parallel_map(read_trace, list(range(8)), max_workers=4)
    finally:
        RpcExecutor.reset_for_tests()

    for item, outcome in results:
        assert not isinstance(outcome, BaseException)
        idx, trace = outcome
        assert idx == item
        assert trace == "parent-job"


def test_parallel_map_sequential_path_propagates_trace_id():

    def read_trace(item: int) -> str | None:
        return trace_id_var.get()

    with bind_trace_context(trace_id="serial"):
        results = parallel_map(read_trace, [1, 2, 3], max_workers=1)

    assert [r for _, r in results] == ["serial", "serial", "serial"]
