"""Child bodies for the compute-isolation tests; module-level so a fork-server child can import them."""

from __future__ import annotations

import os
import signal
import time
from typing import Any

from utils.logging import record_degraded, record_stage_metric


def echo(value: Any) -> Any:
    return value


def report(value: Any) -> dict[str, Any]:
    record_degraded(phase="child_phase", exc=RuntimeError("degraded in child"), context={"value": value})
    record_stage_metric("child_metric", value)
    return {"pid": os.getpid(), "value": value}


def fail(message: str) -> None:
    raise ValueError(message)


def burn_cpu(seconds: float) -> float:
    deadline = time.process_time() + seconds
    total = 0.0
    while time.process_time() < deadline:
        total += sum(i * i for i in range(1000))
    return total


def allocate(megabytes: int) -> int:
    blocks = [bytearray(1024 * 1024) for _ in range(megabytes)]
    for block in blocks:
        block[0] = 1
    time.sleep(5)
    return len(blocks)


def raise_memory_error() -> None:
    raise MemoryError()


def crash() -> None:
    os.kill(os.getpid(), signal.SIGSEGV)


def sleep_then_echo(seconds: float, value: Any) -> Any:
    time.sleep(seconds)
    return value


def spawn_grandchild_and_sleep(pid_file: str) -> None:
    import subprocess

    child = subprocess.Popen(["sleep", "60"])
    with open(pid_file, "w") as fh:
        fh.write(str(child.pid))
    burn_cpu(60)


def write_pid_and_sleep(pid_file: str) -> None:
    with open(pid_file, "w") as fh:
        fh.write(str(os.getpid()))
    time.sleep(60)
