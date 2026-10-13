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


def spawn_and_wait() -> None:
    import subprocess
    import sys

    subprocess.run(
        [sys.executable, "-c", "import time\nt = time.process_time()\nwhile time.process_time() - t < 0.3: pass"],
        check=True,
    )


_kept: list[bytearray] = []


def allocate_and_keep(megabytes: int) -> int:
    _kept.extend(bytearray(1024 * 1024) for _ in range(megabytes))
    for block in _kept:
        block[0] = 1
    return os.getpid()


def exit_now() -> None:
    raise SystemExit(0)


def unpicklable() -> Any:
    return lambda: None


def fork_server_state() -> dict[str, Any]:
    import gc
    import sys

    from sqlalchemy import inspect

    from db.models import Job
    from services.compute_isolation import _PRELOAD

    return {
        "frozen": gc.get_freeze_count(),
        "mappers_configured": inspect(Job).configured,
        "missing_preloads": [name for name in _PRELOAD if name not in sys.modules],
    }


def sleep_then_pid(seconds: float) -> int:
    time.sleep(seconds)
    return os.getpid()


def _refuse_to_load() -> None:
    raise RuntimeError("cannot be unpickled here")


class Unloadable:
    """Pickles fine and fails to load, so the child dies reading its job."""

    def __reduce__(self):
        return (_refuse_to_load, ())
