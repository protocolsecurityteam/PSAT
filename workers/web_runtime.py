"""Supervise the API and one independent company preparer on a warm machine.

The builder can also run as ``python -m workers.company_pages`` elsewhere.
A failed builder restarts independently; API failure restarts the machine.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from threading import Event

from utils.logging import configure_logging

logger = logging.getLogger(__name__)


def enabled() -> bool:
    # Keep the supervisor small: importing the builder also imports the ORM,
    # FastAPI and serializers, none of which this process uses.
    return os.getenv("PSAT_PREPARED_COMPANY_PAGES", "0") == "1" and os.getenv("PSAT_COMPANY_BUILDER_ON_WEB", "1") == "1"


def launch(builder: bool = False) -> subprocess.Popen:
    env = dict(os.environ)
    env.pop("PSAT_WORKER_LIFECYCLE_TOKEN", None)
    env.pop("PSAT_WORKER_BOOT_ID", None)
    command = [sys.executable, "serve.py"]
    if builder:
        command = [sys.executable, "-m", "workers.company_pages"]
        env.update(PSAT_DB_POOL_SIZE="2", PSAT_DB_MAX_OVERFLOW="3", MALLOC_ARENA_MAX="2")
    return subprocess.Popen(command, env=env, start_new_session=True)


def shutdown(children: list[subprocess.Popen]) -> None:
    for child in children:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 25
    for child in children:
        try:
            child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()


def run(stop: Event) -> int:
    children = []
    try:
        api = launch()
        children.append(api)
        builder = launch(True) if enabled() else None
        if builder:
            children.append(builder)
        failures = 0
        retry_at = 0.0
        launched_at = time.monotonic()
        while not stop.wait(1):
            if api.poll() is not None:
                logger.error("API exited", extra={"exit_code": api.returncode})
                return 1
            if builder and builder.poll() is not None:
                if not retry_at:
                    if time.monotonic() - launched_at >= 60:
                        failures = 0
                    retry_at = time.monotonic() + min(60, 2 ** min(failures, 6))
                    failures += 1
                    logger.error("Company preparer exited; restarting", extra={"exit_code": builder.returncode})
                if time.monotonic() >= retry_at:
                    builder.wait()
                    children.remove(builder)
                    builder = launch(True)
                    children.append(builder)
                    launched_at = time.monotonic()
                    retry_at = 0.0
        return 0
    finally:
        shutdown(children)


def main() -> None:
    configure_logging()
    stop = Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    raise SystemExit(run(stop))


if __name__ == "__main__":
    main()
