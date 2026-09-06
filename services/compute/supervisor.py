"""Fixed four-process launcher; no job commands or job arguments."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from db.models import SessionLocal
from services.compute.runtime import WORKER_MODULES, preflight


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("The compute launcher accepts no arguments")
    repository = Path(__file__).resolve().parents[2]
    port = int(os.environ.get("PSAT_EFFECTS_ANVIL_PORT", "8546"))
    with socket.socket() as guard:
        guard.bind(("127.0.0.1", port))
        with SessionLocal() as session:
            preflight(session, repository=repository)
    processes: list[subprocess.Popen] = []
    stopping = False

    def stop(_signum=None, _frame=None):
        nonlocal stopping
        stopping = True
        for process in processes:
            if process.poll() is None:
                process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logs = repository / "logs"
    logs.mkdir(exist_ok=True)
    with ExitStack() as stack:
        try:
            for module in WORKER_MODULES:
                if stopping:
                    break
                log = stack.enter_context((logs / f"local-compute-{module.split('.')[-1]}.log").open("ab"))
                processes.append(
                    subprocess.Popen(
                        [sys.executable, "-m", module], cwd=repository, stdout=log, stderr=subprocess.STDOUT
                    )
                )
            while not stopping and all(process.poll() is None for process in processes):
                time.sleep(0.2)
        finally:
            stop()
            # Workers cancel attempt authority and compiler process groups first,
            # then release leases. Keep the singleton lock until every exit.
            for process in processes:
                process.wait()
    if any(process.returncode not in {0, -signal.SIGTERM} for process in processes):
        raise SystemExit("A compute worker exited unsuccessfully; see local logs")


if __name__ == "__main__":
    main()
