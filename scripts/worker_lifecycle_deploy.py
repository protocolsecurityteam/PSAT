"""CI's cooperative deployment handover. Never sends a Fly stop/scale call.

Run only as part of an authorized deployment. The bridge release must be live
before changing indexer placement. A drain failure aborts deployment rather
than forcing a live analysis to exit. The controller remains the sole starter.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time


def machines() -> list[dict]:
    rows = json.loads(subprocess.check_output(["flyctl", "machines", "list", "-a", "psat", "--json"], text=True))
    if any(
        row.get("config", {}).get("standby_for")
        and row.get("config", {}).get("metadata", {}).get("fly_process_group") in {"workers", "monitor"}
        and row.get("state") not in {"stopped", "destroyed"}
        for row in rows
    ):
        raise RuntimeError("active standby requires failover reconciliation before deployment")
    return rows


def group(rows: list[dict], name: str) -> list[dict]:
    return [
        row
        for row in rows
        if row.get("config", {}).get("metadata", {}).get("fly_process_group") == name
        and not row.get("config", {}).get("standby_for")
        and row.get("state") != "destroyed"
    ]


def admin(action: str) -> None:
    monitors = group(machines(), "monitor")
    if len(monitors) != 1 or monitors[0]["state"] != "started":
        raise RuntimeError("deployment requires one available monitor")
    subprocess.run(
        [
            "flyctl",
            "ssh",
            "console",
            "-a",
            "psat",
            "--machine",
            monitors[0]["id"],
            "-C",
            f"/app/.venv/bin/python -m workers.lifecycle_admin {action}",
        ],
        check=True,
        timeout=30,
    )


def prepare(*, indexer: str, mode: str = "observe", timeout: float = 1200) -> bool:
    workers = group(machines(), "workers")
    if len(workers) != 1:
        raise RuntimeError("expected one worker machine before deployment")
    old = workers[0]["config"].get("env", {})
    old_mode = old.get("PSAT_WORKER_LIFECYCLE_MODE", "off")
    if mode == "off" and (old.get("PSAT_INDEXER_GROUP", "workers") == "monitor" or indexer == "monitor"):
        raise RuntimeError("move indexing back in observe mode before disabling managed ownership")
    if old_mode == "off":
        if indexer == "monitor":
            raise RuntimeError("deploy the observe/workers bridge release before moving the indexer")
        return False
    admin("drain")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        workers = group(machines(), "workers")
        if len(workers) != 1:
            raise RuntimeError("worker topology changed during drain; deployment aborted")
        if workers[0]["state"] == "stopped":
            return True
        time.sleep(5)
    raise TimeoutError("workers did not drain; lifecycle remains paused, operator recovery required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "resume"))
    args = parser.parse_args()
    if args.action == "resume":
        admin("resume")
    else:
        drained = prepare(
            indexer=os.getenv("PSAT_INDEXER_GROUP", "workers"), mode=os.getenv("PSAT_LIFECYCLE_MODE", "off")
        )
        output = os.getenv("GITHUB_OUTPUT")
        if output:
            with open(output, "a") as stream:
                stream.write(f"drained={str(drained).lower()}\n")


if __name__ == "__main__":
    main()
