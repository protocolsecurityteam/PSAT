"""One-time maintenance deployment for the Assessment contraction.

Build before downtime, remove every old stateless machine so Fly cannot restart
one, then migrate and create the new process groups. Never invoked on push.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


def fly(*args: str) -> str:
    return subprocess.run(["flyctl", *args], check=True, capture_output=True, text=True).stdout


def cutover(config: Path, sha: str, backup_reference: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not backup_reference.strip():
        raise ValueError("A full commit SHA and a database backup reference are required")
    source = config.read_text()
    ordinary = 'release_command = "uv run --no-sync alembic upgrade head"'
    if source.count(ordinary) != 1 or not re.search(r'^app = "psat"$', source, re.MULTILINE):
        raise ValueError("Cutover accepts only the production psat configuration with its ordinary release command")
    image = f"registry.fly.io/psat:assessment-cutover-{sha}"
    fly(
        "deploy",
        "-a",
        "psat",
        "--config",
        str(config),
        "--remote-only",
        "--build-only",
        "--push",
        "--image-label",
        f"assessment-cutover-{sha}",
        "--build-arg",
        f"GIT_SHA={sha}",
    )
    machines = json.loads(fly("machines", "list", "-a", "psat", "--json"))
    counts: dict[str, int] = {}
    for machine in machines:
        if machine.get("config", {}).get("mounts"):
            raise RuntimeError("Cutover refuses machines with persistent volumes; no machine was removed")
        if not re.fullmatch(r"[0-9a-f]+", machine["id"]):
            raise ValueError("Invalid machine ID")
        group = machine.get("config", {}).get("metadata", {}).get("fly_process_group")
        if group not in {"web", "workers", "browser", "monitor"}:
            raise RuntimeError("Unexpected process group; reconcile the production inventory before cutover")
        counts[group] = counts.get(group, 0) + 1
    for machine in machines:
        fly("machine", "destroy", machine["id"], "-a", "psat", "--force")
    if json.loads(fly("machines", "list", "-a", "psat", "--json")):
        raise RuntimeError("Old machines remain; refusing the destructive migration")
    # The acknowledgement exists only in this generated release configuration,
    # never as a persistent application secret or the ordinary fly.toml.
    config.write_text(
        source.replace(
            ordinary,
            'release_command = "uv run --no-sync alembic upgrade f6a1c2d3e4b5 '
            "&& uv run --no-sync python -m services.assessment.migrate "
            '&& uv run --no-sync alembic -x assessment_cutover=stopped upgrade head"',
        )
    )
    try:
        fly("deploy", "-a", "psat", "--config", str(config), "--image", image, "--ha=false")
        if counts:
            fly(
                "scale",
                "count",
                "-a",
                "psat",
                "--yes",
                *(f"{group}={count}" for group, count in sorted(counts.items())),
            )
    finally:
        config.write_text(source)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--backup-reference", required=True)
    parser.add_argument("--confirm", choices=["ASSESSMENT CUTOVER"], required=True)
    args = parser.parse_args()
    cutover(args.config, args.sha, args.backup_reference)
