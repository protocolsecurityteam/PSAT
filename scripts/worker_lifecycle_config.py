"""Render one staged Fly layout from the canonical config; never deploy it."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def render(source: str, *, mode: str = "off", indexer: str = "workers", monitor_mb: int = 512) -> str:
    if mode not in {"off", "observe", "enforce"} or indexer not in {"workers", "monitor"}:
        raise ValueError("invalid lifecycle mode or indexer placement")
    if monitor_mb not in {512, 2048, 4096}:
        raise ValueError("monitor_mb must be 512, 2048, or 4096")
    if mode != "off" and monitor_mb < 2048:
        raise ValueError("managed monitoring requires measured headroom; start with at least the 2-GiB candidate")
    if indexer == "monitor" and monitor_mb < 2048:
        raise ValueError("monitor indexer requires at least the candidate 2-GiB allocation")
    if mode == "enforce" and indexer != "monitor":
        raise ValueError("enforce mode requires the always-on indexer")
    for key, value in (("PSAT_WORKER_LIFECYCLE_MODE", mode), ("PSAT_INDEXER_GROUP", indexer)):
        source, count = re.subn(rf'(?m)^(\s*{key}\s*=\s*)"[^"]*"', rf'\g<1>"{value}"', source)
        if count != 1:
            raise ValueError(f"expected one {key} setting")
    pattern = r'(\[\[vm\]\]\s*processes = \["monitor"\]\s*)size = "[^"]+"\s*memory = "[^"]+"'
    size = "shared-cpu-1x" if monitor_mb == 512 else "shared-cpu-2x"
    source, count = re.subn(pattern, rf'\g<1>size = "{size}"\n  memory = "{monitor_mb}mb"', source)
    if count != 1:
        raise ValueError("expected one monitor VM block")
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mode", choices=("off", "observe", "enforce"), default="off")
    parser.add_argument("--indexer", choices=("workers", "monitor"), default="workers")
    parser.add_argument("--monitor-mb", type=int, default=512)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / "fly.toml"
    args.output.write_text(render(source.read_text(), mode=args.mode, indexer=args.indexer, monitor_mb=args.monitor_mb))


if __name__ == "__main__":
    main()
