"""Offline duty/cost sensitivity from structured lifecycle observation JSONL.

No network or DB access. Missing samples are charged as running in the
conservative projection. Prices and cold-start overhead are explicit inputs;
this is a projection, never a claim about invoice-effective savings.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


def summarize(
    rows: list[dict],
    *,
    grace: float,
    startup_s: float,
    hourly: float,
    monitor_delta: float,
    rootfs_gb: float,
    other_delta: float,
) -> dict:
    samples = sorted(
        (r for r in rows if r.get("message") == "worker lifecycle observation"), key=lambda r: r["timestamp"]
    )
    if len(samples) < 2:
        raise ValueError("at least two lifecycle observations required")

    def epoch(row):
        return datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp()

    span = epoch(samples[-1]) - epoch(samples[0])
    if span <= 0:
        raise ValueError("observations must cover a positive duration")
    measured = actual_running = projected = gaps = 0.0
    unknown_actual = 0.0
    wakes = 0
    previous_running = False
    for row, following in zip(samples, samples[1:]):
        delta = epoch(following) - epoch(row)
        covered = min(delta, max(1, float(row.get("sample_seconds", 15))))
        gaps += delta - covered
        measured += covered
        actual = row.get("machine_state")
        if actual == "unobserved":
            unknown_actual += covered
        elif actual not in {"stopped", "suspended"}:
            actual_running += covered
        running = bool(row.get("ready_sources") or row.get("active") or row.get("idle_seconds", 0) < grace)
        if running:
            projected += covered
            wakes += not previous_running
        previous_running = running
    projected = min(span, projected + gaps + wakes * startup_s)
    duty = projected / span
    stopped_hours = 720 * (1 - duty)
    storage = 0.15 * rootfs_gb * (1 - duty)
    savings = stopped_hours * hourly - monitor_delta - storage - other_delta
    return {
        "observation_hours": round(span / 3600, 4),
        "coverage_fraction": measured / span,
        "unknown_actual_hours": (unknown_actual + gaps) / 3600,
        "measured_running_hours": actual_running / 3600,
        "projected_running_fraction_with_gaps_billed": duty,
        "projected_wakes_in_sample": wakes,
        "projected_savings_per_720h": round(savings, 2),
        "assumptions": {
            "grace_seconds": grace,
            "startup_seconds_per_wake": startup_s,
            "worker_hourly": hourly,
            "monitor_upgrade_per_720h": monitor_delta,
            "rootfs_gb": rootfs_gb,
            "other_cost_delta_per_720h": other_delta,
        },
        "limitations": "Sampled counterfactual; does not measure cold-cache amplification, healthy-load "
        "representativeness, paid provider costs, or prepaid reservation-credit effects.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--worker-hourly", type=float, required=True)
    parser.add_argument("--monitor-delta", type=float, required=True)
    parser.add_argument("--rootfs-gb", type=float, required=True)
    parser.add_argument("--other-delta", type=float, required=True)
    parser.add_argument("--startup-seconds", type=float, required=True)
    parser.add_argument("--grace-seconds", type=float, default=300)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.jsonl.read_text().splitlines() if line.strip()]
    print(
        json.dumps(
            summarize(
                rows,
                grace=args.grace_seconds,
                startup_s=args.startup_seconds,
                hourly=args.worker_hourly,
                monitor_delta=args.monitor_delta,
                rootfs_gb=args.rootfs_gb,
                other_delta=args.other_delta,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
