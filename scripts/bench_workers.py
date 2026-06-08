"""Submit one address to a PSAT API, time each pipeline stage, dump JSON.

Two timing sources, kept separate because they answer different questions:

* `stage_elapsed_polled_seconds` — wall-clock from one stage transition to
  the next, observed by polling `/api/jobs/<id>`. Includes queue-wait
  between stages. Always present; this is the user-visible latency.

* `worker_elapsed_seconds` — pure worker process time, scraped from the
  `Worker X completed job Y in Zs` line emitted by workers/base.py:127.
  Only populated when --fly-app is given and we can stream `fly logs`
  from before submission. Note: PolicyWorker advances via a custom path
  in some cases and may not emit this line — that stage will be missing.

Universal across environments: works against local (http://127.0.0.1:8000),
prod (https://psat.fly.dev), and preview apps (https://psat-pr-N.fly.dev).

Usage:

    PSAT_ADMIN_KEY=... uv run python scripts/bench_workers.py \\
        --url https://psat-pr-49.fly.dev \\
        --address 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \\
        --label fly-pr49-baseline \\
        --fly-app psat-pr-49
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Stages we track. Order matters — used to detect transitions.
STAGES = ["discovery", "static", "resolution", "policy", "coverage", "selection", "done"]

# Matches the per-job timing line from workers/base.py:127.
#   "Worker StaticWorker-653-... completed job <uuid> in 3.0s"
TIMING_RE = re.compile(r"Worker\s+(?P<worker>\S+)\s+completed job\s+(?P<job>[0-9a-f-]{36})\s+in\s+(?P<sec>[\d.]+)s")
# Worker class name → stage. Lowercase first chunk before "Worker".
WORKER_TO_STAGE = {
    "discoveryworker": "discovery",
    "staticworker": "static",
    "resolutionworker": "resolution",
    "policyworker": "policy",
    "coverageworker": "coverage",
    "selectionworker": "selection",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def http_post(url: str, body: dict, admin_key: str) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-PSAT-Admin-Key": admin_key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def http_get(url: str, admin_key: str) -> dict:
    req = urllib.request.Request(url, headers={"X-PSAT-Admin-Key": admin_key})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def submit(base_url: str, address: str, admin_key: str, *, force: bool = False) -> dict:
    body: dict = {"address": address}
    if force:
        body["force"] = True
    return http_post(f"{base_url.rstrip('/')}/api/analyze", body, admin_key)


def poll_until_done(
    base_url: str, job_id: str, admin_key: str, *, poll_interval: float, timeout_s: float
) -> tuple[dict, list[dict]]:
    """Poll the job until it reaches a terminal state.

    Returns (final_job_record, transitions). `transitions` is a list of
    {"stage": ..., "first_seen_offset_s": float} — the offset is wall-clock
    seconds since polling started, which is also approximately seconds
    since the job hit the queue (since polling starts immediately after
    submit returns).
    """
    transitions: list[dict] = []
    seen_stages: set[str] = set()
    started = time.monotonic()
    deadline = started + timeout_s
    last: dict = {}
    url = f"{base_url.rstrip('/')}/api/jobs/{job_id}"
    while time.monotonic() < deadline:
        try:
            last = http_get(url, admin_key)
        except urllib.error.URLError as e:
            print(f"[bench] poll error (transient): {e}", file=sys.stderr)
            time.sleep(poll_interval)
            continue

        stage = last.get("stage")
        if stage and stage not in seen_stages:
            seen_stages.add(stage)
            offset = round(time.monotonic() - started, 2)
            transitions.append({"stage": stage, "first_seen_offset_s": offset})
            print(f"[bench] +{offset:>6.2f}s  stage={stage}  status={last.get('status')}")

        status = last.get("status")
        if status in {"completed", "failed", "cancelled"}:
            return last, transitions
        time.sleep(poll_interval)
    raise TimeoutError(f"job {job_id} did not finish within {timeout_s}s")


def follow_all_to_terminal(
    base_url: str,
    admin_key: str,
    *,
    poll_interval: float,
    timeout_s: float,
    started_monotonic: float,
) -> list[dict]:
    """Poll /api/jobs until every job in the DB is in a terminal state.

    Use after a `force=true` submit + an empty DB: any job present here is part
    of the cascade we triggered. Returns the final job records (sorted by
    created_at). The wall clock starts from `started_monotonic` (typically the
    moment we submitted the parent) so the caller can compute total cascade
    time including any new jobs spawned mid-flight.
    """
    deadline = time.monotonic() + timeout_s
    seen: dict[str, dict] = {}
    last_print = -1.0
    url = f"{base_url.rstrip('/')}/api/jobs?limit=200"
    while time.monotonic() < deadline:
        try:
            data = http_get(url, admin_key)
        except urllib.error.URLError as e:
            print(f"[bench] cascade poll error (transient): {e}", file=sys.stderr)
            time.sleep(poll_interval)
            continue
        items = data if isinstance(data, list) else data.get("items", data.get("jobs", []))
        terminal_states = {"completed", "failed", "cancelled"}
        active_jobs: list[dict] = []
        for j in items:
            jid = j.get("job_id")
            if jid:
                seen[jid] = j
            if j.get("status") not in terminal_states:
                active_jobs.append(j)

        offset = round(time.monotonic() - started_monotonic, 1)
        # Print state at most every 10s so the log stays readable on long cascades.
        if offset - last_print >= 10:
            terminal = len(seen) - len(active_jobs)
            print(
                f"[bench cascade] +{offset:>6.1f}s  jobs: {len(seen)} total, {terminal} done, {len(active_jobs)} active"
            )
            for j in active_jobs[:8]:
                print(f"               · {j.get('stage'):<10} {j.get('status'):<10} {j.get('name', '')[:60]}")
            last_print = offset

        # Need at least one job ever seen, AND none currently active.
        if seen and not active_jobs:
            print(f"[bench cascade] all {len(seen)} jobs reached terminal at +{offset:.1f}s")
            return sorted(seen.values(), key=lambda j: j.get("created_at", ""))
        time.sleep(poll_interval)
    raise TimeoutError(f"cascade did not finish within {timeout_s}s ({len(seen)} jobs seen)")


def stage_elapsed_from_transitions(transitions: list[dict], total_seconds: float) -> dict[str, float]:
    """Approximate per-stage elapsed by diffing consecutive transition offsets.

    Less precise than fly-logs scraping (poll cadence + queue latency
    bleed in), but works against any API. The final stage runs from its
    first-seen offset to total_seconds.
    """
    if not transitions:
        return {}
    out: dict[str, float] = {}
    for i, t in enumerate(transitions):
        end = transitions[i + 1]["first_seen_offset_s"] if i + 1 < len(transitions) else total_seconds
        out[t["stage"]] = round(end - t["first_seen_offset_s"], 2)
    return out


class FlyLogTail:
    """Background `fly logs -a <app>` tail captured to a temp file.

    `fly logs` without `--no-tail` streams forever; we start it before
    submitting the job and stop it once the job finishes. Reading the
    captured file post-hoc gives us every emitted line in the run window
    — `--no-tail` alone returns only a tiny recent slice and routinely
    misses the early stages.
    """

    def __init__(self, app: str) -> None:
        self.app = app
        self.tmpfile = Path(f"/tmp/psat_bench_{os.getpid()}_{int(time.time())}.log")
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        try:
            self._proc = subprocess.Popen(
                ["fly", "logs", "-a", self.app],
                stdout=open(self.tmpfile, "w"),
                stderr=subprocess.STDOUT,
            )
            # `fly logs` takes ~1-2s to authenticate + start streaming.
            # Sleep so we don't miss the discovery worker's claim line.
            time.sleep(2.5)
        except FileNotFoundError as e:
            print(f"[bench] fly CLI not found ({e}); proceeding without log tail", file=sys.stderr)
            self._proc = None

    def stop_and_read(self) -> str:
        if self._proc is None:
            return ""
        # Give buffered writes ~1s to land before we kill the tail.
        time.sleep(1.0)
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        try:
            return self.tmpfile.read_text(errors="replace")
        finally:
            try:
                self.tmpfile.unlink()
            except OSError:
                pass


def stage_elapsed_from_log_text(log_text: str, job_id: str) -> tuple[dict[str, float], list[str]]:
    """Extract per-worker elapsed seconds + raw lines for one job_id.

    Legacy fallback path. Replaced by ``stage_elapsed_from_artifacts`` for
    any deployment running the schema-v2 ``stage_timing_<stage>`` artifacts;
    this remains for older deploys that don't expose
    ``/api/jobs/{id}/stage_timings``."""
    matches: dict[str, float] = {}
    raw: list[str] = []
    for line in log_text.splitlines():
        if job_id not in line:
            continue
        m = TIMING_RE.search(line)
        if not m:
            continue
        worker = m.group("worker").split("-", 1)[0].lower()
        stage = WORKER_TO_STAGE.get(worker)
        if stage:
            matches[stage] = float(m.group("sec"))
            raw.append(line.strip())
    return matches, raw


def stage_elapsed_from_artifacts(base_url: str, job_id: str, admin_key: str) -> dict[str, float]:
    """Fetch per-stage worker elapsed seconds from the schema-v2
    ``stage_timing_<stage>`` artifacts via /api/jobs/{id}/stage_timings.

    Returns ``{stage: elapsed_s}``. Empty dict if the endpoint isn't
    available (404 from older deploys) or no artifacts have been written
    yet — caller falls back to ``stage_elapsed_from_log_text``.

    The artifact-based path is reliable: persisted directly by the
    worker, not buffered through Fly's log stream. Closes the
    observability gap that left ``worker_elapsed_seconds`` mostly empty
    in bench JSON when log lines were dropped under load."""
    url = f"{base_url.rstrip('/')}/api/jobs/{job_id}/stage_timings"
    try:
        resp = http_get(url, admin_key)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        raise
    timings = resp.get("stage_timings") or {}
    out: dict[str, float] = {}
    for stage, payload in timings.items():
        if isinstance(payload, dict) and isinstance(payload.get("elapsed_s"), (int, float)):
            out[stage] = float(payload["elapsed_s"])
    return out


def build_summary(args, submit_resp, final_job, transitions, polled, worker, raw_lines):
    return {
        "label": args.label,
        "url": args.url,
        "address": args.address,
        "fly_app": args.fly_app,
        "job_id": submit_resp["job_id"],
        "submitted_at_local": submit_resp.get("created_at"),
        "completed_at_local": final_job.get("updated_at"),
        "total_seconds": round(transitions[-1]["first_seen_offset_s"], 2) if transitions else None,
        "final_status": final_job.get("status"),
        "final_stage": final_job.get("stage"),
        "final_detail": final_job.get("detail"),
        "stage_transitions": transitions,
        "stage_elapsed_polled_seconds": polled,
        "worker_elapsed_seconds": worker,
        "fly_log_lines": raw_lines,
        "bench_started_at": now_iso(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("PSAT_BENCH_URL", "https://psat.fly.dev"))
    parser.add_argument("--address", default="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
    parser.add_argument("--admin-key", default=os.environ.get("PSAT_ADMIN_KEY"))
    parser.add_argument("--label", default="unlabelled", help="Human tag for this run")
    parser.add_argument("--fly-app", default=None, help="Fly app name to scrape logs from")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=1800.0)
    parser.add_argument("--out", default=None, help="Output JSON path (auto if unset)")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force a re-run cascade with proxy implementation dedupe scoped to this run.",
    )
    parser.add_argument(
        "--follow-all-jobs",
        action="store_true",
        help=(
            "After parent reaches terminal, wait until every job in /api/jobs "
            "is also terminal. Use for proxies that cascade into impl + sibling "
            "analyses (e.g. etherfi LP). Assumes empty bench DB at start."
        ),
    )
    args = parser.parse_args()

    if not args.admin_key:
        print("error: --admin-key or PSAT_ADMIN_KEY required", file=sys.stderr)
        return 2

    log_tail: FlyLogTail | None = None
    if args.fly_app:
        log_tail = FlyLogTail(args.fly_app)
        print(f"[bench] starting fly logs tail for app={args.fly_app}")
        log_tail.start()

    print(f"[bench] submitting {args.address} → {args.url}{' (force=True)' if args.force else ''}")
    submit_started = time.monotonic()
    submit_resp = submit(args.url, args.address, args.admin_key, force=args.force)
    job_id = submit_resp["job_id"]
    print(f"[bench] job_id={job_id}")

    final_job, transitions = poll_until_done(
        args.url,
        job_id,
        args.admin_key,
        poll_interval=args.poll_interval,
        timeout_s=args.timeout,
    )

    total = transitions[-1]["first_seen_offset_s"] if transitions else 0.0
    polled = stage_elapsed_from_transitions(transitions, total)
    worker_elapsed: dict[str, float] = {}
    raw_lines: list[str] = []

    cascade_jobs: list[dict] = []
    cascade_total_s: float | None = None
    if args.follow_all_jobs:
        cascade_jobs = follow_all_to_terminal(
            args.url,
            args.admin_key,
            poll_interval=max(args.poll_interval * 4, 5.0),  # cascades are long; poll less frequently
            timeout_s=args.timeout * 4,  # cascade can be 4-10x parent
            started_monotonic=submit_started,
        )
        cascade_total_s = round(time.monotonic() - submit_started, 2)

    # Prefer the schema-v2 stage_timing_<stage> artifacts (reliable —
    # written by the worker directly). Fall back to Fly log scraping
    # only when the API endpoint isn't there (older deploys) or the
    # artifacts are empty.
    artifact_timings = stage_elapsed_from_artifacts(args.url, job_id, args.admin_key)
    if artifact_timings:
        worker_elapsed = artifact_timings
        timing_source = "artifact"
    else:
        timing_source = "fly-log-fallback" if log_tail is not None else "none"
    if log_tail is not None:
        log_text = log_tail.stop_and_read()
        scraped, raw_lines = stage_elapsed_from_log_text(log_text, job_id)
        if not artifact_timings:
            worker_elapsed = scraped

    # Per-cascade-job stage timings (only useful in --follow-all-jobs mode).
    # Cheap: one HTTP call per child job, all cached server-side.
    cascade_stage_timings: dict[str, dict[str, float]] = {}
    if cascade_jobs:
        for cj in cascade_jobs:
            cj_id = cj.get("job_id")
            if not cj_id:
                continue
            try:
                t = stage_elapsed_from_artifacts(args.url, cj_id, args.admin_key)
            except Exception as exc:
                print(f"[bench] warn: stage_timings fetch failed for {cj_id}: {exc}", file=sys.stderr)
                continue
            if t:
                cascade_stage_timings[cj_id] = t

    summary = build_summary(args, submit_resp, final_job, transitions, polled, worker_elapsed, raw_lines)
    summary["worker_timing_source"] = timing_source
    if cascade_stage_timings:
        summary["cascade_stage_timings"] = cascade_stage_timings
    if args.follow_all_jobs:
        summary["cascade_total_seconds"] = cascade_total_s
        summary["cascade_job_count"] = len(cascade_jobs)
        summary["cascade_jobs"] = [
            {
                "job_id": j.get("job_id"),
                "name": j.get("name"),
                "address": j.get("address"),
                "status": j.get("status"),
                "stage": j.get("stage"),
                "created_at": j.get("created_at"),
                "updated_at": j.get("updated_at"),
            }
            for j in cascade_jobs
        ]

    if args.out:
        out_path = Path(args.out)
    else:
        out_dir = Path("bench_results/runs")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = out_dir / f"{ts}_{args.label}_{job_id[:8]}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))

    print()
    if cascade_total_s is not None:
        cascade_failed = sum(1 for j in cascade_jobs if j.get("status") == "failed")
        print(f"[bench] cascade total={cascade_total_s}s ({len(cascade_jobs)} jobs, {cascade_failed} failed)")
    print(f"[bench] parent final_status={summary['final_status']} total={summary['total_seconds']}s")
    print(f"[bench] {'stage':<12} {'polled':>8s}  {'worker':>8s}")
    all_stages = list(polled.keys())
    for s in worker_elapsed:
        if s not in all_stages:
            all_stages.append(s)
    for stage in all_stages:
        p = f"{polled[stage]:.2f}s" if stage in polled else "—"
        w = f"{worker_elapsed[stage]:.2f}s" if stage in worker_elapsed else "—"
        print(f"          {stage:<12} {p:>8s}  {w:>8s}")
    print(f"[bench] wrote {out_path}")
    return 0 if summary["final_status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
