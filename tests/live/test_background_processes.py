"""Read-only endpoint shapes pass even when every background loop is crash-looping, so these assert on the loops' own
heartbeats.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from tests.live.conftest import LiveClient

# Worker-group drainers legitimately sleep between jobs under the enforced lifecycle.
ALWAYS_ON = (
    "event_log_indexer",
    "protocol_scanner",
    "protocol_poller",
    "protocol_tvl",
    "protocol_restaking",
    "role_holder_plane",
    "protocol_score",
    "ops_alerter",
    "worker_lifecycle",
)
BOOT_DEADLINE_S = 600
POLL_S = 15
RERUN_HINT = (
    "rerun-live-tests reuses a preview whose monitor/workers were destroyed after the "
    "previous run; redeploy (push) to recreate them"
)


def _wait_for_fleet(
    live_client: LiveClient, problems: Callable[[dict[str, dict[str, Any]]], list[str]]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    deadline = time.monotonic() + BOOT_DEADLINE_S
    while True:
        daemons = {d["process"]: d for d in live_client.fleet().get("daemons") or []}
        found = problems(daemons)
        if not found or time.monotonic() >= deadline:
            return daemons, found
        time.sleep(POLL_S)


def _heartbeat_problems(daemons: dict[str, dict[str, Any]]) -> list[str]:
    found = []
    for process in ALWAYS_ON:
        entry = daemons.get(process)
        if entry is None:
            found.append(f"{process}: absent from /api/fleet")
        elif not entry.get("alive"):
            found.append(f"{process}: no fresh heartbeat (last {entry.get('last_beat_at')})")
        elif entry.get("status") == "error":
            found.append(f"{process}: error {entry.get('detail')}")
    return found


def test_always_on_processes_report_fresh_heartbeats(live_client: LiveClient):
    _, problems = _wait_for_fleet(live_client, _heartbeat_problems)
    assert not problems, f"background processes not running after {BOOT_DEADLINE_S}s: {problems}. {RERUN_HINT}"


def _lifecycle_problems(daemons: dict[str, dict[str, Any]]) -> list[str]:
    entry = daemons.get("worker_lifecycle")
    if entry is None or not entry.get("alive"):
        return ["worker_lifecycle has no fresh heartbeat"]
    detail = entry.get("detail") or {}
    found = []
    if entry.get("status") != "running":
        found.append(f"status {entry.get('status')!r}: {detail}")
    if detail.get("mode") != "enforce":
        found.append(f"mode {detail.get('mode')!r}")
    if detail.get("paused") is not False:
        found.append(f"paused {detail.get('paused')!r}")
    # The controller couldn't read Fly machine state, so it could never start a sleeping worker.
    if detail.get("machine_state") in (None, "unobserved"):
        found.append(f"machine_state {detail.get('machine_state')!r}")
    return found


def test_worker_lifecycle_controller_is_enforcing_with_fly_access(live_client: LiveClient):
    _, problems = _wait_for_fleet(live_client, _lifecycle_problems)
    assert not problems, f"worker lifecycle controller cannot manage workers: {problems}. {RERUN_HINT}"
