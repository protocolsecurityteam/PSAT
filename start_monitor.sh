#!/bin/bash
# `monitor` process group: the event scanner, state poller, and TVL
# tracker, plus the enrollment reconciler. The reconciler converges
# monitored_contracts on a cadence — notably the controller Safes /
# Timelocks the per-job enrollment hint (enroll_controllers=False)
# deliberately skips, and anything the one-shot boot reconcile missed
# because it ran before the protocol existed. Without it controllers
# never land in monitoring until a manual /re-enroll.
# DO NOT scale above 1 — the scanner/poller race on scan state and
# duplicate writes. (The reconciler only does idempotent upserts, so it
# is safe as a co-process; the scanners are why this stays a singleton.)
set -e

cd "$(dirname "$0")"

export PYTHONUNBUFFERED=1

PIDS=()

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [ ${#PIDS[@]} -gt 0 ]; then
    kill "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
  exit $exit_code
}

trap cleanup EXIT INT TERM

PY=(uv run --no-sync python)

"${PY[@]}" -m workers.protocol_monitor &
PIDS+=($!)
"${PY[@]}" -m workers.protocol_monitor --poll &
PIDS+=($!)
"${PY[@]}" -m workers.protocol_monitor --tvl &
PIDS+=($!)
"${PY[@]}" -m workers.protocol_monitor --reconcile &
PIDS+=($!)

echo "Monitors started: ${PIDS[*]}"
# Exit on first death — Fly restarts the machine and relaunches all
# four. A silently-dead scanner is worse than a 30s restart.
wait -n
