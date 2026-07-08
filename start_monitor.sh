#!/bin/bash
# `monitor` process group: the event scanner, state poller, and TVL
# tracker. The enrollment reconciler runs on the 16GB `workers` box
# instead — its per-tick governance-view computation is the heavy
# compute this 512MB VM must not carry.
# DO NOT scale above 1 — the scanner/poller race on scan state and
# duplicate writes.
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

echo "Monitors started: ${PIDS[*]}"
# Exit on first death — Fly restarts the machine and relaunches all
# three. A silently-dead scanner is worse than a 30s restart.
wait -n
