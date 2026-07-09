#!/bin/bash
# `monitor` process group: the event scanner, state poller, and TVL
# tracker. The enrollment reconciler runs on the 16GB `workers` box
# instead — its per-tick governance-view computation is the heavy
# compute this 512MB VM must not carry.
# Scaling above 1 is safe but wasteful: scan/poll passes are gated by the
# per-chain 'protocol_scanner:<chain>' / 'protocol_poller:<chain>' daemon
# leases (db/queue.py), so a duplicate machine acquires nothing and skips its
# passes. Independently on the scan path, the partial unique index on
# monitored_events makes a duplicate insert a no-op. Extra machines burn RPC
# for zero extra work — run 1.
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
