#!/bin/bash
# `monitor` process group: one interpreter running the event scanner, state
# poller, and TVL tracker as three supervised daemon threads
# (workers/protocol_monitor.py default mode). A small in-process Supervisor
# restarts any loop that dies with exponential backoff and an error heartbeat,
# so one loop's death never touches its siblings or the process; a crash-loop
# degrades and pages via fly `[[restart]] policy="always"` instead of
# exhausting a retry budget and stopping the machine for good. SIGTERM joins all
# threads within a bounded timeout and exits 0.
#
# The enrollment reconciler runs on the 16GB `workers` box instead — its
# per-tick governance-view computation is the heavy compute this 512MB VM must
# not carry.
#
# Scaling above 1 is safe but wasteful: scan/poll passes are gated by the
# per-chain 'protocol_scanner:<chain>' / 'protocol_poller:<chain>' daemon
# leases (db/queue.py), so a duplicate machine acquires nothing and skips its
# passes. Independently on the scan path, the partial unique index on
# monitored_events makes a duplicate insert a no-op. Extra machines burn RPC
# for zero extra work — run 1.
set -e

cd "$(dirname "$0")"

export PYTHONUNBUFFERED=1

exec uv run --no-sync python -m workers.protocol_monitor
