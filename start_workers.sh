#!/bin/bash
# `workers` process group: queue consumers only. Scaled as a group via
# `fly scale count --process-group workers N`.
# dapp_crawl_worker lives in `browser`; protocol_monitor in `monitor`.
set -e

cd "$(dirname "$0")"

export PYTHONUNBUFFERED=1

# Cap glibc's per-thread malloc arenas so freed pages return to the kernel
# instead of staying mapped in the process's address space. Default is
# 8×CPU per process; with 12 Python procs × ~16 arenas each, freed-but-
# still-mapped fragmentation drove the cgroup staircase observed during
# audit-heavy live runs (cgroup climbed +900MB while individual workers
# sawtoothed at the Python level — classic glibc-arena retention). Two
# arenas per process trades a little intra-process malloc lock contention
# for far better consolidation; CPython's GIL serializes most allocation
# work anyway, so the contention cost is well under the reclaim-throttling
# cost we hit at ~80% of the 4GB cgroup. Override per-machine if needed.
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"

# Worker DB pool sizing. Bumped from 4+6 to 6+10 to make room for in-process
# job concurrency (PSAT_<STAGE>_JOB_CONCURRENCY > 1 — opt-in per stage).
# Per-job worst case: 1 dispatcher session + 1 job session + heartbeat/timing
# fresh sessions ≈ 3 sessions in flight; 6+10 covers K=2 with headroom.
# With ~10 worker procs per VM this still stays well under Neon's pool ceiling.
# Override per-process by exporting PSAT_DB_POOL_SIZE / PSAT_DB_MAX_OVERFLOW
# before this script.
export PSAT_DB_POOL_SIZE="${PSAT_DB_POOL_SIZE:-6}"
export PSAT_DB_MAX_OVERFLOW="${PSAT_DB_MAX_OVERFLOW:-10}"

# In-process job concurrency. K=1 (default) keeps the legacy single-job loop
# byte-identical. Opt in per stage by setting PSAT_<STAGE>_JOB_CONCURRENCY.
# Recommended starting points (I/O-heavy stages first; static is CPU-bound on
# Slither so K=1 stays safer there):
#   PSAT_RESOLUTION_JOB_CONCURRENCY=2
#   PSAT_POLICY_JOB_CONCURRENCY=2
# Or set PSAT_JOB_CONCURRENCY for a fleet-wide default.

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

if [ -x ".venv/bin/python" ]; then
  PYTHON_CMD=(./.venv/bin/python)
elif command -v uv >/dev/null 2>&1; then
  PYTHON_CMD=(uv run --no-sync python)
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD=(python3)
elif command -v python >/dev/null 2>&1; then
  PYTHON_CMD=(python)
else
  echo "ERROR: No Python interpreter found. Run 'uv sync' or activate the project virtualenv."
  exit 1
fi

echo "Starting PSAT workers with: ${PYTHON_CMD[*]}"

# Worker counts are env-tunable so the bench harness can sweep them
# without rebuilding the image. Defaults match the long-standing prod
# fleet shape; cascade benches found 1-4 to be the useful range per
# stage. Recommended values per VM size:
#   shared-cpu-1x:    static=1 resolution=1 policy=1
#   performance-2x:   static=2 resolution=2 policy=1   (current default)
#   performance-4x:   static=4 resolution=2 policy=2
STATIC_COUNT="${PSAT_STATIC_WORKERS:-2}"
RESOLUTION_COUNT="${PSAT_RESOLUTION_WORKERS:-1}"
POLICY_COUNT="${PSAT_POLICY_WORKERS:-1}"
echo "  static workers:     $STATIC_COUNT (set PSAT_STATIC_WORKERS to override)"
echo "  resolution workers: $RESOLUTION_COUNT (set PSAT_RESOLUTION_WORKERS to override)"
echo "  policy workers:     $POLICY_COUNT (set PSAT_POLICY_WORKERS to override)"

"${PYTHON_CMD[@]}" -m workers.discovery &
PIDS+=($!)
for _ in $(seq 1 "$STATIC_COUNT"); do
  "${PYTHON_CMD[@]}" -m workers.static_worker &
  PIDS+=($!)
done
for _ in $(seq 1 "$RESOLUTION_COUNT"); do
  "${PYTHON_CMD[@]}" -m workers.resolution_worker &
  PIDS+=($!)
done
for _ in $(seq 1 "$POLICY_COUNT"); do
  "${PYTHON_CMD[@]}" -m workers.policy_worker &
  PIDS+=($!)
done
# Effects stage (EFFECTS_RESOLUTION_SPEC): sits between policy and coverage.
# Launched unconditionally so enabling PSAT_EFFECTS_STAGE never parks jobs at a
# stage no worker drains; idles when the flag is off. Single instance
# (PSAT_EFFECTS_JOB_CONCURRENCY=1, inv. 16 — anvil snapshot/revert is
# process-global).
"${PYTHON_CMD[@]}" -m workers.effects_worker &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.coverage_worker &
PIDS+=($!)
# Drains audit_contract_coverage rows where equivalence_status='pending'.
# Single instance is enough — concurrency is intentionally low (default 2
# threads) so we don't reintroduce the Etherscan rate-limit cascade the
# inline verify path used to cause (#82).
"${PYTHON_CMD[@]}" -m workers.coverage_verify &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.defillama_worker &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.selection_worker &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.audit_text_extraction &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.audit_scope_extraction &
PIDS+=($!)
# v2 capability resolver indexer. It follows generic event hints
# discovered by the semantic predicate pipeline.
"${PYTHON_CMD[@]}" -m workers.event_log_indexer &
PIDS+=($!)
# Enrollment reconciler drainer. Moved off the 512MB `monitor` VM: its
# per-tick governance-view recompute is jobs-pipeline-weight and belongs
# on this 16GB box. Its loop swallows exceptions, so the shared `wait -n`
# fate here is process-death-only.
"${PYTHON_CMD[@]}" -m workers.protocol_monitor --reconcile &
PIDS+=($!)

echo "All workers started: ${PIDS[*]}"
# Exit on first death — Fly restarts the machine so every worker
# relaunches. Silent-dead-worker is worse than a 30s restart.
wait -n
