#!/bin/bash
# `workers` process group: queue consumers only. Scaled as a group via
# `fly scale count --process-group workers N`.
# dapp_crawl_worker lives in `browser`; protocol_monitor in `monitor`.
set -e
unset PSAT_WORKER_LIFECYCLE_TOKEN

cd "$(dirname "$0")/.."

export PYTHONUNBUFFERED=1

# This script's stdout is redirected into the JSONL log stream (deploy/start_local.sh,
# deploy/start_container.sh), so a bare `echo` lands there as a line no JSON reader can
# parse. Emit the launcher's own lines in the same one-object-per-line shape the
# Python processes use. Level is the first argument; the rest is the message.
log_json() {
  local level="$1"
  shift
  local msg="$*"
  msg=${msg//\\/\\\\}
  msg=${msg//\"/\\\"}
  printf '{"timestamp":"%s","level":"%s","logger":"start_workers","message":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "$level" "$msg"
}

# The hypersync client is Rust; its env_logger writes plaintext straight to fd 2,
# bypassing Python logging. This pin does NOT change today's output: env_logger's
# default with RUST_LOG unset is already `error`, and the 429 retry lines are
# ERROR — they still land in the log file as plaintext. It is only a guardrail
# against an upstream default-level change dumping Rust INFO/DEBUG in here.
# Actually capturing that stderr needs an fd-level pump, and the hypersync call
# sites live in services/resolution/repos — both out of this lane; deferred. A
# hypersync failure that degrades a fold is already reported on the Python side
# by `_note_partial_reason`, so the JSON stream is not blind to the outcome.
export RUST_LOG="${RUST_LOG:-error}"

# requests warns about its urllib3/charset_normalizer version skew at IMPORT
# time — before any process reaches configure_logging(), so captureWarnings
# cannot reach it — costing ~46 raw plaintext lines per run, two per worker.
# Scoped to warnings raised BY the requests module, not a blanket ignore: any
# warning from anywhere else still surfaces. The skew it reports is real and
# wants fixing at the dependency level; this only stops it re-announcing itself
# once per process.
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore::Warning:requests}"

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

if [ -x ".venv/bin/python" ]; then
  PYTHON_CMD=(./.venv/bin/python)
elif command -v uv >/dev/null 2>&1; then
  PYTHON_CMD=(uv run --no-sync python)
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD=(python3)
elif command -v python >/dev/null 2>&1; then
  PYTHON_CMD=(python)
else
  log_json ERROR "No Python interpreter found. Run 'uv sync' or activate the project virtualenv."
  exit 1
fi

if [ "${PSAT_WORKER_LIFECYCLE_MODE:-off}" != "off" ] && [ "${PSAT_RUNTIME_CHILD:-0}" != "1" ]; then
  exec "${PYTHON_CMD[@]}" -m workers.machine_runtime workers
fi

log_json INFO "Starting PSAT workers with: ${PYTHON_CMD[*]}"

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
log_json INFO "static workers: $STATIC_COUNT (set PSAT_STATIC_WORKERS to override)"
log_json INFO "resolution workers: $RESOLUTION_COUNT (set PSAT_RESOLUTION_WORKERS to override)"
log_json INFO "policy workers: $POLICY_COUNT (set PSAT_POLICY_WORKERS to override)"

# Address-space cap per worker process, sized from the workers' measured footprints so no single process can push
# the VM into reclaim. The stage workers and the effects worker cover the compilers and the anvil fork they spawn, which
# inherit the cap; a stage worker's budgeted compute child inherits it too.
HEAVY_CAP_MB="${PSAT_HEAVY_WORKER_AS_MB:-6144}"
WORKER_CAP_MB="${PSAT_WORKER_AS_MB:-4096}"

SPECS=("discovery|$WORKER_CAP_MB|workers.discovery")
for i in $(seq 1 "$STATIC_COUNT"); do
  SPECS+=("static_worker.$i|$HEAVY_CAP_MB|workers.static_worker")
done
for i in $(seq 1 "$RESOLUTION_COUNT"); do
  SPECS+=("resolution_worker.$i|$HEAVY_CAP_MB|workers.resolution_worker")
done
for i in $(seq 1 "$POLICY_COUNT"); do
  SPECS+=("policy_worker.$i|$HEAVY_CAP_MB|workers.policy_worker")
done
# Effects stage: sits between policy and coverage.
# Launched unconditionally so enabling PSAT_EFFECTS_STAGE never parks jobs at a
# stage no worker drains; idles when the flag is off. Single instance
# (PSAT_EFFECTS_JOB_CONCURRENCY=1 — anvil snapshot/revert is
# process-global).
SPECS+=("effects_worker|$HEAVY_CAP_MB|workers.effects_worker")
SPECS+=("coverage_worker|$WORKER_CAP_MB|workers.coverage_worker")
# Drains audit_contract_coverage rows where equivalence_status='pending'.
# Single instance is enough — concurrency is intentionally low (default 2
# threads) so we don't reintroduce the Etherscan rate-limit cascade the
# inline verify path used to cause (#82).
SPECS+=("coverage_verify|$WORKER_CAP_MB|workers.coverage_verify")
SPECS+=("defillama_worker|$WORKER_CAP_MB|workers.defillama_worker")
SPECS+=("selection_worker|$WORKER_CAP_MB|workers.selection_worker")
SPECS+=("audit_text_extraction|$WORKER_CAP_MB|workers.audit_text_extraction")
SPECS+=("audit_scope_extraction|$WORKER_CAP_MB|workers.audit_scope_extraction")
# v2 capability resolver indexer. It follows generic event hints
# discovered by the semantic predicate pipeline.
if [ "${PSAT_INDEXER_GROUP:-workers}" = "workers" ]; then
  if [ "${PSAT_WORKER_LIFECYCLE_MODE:-off}" != "off" ]; then
    SPECS+=("event_log_indexer|$WORKER_CAP_MB|workers.machine_runtime indexer")
  else
    SPECS+=("event_log_indexer|$WORKER_CAP_MB|workers.event_log_indexer")
  fi
fi
# Enrollment reconciler drainer. Moved off the 512MB `monitor` VM: its
# per-tick governance-view recompute is jobs-pipeline-weight and belongs
# on this 16GB box.
SPECS+=("enrollment_reconciler|$WORKER_CAP_MB|workers.protocol_monitor --reconcile")

log_json INFO "Supervising ${#SPECS[@]} workers"
# The supervisor restarts a dead worker alone and exits nonzero only on a restart loop, which restarts the machine.
# exec, so SIGTERM from the platform or the lifecycle runtime reaches it directly and drains every worker.
exec "${PYTHON_CMD[@]}" -m workers.process_supervisor "${SPECS[@]}"
