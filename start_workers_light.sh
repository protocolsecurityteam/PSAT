#!/bin/bash
# Process group: workers-light. Network-bound + lightweight workers
# (discovery, coverage, defillama, selection, audit pipeline).
# Pairs with workers-heavy in the bench split experiment — shared-cpu
# is plenty for these.
set -e

cd "$(dirname "$0")"

export PYTHONUNBUFFERED=1

# Match start_workers.sh: bumped to 6+10 to cover in-process job concurrency
# (PSAT_<STAGE>_JOB_CONCURRENCY > 1, opt-in per stage).
export PSAT_DB_POOL_SIZE="${PSAT_DB_POOL_SIZE:-6}"
export PSAT_DB_MAX_OVERFLOW="${PSAT_DB_MAX_OVERFLOW:-10}"

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
  echo "ERROR: No Python interpreter found."
  exit 1
fi

echo "Starting PSAT workers-light with: ${PYTHON_CMD[*]}"

"${PYTHON_CMD[@]}" -m workers.discovery &
PIDS+=($!)
# Effects stage (EFFECTS_RESOLUTION_SPEC): between policy and coverage. Launched
# unconditionally so enabling PSAT_EFFECTS_STAGE never parks jobs; idles off.
"${PYTHON_CMD[@]}" -m workers.effects_worker &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.coverage_worker &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.defillama_worker &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.selection_worker &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.audit_text_extraction &
PIDS+=($!)
"${PYTHON_CMD[@]}" -m workers.audit_scope_extraction &
PIDS+=($!)

echo "All light workers started: ${PIDS[*]}"
wait -n
