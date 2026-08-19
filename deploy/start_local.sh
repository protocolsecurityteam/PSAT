#!/bin/bash
set -e

cd "$(dirname "$0")/.."

# Load .env
if [ ! -f .env ]; then
  echo "ERROR: .env file not found. Copy .env.example to .env and fill in values."
  exit 1
fi
set -a
source .env
set +a

# Unbuffered Python so each process's JSON logs flush to the log file promptly
# (block buffering would otherwise delay them). deploy/start_workers.sh sets this for the
# worker fleet; here it also covers the API, monitors, and dapp worker below.
export PYTHONUNBUFFERED=1

# Guardrail only — `error` is already env_logger's default with RUST_LOG unset,
# so hypersync's Rust 429 retry lines still reach the JSONL file below as
# plaintext (see deploy/start_workers.sh; fd-level capture is deferred).
export RUST_LOG="${RUST_LOG:-error}"

# Silence requests' import-time dependency-skew warning, which fires before any
# process can configure logging. Scoped to the requests module (see
# deploy/start_workers.sh), not a blanket ignore.
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore::Warning:requests}"

WORKER_PATTERN='workers\.(discovery|static_worker|resolution_worker|policy_worker|effects_worker|coverage_worker|coverage_verify|selection_worker|dapp_crawl_worker|defillama_worker|audit_text_extraction|audit_scope_extraction|event_log_indexer|protocol_monitor)'
API_PID=""
WORKERS_PID=""
BROWSER_PID=""
MONITOR_PID=""

# Check required env vars
missing=()
[ -z "$DATABASE_URL" ]      && missing+=("DATABASE_URL")
[ -z "$ETHERSCAN_API_KEY" ] && missing+=("ETHERSCAN_API_KEY")
[ -z "$ERPC_BASE_URL" ]     && missing+=("ERPC_BASE_URL")
[ -z "$ERPC_SECRET" ]       && missing+=("ERPC_SECRET")
[ -z "$ENVIO_API_TOKEN" ]   && missing+=("ENVIO_API_TOKEN")
[ -z "$TAVILY_API_KEY" ]    && missing+=("TAVILY_API_KEY")

if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: Missing required environment variables in .env:"
  for var in "${missing[@]}"; do
    echo "  - $var"
  done
  exit 1
fi

# Start postgres if not running
if ! docker compose ps postgres --status running -q 2>/dev/null | grep -q .; then
  echo "Starting postgres..."
  docker compose up postgres -d
  echo "Waiting for postgres to be healthy..."
  until docker compose ps postgres --status running -q 2>/dev/null | grep -q .; do
    sleep 1
  done
  sleep 3
fi

# Start minio (object storage) if not running.
# With ARTIFACT_STORAGE_* set, artifact bodies live in minio; without them,
# the app falls back to inline Postgres storage.
if ! docker compose ps minio --status running -q 2>/dev/null | grep -q .; then
  echo "Starting minio..."
  docker compose up minio minio-init -d
  echo "Waiting for minio to be healthy..."
  until docker compose ps minio --status running -q 2>/dev/null | grep -q .; do
    sleep 1
  done
  # minio-init creates the bucket then exits 0 — wait for that to complete.
  # Note: `docker compose ps` hides stopped containers by default, so pass -a.
  until [ "$(docker compose ps -a minio-init --format '{{.State}}' 2>/dev/null)" = "exited" ]; do
    sleep 1
  done
fi

# Report which artifact storage mode the app will use on boot.
if [ -n "$ARTIFACT_STORAGE_ENDPOINT" ] && [ -n "$ARTIFACT_STORAGE_BUCKET" ] \
   && [ -n "$ARTIFACT_STORAGE_ACCESS_KEY" ] && [ -n "$ARTIFACT_STORAGE_SECRET_KEY" ]; then
  echo "Artifact storage: minio ($ARTIFACT_STORAGE_ENDPOINT → $ARTIFACT_STORAGE_BUCKET)"
  echo "  Console: http://localhost:9001 (login: $ARTIFACT_STORAGE_ACCESS_KEY)"
else
  echo "WARNING: ARTIFACT_STORAGE_* not fully set in .env — app will use inline Postgres fallback."
  echo "  To use minio, add to .env:"
  echo "    ARTIFACT_STORAGE_ENDPOINT=http://localhost:9000"
  echo "    ARTIFACT_STORAGE_BUCKET=psat-artifacts"
  echo "    ARTIFACT_STORAGE_ACCESS_KEY=psat-minio"
  echo "    ARTIFACT_STORAGE_SECRET_KEY=psat-minio-secret"
fi

cleanup_stale_workers() {
  local stale
  stale=$(pgrep -af "$WORKER_PATTERN" || true)
  if [ -z "$stale" ]; then
    return
  fi

  echo "Stopping stale workers..."
  echo "$stale"
  pkill -f "$WORKER_PATTERN" 2>/dev/null || true

  for _ in $(seq 1 20); do
    if ! pgrep -f "$WORKER_PATTERN" >/dev/null 2>&1; then
      echo "Stale workers stopped."
      return
    fi
    sleep 0.5
  done

  echo "ERROR: Failed to stop stale workers."
  pgrep -af "$WORKER_PATTERN" || true
  exit 1
}

cleanup_stale_workers

echo "Initializing database tables..."
uv run alembic upgrade head

# Ensure Playwright browsers are installed (needed by dapp_crawl_worker)
if ! [ -d "$HOME/.cache/ms-playwright/chromium_headless_shell-1208" ]; then
  echo "Installing Playwright browsers..."
  uv run playwright install chromium
fi

# Trap to clean up background processes on exit
cleanup() {
  echo ""
  echo "Shutting down..."
  if [ -n "$API_PID" ]; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  if [ -n "$WORKERS_PID" ]; then
    kill "$WORKERS_PID" 2>/dev/null || true
    wait "$WORKERS_PID" 2>/dev/null || true
  fi
  if [ -n "$BROWSER_PID" ]; then
    kill "$BROWSER_PID" 2>/dev/null || true
    wait "$BROWSER_PID" 2>/dev/null || true
  fi
  if [ -n "$MONITOR_PID" ]; then
    kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
  fi
  echo "Done."
}
trap cleanup EXIT INT TERM

# Stream every long-running process's logs (JSON on stderr, see utils/logging.py) to
# one timestamped file instead of the terminal, so a run stays queryable afterward.
# logs/local-latest.jsonl always points at the newest run. (logs/ is git-ignored.)
mkdir -p logs
LOG_FILE="logs/local-$(date +%F-%H%M%S).jsonl"
ln -sfn "$(basename "$LOG_FILE")" logs/local-latest.jsonl 2>/dev/null || true

# Start API. `python serve.py` (not `uvicorn api:app`): only the programmatic
# launcher can hand uvicorn a log config, so its own lines — including a bind
# failure, which happens before the app's lifespan — land in this JSONL file as
# JSON instead of plaintext. It also drops uvicorn's access line, which
# duplicated the api middleware's richer one on every request.
echo "Starting API on http://127.0.0.1:8000 ..."
PSAT_API_HOST=127.0.0.1 PSAT_API_PORT=8000 PSAT_API_RELOAD=1 \
  uv run python serve.py >>"$LOG_FILE" 2>&1 &
API_PID=$!
sleep 2

# Start workers
echo "Starting workers..."
bash deploy/start_workers.sh >>"$LOG_FILE" 2>&1 &
WORKERS_PID=$!

# Start dapp crawl worker — the `browser` process group (deploy/start_browser.sh).
# Prod isolates it on its own RAM-heavy VM for Chromium; locally it runs
# alongside. Playwright chromium was ensured above.
echo "Starting dapp crawl worker (browser)..."
uv run python -m workers.dapp_crawl_worker >>"$LOG_FILE" 2>&1 &
BROWSER_PID=$!

# Start protocol monitor. Default mode is the whole monitor: scanner, poller,
# TVL, restaking, role-holder and score run as supervised threads in this one
# process. The --poll/--tvl flag modes are rollback levers for running a single
# loop ALONE — launching them alongside default mode gives every one of those
# loops two live instances. The enrollment reconciler is not a default-mode
# loop; deploy/start_workers.sh (started above) is what runs it.
echo "Starting protocol monitor..."
uv run python -m workers.protocol_monitor >>"$LOG_FILE" 2>&1 &
MONITOR_PID=$!

echo ""
echo "=== PSAT running ==="
echo "  API:     http://127.0.0.1:8000"
echo "  Health:  http://127.0.0.1:8000/api/health"
echo "  Logs:    $LOG_FILE  (newest -> logs/local-latest.jsonl)"
echo "           follow:  tail -f logs/local-latest.jsonl"
echo "           query:   jq -c 'select(.level==\"ERROR\")' logs/local-latest.jsonl     (browse: lnav logs/local-latest.jsonl)"
echo ""
echo "Press Ctrl+C to stop."
wait
