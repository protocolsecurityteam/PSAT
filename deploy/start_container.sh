#!/bin/bash
set -e

cd "$(dirname "$0")/.."

echo "[entrypoint] Running Alembic migrations (idempotent)..."
# Hard ceiling so a stuck schema migration can't keep uvicorn from
# binding port 8000; Fly restarts the machine and retries.
timeout 60s uv run --no-sync alembic upgrade head

echo "[entrypoint] Starting background workers..."
./deploy/start_workers.sh &

echo "[entrypoint] Starting API on 0.0.0.0:8000..."
# --limit-concurrency gives the event loop backpressure before Fly's
# hard_limit=100 piles connections on us. No --workers: uvicorn's
# preforking shares the SQLAlchemy engine across children, and
# psycopg2 sockets are not fork-safe — children crash on first DB
# access.
#
# This is the image's CMD. Fly's [processes] overrides it with deploy/start_web.sh, so
# only a plain `docker run` lands here — which is exactly why it must use the
# same launcher: on the uvicorn CLI there is no way to attach the JSON log
# config, and every server line reverts to plaintext.
export PSAT_API_HOST=0.0.0.0
export PSAT_API_PORT=8000
export PSAT_API_LIMIT_CONCURRENCY=200
exec uv run --no-sync python serve.py
