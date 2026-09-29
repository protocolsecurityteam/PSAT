#!/bin/bash
# `web` process group: independently supervised API and company preparation.
set -e
unset PSAT_WORKER_LIFECYCLE_TOKEN

cd "$(dirname "$0")/.."

# --limit-concurrency gives the event loop backpressure before Fly's
# hard_limit=100 piles connections on us. No --workers: uvicorn's
# preforking shares the SQLAlchemy engine across children, and
# psycopg2 sockets are not fork-safe — children crash on first DB
# access.
#
# The supervisor launches serve.py to apply JSON logging without importing
# api twice, and restarts the company builder independently of the API.
export PSAT_API_HOST=0.0.0.0
export PSAT_API_PORT=8000
export PSAT_API_LIMIT_CONCURRENCY=200
exec uv run --no-sync python -m workers.web_runtime
