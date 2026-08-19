#!/bin/bash
# `web` process group: FastAPI only.
set -e

cd "$(dirname "$0")/.."

# --limit-concurrency gives the event loop backpressure before Fly's
# hard_limit=100 piles connections on us. No --workers: uvicorn's
# preforking shares the SQLAlchemy engine across children, and
# psycopg2 sockets are not fork-safe — children crash on first DB
# access.
#
# `python serve.py` runs api.serve(), which is uvicorn.run() with our JSON log
# config attached — the uvicorn CLI can only take that as a file. Same server,
# same settings; uvicorn's own lines stop bypassing the JSON stream and its
# access line (a duplicate of the api middleware's) is off. serve.py rather than
# api.py: uvicorn imports `api` itself, so running api.py directly would execute
# its module body a second time and build a whole throwaway app.
export PSAT_API_HOST=0.0.0.0
export PSAT_API_PORT=8000
export PSAT_API_LIMIT_CONCURRENCY=200
exec uv run --no-sync python serve.py
