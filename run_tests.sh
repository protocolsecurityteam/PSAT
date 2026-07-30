#!/bin/bash
# Per-unit isolated offline test runner (worktree u8).
# Usage: ./run_tests.sh [pytest args, e.g. tests/test_x.py]
# Do NOT source .env around this; it exports its own CI-faithful env.
set -e
cd "$(dirname "$0")"
N="${PSAT_XDIST_N:-2}"
export TEST_DATABASE_URL="postgresql://psat:psat@localhost:5433/psat_test_u8"
export DATABASE_URL="$TEST_DATABASE_URL"
export TEST_ARTIFACT_STORAGE_ENDPOINT="http://localhost:9000"
export TEST_ARTIFACT_STORAGE_BUCKET="psat-artifacts-test-u8"
export TEST_ARTIFACT_STORAGE_ACCESS_KEY="psat-minio"
export TEST_ARTIFACT_STORAGE_SECRET_KEY="psat-minio-secret"
export PSAT_LLM_STUB_DIR="tests/fixtures/scope_extraction/llm_responses"
export PSAT_DB_POOL_SIZE="${PSAT_DB_POOL_SIZE:-2}"
export PSAT_DB_MAX_OVERFLOW="${PSAT_DB_MAX_OVERFLOW:-3}"
export PYTHONPATH="$(pwd)"
if ! ./.venv/bin/python -c "import xdist" 2>/dev/null; then
  uv pip install --python ./.venv/bin/python pytest-xdist >/dev/null
fi
if ! PGPASSWORD=psat psql -h localhost -p 5433 -U psat -d postgres -tAc       "SELECT 1 FROM pg_database WHERE datname='psat_test_u8'" 2>/dev/null | grep -q 1; then
  PGPASSWORD=psat psql -h localhost -p 5433 -U psat -d postgres -c "CREATE DATABASE psat_test_u8 OWNER psat;" >/dev/null
fi
./.venv/bin/python -m alembic upgrade head >/dev/null 2>&1 || true
exec ./.venv/bin/python -m pytest -m "not live" -n "$N" --dist loadfile   -p local_perf_xdist -p local_netguard -q "$@"
