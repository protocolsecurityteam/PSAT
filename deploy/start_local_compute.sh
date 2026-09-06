#!/usr/bin/env bash
set -euo pipefail
if (( $# != 0 )); then
  echo 'The compute launcher accepts no arguments' >&2
  exit 2
fi
compute_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
compute_env="$compute_root/.env.compute"
if [[ ! -f "$compute_env" || -L "$compute_env" || ! -O "$compute_env" ]]; then
  echo 'A dedicated, operator-owned .env.compute file is required' >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$compute_env")" != 600 ]]; then
  echo '.env.compute must have mode 600' >&2
  exit 1
fi
mkdir -p -- "$compute_root/logs"
exec 9>"$compute_root/logs/local-compute.lock"
if ! flock -n 9; then
  echo 'A local compute launcher is already running' >&2
  exit 1
fi
set -a
# shellcheck disable=SC1090
source "$compute_env"
set +a
export PYTHON_DOTENV_DISABLED=1
export PSAT_COMPUTE_TARGET=local
cd -- "$compute_root"
exec "$compute_root/.venv/bin/python" -m services.compute.supervisor
