#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [--dry-run] start|stop APP ORGANIZATION PORT STATE_DIR" >&2
  exit 2
}

dry_run=0
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=1
  shift
fi
[[ $# -eq 5 ]] || usage
operation=$1
app=$2
organization=$3
port=$4
state_dir=$5

[[ "$operation" == "start" || "$operation" == "stop" ]] || usage
[[ "$app" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid app" >&2; exit 2; }
[[ "$organization" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid organization" >&2; exit 2; }
[[ "$organization" != "personal" && "$organization" != "protosec" ]] || { echo "refusing non-staging organization" >&2; exit 2; }
if [[ ! "$port" =~ ^[0-9]{4,5}$ ]] || (( port < 1024 || port > 65535 )); then
  echo "invalid port" >&2
  exit 2
fi
[[ "$state_dir" == /* ]] || { echo "state directory must be absolute" >&2; exit 2; }

pid_file="$state_dir/fly-proxy.pid"
log_file="$state_dir/fly-proxy.log"

if (( dry_run )); then
  printf '%q ' flyctl proxy "${port}:80" "${app}.flycast" --org "$organization" --bind-addr 127.0.0.1 --quiet
  printf '\n'
  exit 0
fi

mkdir -p "$state_dir"

if [[ "$operation" == "stop" ]]; then
  if [[ ! -f "$pid_file" ]]; then
    exit 0
  fi
  pid=$(<"$pid_file")
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo "invalid proxy pid file" >&2; exit 1; }
  if kill -0 "$pid" 2>/dev/null; then
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
    [[ "$cmdline" == *"flyctl proxy"* && "$cmdline" == *"${app}.flycast"* ]] || {
      echo "refusing to stop process that is not the expected Fly proxy" >&2
      exit 1
    }
    kill "$pid"
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    kill -0 "$pid" 2>/dev/null && { echo "Fly proxy did not stop" >&2; exit 1; }
  fi
  rm -f "$pid_file" "$log_file"
  exit 0
fi

[[ ! -e "$pid_file" ]] || { echo "proxy state already exists" >&2; exit 1; }
: "${FLY_API_TOKEN:?FLY_API_TOKEN is required}"
flyctl proxy "${port}:80" "${app}.flycast" --org "$organization" --bind-addr 127.0.0.1 --quiet >"$log_file" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$pid_file"

cleanup_failed_start() {
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -f "$pid_file"
}

for _ in $(seq 1 60); do
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" || status=$?
    echo "Fly private proxy exited before it became ready (status ${status:-0})" >&2
    sed -n '1,80p' "$log_file" >&2
    cleanup_failed_start
    exit 1
  fi
  # Any HTTP response proves the authenticated private route is accepting
  # connections; the caller separately requires a healthy application response.
  if curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:${port}/api/health"; then
    exit 0
  fi
  sleep 1
done

echo "Fly private proxy was not ready within 60 seconds" >&2
sed -n '1,80p' "$log_file" >&2
cleanup_failed_start
exit 1
