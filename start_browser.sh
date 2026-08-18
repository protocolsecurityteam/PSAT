#!/bin/bash
# `browser` process group: Playwright + dapp_crawl_worker only.
# Isolated because Chromium's RAM profile is much heavier than the
# other queue workers — sharing a VM risks OOMing everything together.
set -e

cd "$(dirname "$0")"

export PYTHONUNBUFFERED=1

# The hypersync client is Rust; its env_logger writes plaintext straight to fd 2,
# bypassing Python logging. This pin does NOT change today's output: env_logger's
# default with RUST_LOG unset is already `error`. It is only a guardrail against
# an upstream default-level change dumping Rust INFO/DEBUG into the log stream.
export RUST_LOG="${RUST_LOG:-error}"

# requests warns about its urllib3/charset_normalizer version skew at IMPORT
# time — before this process reaches configure_logging(), so captureWarnings
# cannot reach it. Scoped to warnings raised BY the requests module, not a
# blanket ignore: any warning from anywhere else still surfaces. The skew it
# reports is real and wants fixing at the dependency level; this only stops it
# re-announcing itself once per process.
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore::Warning:requests}"

exec uv run --no-sync python -m workers.dapp_crawl_worker
