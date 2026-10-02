"""Event-log indexer knobs. Values only; every environment runs these defaults unless an operator overrides one."""

from __future__ import annotations

import os

INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_INTERVAL_S", "60"))
CONFIRMATION_DEPTH = int(os.getenv("PSAT_EVENT_INDEXER_FINALITY_DEPTH", "12"))

# ``paged`` streams bounded pages with no transaction held during RPC; ``legacy`` is the whole-window engine.
ENGINE = os.getenv("PSAT_EVENT_INDEXER_ENGINE", "paged").strip().lower() or "paged"

# Widest block range one page may request. Wide because HyperRPC bills per request regardless of range.
MAX_BLOCK_SPAN = int(os.getenv("PSAT_EVENT_INDEXER_MAX_BLOCK_SPAN", "500000"))
# Secondary limits behind the time budgets: pages per group visit and per pass.
MAX_WINDOWS_PER_CURSOR = int(os.getenv("PSAT_EVENT_INDEXER_MAX_WINDOWS_PER_CURSOR", "50"))
MAX_WINDOWS_PER_PASS = int(os.getenv("PSAT_EVENT_INDEXER_MAX_WINDOWS_PER_PASS", "100"))
INSERT_BATCH = int(os.getenv("PSAT_EVENT_INDEXER_INSERT_BATCH", "1000"))
# Each write prefix is its own commit, whole blocks at a time; the INSERT trigger holds the reconciliation row until
# commit.
WRITE_MAX_ROWS = 5_000
WRITE_MAX_BYTES = 4 * 1024 * 1024

# Monitored contracts still needing a cursor, worked per pass (each mints a cold backfill). Fully enrolled addresses
# cost one lookup and don't count, so the fleet drains and settles at zero.
TRACKED_TOPIC_ENROLL_LIMIT = int(os.getenv("PSAT_EVENT_INDEXER_TRACKED_TOPIC_LIMIT", "50"))
# A memory/latency bound on how many contracts a pass looks at, not a work budget; keep it above the fleet size or the
# tail is unreachable.
TRACKED_TOPIC_SCAN_LIMIT = int(os.getenv("PSAT_EVENT_INDEXER_TRACKED_TOPIC_SCAN_LIMIT", "5000"))
# Only cold history uses the short pause; warm groups use the normal interval.
BACKFILL_BUSY_INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_BACKFILL_BUSY_INTERVAL_S", "2"))

# Adaptive page span: aim each page at TARGET_PAGE_LOGS; a group of unknown density starts at INITIAL_SPAN blocks and
# doubles while pages come back under half the target.
TARGET_PAGE_LOGS = int(os.getenv("PSAT_EVENT_INDEXER_TARGET_PAGE_LOGS", "25000"))
INITIAL_SPAN = int(os.getenv("PSAT_EVENT_INDEXER_INITIAL_SPAN", "50000"))
# Memory ceiling: a larger page is discarded and bisected, down to one block.
MAX_PAGE_LOGS = int(os.getenv("PSAT_EVENT_INDEXER_MAX_PAGE_LOGS", "100000"))
# The lowest request span persisted after an upstream size refusal (the fetcher's bisect floor); one backlog's limit.
MIN_REQUEST_SPAN_LIMIT = int(os.getenv("PSAT_EVENT_INDEXER_MIN_REQUEST_SPAN_LIMIT", "10000"))
# Above eRPC's 30 s maxTimeout so the client receives eRPC's verdict. Only safe with the ceiling above.
GETLOGS_TIMEOUT_S = float(os.getenv("PSAT_EVENT_INDEXER_GETLOGS_TIMEOUT_S", "35"))

# Warm sweep: addresses per batched request, and the most lag a group may carry into a batch (a lagging member could
# otherwise pull another address's dense, non-enrolled topic).
WARM_BATCH_ADDRESSES = int(os.getenv("PSAT_EVENT_INDEXER_WARM_BATCH_ADDRESSES", "50"))
WARM_BATCH_MAX_LAG = int(os.getenv("PSAT_EVENT_INDEXER_WARM_BATCH_MAX_LAG", "1000"))

GROUP_BUDGET_S = float(os.getenv("PSAT_EVENT_INDEXER_GROUP_BUDGET_S", "30"))
PASS_BUDGET_S = float(os.getenv("PSAT_EVENT_INDEXER_PASS_BUDGET_S", "120"))

# Addresses whose floor witness is re-attempted per enrolment pass (each costs one Etherscan lookup and three RPC
# reads). Steady state, with every witness decided, costs nothing.
FLOOR_WITNESS_RETRY_BUDGET = int(os.getenv("PSAT_FLOOR_WITNESS_RETRY_BUDGET", "10"))
# Consecutive floor-witness failures after which each retry logs a WARNING; the retry backoff bounds how often.
FLOOR_WITNESS_FAILURE_ALERT = 5
