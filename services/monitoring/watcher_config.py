"""Env, lease and per-chain tuning for the unified watcher loops.

Re-exported by ``unified_watcher``; patch-targeted names (``MAX_BATCH_SIZE``, ``get_latest_block``, ``rpc_request``)
stay there.
"""

from __future__ import annotations

import os
import uuid

from sqlalchemy.exc import OperationalError

from utils.chains import UnknownChainError, chain_by_name

MAX_BLOCK_RANGE = 2000
DEFAULT_SCAN_INTERVAL = int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600"))
DEFAULT_POLL_INTERVAL = int(os.getenv("PROTOCOL_POLL_INTERVAL", "600"))
# Contracts one poll pass claims, oldest cursor first; bounds pass memory.
DEFAULT_POLL_CONTRACTS_PER_PASS = 500

# Only confirmed logs: a reorged event would already have sent a Discord notification and a reanalysis job.
DEFAULT_CONFIRMATION_DEPTH = 12
# Must sit well below MAX_BLOCK_RANGE so a provider range cap bisects rather than failing the cohort.
FETCHER_MIN_BISECT_SPAN = 125

# Runaway-cursor backstop, in wall-clock seconds (~139 days) rather than blocks: a block count would mean ~23 days on
# Base and demote every Base cohort after a three-week outage.
DEFAULT_RUNAWAY_LAG_SECONDS = 12_000_000
DEFAULT_RUNAWAY_WINDOWS_PER_PASS = 1

# Reads over this are recorded as skipped (verify_status), never dropped.
DEFAULT_MAX_VERIFY_READS_PER_PASS = 25

# Enrollment-queue reason when relational sync sees a controller rotation, so a newly installed governance Safe is
# monitored before the slow sweep.
_GOVERNANCE_ROTATION_REASON = "governance_rotation"

# Only these writes install a new controller address and so warrant re-enrollment.
_GOVERNANCE_ROTATION_WRITE_TARGETS = frozenset(
    {"owner", "_owner", "admin", "_admin", "authority", "implementation", "beacon"}
)


# Per-process, so this interpreter always re-acquires its own lease and a separate process loses.
_LEASE_HOLDER = uuid.uuid4()


def _scanner_lease_name(chain: str) -> str:
    return f"protocol_scanner:{chain}"


def _poller_lease_name(chain: str) -> str:
    return f"protocol_poller:{chain}"


def _scan_int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _scan_float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _max_getlogs_range_for(chain: str) -> int:
    """Per-chain getLogs window width from the registry; falls back to ``MAX_BLOCK_RANGE``."""
    try:
        return chain_by_name(chain).max_getlogs_range
    except UnknownChainError:
        return MAX_BLOCK_RANGE


def _runaway_lag_blocks_for(chain: str) -> int:
    """Runaway threshold in blocks for *chain*.

    0 disables it, including when the block time is unknown: demotion needs a witness, not a guess.
    """
    budget_s = max(0, _scan_int_env("PSAT_SCAN_RUNAWAY_LAG_SECONDS", DEFAULT_RUNAWAY_LAG_SECONDS))
    if not budget_s:
        return 0
    try:
        block_time = chain_by_name(chain).block_time_s
    except UnknownChainError:
        return 0
    if block_time <= 0:
        return 0
    return int(budget_s / block_time)


def _confirmation_depth_for(chain: str) -> int:
    """Per-chain reorg depth; ``PSAT_SCAN_CONFIRMATION_DEPTH`` overrides fleet-wide."""
    raw = os.getenv("PSAT_SCAN_CONFIRMATION_DEPTH")
    if raw is not None:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    try:
        return chain_by_name(chain).confirmation_depth
    except UnknownChainError:
        return DEFAULT_CONFIRMATION_DEPTH


# Deadlocks arrive wrapped in SQLAlchemy's OperationalError, or raw from event listeners (tests). Optional import, as in
# workers/retry_policy.py.
try:
    import psycopg2
    from psycopg2.errors import DeadlockDetected as _PgDeadlockDetected

    _DEADLOCK_TYPES: tuple[type[BaseException], ...] = (_PgDeadlockDetected,)
    _PSYCOPG2_ERROR: tuple[type[BaseException], ...] = (psycopg2.Error,)
except Exception:  # pragma: no cover — psycopg2 is a hard dep in production
    _DEADLOCK_TYPES = ()
    _PSYCOPG2_ERROR = ()

_DEADLOCK_PGCODE = "40P01"

# Both shapes poison the session, so they must reach the chunk handler, not a bare ``except Exception``.
_DB_ERROR_TYPES: tuple[type[BaseException], ...] = (OperationalError,) + _PSYCOPG2_ERROR


def _is_deadlock_error(exc: BaseException) -> bool:
    """True iff *exc* is or wraps a Postgres deadlock, where only one side aborted and can retry.

    Connection loss returns False so the pass dies instead of masking a lost database.
    """
    if _DEADLOCK_TYPES and isinstance(exc, _DEADLOCK_TYPES):
        return True
    if getattr(exc, "pgcode", None) == _DEADLOCK_PGCODE:
        return True
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    if _DEADLOCK_TYPES and isinstance(orig, _DEADLOCK_TYPES):
        return True
    return getattr(orig, "pgcode", None) == _DEADLOCK_PGCODE


def _poll_startup_offset(interval: float) -> float:
    """Delay before the poller's first pass, half an interval by default.

    Scanner and poller share an interval and boot together; without the shift both write ``monitored_contracts`` in
    lockstep. Only the poller shifts, and it stays under the staleness window. ``PSAT_POLL_STARTUP_OFFSET_S=0`` disables
    it.
    """
    raw = os.getenv("PSAT_POLL_STARTUP_OFFSET_S")
    if raw is not None:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return max(0.0, interval / 2.0)


# Exact ids, so relational sync never touches controllers that merely contain "owner" (e.g. token_owner_registry).
_OWNER_CONTROLLER_IDS = ("owner", "state_variable:owner")
# Solmate/DSAuth authority pointer, synced on ``authority_updated``.
_AUTHORITY_CONTROLLER_IDS = ("authority", "state_variable:authority", "external_contract:authority")
