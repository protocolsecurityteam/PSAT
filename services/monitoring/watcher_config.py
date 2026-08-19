"""Env / lease / per-chain tuning for the unified watcher loops.

Lifted verbatim from ``services.monitoring.unified_watcher``, which
re-exports every name so existing imports and the enrichment lazy import
keep resolving. Patch-targeted attributes (``MAX_BATCH_SIZE``,
``get_latest_block``, ``rpc_request``) deliberately stay in
``unified_watcher``.
"""

from __future__ import annotations

import os
import uuid

from sqlalchemy.exc import OperationalError

from utils.chains import UnknownChainError, chain_by_name

MAX_BLOCK_RANGE = 2000
DEFAULT_SCAN_INTERVAL = int(os.getenv("PROTOCOL_SCAN_INTERVAL", "600"))
DEFAULT_POLL_INTERVAL = int(os.getenv("PROTOCOL_POLL_INTERVAL", "600"))
# Poller rotation slice — how many needs_polling contracts one pass claims,
# ordered oldest-cursor-first. Bounds the pass to O(slice) memory.
DEFAULT_POLL_CONTRACTS_PER_PASS = 500

# monitored_events must only ingest confirmed logs — a reorg-rewound event
# would have already fired a Discord notification and a reanalysis job that
# cannot be un-sent. Every window end is clamped to head − this depth.
DEFAULT_CONFIRMATION_DEPTH = 12
# The shared getLogs fetcher bisects a rejected window down to this floor
# before re-raising. It must sit well below MAX_BLOCK_RANGE so a provider
# range/response-cap rejection actually bisects instead of failing the cohort.
FETCHER_MIN_BISECT_SPAN = 125

# Runaway-cursor backstop (see ``scan_for_events``). The budget is WALL CLOCK,
# not blocks: ~139 days of the cohort's own chain. No outage-driven backfill
# reaches that, so a cohort past it is carrying a broken cursor rather than
# doing real work. Expressing it in blocks would make the threshold mean
# different things per chain — 1M blocks is ~139 days of mainnet but ~23 days of
# Base, so a uniform block count would demote every Base cohort after a
# three-week outage, exactly when catch-up matters most.
DEFAULT_RUNAWAY_LAG_SECONDS = 12_000_000
DEFAULT_RUNAWAY_WINDOWS_PER_PASS = 1

# One read per dirty controller per scan pass. Reads beyond this are RECORDED
# as skipped (services/monitoring/verify_status.py), never silently dropped —
# a skipped read is a not-determined interval, not an earned negative.
DEFAULT_MAX_VERIFY_READS_PER_PASS = 25

# Reason stamped on the enrollment-queue row when the watcher's relational sync
# observes an on-chain controller rotation (owner/admin/authority/implementation).
# Closes the gap where a rotation installs a new governance Safe that would
# otherwise stay unmonitored until the slow sweep.
_GOVERNANCE_ROTATION_REASON = "governance_rotation"

# Write targets whose sync actually installs a new privileged controller — the
# only changes that can bring a new governance principal into scope and so
# warrant re-enrolling the protocol. Pause/threshold/roles writes mutate state
# but don't add a controller address, so they don't mark.
_GOVERNANCE_ROTATION_WRITE_TARGETS = frozenset(
    {"owner", "_owner", "admin", "_admin", "authority", "implementation", "beacon"}
)


# Stable per-process lease holder. Generated once at import so every pass this
# interpreter runs re-acquires its OWN lease (the ``holder = EXCLUDED.holder``
# branch always wins), and a genuinely separate process — the thing the
# singleton lease exists to exclude — carries a different uuid and loses.
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
    """Per-chain getLogs window width from the registry. Mainnet's
    registry value equals ``MAX_BLOCK_RANGE`` so mainnet is unchanged; an
    unresolvable chain falls back to the fleet-wide constant."""
    try:
        return chain_by_name(chain).max_getlogs_range
    except UnknownChainError:
        return MAX_BLOCK_RANGE


def _runaway_lag_blocks_for(chain: str) -> int:
    """The runaway threshold in blocks for *chain*, from the wall-clock budget.

    0 disables the backstop — either because the operator set the budget to 0,
    or because the chain's block time is not in the registry. An unresolvable
    chain gives no honest way to convert seconds to blocks, and a borrowed
    conversion would demote a cohort on a guess; not-determined means the
    backstop does not fire (demotion needs a witness).
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
    """Per-chain reorg-confirmation depth. An explicit
    ``PSAT_SCAN_CONFIRMATION_DEPTH`` override still wins fleet-wide (operator
    lever); otherwise the registry's per-chain depth applies. Mainnet's registry
    value equals ``DEFAULT_CONFIRMATION_DEPTH`` so mainnet is unchanged."""
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


# psycopg2 raises DeadlockDetected (SQLSTATE 40P01) when Postgres aborts one
# side of a lock cycle. Driver errors from real cursor executes (including
# autoflush) always arrive wrapped in a SQLAlchemy OperationalError (``.orig``);
# the raw psycopg2 form only occurs when an error is raised from an event
# listener (e.g. before_cursor_execute in tests), which SQLAlchemy does not
# wrap. Both shapes are recognized as belt-and-braces. The
# defensive import mirrors workers/retry_policy.py so a psycopg2-less test env
# still imports the module.
try:
    import psycopg2
    from psycopg2.errors import DeadlockDetected as _PgDeadlockDetected

    _DEADLOCK_TYPES: tuple[type[BaseException], ...] = (_PgDeadlockDetected,)
    _PSYCOPG2_ERROR: tuple[type[BaseException], ...] = (psycopg2.Error,)
except Exception:  # pragma: no cover — psycopg2 is a hard dep in production
    _DEADLOCK_TYPES = ()
    _PSYCOPG2_ERROR = ()

_DEADLOCK_PGCODE = "40P01"

# Every DB error shape a chunk's writes can raise: SQLAlchemy's wrapper plus the
# raw psycopg2 error (which is NOT a subclass of SQLAlchemy's). Both poison the
# session, so both must reach the chunk handler rather than a bare
# ``except Exception`` that would swallow them into a pending-rollback session.
_DB_ERROR_TYPES: tuple[type[BaseException], ...] = (OperationalError,) + _PSYCOPG2_ERROR


def _is_deadlock_error(exc: BaseException) -> bool:
    """True iff *exc* is (or wraps) a Postgres deadlock — only ONE side is
    aborted and the aborted side can simply retry, everything else stays
    committed.

    Handles both the SQLAlchemy-wrapped form (psycopg2 error on ``.orig``) and
    the raw psycopg2 form. Deliberately narrow otherwise: a connection-loss
    error returns False so the caller re-raises it and the pass dies honestly
    instead of masking a lost database as a per-chunk hiccup.
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
    """Delay before the poller's FIRST pass so it doesn't fire in lockstep with
    the scanner.

    The scan and poll loops share the same interval and the supervisor boots
    them together, so without a phase shift both write ``monitored_contracts``
    at the same instant every cycle. A half-interval offset de-phases them for
    the whole run (equal periods stay half a cycle apart). Only the poller
    shifts — the scanner's first pass must not be delayed, since watchers care
    about scan latency, not poll latency. The offset stays well under the
    poller's staleness window (``3 × interval``, process_meta) so the delayed
    first heartbeat never reads as dead. Overridable via
    ``PSAT_POLL_STARTUP_OFFSET_S`` (0 disables the shift).
    """
    raw = os.getenv("PSAT_POLL_STARTUP_OFFSET_S")
    if raw is not None:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return max(0.0, interval / 2.0)


# Controller IDs that represent the contract owner. Used by relational sync
# to update only the real owner row, not unrelated controller values that
# happen to contain "owner" in their name (e.g. token_owner_registry).
_OWNER_CONTROLLER_IDS = ("owner", "state_variable:owner")
# Solmate-Auth / DSAuth-style authority pointer. Sync target for the
# ``authority_updated`` event emitted by Solmate's ``Auth.setAuthority``.
_AUTHORITY_CONTROLLER_IDS = ("authority", "state_variable:authority", "external_contract:authority")
