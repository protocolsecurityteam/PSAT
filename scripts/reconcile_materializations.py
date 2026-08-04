"""Queue bounded re-analysis for monitored contracts with no current
materialization (F4, invariant 11).

The main pipeline now leaves a materialization row behind (F4a) and the sweep
lifted the historical ones (F4b), so the invariant holds — until
``ANALYSIS_SCHEMA_VERSION`` is bumped, at which point every row reads as a miss
at once and the fleet quietly falls back to baseline-only watching. This is the
clamp for that: it re-analyzes the backlog at a rate somebody chose.

Spend is decided, not emergent. The daily cap is
``PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY`` (default 25, ``0`` disables
queuing); jobs already issued against it in the last 24 h are counted before
anything new is proposed; and the remainder is *reported*, not quietly issued.
The backlog itself rides ``/api/fleet`` and the ops tick (F9c) so a decaying
fleet is visible while it is still small.

Contracts already being built (``status='building'``) are excluded: a builder is
running for them, and a rebuild job would pay for the same bundle twice.

**Dry run is the default.** ``--apply`` creates jobs and is operator-run::

    uv run python -m scripts.reconcile_materializations
    uv run python -m scripts.reconcile_materializations --budget 5 --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from sqlalchemy.orm import Session

from db.models import SessionLocal
from db.queue import create_job
from services.monitoring.materialization_reconciler import (
    REBUILD_REQUEST_KEY,
    RebuildCandidate,
    plan_rebuilds,
)
from utils.chains import chain_enabled

logger = logging.getLogger(__name__)


def queue_rebuilds(session: Session, candidates: list[RebuildCandidate]) -> dict[str, int]:
    """Create one re-analysis job per candidate. Operator-run only.

    Chain-gated the same way ``reanalysis.maybe_queue_reanalysis`` is: a legacy
    row on a chain this deployment has disabled must never re-spawn analysis
    work on it.

    ``force`` is load-bearing, not a flourish. Discovery's same-address static
    cache (``find_completed_static_cache``) is NOT version-gated, so without it
    a rebuild issued after a schema bump — the one event this reconciler exists
    for — copies the superseded era's artifacts, skips analysis entirely, and
    clears the backlog without a single contract being re-analyzed. ``force``
    is the documented escape hatch that makes the job fetch and analyze for
    real.
    """
    counts = {"queued": 0, "skipped_chain_not_enabled": 0}
    for candidate in candidates:
        if not chain_enabled(candidate.chain):
            counts["skipped_chain_not_enabled"] += 1
            continue
        request: dict = {
            "address": candidate.address,
            "chain": candidate.chain,
            "name": f"Materialization rebuild ({candidate.reason})",
            "force": True,
            REBUILD_REQUEST_KEY: True,
        }
        if candidate.protocol_id:
            request["protocol_id"] = candidate.protocol_id
        job = create_job(session, request)
        logger.info(
            "queued materialization rebuild job %s for %s (%s, %s)",
            job.id,
            candidate.address,
            candidate.chain,
            candidate.reason,
        )
        counts["queued"] += 1
    return counts


def format_table(candidates: list[RebuildCandidate]) -> str:
    if not candidates:
        return "no rebuilds within budget"
    header = f"{'address':<44}{'chain':<10}{'reason':<22}{'protocol':>9}"
    lines = [header, "-" * len(header)]
    for c in candidates:
        lines.append(f"{c.address:<44}{c.chain:<10}{c.reason:<22}{(c.protocol_id if c.protocol_id else '-'):>9}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Queue the jobs. Off by default (dry run reports only).")
    ap.add_argument(
        "--budget",
        type=int,
        default=None,
        help="Override the daily cap for this run (still net of jobs already queued in the last 24h).",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    with SessionLocal() as session:
        candidates, backlog = plan_rebuilds(session, budget=args.budget)
        print(json.dumps(backlog, indent=2, sort_keys=True))
        print()
        print(format_table(candidates))
        if not args.apply:
            print(f"\ndry run: {len(candidates)} rebuild job(s) would be queued. Re-run with --apply to queue.")
            return 0
        counts = queue_rebuilds(session, candidates)
        print("\napplied: " + json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
