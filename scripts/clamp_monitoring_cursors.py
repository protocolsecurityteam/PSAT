"""One-off repair for monitored-contract scan cursors that no honest scan can
reach (F6, invariant 9: bounded, honest scanning).

Two shapes, both observed on the working fleet:

``below_floor``
    ``last_scanned_block < enrollment_block``. The cursor sits under the floor
    the row itself declares as the start of watching, so every pass re-fetches
    blocks that are pre-enrollment by definition. Repair: raise the cursor to
    the floor. Nothing is skipped — those blocks were never ours to watch.

``unfloored_runaway``
    A row with no honest floor (``enrollment_block`` NULL or 0) whose cursor is
    more than ``--max-lag`` blocks behind head. The audited case
    (``0xe2acf9f8…``: floor 0, cursor 9,400,000, ~16M behind) is a legacy row
    the most-behind-first scheduler serves first on every pass, forever, while
    the rest of the fleet waits. Repair: move the cursor to the target block and
    declare the floor there.

    The blocks between the old cursor and the target are **not** scanned by this
    script and are not silently forgotten: each clamp appends a ``scan_gaps``
    entry to ``monitoring_config`` naming the interval, so a not-determined
    window stays visible to any reader instead of being backfilled into a claim
    of continuous coverage. Raising the floor is also protective — without it
    the scanner would eventually publish decade-old events as live changes.

**Dry run is the default.** The mutating path requires ``--apply`` and is
operator-run; no agent executes it. Usage::

    # report only (no writes) — the default
    uv run python -m scripts.clamp_monitoring_cursors

    # one row, explicit target, no RPC
    uv run python -m scripts.clamp_monitoring_cursors --address 0xe2acf9f8... \\
        --target-block 25662000 --apply

Heads are read per chain over RPC unless ``--target-block`` pins one. A chain
whose head does not answer is reported and skipped: a clamp target that was
never witnessed is not a target.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import MonitoredContract, SessionLocal
from services.monitoring.chain_rpc import chain_id_for, rpc_for_chain
from utils.rpc import default_rpc_url, rpc_request

logger = logging.getLogger(__name__)

BELOW_FLOOR = "below_floor"
UNFLOORED_RUNAWAY = "unfloored_runaway"

#: Default runaway threshold. ~1M mainnet blocks is ≈4 months — far beyond any
#: outage-driven backfill, so a row past it is a broken cursor, not a busy one.
DEFAULT_MAX_LAG = 1_000_000


@dataclass
class Clamp:
    """One proposed repair. ``skipped_from``/``skipped_to`` is the interval the
    clamp does not scan (``None`` when the class skips nothing)."""

    address: str
    chain: str
    kind: str
    old_cursor: int
    new_cursor: int
    old_floor: int | None
    new_floor: int | None
    skipped_from: int | None = None
    skipped_to: int | None = None


def _head_for(chain: str, rpc_url: str | None) -> int | None:
    # ``rpc_for_chain`` treats its second argument as the mainnet seed / override;
    # an unset --rpc-url falls through to the deployment's own mainnet route.
    url = rpc_for_chain(chain, rpc_url or default_rpc_url(chain_id=1) or "")
    try:
        return int(rpc_request(url, "eth_blockNumber", [], chain_id=chain_id_for(chain)), 16)
    except Exception as exc:
        logger.warning(
            "head not determined for chain %s: %s", chain, exc, extra={"chain": chain, "exc_type": type(exc).__name__}
        )
        return None


def plan_clamps(
    session: Session,
    *,
    heads: dict[str, int | None],
    max_lag: int = DEFAULT_MAX_LAG,
    chain: str | None = None,
    address: str | None = None,
) -> list[Clamp]:
    """The repairs the current rows call for. Reads only.

    *heads* maps chain → head block (``None`` = not determined, which suppresses
    the runaway class for that chain; the below-floor class needs no head).
    """
    stmt = select(MonitoredContract).where(MonitoredContract.is_active.is_(True))
    if chain:
        stmt = stmt.where(MonitoredContract.chain == chain)
    if address:
        stmt = stmt.where(MonitoredContract.address == address.lower())

    out: list[Clamp] = []
    for mc in session.execute(stmt).scalars().all():
        cursor = mc.last_scanned_block or 0
        floor = mc.enrollment_block
        if floor is not None and cursor < floor:
            out.append(
                Clamp(
                    address=mc.address,
                    chain=mc.chain,
                    kind=BELOW_FLOOR,
                    old_cursor=cursor,
                    new_cursor=floor,
                    old_floor=floor,
                    new_floor=floor,
                )
            )
            continue
        if floor:  # a real floor and a cursor at or above it — nothing to repair
            continue
        head = heads.get(mc.chain)
        if head is None or head - cursor <= max_lag:
            continue
        out.append(
            Clamp(
                address=mc.address,
                chain=mc.chain,
                kind=UNFLOORED_RUNAWAY,
                old_cursor=cursor,
                new_cursor=head,
                old_floor=floor,
                new_floor=head,
                skipped_from=cursor + 1,
                skipped_to=head,
            )
        )
    return out


def apply_clamps(session: Session, clamps: list[Clamp], *, now: datetime | None = None) -> int:
    """Persist *clamps*. Operator-run only — never called by the dry-run path.

    Returns the number of rows updated.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    updated = 0
    for clamp in clamps:
        mc = session.execute(
            select(MonitoredContract).where(
                MonitoredContract.address == clamp.address,
                MonitoredContract.chain == clamp.chain,
            )
        ).scalar_one_or_none()
        if mc is None:
            continue
        # Re-check under the current row: a scan pass between planning and
        # applying may have advanced the cursor past the target, and a clamp
        # must never rewind one.
        if (mc.last_scanned_block or 0) >= clamp.new_cursor:
            continue
        if clamp.skipped_from is not None:
            config = dict(mc.monitoring_config or {})
            gaps = list(config.get("scan_gaps") or [])
            gaps.append(
                {
                    "from_block": clamp.skipped_from,
                    "to_block": clamp.skipped_to,
                    "reason": clamp.kind,
                    "clamped_at": stamp,
                }
            )
            config["scan_gaps"] = gaps
            mc.monitoring_config = config
        mc.last_scanned_block = clamp.new_cursor
        if clamp.new_floor is not None:
            mc.enrollment_block = clamp.new_floor
        updated += 1
    session.commit()
    return updated


def format_table(clamps: list[Clamp]) -> str:
    if not clamps:
        return "no cursors need clamping"
    header = f"{'address':<44}{'chain':<10}{'kind':<19}{'cursor':>12} -> {'new':>12}{'floor':>12} -> {'new':>12}"
    lines = [header, "-" * len(header)]
    for c in clamps:
        lines.append(
            f"{c.address:<44}{c.chain:<10}{c.kind:<19}{c.old_cursor:>12} -> {c.new_cursor:>12}"
            f"{('null' if c.old_floor is None else c.old_floor):>12} -> "
            f"{('null' if c.new_floor is None else c.new_floor):>12}"
        )
        if c.skipped_from is not None:
            lines.append(f"{'':<44}{'':<10}unscanned interval recorded: [{c.skipped_from}, {c.skipped_to}]")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Write the clamps. Off by default (dry run reports only).")
    ap.add_argument("--chain", default=None, help="Restrict to one chain (monitored_contracts.chain name).")
    ap.add_argument("--address", default=None, help="Restrict to one address.")
    ap.add_argument(
        "--max-lag", type=int, default=DEFAULT_MAX_LAG, help=f"Runaway threshold (default {DEFAULT_MAX_LAG})."
    )
    ap.add_argument(
        "--target-block",
        type=int,
        default=None,
        help="Clamp target for the runaway class instead of reading heads over RPC. "
        "Requires --chain or --address: a block number belongs to exactly one chain.",
    )
    ap.add_argument("--rpc-url", default=None, help="Mainnet RPC seed; other chains resolve their own route.")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.target_block is not None and not (args.chain or args.address):
        # A block number is a fact about ONE chain. Applied fleet-wide it would
        # write a mainnet head as a Base row's cursor AND its enrollment floor —
        # a floor nothing witnessed, on a chain that never reached that height.
        ap.error("--target-block requires --chain or --address (a block number belongs to one chain)")

    with SessionLocal() as session:
        stmt = select(MonitoredContract.chain).where(MonitoredContract.is_active.is_(True)).distinct()
        if args.chain:
            stmt = stmt.where(MonitoredContract.chain == args.chain)
        if args.address:
            stmt = stmt.where(MonitoredContract.address == args.address.lower())
        chains = {c for (c,) in session.execute(stmt).all() if c}

        if args.target_block is not None and len(chains) > 1:
            # The same address is a distinct deployment per chain; one block
            # number cannot be the head of two of them.
            ap.error(f"--target-block selects rows on {len(chains)} chains ({sorted(chains)}); narrow with --chain")

        heads: dict[str, int | None] = {}
        for chain in sorted(chains):
            heads[chain] = args.target_block if args.target_block is not None else _head_for(chain, args.rpc_url)
            if heads[chain] is None:
                logger.warning("chain %s head not determined — its runaway rows are left alone", chain)

        clamps = plan_clamps(session, heads=heads, max_lag=args.max_lag, chain=args.chain, address=args.address)
        print(format_table(clamps))

        if not args.apply:
            print(f"\ndry run: {len(clamps)} row(s) would be clamped. Re-run with --apply to write.")
            return 0

        updated = apply_clamps(session, clamps)
        print(f"\napplied: {updated} row(s) clamped.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
