"""Deployer backfill (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.3.1).

Etherscan ``getcontractcreation`` for every contracts row with NULL
``deployer``, routed per chain and chunked 5 addresses/call through
``probes.fetch_creations`` — which persists ``creation_tx_hash`` /
``creation_block`` into ``contract_creation_witnesses``. This script
additionally copies the returned ``contractCreator`` into
``contracts.deployer`` (``fetch_creations`` itself never writes that column).

Rate limiting is the Etherscan client's global ``ETHERSCAN_RATE_LIMIT``
(every call goes through ``etherscan.get``); ``--rate-limit`` overrides it
for this run. Idempotent: a re-run selects only rows still NULL. Rows whose
chain name resolves to no chain id cannot be queried and are reported by
name, never silently dropped.

**Dry run is the default.** ``--apply`` fetches and writes::

    uv run python -m scripts.backfill_deployers
    uv run python -m scripts.backfill_deployers --chain ethereum --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Contract, SessionLocal
from services.clients import etherscan
from services.clients.rpc import chain_id_for_chain_name
from services.discovery.probes import fetch_creations
from utils.chains import canonical_chain

logger = logging.getLogger(__name__)

#: Addresses per fetch_creations call site — 5 Etherscan calls per chunk,
#: one commit per chunk so an interrupted run keeps its progress.
CHUNK = 25


@dataclass(frozen=True)
class Target:
    contract_id: int
    address: str
    chain: str
    chain_id: int


def _chain_key(chain: str | None) -> str:
    # NULL≡'ethereum' — the same mainnet-coalescing convention as the gate.
    return ((canonical_chain(chain) or chain) or "ethereum").lower()


def plan_targets(
    session: Session, *, chain: str | None = None, limit: int | None = None
) -> tuple[list[Target], dict[str, int]]:
    """(fetchable rows, per-chain-name count of rows whose chain id is not
    resolvable). Reads only."""
    stmt = (
        select(Contract.id, Contract.address, Contract.chain)
        .where(Contract.deployer.is_(None))
        .order_by(Contract.chain, Contract.address, Contract.id)
    )
    targets: list[Target] = []
    unresolvable: dict[str, int] = {}
    for contract_id, address, raw_chain in session.execute(stmt):
        chain_key = _chain_key(raw_chain)
        if chain is not None and chain_key != _chain_key(chain):
            continue
        if not address:
            continue
        chain_id = chain_id_for_chain_name(chain_key)
        if chain_id is None:
            unresolvable[chain_key] = unresolvable.get(chain_key, 0) + 1
            continue
        targets.append(Target(contract_id=contract_id, address=address.lower(), chain=chain_key, chain_id=chain_id))
        if limit is not None and len(targets) >= limit:
            break
    return targets, unresolvable


def run_backfill(session: Session, targets: list[Target], *, commit: bool = True, chunk: int = CHUNK) -> dict[str, int]:
    """Fetch creations chunk-by-chunk and fill ``contracts.deployer``.
    Returns counts: filled / unanswered / no_creator."""
    counts = {"filled": 0, "unanswered": 0, "no_creator": 0}
    total = len(targets)
    done = 0
    by_chain: dict[int, list[Target]] = {}
    for target in targets:
        by_chain.setdefault(target.chain_id, []).append(target)
    for chain_id in sorted(by_chain):
        rows = by_chain[chain_id]
        for start in range(0, len(rows), chunk):
            batch = rows[start : start + chunk]
            creations = fetch_creations(session, [t.address for t in batch], chain_id=chain_id)
            for target in batch:
                answer = creations.get(target.address)
                if answer is None:
                    counts["unanswered"] += 1
                    continue
                _tx, _block, creator = answer
                if not creator:
                    counts["no_creator"] += 1
                    continue
                contract = session.get(Contract, target.contract_id)
                if contract is not None and contract.deployer is None:
                    contract.deployer = creator
                    counts["filled"] += 1
            if commit:
                session.commit()
            done += len(batch)
            logger.info(
                "deployer backfill progress",
                extra={"chain_id": chain_id, "done": done, "total": total, **counts},
            )
    return counts


def format_targets(targets: list[Target], unresolvable: dict[str, int]) -> str:
    lines = [f"{len(targets)} row(s) with NULL deployer on resolvable chains"]
    per_chain: dict[str, int] = {}
    for target in targets:
        per_chain[target.chain] = per_chain.get(target.chain, 0) + 1
    for chain in sorted(per_chain):
        lines.append(f"  {chain:<12} {per_chain[chain]}")
    for chain in sorted(unresolvable):
        lines.append(f"  {chain:<12} {unresolvable[chain]} row(s) SKIPPED: chain id not resolvable")
    return "\n".join(lines)


def apply_rate_limit_override(calls_per_sec: int) -> None:
    if calls_per_sec <= 0:
        raise ValueError(f"--rate-limit must be a positive calls/sec, got {calls_per_sec}")
    # The client rate limit is process-global module state; this run-scoped
    # override is the operator control the client does not expose itself.
    etherscan._min_interval = 1.0 / calls_per_sec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Fetch and write. Off by default (dry run reports only).")
    ap.add_argument("--chain", default=None, help="Restrict to one chain name.")
    ap.add_argument("--limit", type=int, default=None, help="Cap the number of rows processed this run.")
    ap.add_argument(
        "--rate-limit", type=int, default=None, help="Override ETHERSCAN_RATE_LIMIT (calls/sec) for this run."
    )
    args = ap.parse_args(argv)

    from utils.logging import configure_logging

    configure_logging()

    if args.rate_limit is not None:
        apply_rate_limit_override(args.rate_limit)

    with SessionLocal() as session:
        targets, unresolvable = plan_targets(session, chain=args.chain, limit=args.limit)
        print(format_targets(targets, unresolvable))
        if not args.apply:
            print(f"\ndry run: {len(targets)} row(s) would be fetched. Re-run with --apply to write.")
            return 0
        counts = run_backfill(session, targets)
        print("\napplied: " + json.dumps(counts, sort_keys=True))
        if targets and counts["filled"] == 0:
            # A whole run answering nothing is the silent-starvation shape
            # (expired key, exhausted quota) — fail loud, not green.
            print("no rows filled — check ETHERSCAN_API_KEY / quota", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
