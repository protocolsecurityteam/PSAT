"""Code-probe backfill (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.3.2).

Runs the gate's own corroboration probe (``membership_gate.probe`` →
``probes.run_probe``) for every contracts row lacking a code fact for its own
(address, chain) — so verdict strictness and attempt persistence are exactly
the live path's. Probes may run on any eRPC-routable chain (invariant 10);
a row on an unroutable chain gets a persisted ``not_routable`` attempt so its
parked state stays explainable (invariant 5), never a silent skip.

Idempotent: rows with a code fact are skipped; rows already parked as
``not_routable`` are skipped unless ``--retry-parked`` (routability only
changes with deployment config). Failed (``rpc_error``) attempts are retried
by default.

**Dry run is the default.** ``--apply`` probes and writes::

    uv run python -m scripts.backfill_code_probes
    uv run python -m scripts.backfill_code_probes --chain base --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Contract, ContractCreationWitness, ContractProbeAttempt, SessionLocal
from services.clients.rpc import chain_id_for_chain_name
from services.discovery import membership_gate as gate
from services.discovery.probes import STATUS_NOT_ROUTABLE, UNRESOLVABLE_CHAIN_ID
from utils.chains import canonical_chain

logger = logging.getLogger(__name__)

#: Rows per commit — an interrupted run keeps every finished probe.
COMMIT_EVERY = 20


def _chain_key(chain: str | None) -> str:
    return ((canonical_chain(chain) or chain) or "ethereum").lower()


def plan_targets(
    session: Session,
    *,
    chain: str | None = None,
    limit: int | None = None,
    retry_parked: bool = False,
) -> tuple[list[int], dict[str, int]]:
    """(contract ids to probe, count breakdown). Reads only.

    A code-absent fact is evidence-at-a-block (spec §3.4), so a pre-gate
    absent verdict must not stand as current: rows whose fact says absent but
    that have NO probe attempt for (contract, chain) — every gate-era probe
    persists one — are re-targeted (``stale_absent_retargeted``). A fresh
    gate-era verdict (attempt row present) is skipped as before.
    """
    probed: dict[tuple[int, str], bool] = {
        (chain_id, address): bool(code_absent)
        for chain_id, address, code_absent in session.execute(
            select(
                ContractCreationWitness.chain_id,
                ContractCreationWitness.address,
                ContractCreationWitness.code_absent_at_probe,
            ).where(ContractCreationWitness.code_probe_block.is_not(None))
        )
    }
    parked: set[tuple[int, int]] = set()
    attempted: set[tuple[int, int]] = set()
    for contract_id, attempt_chain_id, results in session.execute(
        select(ContractProbeAttempt.contract_id, ContractProbeAttempt.chain_id, ContractProbeAttempt.results)
    ):
        status = results.get("status") if isinstance(results, dict) else None
        # An rpc_error attempt is an attempt, never a verdict: it must not
        # let a stale absent fact stand as attempted.
        if status != "rpc_error":
            attempted.add((contract_id, attempt_chain_id))
        if not retry_parked and status == STATUS_NOT_ROUTABLE:
            parked.add((contract_id, attempt_chain_id))

    targets: list[int] = []
    skipped = {"has_code_fact": 0, "parked_not_routable": 0, "stale_absent_retargeted": 0}
    stmt = select(Contract.id, Contract.address, Contract.chain).order_by(Contract.chain, Contract.address, Contract.id)
    for contract_id, address, raw_chain in session.execute(stmt):
        chain_key = _chain_key(raw_chain)
        if chain is not None and chain_key != _chain_key(chain):
            continue
        if not address:
            continue
        chain_id = chain_id_for_chain_name(chain_key)
        stale_absent = False
        if chain_id is not None and (chain_id, address.lower()) in probed:
            code_absent = probed[(chain_id, address.lower())]
            if code_absent and (contract_id, chain_id) not in attempted:
                stale_absent = True
            else:
                skipped["has_code_fact"] += 1
                continue
        attempt_key = UNRESOLVABLE_CHAIN_ID if chain_id is None else chain_id
        if (contract_id, attempt_key) in parked:
            skipped["parked_not_routable"] += 1
            continue
        if stale_absent:
            skipped["stale_absent_retargeted"] += 1
        targets.append(contract_id)
        if limit is not None and len(targets) >= limit:
            break
    return targets, skipped


def run_probes(session: Session, contract_ids: list[int], *, commit: bool = True) -> dict[str, int]:
    """Probe each row through the gate; every outcome persists. Returns
    counts: code_present / code_absent / not_routable / rpc_error."""
    counts = {"code_present": 0, "code_absent": 0, "not_routable": 0, "rpc_error": 0}
    total = len(contract_ids)
    for done, contract_id in enumerate(contract_ids, start=1):
        contract = session.get(Contract, contract_id)
        if contract is None:
            continue
        result = gate.probe(session, contract)
        if not result.routable:
            counts["not_routable"] += 1
        elif result.code_present is None:
            counts["rpc_error"] += 1
        elif result.code_present:
            counts["code_present"] += 1
        else:
            counts["code_absent"] += 1
        if commit and (done % COMMIT_EVERY == 0 or done == total):
            session.commit()
        if done % COMMIT_EVERY == 0 or done == total:
            logger.info("code-probe backfill progress", extra={"done": done, "total": total, **counts})
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Probe and write. Off by default (dry run reports only).")
    ap.add_argument("--chain", default=None, help="Restrict to one chain name.")
    ap.add_argument("--limit", type=int, default=None, help="Cap the number of rows probed this run.")
    ap.add_argument(
        "--retry-parked",
        action="store_true",
        help="Re-attempt rows already parked as not_routable (after a routing/config change).",
    )
    args = ap.parse_args(argv)

    from utils.logging import configure_logging

    configure_logging()

    with SessionLocal() as session:
        targets, skipped = plan_targets(session, chain=args.chain, limit=args.limit, retry_parked=args.retry_parked)
        print(
            f"{len(targets)} row(s) to probe "
            f"({skipped['stale_absent_retargeted']} stale absent re-targeted); "
            "skipped: " + json.dumps(skipped, sort_keys=True)
        )
        if not args.apply:
            print(f"\ndry run: {len(targets)} row(s) would be probed. Re-run with --apply to write.")
            return 0
        counts = run_probes(session, targets)
        print("\napplied: " + json.dumps(counts, sort_keys=True))
        attempted = sum(counts.values())
        if attempted and counts["rpc_error"] == attempted:
            # Every probe failing is a broken wire, not a probed fleet.
            print("every probe attempt failed — check ERPC_BASE_URL / routing", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
