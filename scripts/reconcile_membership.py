"""Membership reconcile (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3.4 safety net,
§5.4, invariant 13).

Recomputes the gate verdict for every claimed row FROM STORED WITNESSES ONLY —
no probes, no Etherscan — and reports any row whose state disagrees with its
evidence. The verdict is the gate's own ``promote`` run inside a rolled-back
savepoint, so edge validity (via-address still a member, perimeter fact still
held, deployer registry row unrevoked) is re-verified by the gate's own
internals, never a fork of them: reconcile and gate cannot diverge.

Drift on a freshly gated DB is a bug report, never routine correction — the
report exits nonzero so it cannot pass silently.

**``--report`` is the default** (read-only; exit 0 on zero drift, 1 on drift).
``--apply`` fixes drift through the gate primitives (revoke + demote, or
promote), cascading demotions to quiescence, and logs every row::

    uv run python -m scripts.reconcile_membership
    uv run python -m scripts.reconcile_membership --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from db.models import ADMITTING_WITNESS_RULES, Contract, SessionLocal
from scripts.membership_reporting import active_witness_rules, closest_miss, format_row_line, would_promote
from services.discovery import membership_gate as gate
from services.discovery.membership_gate import _revocation_quiescence, _witness_fact_holds

logger = logging.getLogger(__name__)

DRIFT_MEMBER_NO_EVIDENCE = "member_without_supporting_evidence"
DRIFT_CANDIDATE_WITH_EVIDENCE = "candidate_with_supporting_evidence"

#: Fix passes are bounded; drift deep enough to need more is a bug, not load.
_APPLY_PASS_CAP = 10


@dataclass(frozen=True)
class Drift:
    kind: str
    contract_id: int
    address: str
    chain: str | None
    protocol_id: int
    detail: dict[str, Any]


def audit(session: Session, *, protocol_ids: list[int] | None = None) -> list[Drift]:
    """Every claimed row whose stored state disagrees with the gate verdict
    recomputed from its stored witnesses. Reads only (savepoints roll back)."""
    stmt = select(Contract).where(or_(Contract.protocol_id.is_not(None), Contract.nominated_protocol_id.is_not(None)))
    if protocol_ids:
        stmt = stmt.where(or_(Contract.protocol_id.in_(protocol_ids), Contract.nominated_protocol_id.in_(protocol_ids)))
    drifts: list[Drift] = []
    for contract in session.execute(stmt.order_by(Contract.id)).scalars():
        protocol_id = contract.protocol_id if contract.protocol_id is not None else contract.nominated_protocol_id
        assert protocol_id is not None  # the WHERE clause guarantees a claim
        is_member = contract.protocol_id is not None
        supported = would_promote(session, contract, protocol_id)
        if is_member and not supported:
            drifts.append(
                Drift(
                    kind=DRIFT_MEMBER_NO_EVIDENCE,
                    contract_id=contract.id,
                    address=(contract.address or "").lower(),
                    chain=contract.chain,
                    protocol_id=protocol_id,
                    detail=closest_miss(session, contract, protocol_id),
                )
            )
        elif not is_member and supported:
            drifts.append(
                Drift(
                    kind=DRIFT_CANDIDATE_WITH_EVIDENCE,
                    contract_id=contract.id,
                    address=(contract.address or "").lower(),
                    chain=contract.chain,
                    protocol_id=protocol_id,
                    detail={
                        "rules": ",".join(
                            active_witness_rules(session, contract_id=contract.id, protocol_id=protocol_id)
                        )
                    },
                )
            )
    return drifts


def apply_fixes(session: Session, drifts: list[Drift]) -> int:
    """Fix each drift through the gate's own primitives; demotions cascade to
    quiescence so dependents of a fixed row settle in the same pass. Returns
    the number of rows actually fixed (stale drifts and refused promotes
    don't count)."""
    fixed_count = 0
    demoted_addresses: set[str] = set()
    for drift in drifts:
        contract = session.get(Contract, drift.contract_id)
        if contract is None:
            continue
        if drift.kind == DRIFT_MEMBER_NO_EVIDENCE:
            if contract.protocol_id != drift.protocol_id:
                continue
            # Re-verify against the in-pass state: an earlier fix in this
            # pass (a re-promoted via-member) can restore this row's support,
            # and a supported member must never be demoted.
            if would_promote(session, contract, drift.protocol_id):
                continue
            for witness in gate.active_witnesses(session, contract_id=contract.id, protocol_id=drift.protocol_id):
                if witness.rule in ADMITTING_WITNESS_RULES and not _witness_fact_holds(
                    session,
                    contract=contract,
                    protocol_id=drift.protocol_id,
                    rule=witness.rule,
                    evidence=witness.evidence,
                    via_address=witness.via_address,
                ):
                    gate.revoke_witness(session, witness, reason="reconcile_via_fact_not_held")
            gate.demote_member(session, contract=contract, reason="reconcile_drift", evidence=drift.detail)
            if contract.address:
                demoted_addresses.add(contract.address.lower())
            fixed = True
        else:
            # ``promote`` re-verifies the evidence itself; a refusal means the
            # drift went stale within this pass and the next audit re-judges.
            fixed = gate.promote(session, contract=contract, protocol_id=drift.protocol_id)
        if fixed:
            fixed_count += 1
            logger.info(
                "membership drift fixed",
                extra={"kind": drift.kind, "contract_id": drift.contract_id, "protocol_id": drift.protocol_id},
            )
    if demoted_addresses:
        _revocation_quiescence(session, demoted_addresses)
    return fixed_count


def format_drifts(drifts: list[Drift]) -> str:
    if not drifts:
        return "zero drift"
    lines = [json.dumps({d.kind: sum(1 for x in drifts if x.kind == d.kind) for d in drifts}, sort_keys=True)]
    for drift in drifts:
        lines.append(
            format_row_line(
                "drift",
                contract_id=drift.contract_id,
                address=drift.address,
                chain=drift.chain,
                protocol_id=drift.protocol_id,
                detail={"kind": drift.kind, **drift.detail},
            )
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Fix drift. Off by default (report is read-only).")
    ap.add_argument("--protocol-id", type=int, action="append", default=None, help="Restrict to one or more protocols.")
    args = ap.parse_args(argv)

    from utils.logging import configure_logging

    configure_logging()

    with SessionLocal() as session:
        drifts = audit(session, protocol_ids=args.protocol_id)
        print(format_drifts(drifts))
        if not args.apply:
            if drifts:
                print(f"\n{len(drifts)} drifted row(s) — drift on a freshly gated DB is a bug report.")
                return 1
            return 0
        fixed_total = 0
        for _pass in range(_APPLY_PASS_CAP):
            if not drifts:
                break
            fixed_total += apply_fixes(session, drifts)
            drifts = audit(session, protocol_ids=args.protocol_id)
        session.commit()
        print(f"\napplied: {fixed_total} drifted row(s) fixed.")
        if drifts:
            print(f"{len(drifts)} drifted row(s) REMAIN after {_APPLY_PASS_CAP} passes — bug, investigate.")
            print(format_drifts(drifts))
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
