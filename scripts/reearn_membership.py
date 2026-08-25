"""Re-earn migration (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.3.3, invariant 12).

Runs the full membership gate over every existing row: membership is re-earned
from grounded evidence (W5/W6 seeds + stored facts), never inherited from a
row's prior stamp — a member whose only support is another member's prior
stamp does not survive, exactly as the gate would have decided from scratch.

Order per §5.3.3:

1. Legacy ``inventory`` rows convert to W5 witnesses — only where job
   provenance proves the admin submission (the legacy router stamped
   ``discovery_sources=["inventory"]`` on the job request); tag-only rows are
   reported, never converted (the same tag is also written by the inventory
   *search* pipeline, which asserts nothing).
2. DefiLlama-sourced rows that pass W1 get W6 seed witnesses.
3. Every member's stamp is cleared in-session (nomination preserved) and the
   gate's own ``evaluate`` fixpoint re-earns membership from the seeds — two
   passes: pass 1 defers registry evidence-LOSS revocations (the cleared-stamp
   world fabricates loss; positive counterevidence still revokes), pass 2 runs
   the normal gate over the settled world so a genuine loss revokes for real.
4. Members that do not re-earn are DEMOTED to candidate through
   ``demote_member`` (``protocol_id`` → NULL, ``nominated_protocol_id`` kept,
   enrollment/scoring marked dirty), each logged with its closest-miss
   evidence. Nothing is ever deleted (invariant 12).

The printed diff is a FULL-TABLE membership comparison: a ``--protocol-id``
filter targets the seeding/clearing, but any cross-protocol cascade the
fixpoint causes (a deployer collision demoting another protocol's member)
appears in the report with its own line and counts.

**``--report`` (default) prints the full diff and rolls back — the owner
reviews the demotion list before ``--apply``. Never auto-applied on deploy.**
Etherscan spend is bounded: only Class-B deployer enumerations touch the wire,
capped by ``--enumeration-budget`` — and a ``--report`` run followed by
``--apply`` pays that enumeration cost twice (each run enumerates afresh;
``txlist`` is not cached).

    uv run python -m scripts.reearn_membership
    uv run python -m scripts.reearn_membership --protocol-id 1 --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.models import (
    ADMITTING_WITNESS_RULES,
    WITNESS_RULE_W5_HUMAN,
    Contract,
    ContractMembershipWitness,
    Job,
    ProtocolDeployer,
    SessionLocal,
)
from scripts.membership_reporting import active_witness_rules, closest_miss, format_row_line
from services.discovery import membership_gate as gate
from services.discovery.deployer_enumeration import session_deployer_enumerator
from services.discovery.membership_gate import _witness_fact_holds

logger = logging.getLogger(__name__)

#: W5 actor for converted legacy ``inventory`` rows — the honest record that
#: the assertion is a conversion of recorded history, not a fresh submission.
CONVERSION_ACTOR = "legacy_inventory_conversion"

DEFAULT_ENUMERATION_BUDGET = 50


@dataclass(frozen=True)
class RowChange:
    kind: str  # promote | demote | prune | w5skip
    contract_id: int
    address: str
    chain: str | None
    protocol_id: int
    detail: dict[str, Any]


@dataclass
class ReearnReport:
    converted_w5: list[int] = field(default_factory=list)
    w5_provenance_missing: list[int] = field(default_factory=list)
    seeded_w6: list[int] = field(default_factory=list)
    changes: list[RowChange] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


class BudgetedEnumerator:
    """The shared worker-context enumerator, capped. Past the budget every
    verdict is (nothing, incomplete) — which can never license Class B — and
    the refused EOA is RECORDED so the report can name the budget, not the
    chain, as the missing piece (item: budget honesty). Results are memoized,
    so one EOA costs one budget charge across both evaluate passes.

    ``budget`` must be ≥ 1: a zero budget means "no enumerator" and is
    expressed by passing ``enumerator=None`` (the CLI's ``0`` does exactly
    that), never by an enumerator that refuses everything."""

    def __init__(self, session: Session, budget: int) -> None:
        if budget < 1:
            raise ValueError("budget must be >= 1; enumeration is disabled by passing enumerator=None")
        self._inner = session_deployer_enumerator(session)
        self._cache: dict[str, tuple[list[str], bool]] = {}
        self.budget = budget
        self.used = 0
        self.exhausted: set[str] = set()

    def __call__(self, deployer: str) -> tuple[list[str], bool]:
        addr = deployer.lower()
        cached = self._cache.get(addr)
        if cached is not None:
            return cached
        if self.used >= self.budget:
            self.exhausted.add(addr)
            logger.warning(
                "deployer enumeration budget exhausted",
                extra={"budget": self.budget, "deployer": addr},
            )
            return [], False
        self.used += 1
        history, complete = self._inner(addr)
        result = (list(history), complete)
        self._cache[addr] = result
        return result


def _target_rows(session: Session, protocol_ids: list[int] | None) -> list[Contract]:
    stmt = select(Contract).where(or_(Contract.protocol_id.is_not(None), Contract.nominated_protocol_id.is_not(None)))
    if protocol_ids:
        stmt = stmt.where(or_(Contract.protocol_id.in_(protocol_ids), Contract.nominated_protocol_id.in_(protocol_ids)))
    return list(session.execute(stmt.order_by(Contract.id)).scalars())


def _claimed_protocol(contract: Contract) -> int | None:
    return contract.protocol_id if contract.protocol_id is not None else contract.nominated_protocol_id


def _has_witness(session: Session, *, contract_id: int, protocol_id: int, rule: str) -> bool:
    return (
        session.execute(
            select(ContractMembershipWitness.id)
            .where(
                ContractMembershipWitness.contract_id == contract_id,
                ContractMembershipWitness.protocol_id == protocol_id,
                ContractMembershipWitness.rule == rule,
            )
            .limit(1)
        ).first()
        is not None
    )


def _admin_inventory_job_exists(session: Session, contract: Contract, protocol_id: int) -> bool:
    """Job provenance for the legacy admin-submission shape: a job for this
    address whose REQUEST carries the router-stamped ``inventory`` source and
    the same protocol linkage. The contract-side tag alone proves nothing —
    the inventory search pipeline writes the same tag."""
    address = (contract.address or "").lower()
    if not address:
        return False
    return (
        session.execute(
            select(Job.id)
            .where(
                func.lower(Job.address) == address,
                Job.request.isnot(None),
                Job.request.contains({"discovery_sources": ["inventory"]}),
                or_(Job.protocol_id == protocol_id, Job.request.contains({"protocol_id": protocol_id})),
            )
            .limit(1)
        ).first()
        is not None
    )


def convert_inventory_to_w5(
    session: Session, rows: list[Contract], *, asserted_at: datetime
) -> tuple[list[int], list[int]]:
    """§5.3.3(a): legacy ``inventory`` rows with proven admin-submission
    provenance convert to a W5 witness (conversion actor + timestamp). Returns
    (converted ids, tag-only ids skipped for missing provenance). A row that
    already carries a W5 row (active or revoked) is left alone."""
    converted: list[int] = []
    skipped: list[int] = []
    for contract in rows:
        protocol_id = _claimed_protocol(contract)
        if protocol_id is None or "inventory" not in (contract.discovery_sources or []):
            continue
        if _has_witness(session, contract_id=contract.id, protocol_id=protocol_id, rule=WITNESS_RULE_W5_HUMAN):
            continue
        if not _admin_inventory_job_exists(session, contract, protocol_id):
            skipped.append(contract.id)
            continue
        gate.write_witness(
            session,
            contract_id=contract.id,
            protocol_id=protocol_id,
            rule=WITNESS_RULE_W5_HUMAN,
            evidence=gate.w5_evidence(actor=CONVERSION_ACTOR, asserted_at=asserted_at),
        )
        converted.append(contract.id)
    return converted, skipped


def seed_w6(session: Session, rows: list[Contract]) -> list[int]:
    """§5.3.3(b): W6 seeds for defillama-sourced rows that pass W1, minted
    through the gate's single W6 producer (``gate.seed_llama_witness``). The
    W6 evidence shape itself requires the code-probe facts (invariant 3), so
    a row without a code-present probe cannot be seeded."""
    return [contract.id for contract in rows if gate.seed_llama_witness(session, contract=contract)]


#: (protocol_id, nominated_protocol_id, state, address, chain) per claimed row.
_Snapshot = dict[int, tuple[int | None, int | None, str, str, str | None]]


def _membership_snapshot(session: Session) -> _Snapshot:
    """FULL-TABLE membership state — the diff base. Never scoped: a scoped run
    can cascade cross-protocol (invariant 8), and every changed row must
    appear in the report."""
    out: _Snapshot = {}
    for contract in session.execute(
        select(Contract).where(or_(Contract.protocol_id.is_not(None), Contract.nominated_protocol_id.is_not(None)))
    ).scalars():
        out[contract.id] = (
            contract.protocol_id,
            contract.nominated_protocol_id,
            gate.resolve_membership_state(session, contract),
            (contract.address or "").lower(),
            contract.chain,
        )
    return out


def run_reearn(
    session: Session,
    *,
    protocol_ids: list[int] | None = None,
    enumerator: gate.DeployerEnumerator | None = None,
    now: datetime | None = None,
) -> ReearnReport:
    """Full re-earn over the targeted rows. Mutates the session without
    committing — the caller commits (``--apply``) or rolls back (``--report``)."""
    stamp = now or datetime.now(timezone.utc)
    rows = _target_rows(session, protocol_ids)
    report = ReearnReport()

    pre = _membership_snapshot(session)

    report.converted_w5, report.w5_provenance_missing = convert_inventory_to_w5(session, rows, asserted_at=stamp)
    report.seeded_w6 = seed_w6(session, rows)

    # §5.3.3(c): membership is re-earned, never carried — clear every stamp
    # (nomination preserved for demotion provenance, invariant 4) and let the
    # gate's own fixpoint settle the member set from the seeds.
    former_members: dict[int, int] = {}
    for contract in rows:
        if contract.protocol_id is not None:
            if contract.nominated_protocol_id is None:
                contract.nominated_protocol_id = contract.protocol_id
            former_members[contract.id] = contract.protocol_id
            contract.protocol_id = None
    session.flush()

    candidate_ids = tuple(sorted(c.id for c in rows if c.nominated_protocol_id is not None))
    # Pass 1: re-ground memberships. The cleared-stamp world must not mint
    # registry LOSS verdicts (it fabricates them); positive counterevidence
    # still revokes.
    gate.evaluate(
        session,
        gate.FactsDelta(recheck_contract_ids=candidate_ids),
        deployer_enumerator=enumerator,
        defer_registry_loss_revocation=True,
    )
    # Pass 2: the normal gate over the settled world — a loss that persists
    # here is real and revokes for real. Every standing registry EOA of the
    # touched protocols is named, so the settled-world ladder check runs even
    # when no candidate happens to name the EOA.
    touched_protocols = sorted(
        {c.protocol_id for c in rows if c.protocol_id is not None}
        | {c.nominated_protocol_id for c in rows if c.nominated_protocol_id is not None}
    )
    standing_registry_eoas = tuple(
        sorted(
            address.lower()
            for (address,) in session.execute(
                select(ProtocolDeployer.address)
                .where(ProtocolDeployer.protocol_id.in_(touched_protocols), ProtocolDeployer.revoked_at.is_(None))
                .distinct()
            )
        )
    )
    gate.evaluate(
        session,
        gate.FactsDelta(recheck_contract_ids=candidate_ids, changed_deployer_addresses=standing_registry_eoas),
        deployer_enumerator=enumerator,
    )

    budget_exhausted = getattr(enumerator, "exhausted", None) or set()

    # §5.3.3(d): demotions, each through the gate primitive with closest-miss.
    for contract_id in sorted(former_members):
        contract = session.get(Contract, contract_id)
        if contract is None:
            continue
        protocol_id = former_members[contract_id]
        if contract.protocol_id is not None:
            # Re-earned — or promoted elsewhere by the fixpoint; either way the
            # stamp is the gate's and must not be clobbered by a restore.
            if contract.protocol_id != protocol_id:
                logger.warning(
                    "former member settled under a different protocol",
                    extra={
                        "contract_id": contract_id,
                        "former_protocol_id": protocol_id,
                        "settled_protocol_id": contract.protocol_id,
                    },
                )
            continue
        miss = closest_miss(session, contract, protocol_id, budget_exhausted_deployers=budget_exhausted)
        for witness in gate.active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id):
            if witness.rule in ADMITTING_WITNESS_RULES and not _witness_fact_holds(
                session,
                contract=contract,
                protocol_id=protocol_id,
                rule=witness.rule,
                evidence=witness.evidence,
                via_address=witness.via_address,
            ):
                gate.revoke_witness(session, witness, reason="reearn_via_fact_not_held")
        contract.protocol_id = protocol_id
        gate.demote_member(session, contract=contract, reason="reearn_no_verified_witness", evidence=miss)

    post = _membership_snapshot(session)

    counts = {
        "converted_w5": len(report.converted_w5),
        "w5_skipped_no_provenance": len(report.w5_provenance_missing),
        "seeded_w6": len(report.seeded_w6),
        "enumeration_budget_exhausted_eoas": len(budget_exhausted),
        "promote": 0,
        "demote": 0,
        "prune": 0,
        "unchanged_member": 0,
        "unchanged_candidate": 0,
        "unchanged_pruned": 0,
        # Rows with neither id (spec §3.1 ``unclaimed``) are outside the model
        # until re-nominated; counted so the report accounts for every row.
        "unclaimed_untouched": session.execute(
            select(func.count())
            .select_from(Contract)
            .where(Contract.protocol_id.is_(None), Contract.nominated_protocol_id.is_(None))
        ).scalar_one(),
    }

    for contract_id in sorted(pre.keys() | post.keys()):
        pre_row = pre.get(contract_id)
        post_row = post.get(contract_id)
        if post_row is None:
            continue  # a claim never disappears (invariant 4)
        _post_protocol, post_nominated, post_state, address, chain = post_row
        pre_state = pre_row[2] if pre_row is not None else "candidate"
        protocol_id = _post_protocol if _post_protocol is not None else post_nominated
        assert protocol_id is not None  # snapshot rows are claimed by construction
        if pre_state == post_state:
            counts[f"unchanged_{post_state}"] += 1
            continue
        contract = session.get(Contract, contract_id)
        assert contract is not None
        if post_state == "member":
            kind = "promote"
            detail: dict[str, Any] = {
                "rules": ",".join(active_witness_rules(session, contract_id=contract_id, protocol_id=protocol_id))
            }
        elif post_state == "pruned":
            kind = "prune"
            detail = closest_miss(session, contract, protocol_id, budget_exhausted_deployers=budget_exhausted)
        else:
            kind = "demote"
            detail = closest_miss(session, contract, protocol_id, budget_exhausted_deployers=budget_exhausted)
        counts[kind] += 1
        report.changes.append(
            RowChange(
                kind=kind, contract_id=contract_id, address=address, chain=chain, protocol_id=protocol_id, detail=detail
            )
        )

    for contract_id in report.w5_provenance_missing:
        row = post.get(contract_id)
        if row is None:
            continue
        protocol_id = row[0] if row[0] is not None else row[1]
        assert protocol_id is not None
        report.changes.append(
            RowChange(
                kind="w5skip",
                contract_id=contract_id,
                address=row[3],
                chain=row[4],
                protocol_id=protocol_id,
                detail={"missing": "admin_provenance", "tag": "inventory"},
            )
        )

    report.counts = counts
    return report


def format_report(report: ReearnReport) -> str:
    lines = [json.dumps(report.counts, sort_keys=True)]
    for change in sorted(report.changes, key=lambda c: (c.kind, c.contract_id)):
        lines.append(
            format_row_line(
                change.kind,
                contract_id=change.contract_id,
                address=change.address,
                chain=change.chain,
                protocol_id=change.protocol_id,
                detail=change.detail,
            )
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Commit the re-earn. Off by default (report rolls back).")
    ap.add_argument("--protocol-id", type=int, action="append", default=None, help="Restrict to one or more protocols.")
    ap.add_argument(
        "--enumeration-budget",
        type=int,
        default=DEFAULT_ENUMERATION_BUDGET,
        help=f"Max Etherscan deployer enumerations this run (default {DEFAULT_ENUMERATION_BUDGET}; 0 disables). "
        "A --report run and the --apply after it each spend their own budget.",
    )
    args = ap.parse_args(argv)

    from utils.logging import configure_logging

    configure_logging()

    with SessionLocal() as session:
        enumerator = BudgetedEnumerator(session, args.enumeration_budget) if args.enumeration_budget > 0 else None
        report = run_reearn(session, protocol_ids=args.protocol_id, enumerator=enumerator)
        print(format_report(report))
        if not args.apply:
            session.rollback()
            print(
                f"\nreport only: {report.counts['promote']} promote / {report.counts['demote']} demote / "
                f"{report.counts['prune']} prune row(s). Nothing written. Re-run with --apply after review."
            )
            return 0
        session.commit()
        print(f"\napplied: {report.counts['promote']} promote / {report.counts['demote']} demote row(s) committed.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
