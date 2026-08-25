"""Re-earn migration (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.3.3, invariant 12).

Runs the full membership gate over every existing row: membership is re-earned
from grounded evidence (W5/W6 seeds + stored facts), never inherited from a
row's prior stamp — a member whose only support is another member's prior
stamp does not survive, exactly as the gate would have decided from scratch.

Order per §5.3.3:

1. Legacy ``inventory`` source-tag rows convert to W5 witnesses (those rows
   WERE admin-submitted; the actor records the conversion honestly).
2. DefiLlama-sourced rows that pass W1 get W6 seed witnesses.
3. Every member's stamp is cleared in-session (nomination preserved) and the
   gate's own ``evaluate`` fixpoint re-earns membership from the seeds.
4. Members that do not re-earn are DEMOTED to candidate through
   ``demote_member`` (``protocol_id`` → NULL, ``nominated_protocol_id`` kept,
   enrollment/scoring marked dirty), each logged with its closest-miss
   evidence. Nothing is ever deleted (invariant 12).

**``--report`` (default) prints the full diff and rolls back — the owner
reviews the demotion list before ``--apply``. Never auto-applied on deploy.**
Etherscan spend is bounded: only Class-B deployer enumerations touch the wire,
capped by ``--enumeration-budget``.

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
    WITNESS_RULE_W6_LLAMA_SEED,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    Protocol,
    SessionLocal,
)
from scripts.membership_reporting import active_witness_rules, closest_miss, format_row_line
from services.clients.rpc import chain_id_for_chain_name
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
    kind: str  # promote | demote | prune
    contract_id: int
    address: str
    chain: str | None
    protocol_id: int
    detail: dict[str, Any]


@dataclass
class ReearnReport:
    converted_w5: list[int] = field(default_factory=list)
    seeded_w6: list[int] = field(default_factory=list)
    changes: list[RowChange] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def budgeted_enumerator(session: Session, budget: int) -> gate.DeployerEnumerator:
    """The shared worker-context enumerator, capped: past the budget every
    verdict is (nothing, incomplete) — which can never license Class B, only
    defer it to a later run."""
    inner = session_deployer_enumerator(session)
    used = {"n": 0}

    def _enumerate(deployer: str) -> tuple[list[str], bool]:
        if used["n"] >= budget:
            logger.warning(
                "deployer enumeration budget exhausted",
                extra={"budget": budget, "deployer": deployer},
            )
            return [], False
        used["n"] += 1
        history, complete = inner(deployer)
        return list(history), complete

    return _enumerate


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


def convert_inventory_to_w5(session: Session, rows: list[Contract], *, asserted_at: datetime) -> list[int]:
    """§5.3.3(a): legacy ``inventory`` source-tag rows were admin-submitted;
    record that as a W5 witness with the conversion actor + timestamp. A row
    that already carries a W5 row (active or revoked) is left alone."""
    converted: list[int] = []
    for contract in rows:
        protocol_id = _claimed_protocol(contract)
        if protocol_id is None or "inventory" not in (contract.discovery_sources or []):
            continue
        if _has_witness(session, contract_id=contract.id, protocol_id=protocol_id, rule=WITNESS_RULE_W5_HUMAN):
            continue
        gate.write_witness(
            session,
            contract_id=contract.id,
            protocol_id=protocol_id,
            rule=WITNESS_RULE_W5_HUMAN,
            evidence=gate.w5_evidence(actor=CONVERSION_ACTOR, asserted_at=asserted_at),
        )
        converted.append(contract.id)
    return converted


def seed_w6(session: Session, rows: list[Contract]) -> list[int]:
    """§5.3.3(b): W6 seeds for defillama-sourced rows that pass W1. The W6
    evidence shape itself requires the code-probe facts (invariant 3), so a
    row without a code-present probe cannot be seeded."""
    seeded: list[int] = []
    protocols: dict[int, Protocol | None] = {}
    for contract in rows:
        protocol_id = _claimed_protocol(contract)
        if protocol_id is None or "defillama" not in (contract.discovery_sources or []):
            continue
        chain_id = chain_id_for_chain_name(contract.chain)
        if chain_id is None or not contract.address:
            continue
        code_row = session.get(ContractCreationWitness, (chain_id, contract.address.lower()))
        if code_row is None or code_row.code_probe_block is None or code_row.code_absent_at_probe:
            continue
        if _has_witness(session, contract_id=contract.id, protocol_id=protocol_id, rule=WITNESS_RULE_W6_LLAMA_SEED):
            continue
        if protocol_id not in protocols:
            protocols[protocol_id] = session.get(Protocol, protocol_id)
        protocol = protocols[protocol_id]
        if protocol is None:
            continue
        # Adapter provenance: the DefiLlama family slug when resolved, else
        # the protocol name the adapter scan matched on.
        adapter_slug = protocol.canonical_slug or protocol.name
        gate.write_witness(
            session,
            contract_id=contract.id,
            protocol_id=protocol_id,
            rule=WITNESS_RULE_W6_LLAMA_SEED,
            evidence=gate.w6_evidence(
                adapter_slug=adapter_slug,
                chain_id=chain_id,
                code_probe_block=code_row.code_probe_block,
            ),
        )
        seeded.append(contract.id)
    return seeded


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

    pre_state: dict[int, str] = {c.id: gate.resolve_membership_state(session, c) for c in rows}

    report.converted_w5 = convert_inventory_to_w5(session, rows, asserted_at=stamp)
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
    gate.evaluate(
        session,
        gate.FactsDelta(recheck_contract_ids=candidate_ids),
        deployer_enumerator=enumerator,
    )

    # §5.3.3(d): demotions, each through the gate primitive with closest-miss.
    for contract_id in sorted(former_members):
        contract = session.get(Contract, contract_id)
        if contract is None:
            continue
        protocol_id = former_members[contract_id]
        if contract.protocol_id == protocol_id:
            continue
        miss = closest_miss(session, contract, protocol_id)
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

    counts = {
        "converted_w5": len(report.converted_w5),
        "seeded_w6": len(report.seeded_w6),
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
    for contract in rows:
        post = gate.resolve_membership_state(session, contract)
        pre = pre_state[contract.id]
        protocol_id = _claimed_protocol(contract)
        assert protocol_id is not None  # _target_rows selects claimed rows only
        if pre == post:
            counts[f"unchanged_{post}"] += 1
            continue
        if post == "member":
            kind = "promote"
            detail: dict[str, Any] = {
                "rules": ",".join(active_witness_rules(session, contract_id=contract.id, protocol_id=protocol_id))
            }
        elif post == "pruned":
            kind = "prune"
            detail = closest_miss(session, contract, protocol_id)
        else:
            kind = "demote"
            detail = closest_miss(session, contract, protocol_id)
        counts[kind] += 1
        report.changes.append(
            RowChange(
                kind=kind,
                contract_id=contract.id,
                address=(contract.address or "").lower(),
                chain=contract.chain,
                protocol_id=protocol_id,
                detail=detail,
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
        help=f"Max Etherscan deployer enumerations this run (default {DEFAULT_ENUMERATION_BUDGET}; 0 disables).",
    )
    args = ap.parse_args(argv)

    from utils.logging import configure_logging

    configure_logging()

    with SessionLocal() as session:
        enumerator = budgeted_enumerator(session, args.enumeration_budget) if args.enumeration_budget > 0 else None
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
